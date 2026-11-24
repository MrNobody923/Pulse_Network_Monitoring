"""Core Monitor engine orchestrating storage, LAN discovery, probes, alerts, and SSE events."""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .alerts import AlertsMixin
from .config import DEFAULT_CONFIG, merge_config, utc_now
from .diagnostics import DiagnosticsMixin
from .discovery import DiscoveryMixin
from .game_detector import GameDetectorMixin, host_game_processes, list_windows_processes
from .isp_speed import IspSpeedMixin
from .operations import OperationsMixin
from .port_scanner import PortScannerMixin
from .probes import ProbesMixin
from .storage import StorageMixin
from .topology import TopologyMixin


class Monitor(
    StorageMixin,
    DiscoveryMixin,
    AlertsMixin,
    IspSpeedMixin,
    ProbesMixin,
    DiagnosticsMixin,
    PortScannerMixin,
    TopologyMixin,
    GameDetectorMixin,
    OperationsMixin,
):
    """Central network monitoring engine managing telemetry loops and state snapshots."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        data_dir = self._data_dir()
        config_file = self._config_file()
        data_dir.mkdir(parents=True, exist_ok=True)
        if config_file.exists():
            try:
                self.config = merge_config(
                    json.loads(config_file.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Unable to load {config_file}: {exc}") from exc
        else:
            self.config = json.loads(json.dumps(DEFAULT_CONFIG))
            self.save_config()

        self.event_subscribers: set[queue.Queue[dict | None]] = set()
        self._discovered_networks: list[ipaddress.IPv4Network] = []
        self._skip_live_probe_in_test = False
        self.history: dict[str, list[float | None]] = {}
        self.device_status: dict[str, bool] = {}
        self.latest_devices: dict[str, dict] = {}
        self.active_alerts: dict[str, dict] = {
            alert["key"]: alert
            for alert in self.config.get("alerts", [])
            if alert.get("key")
            and alert.get("status") in {"ACTIVE", "ACKNOWLEDGED", "INVESTIGATING"}
        }
        self._event_store()
        self._topology_store()
        self._game_store()
        self._operations_store()
        self.router_state = self._initial_router_state()
        self.router_fleet: list[dict] = [self.router_state]
        self.isp_state = self._initial_isp_state()
        self._hydrate_ping_history()
        self._stop = threading.Event()
        self._scan_lock = threading.Lock()
        self._speedtest_lock = threading.Lock()
        self._device_probe_lock = threading.Lock()
        self._next_device_probe: dict[str, tuple[str, float]] = {}
        self._switch_sample_lock = threading.Lock()
        self._isp_probe_lock = threading.Lock()
        self._last_speedtest = 0.0
        try:
            self.refresh_inventory_identities(resolve_live=False)
        except Exception as exc:
            print(f"[monitor] Inventory identity refresh warning: {exc}", flush=True)
        try:
            self.sync_infrastructure_devices()
        except Exception as exc:
            print(f"[monitor] Initial infrastructure sync warning: {exc}", flush=True)
        try:
            self._prune_orphaned_device_alerts()
        except Exception as exc:
            print(f"[monitor] Alert cleanup warning: {exc}", flush=True)

    def _hydrated_devices(self) -> list[dict]:
        return [
            {
                "status": "unknown",
                **device,
                **self.latest_devices.get(device["ip"], {}),
                "favorite": device.get("favorite", False),
                "favoriteKey": device.get(
                    "favoriteKey",
                    f"mac:{device['mac'].lower()}" if device.get("mac") else f"ip:{device['ip']}",
                ),
                "archived": device.get("archived", False),
                "probeIntervalSec": self.device_probe_interval(device),
            }
            for device in self.get_devices()
        ]

    def probe_all_devices(self) -> list[dict]:
        """Probe all monitored Access Points, Switches, and Gateways concurrently and correlate diagnostics."""
        return self._probe_device_batch(force=True)

    def device_probe_interval(self, device: dict) -> int:
        try:
            base = max(5, min(20, int(self.config.get("devicePollIntervalSec", 15))))
        except (TypeError, ValueError):
            base = 15
        role = str(device.get("type") or "").lower()
        if role in {"gateway", "router", "switch", "firewall"}:
            return base
        return max(30 if role in {"ap", "server"} else 60, base)

    def _probe_device_batch(self, *, force: bool = False) -> list[dict]:
        with self._device_probe_lock:
            devices = self.get_devices()
            now = time.monotonic()
            active_ids = {device["id"] for device in devices}
            self._next_device_probe = {key: value for key, value in self._next_device_probe.items() if key in active_ids}
            due = []
            for device in devices:
                last_ip, deadline = self._next_device_probe.get(device["id"], ("", 0.0))
                if force or (not device["archived"] and (last_ip != device["ip"] or now >= deadline)):
                    due.append(device)
            if not due:
                return []
            before = self.latest_devices.copy()
            with ThreadPoolExecutor(max_workers=min(16, len(due))) as pool:
                results = list(pool.map(self.probe_device, due))
            with self.lock:
                active = {device["ip"]: device["id"] for device in self.config["devices"]}
                merged = {ip: result for ip, result in self.latest_devices.items() if active.get(ip) == result.get("id")}
                for result in results:
                    ip, device_id = result["ip"], result["id"]
                    if active.get(ip) != device_id:
                        continue
                    previous = before.get(ip, {})
                    first_failure = result.get("connectivityState") == "DEVICE_DOWN" and previous.get("connectivityState") != "DEVICE_DOWN"
                    delay = 5 if first_failure else self.device_probe_interval(result)
                    self._next_device_probe[device_id] = (ip, time.monotonic() + delay)
                    merged[ip] = result
                self.enrich_fleet_diagnostics(list(merged.values()))
                self.latest_devices = merged
            return results

    def get_mobile_summary(self) -> dict:
        """Return a compact, mobile-app-ready status payload for dashboard & push/polling clients."""
        from .config import API_VERSION

        devices = self._hydrated_devices()
        isp = self.get_isp_state()
        router = dict(self.router_state)
        topo = self.get_topology()
        alerts = self.get_active_alerts()
        live = isp.get("liveThroughput") or {}
        last_speed = isp.get("lastSpeedTest") or {}

        down_devices = [
            {
                "id": d.get("id"),
                "name": d.get("name"),
                "ip": d.get("ip"),
                "type": d.get("type"),
                "status": d.get("connectivityState") or d.get("status"),
                "latencyMs": d.get("latencyMs"),
                "diagnosisTitle": d.get("diagnosisTitle"),
                "likelyFault": d.get("likelyFault"),
                "fixSteps": d.get("fixSteps", []),
            }
            for d in devices
            if not d.get("archived") and (d.get("status") in {"offline", "warning"} or not d.get("alive", True))
        ]

        return {
            "apiVersion": API_VERSION,
            "serverTime": utc_now(),
            "health": {
                "overall": isp.get("overallHealth", "UNKNOWN"),
                "score": isp.get("healthScore"),
                "routerReachable": bool(router.get("reachable")),
                "wanInternetStatus": router.get("wanInternetStatus", "UNKNOWN"),
            },
            "router": {
                "ip": router.get("ip"),
                "model": router.get("model"),
                "reachable": bool(router.get("reachable")),
                "telemetryAvailable": bool(router.get("telemetryAvailable")),
            },
            "routers": [
                {
                    "ip": r.get("ip"),
                    "model": r.get("model"),
                    "role": r.get("role"),
                    "reachable": bool(r.get("reachable")),
                    "latencyMs": r.get("latencyMs"),
                    "openPorts": r.get("openPorts", []),
                    "telemetryAvailable": bool(r.get("telemetryAvailable")),
                }
                for r in self.get_router_fleet()
            ],
            "isp": {
                "provider": (isp.get("provider") or {}).get("provider"),
                "asn": (isp.get("provider") or {}).get("asn"),
                "publicIp": (isp.get("provider") or {}).get("publicIp"),
                "location": (isp.get("provider") or {}).get("location"),
                "latencyMs": isp.get("tier1LatencyMs"),
                "gatewayLatencyMs": isp.get("wanGatewayLatencyMs"),
                "jitterMs": isp.get("jitterMs"),
                "dnsMs": isp.get("dnsResolutionMs"),
                "packetLossPct": isp.get("packetLossPct"),
                "downloadMbps": last_speed.get("downloadMbps"),
                "uploadMbps": last_speed.get("uploadMbps"),
                "speedTestAt": last_speed.get("timestamp"),
                "monitorWifiSignal": live.get("wifiSignal"),
                "liveRxMbps": live.get("rxMbps"),
                "liveTxMbps": live.get("txMbps"),
                "liveSource": live.get("source"),
                "routerWanThroughput": isp.get("routerWanThroughput"),
                "probeFailurePct": isp.get("probeFailurePct"),
                "probeTimestamp": isp.get("probeTimestamp"),
            },
            "counts": {
                "devicesTotal": len(devices),
                "devicesOnline": sum(1 for d in devices if d.get("alive") and d.get("directlyReachable") is not False),
                "devicesObservedOnly": sum(1 for d in devices if d.get("connectivityState") == "ARP_OBSERVED"),
                "devicesDown": sum(1 for d in devices if d.get("status") == "offline"),
                "devicesDegraded": sum(1 for d in devices if d.get("status") == "warning"),
                "activeAlerts": len(alerts),
                "criticalAlerts": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
                "topology": topo.get("summary", {}),
            },
            "problemDevices": down_devices,
            "activeAlerts": alerts[:25],
            "recentEvents": self.get_events(20),
            "gameActivity": self.get_game_activity(60),
        }

    def snapshot(self) -> dict:
        return {
            "timestamp": utc_now(),
            "router": self.router_state,
            "routers": self.get_router_fleet(),
            "isp": self.get_isp_state(),
            "devices": self._hydrated_devices(),
            "activeAlerts": self.get_active_alerts(),
            "alertsHistory": self.get_alerts(30),
            "alertStats": self.get_alert_stats(),
            "networkInventory": self.get_inventory(),
            "networkEvents": self.get_events(200),
            "topology": self.get_topology(),
            "gameActivity": self.get_game_activity(60),
            "lastDiscoveryAt": self.last_discovery_at(),
            "config": {
                "backgroundScansEnabled": os.environ.get("PULSE_ENABLE_BACKGROUND_SCANS") == "1",
                "routerConfig": {
                    "ip": self.config["router"].get("ip", "192.168.0.1"),
                    "hasToken": bool(self.config["router"].get("stok")),
                },
            },
        }

    def broadcast(self, event_type: str, data: dict) -> None:
        payload = {"event": event_type, "data": data}
        with self.lock:
            subscribers = list(self.event_subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(payload)
            except queue.Full:
                with self.lock:
                    self.event_subscribers.discard(subscriber)
                while True:
                    try:
                        subscriber.get_nowait()
                    except queue.Empty:
                        break
                try:
                    subscriber.put_nowait(None)
                except queue.Full:
                    pass

    def start(self) -> None:
        try:
            nets = ", ".join(str(n) for n in self._known_local_networks()) or "Local LAN"
            dev_count = len(self.get_devices())
            gw_ip = self.config.get("router", {}).get("ip", "192.168.0.1")
            self._record_event(
                "MONITOR_START",
                "INFO",
                "Network Monitor Stream Started",
                f"Active telemetry started on {nets} — monitoring {dev_count} device(s), gateway {gw_ip}, and external WAN probes.",
                ip=gw_ip,
                device_name="Pulse Network Engine",
            )
        except Exception:
            pass
        threading.Thread(
            target=self._monitor_loop, daemon=True, name="network-monitor"
        ).start()
        threading.Thread(
            target=self._isp_ping_loop, daemon=True, name="isp-ping"
        ).start()
        threading.Thread(
            target=self._wan_throughput_loop, daemon=True, name="wan-throughput"
        ).start()
        threading.Thread(
            target=self._router_wan_loop, daemon=True, name="router-wan-throughput"
        ).start()
        threading.Thread(
            target=self._game_realtime_loop, daemon=True, name="game-realtime"
        ).start()
        threading.Thread(
            target=self._game_control_expiry_loop, daemon=True, name="game-control-expiry"
        ).start()
        threading.Thread(target=self._operations_loop, daemon=True, name="incident-notifications").start()
        threading.Thread(target=self._switch_ports_loop, daemon=True, name="switch-ports").start()
        if sys.platform == "win32":
            threading.Thread(
                target=self._host_game_process_loop, daemon=True, name="game-processes"
            ).start()
        self.start_game_listeners()

    def stop(self) -> None:
        self._stop.set()

    def _host_game_process_loop(self) -> None:
        last_seen: dict[tuple[str, str], float] = {}
        while not self._stop.is_set():
            try:
                processes = list_windows_processes()
                if processes is not None:
                    router_ip = self.config.get("router", {}).get("ip") or ""
                    host_ip = self._detect_host_lan_ip("127.0.0.1", router_ip)
                    current = host_game_processes(host_ip, processes)
                    for key in last_seen.keys() - current.keys():
                        self.mark_game_session_ended_by_ip_game(*key)
                        del last_seen[key]
                    for key, payload in current.items():
                        now = time.monotonic()
                        if key not in last_seen or now - last_seen[key] >= 6:
                            self.record_game_detection(payload)
                            last_seen[key] = now
            except Exception as exc:
                print(f"[monitor] Windows game process scan warning: {exc}", flush=True)
            self._stop.wait(1)

    def _game_realtime_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.expire_stale_game_sessions()
                if hasattr(self, "poll_router_logs_for_games"):
                    self.poll_router_logs_for_games()
            except Exception as exc:
                print(f"[monitor] Realtime game loop warning: {exc}", flush=True)
            self._stop.wait(4.0)

    def _isp_ping_loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                isp = self.probe_isp()
                self.broadcast("isp_update", isp)
            except Exception as exc:
                print(f"[monitor] Router/ISP probe failed: {exc}", flush=True)
            try:
                interval = max(8, min(60, int(self.config.get("isp", {}).get("pollIntervalSec", 10))))
            except (TypeError, ValueError):
                interval = 10
            self._stop.wait(max(1.0, interval - (time.monotonic() - started)))

    def _monitor_loop(self) -> None:
        background_scans = os.environ.get("PULSE_ENABLE_BACKGROUND_SCANS") == "1"
        last_scan_attempt: float | None = None
        last_arp_sync: float = 0.0
        last_game_scan: float = 0.0
        next_fleet_check = 0.0
        while not self._stop.is_set():
            cycle_started = time.monotonic()

            probed = self._probe_device_batch()
            fleet_checked = cycle_started >= next_fleet_check
            try:
                if fleet_checked:
                    next_fleet_check = cycle_started + self.device_probe_interval({"type": "router"})
                fleet = self.probe_routers_fleet() if fleet_checked else self.get_router_fleet()
            except Exception as exc:
                print(f"[monitor] Multi-router fleet probe warning: {exc}", flush=True)
                fleet = self.get_router_fleet()
            if background_scans and (cycle_started - last_arp_sync) >= 30:
                last_arp_sync = cycle_started
                try:
                    self.refresh_live_arp_and_infra()
                except Exception as exc:
                    print(f"[monitor] Live ARP sync warning: {exc}", flush=True)
            if background_scans and (cycle_started - last_game_scan) >= 90:
                try:
                    last_game_scan = cycle_started
                    self.scan_lan_for_games()
                except Exception as exc:
                    print(f"[monitor] Automatic LAN game scan warning: {exc}", flush=True)
            if probed or fleet_checked:
                try:
                    game_activity = self.get_game_activity(60)
                except Exception:
                    game_activity = None
                self.broadcast(
                "telemetry",
                {
                    "timestamp": utc_now(),
                    "router": self.router_state,
                    "routers": fleet,
                    "isp": self.get_isp_state(),
                    "devices": self._hydrated_devices(),
                    "topology": self.get_topology(),
                    "activeAlerts": self.get_active_alerts(),
                    "alertStats": self.get_alert_stats(),
                    "networkEvents": self.get_events(200),
                    **({"gameActivity": game_activity} if game_activity is not None else {}),
                },
                )
            full_sweep_due = background_scans and (
                self._daily_discovery_due()
                or (last_scan_attempt is None and not self.get_inventory())
            )
            if full_sweep_due and (
                last_scan_attempt is None or cycle_started - last_scan_attempt >= 300
            ):
                last_scan_attempt = cycle_started
                try:
                    self.discover_devices()
                    self.probe_all_devices()
                    fleet = self.probe_routers_fleet()
                    self.broadcast(
                        "telemetry",
                        {
                            "timestamp": utc_now(),
                            "router": self.router_state,
                            "routers": fleet,
                            "isp": self.get_isp_state(),
                            "devices": self._hydrated_devices(),
                            "topology": self.get_topology(),
                            "networkInventory": self.get_inventory(),
                            "lastDiscoveryAt": self.last_discovery_at(),
                            "activeAlerts": self.get_active_alerts(),
                            "alertStats": self.get_alert_stats(),
                        },
                    )
                except (RuntimeError, OSError) as exc:
                    print(f"[monitor] Real-time LAN discovery failed: {exc}", flush=True)
            self._stop.wait(max(0.5, 5 - (time.monotonic() - cycle_started)))

