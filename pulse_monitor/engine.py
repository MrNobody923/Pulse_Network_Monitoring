"""Core Monitor engine orchestrating storage, LAN discovery, probes, alerts, and SSE events."""

from __future__ import annotations

import json
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .alerts import AlertsMixin
from .config import DEFAULT_CONFIG, merge_config, utc_now
from .diagnostics import DiagnosticsMixin
from .discovery import DiscoveryMixin
from .game_detector import GameDetectorMixin
from .isp_speed import IspSpeedMixin
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
):
    """Central network monitoring engine managing telemetry loops and state snapshots."""

    def __init__(self) -> None:
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

        self.lock = threading.RLock()
        self.event_subscribers: set[object] = set()
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
        self.router_state = self._initial_router_state()
        self.router_fleet: list[dict] = [self.router_state]
        self.isp_state = self._initial_isp_state()
        self._hydrate_ping_history()
        self._stop = threading.Event()
        self._scan_lock = threading.Lock()
        self._speedtest_lock = threading.Lock()
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
            self.latest_devices.get(device["ip"], {**device, "status": "unknown"})
            for device in self.get_devices()
        ]

    def probe_all_devices(self) -> list[dict]:
        """Probe all monitored Access Points, Switches, and Gateways concurrently and correlate diagnostics."""
        devices = self.get_devices()
        if not devices:
            return []
        with ThreadPoolExecutor(max_workers=min(16, len(devices))) as pool:
            results = list(pool.map(self.probe_device, devices))
        self.enrich_fleet_diagnostics(results)
        self.latest_devices = {result["ip"]: result for result in results}
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
                "liveRxMbps": live.get("rxMbps"),
                "liveTxMbps": live.get("txMbps"),
                "liveSource": live.get("source"),
            },
            "counts": {
                "devicesTotal": len(devices),
                "devicesOnline": sum(1 for d in devices if d.get("alive")),
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
            target=self._game_realtime_loop, daemon=True, name="game-realtime"
        ).start()
        self.start_game_listeners()

    def stop(self) -> None:
        self._stop.set()

    def _game_realtime_loop(self) -> None:
        while not self._stop.is_set():
            try:
                expired = self.expire_stale_game_sessions()
                if expired:
                    self.broadcast("game_detected", {"gameActivity": self.get_game_activity(60)})
                if hasattr(self, "poll_router_logs_for_games"):
                    self.poll_router_logs_for_games()
            except Exception as exc:
                print(f"[monitor] Realtime game loop warning: {exc}", flush=True)
            self._stop.wait(4.0)

    def _isp_ping_loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                router = self.probe_router()
                isp = self.probe_isp()
                self.broadcast("router_update", {**router, "fleet": self.get_router_fleet()})
                self.broadcast("isp_update", isp)
            except Exception as exc:
                print(f"[monitor] Router/ISP probe failed: {exc}", flush=True)
            try:
                interval = max(5, min(60, int(self.config.get("isp", {}).get("pollIntervalSec", 5))))
            except (TypeError, ValueError):
                interval = 10
            self._stop.wait(max(1.0, interval - (time.monotonic() - started)))

    def _monitor_loop(self) -> None:
        last_scan_attempt: float | None = None
        last_arp_sync: float = 0.0
        while not self._stop.is_set():
            cycle_started = time.monotonic()

            results = self.probe_all_devices()
            try:
                fleet = self.probe_routers_fleet()
            except Exception as exc:
                print(f"[monitor] Multi-router fleet probe warning: {exc}", flush=True)
                fleet = self.get_router_fleet()
            if (cycle_started - last_arp_sync) >= 45 and hasattr(self, "refresh_live_arp_and_infra"):
                last_arp_sync = cycle_started
                try:
                    self.refresh_live_arp_and_infra()
                except Exception as exc:
                    print(f"[monitor] Live ARP sync warning: {exc}", flush=True)
            try:
                self.expire_stale_game_sessions()
                self.scan_lan_for_games()
            except Exception as exc:
                print(f"[monitor] Automatic LAN game scan warning: {exc}", flush=True)
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
                    "devices": results if results else self._hydrated_devices(),
                    "topology": self.get_topology(),
                    "activeAlerts": self.get_active_alerts(),
                    "alertStats": self.get_alert_stats(),
                    "networkEvents": self.get_events(200),
                    **({"gameActivity": game_activity} if game_activity is not None else {}),
                },
            )
            full_sweep_due = (
                self._daily_discovery_due()
                or last_scan_attempt is None
                or (cycle_started - last_scan_attempt >= 300)
            )
            if full_sweep_due and (
                last_scan_attempt is None or cycle_started - last_scan_attempt >= 120
            ):
                last_scan_attempt = cycle_started
                try:
                    self.discover_devices()
                    results = self.probe_all_devices()
                    fleet = self.probe_routers_fleet()
                    self.broadcast(
                        "telemetry",
                        {
                            "timestamp": utc_now(),
                            "router": self.router_state,
                            "routers": fleet,
                            "isp": self.get_isp_state(),
                            "devices": results if results else self._hydrated_devices(),
                            "topology": self.get_topology(),
                            "networkInventory": self.get_inventory(),
                            "lastDiscoveryAt": self.last_discovery_at(),
                            "activeAlerts": self.get_active_alerts(),
                            "alertStats": self.get_alert_stats(),
                        },
                    )
                except (RuntimeError, OSError) as exc:
                    print(f"[monitor] Real-time LAN discovery failed: {exc}", flush=True)
            try:
                poll_interval = max(
                    5, min(20, int(self.config.get("devicePollIntervalSec", 15)))
                )
            except (TypeError, ValueError):
                poll_interval = 15
            self._stop.wait(max(0.5, poll_interval - (time.monotonic() - cycle_started)))

