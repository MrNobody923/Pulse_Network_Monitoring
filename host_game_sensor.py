"""Windows Host DNS (UDP 53) & Syslog (UDP 514) Game Sensor preserving exact LAN client IPs.

Runs directly on the host OS outside Docker Desktop bridge NAT so incoming DNS queries
and router syslogs keep the real client phone/PC IP (192.168.x.y) before forwarding
game detections to http://127.0.0.1:3000/api/gaming/detect.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from pulse_monitor.config import DATA_DIR, utc_now
from pulse_monitor.game_detector import (
    GameDetectorMixin,
    MONITOR_ONLY_IDS,
    _NETSTAT_GAME_PORTS,
    host_game_processes,
    list_windows_processes,
)
from pulse_monitor.wireshark_capture import WiresharkCaptureEngine


def _detect_local_lan_ip(
    upstream_dns: str = "192.168.0.1", fallback: str = ""
) -> str:
    for probe_target in (upstream_dns or "192.168.0.1", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.3)
                s.connect((probe_target, 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith(("127.", "169.254.")):
                    return ip
        except OSError:
            continue
    return fallback


def _detect_hotspot_ip() -> str:
    try:
        _host, _aliases, addrs = socket.gethostbyname_ex(socket.gethostname())
        for ip in addrs:
            if ip == "192.168.137.1":
                return ip
    except OSError:
        pass
    return ""


class HostGameSensor:
    """Listens on host UDP/TCP 53 (DNS forwarding), UDP 514 (Syslog), LAN broadcasts, processes & ports."""

    def __init__(
        self,
        dns_host: str = "auto",
        dns_port: int = 53,
        syslog_port: int = 514,
        upstream_dns: str = "192.168.0.1",
        api_url: str = "http://127.0.0.1:3000/api/gaming/detect",
        detect_processes: bool = True,
        endpoint_player: str = "",
        endpoint_token: str = "",
    ) -> None:
        self._auto_dns_host = not dns_host or dns_host.strip().lower() == "auto"
        self.dns_host = (
            _detect_local_lan_ip(upstream_dns)
            if self._auto_dns_host
            else dns_host.strip()
        )
        self.hotspot_ip = _detect_hotspot_ip()
        self.dns_port = dns_port
        self.syslog_port = syslog_port
        self.upstream_dns = upstream_dns
        self.api_url = api_url.rstrip("/")
        self._endpoint_player = endpoint_player
        self._endpoint_token = endpoint_token
        base_api = self.api_url.rsplit("/", 1)[0]
        self.blocks_url = base_api + "/blocks"
        self.activity_url = base_api + "/activity"
        self.dismiss_url = base_api + "/dismiss"
        self.heartbeat_url = base_api + "/sensor-heartbeat"
        self._lock = threading.Lock()
        self._dns_worker_slots = threading.BoundedSemaphore(32)
        self._report_slots = threading.BoundedSemaphore(16)
        self._recent_hits: dict[tuple[str, str], float] = {}
        self._active_blocks: list[dict] = []
        self._prevention_mode: str = "alert_only"
        self._flushed_rule_ids: set[str] = set()
        self._detect_processes = detect_processes
        self._dns_forwarding_enabled = os.environ.get("PULSE_ENABLE_DNS_FORWARDING") == "1"
        self._network_changes_enabled = os.environ.get("PULSE_ALLOW_NETWORK_CHANGES") == "1"
        self._background_scans_enabled = os.environ.get("PULSE_ENABLE_BACKGROUND_SCANS") == "1"
        self._last_process_report: dict[tuple[str, str], float] = {}
        self._active_lan_port_hits: dict[tuple[str, str], float] = {}
        self._lan_port_misses: dict[tuple[str, str], int] = {}
        self._dns_queries_total: int = 0
        self._dns_blocked_total: int = 0
        self._dns_forwarded_total: int = 0
        self._dns_forward_failures: int = 0
        self._dns_clients: dict[str, str] = {}
        self._last_dns_client_ip: str = ""
        self._last_dns_domain: str = ""
        self._last_dns_at: str | None = None
        self._bound_dns_ips: set[str] = set()
        self._forwarded_dns_domains: dict[str, float] = {}
        self._wireshark_engine: WiresharkCaptureEngine | None = None
        self._stop = threading.Event()

    def _is_blocked(self, client_ip: str, game_id: str) -> dict | None:
        with self._lock:
            blocks = list(self._active_blocks)
        for rule in blocks:
            if rule.get("scope") == "device_throttle" or rule.get("cutRouters"):
                continue
            if rule.get("ip") in (client_ip, "*") and (
                rule.get("gameId") in (game_id, "*")
                or rule.get("scope") in {"device_all_games", "device_wifi_cut"}
            ):
                return rule
        return None

    def _ensure_wireshark_engine(self) -> WiresharkCaptureEngine:
        if self._wireshark_engine is None:
            infra_set = {x for x in (self.upstream_dns, "192.168.0.1") if x}
            self_set = {x for x in (self.dns_host, self.hotspot_ip) if x}
            self._wireshark_engine = WiresharkCaptureEngine(
                on_detection=self._handle_wireshark_detection,
                pcap_path=DATA_DIR / "wireshark_live.pcap",
                custom_tshark_path=os.environ.get("PULSE_TSHARK_PATH", ""),
                is_forwarded_dns_fn=self._is_forwarded_dns_query,
                infra_ips=infra_set,
                self_ips=self_set,
            )
        return self._wireshark_engine

    def _is_forwarded_dns_query(self, ip: str, domain: str) -> bool:
        if ip not in {self.dns_host, self.hotspot_ip}:
            return False
        dom = str(domain or "").strip().lower()
        if not dom:
            return False
        with self._lock:
            ts = self._forwarded_dns_domains.get(dom)
        return bool(ts is not None and (time.monotonic() - ts) < 4.0)

    def _handle_wireshark_detection(self, payload: dict) -> None:
        client_ip = str(payload.get("ip") or "").strip()
        game_id = str(payload.get("gameId") or "").strip()
        if not client_ip or not game_id:
            return
        if self._should_report(client_ip, game_id, cooldown=3.5):
            print(
                f"[host-sensor] {payload.get('detectionMethod', 'Wireshark')} {client_ip} -> "
                f"{payload.get('matchedIndicator') or game_id}",
                flush=True,
            )
            self._submit_live_detection(payload)

    def _submit_live_detection(self, payload: dict) -> None:
        if not self._report_slots.acquire(blocking=False):
            return

        def deliver() -> None:
            try:
                for retry_delay in (0.5, 1.5, None):
                    if self._post_detection(payload):
                        return
                    if retry_delay is None or self._stop.wait(retry_delay):
                        return
            finally:
                self._report_slots.release()

        try:
            threading.Thread(target=deliver, daemon=True).start()
        except RuntimeError:
            self._report_slots.release()

    def _apply_policy_and_blocks(self, payload: dict) -> None:
        blocks = payload.get("blocks")
        policy = payload.get("policy")
        ws_cfg = payload.get("wireshark")
        with self._lock:
            if not self._network_changes_enabled or not (isinstance(policy, dict) and policy.get("restrictionsEnabled") is True):
                self._active_blocks = []
                self._prevention_mode = "alert_only"
            elif isinstance(blocks, list):
                self._active_blocks = [rule for rule in blocks if isinstance(rule, dict) and not rule.get("controlStatus")]
                self._prevention_mode = str(policy.get("preventionMode") or "alert_only").strip().lower()
        if isinstance(ws_cfg, dict) and self._wireshark_engine is not None:
            self._wireshark_engine.configure(
                enabled=ws_cfg.get("enabled"),
                selected_interfaces=ws_cfg.get("selectedInterfaces"),
            )

    def _send_sensor_heartbeat(self) -> None:
        ws_status = self._wireshark_engine.status_snapshot() if self._wireshark_engine is not None else None
        with self._lock:
            hb_payload = {
                "pid": os.getpid(),
                "dnsHost": self.dns_host,
                "dnsPort": self.dns_port,
                "dnsForwardingEnabled": self._dns_forwarding_enabled,
                "hotspotIp": self.hotspot_ip,
                "dnsQueriesTotal": self._dns_queries_total,
                "dnsBlockedTotal": self._dns_blocked_total,
                "dnsForwardedTotal": self._dns_forwarded_total,
                "dnsForwardFailures": self._dns_forward_failures,
                "dnsClients": dict(self._dns_clients),
                "lastDnsClientIp": self._last_dns_client_ip,
                "lastDnsDomain": self._last_dns_domain,
                "lastDnsAt": self._last_dns_at,
                "wireshark": ws_status,
            }
        body = json.dumps(hb_payload).encode("utf-8")
        req = urllib.request.Request(
            self.heartbeat_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                self._apply_policy_and_blocks(json.loads(resp.read().decode("utf-8")))
        except Exception:
            pass

    def _sync_blocks_loop(self) -> None:
        last_heartbeat = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            if (now - last_heartbeat) >= 1.8:
                if getattr(self, "_auto_dns_host", False):
                    latest_ip = _detect_local_lan_ip(self.upstream_dns)
                    if latest_ip != self.dns_host:
                        self.dns_host = latest_ip
                        if "0.0.0.0" not in self._bound_dns_ips:
                            self._ensure_dns_listeners(self.dns_host)
                self.hotspot_ip = _detect_hotspot_ip()
                if self._auto_dns_host and self.hotspot_ip and "0.0.0.0" not in self._bound_dns_ips:
                    self._ensure_dns_listeners(self.hotspot_ip)
                self._send_sensor_heartbeat()
                last_heartbeat = now
            elif self._network_changes_enabled:
                try:
                    with urllib.request.urlopen(self.blocks_url, timeout=1.2) as resp:
                        self._apply_policy_and_blocks(json.loads(resp.read().decode("utf-8")))
                except Exception:
                    pass
            if self._stop.wait(0.35):
                break

    def _should_report(self, client_ip: str, game_id: str, cooldown: float = 4.0) -> bool:
        now = time.monotonic()
        key = (client_ip, game_id)
        with self._lock:
            prev = self._recent_hits.get(key)
            if prev is not None and (now - prev) < cooldown:
                return False
            self._recent_hits[key] = now
            return True

    def _post_json(self, url: str, payload: dict) -> bool:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self._endpoint_token:
            req.add_unredirected_header("Authorization", f"Bearer {self._endpoint_token}")
        try:
            with urllib.request.urlopen(req, timeout=3.0):
                return True
        except Exception as exc:
            print(f"[host-sensor] POST {url} warning: {exc}", flush=True)
            return False

    def _post_detection(self, payload: dict) -> bool:
        if self._endpoint_player:
            payload = {"ip": payload["ip"], "process": payload["process"], "player": self._endpoint_player}
        else:
            payload = {**payload, "includeActivity": False}
        return self._post_json(self.api_url, payload)

    def _post_dismiss(self, client_ip: str, game_id: str) -> bool:
        if self._endpoint_player:
            return self._post_json(self.api_url, {
                "ip": client_ip, "gameId": game_id, "player": self._endpoint_player, "ended": True,
            })
        return self._post_json(self.dismiss_url, {"ip": client_ip, "gameId": game_id})

    @staticmethod
    def _subprocess_flags() -> int:
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)) if sys.platform == "win32" else 0

    def _scan_host_processes(self, running_procs: list[str]) -> None:
        current = host_game_processes(self.dns_host, running_procs) if self.dns_host else {}
        last_report = self._last_process_report
        for key in last_report.keys() - current.keys():
            if self._post_dismiss(*key):
                del last_report[key]
        for key, payload in current.items():
            now = time.monotonic()
            if key not in last_report or now - last_report[key] >= 6:
                if self._post_detection(payload):
                    last_report[key] = now

    def _host_process_loop(self) -> None:
        next_heartbeat = 0.0
        while not self._stop.is_set():
            processes = list_windows_processes(current_session_only=bool(self._endpoint_player))
            if processes is not None:
                now = time.monotonic()
                if self._endpoint_player and now >= next_heartbeat:
                    next_heartbeat = now + 30
                    self._post_json(self.api_url, {
                        "ip": self.dns_host, "heartbeat": True,
                    })
                self._scan_host_processes(processes)
            self._stop.wait(1)

    def _sweep_lan_game_ports(self) -> None:
        try:
            with urllib.request.urlopen(self.activity_url, timeout=2.0) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return

        devices = payload.get("onlineDevices") or []
        ips = [
            str(d.get("ip") or "").strip()
            for d in devices
            if isinstance(d, dict)
            and str(d.get("ip") or "").strip()
            and not bool(d.get("isMobile"))
        ]
        if not ips:
            return

        now = time.monotonic()
        lan_listen_ports = (27036, 27015, 19132, 25565)
        hits = GameDetectorMixin._batch_scan_ports_nonblocking(ips[:80], lan_listen_ports, timeout_sec=0.12)
        seen_now: dict[tuple[str, str], int] = {}
        for ip_key, open_port in hits.items():
            sig = GameDetectorMixin._match_game_signature(port=open_port)
            if not sig:
                continue
            key = (ip_key, sig["id"])
            seen_now[key] = open_port
            self._lan_port_misses.pop(key, None)
            if self._is_blocked(ip_key, sig["id"]):
                continue
            prev_ts = self._active_lan_port_hits.get(key)
            if prev_ts is None or (now - prev_ts) >= 35.0:
                if prev_ts is None:
                    print(
                        f"[host-sensor] Auto Port {ip_key}:{open_port} -> [{sig['name']}]",
                        flush=True,
                    )
                self._active_lan_port_hits[key] = now

        ip_set = set(ips)
        for key in list(self._active_lan_port_hits.keys()):
            ip_k, gid = key
            if key in seen_now or ip_k not in ip_set:
                continue
            misses = self._lan_port_misses.get(key, 0) + 1
            if misses >= 2:
                self._lan_port_misses.pop(key, None)
                self._active_lan_port_hits.pop(key, None)
            else:
                self._lan_port_misses[key] = misses

    def _enforce_active_blocks(self) -> None:
        with self._lock:
            blocks = [r for r in self._active_blocks if r.get("scope") != "device_throttle" and not r.get("cutRouters")]
        if not blocks:
            self._flushed_rule_ids.clear()
            return

        active_rule_ids = {str(r.get("id") or "") for r in blocks}
        self._flushed_rule_ids.intersection_update(active_rule_ids)

        host_rules = [r for r in blocks if r.get("ip") in (self.dns_host, "*")]
        if host_rules and sys.platform == "win32":
            new_host_ids = [
                str(r.get("id") or "")
                for r in host_rules
                if str(r.get("id") or "") and str(r.get("id") or "") not in self._flushed_rule_ids
            ]
            if new_host_ids:
                try:
                    subprocess.run(
                        ["ipconfig", "/flushdns"],
                        capture_output=True,
                        text=True,
                        timeout=2.5,
                        creationflags=self._subprocess_flags(),
                    )
                    self._flushed_rule_ids.update(new_host_ids)
                except Exception:
                    pass
            try:
                procs = list_windows_processes() or []
                killed_procs: set[str] = set()
                for proc_name in procs:
                    if not proc_name or proc_name.lower() in killed_procs:
                        continue
                    sig = GameDetectorMixin._match_game_signature(process=proc_name)
                    if sig and sig["id"] not in MONITOR_ONLY_IDS and self._is_blocked(self.dns_host, sig["id"]):
                        killed_procs.add(proc_name.lower())
                        subprocess.run(
                            ["taskkill", "/F", "/IM", proc_name],
                            capture_output=True,
                            text=True,
                            timeout=2.5,
                            creationflags=self._subprocess_flags(),
                        )
                        print(
                            f"[host-sensor] Terminated blocked game process: {proc_name} [{sig['name']}]",
                            flush=True,
                        )
            except Exception:
                pass

    def _scan_host_netstat_ports(self) -> None:
        if sys.platform != "win32":
            return
        try:
            res = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True,
                text=True,
                timeout=2.5,
                creationflags=self._subprocess_flags(),
            )
            if res.returncode != 0:
                return
        except Exception:
            return

        own_pid = str(os.getpid())
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0].upper() != "TCP" or parts[3].upper() != "ESTABLISHED":
                continue
            if parts[-1] == own_pid or ":" not in parts[1] or ":" not in parts[2]:
                continue
            local_ip = parts[1].rsplit(":", 1)[0].strip("[]")
            remote_ip = parts[2].rsplit(":", 1)[0].strip("[]")
            if local_ip != self.dns_host:
                continue
            try:
                remote_port = int(parts[2].rsplit(":", 1)[1])
                r_addr = ipaddress.ip_address(remote_ip)
            except ValueError:
                continue
            if r_addr.is_private or r_addr.is_loopback or r_addr.is_link_local or r_addr.is_multicast:
                continue
            if remote_port not in _NETSTAT_GAME_PORTS:
                continue
            sig = GameDetectorMixin._match_game_signature(port=remote_port)
            if not sig or self._is_blocked(self.dns_host, sig["id"]):
                continue
            if self._should_report(self.dns_host, sig["id"], cooldown=5.0):
                print(
                    f"[host-sensor] Outbound {parts[1]} -> {parts[2]} [{sig['name']}]",
                    flush=True,
                )
                self._post_detection({
                    "ip": self.dns_host,
                    "gameId": sig["id"],
                    "port": remote_port,
                    "matchedIndicator": f"TCP -> {parts[2]}",
                    "detectionMethod": "Auto Outbound Game Connection (netstat)",
                })

    def _auto_detect_loop(self) -> None:
        last_lan_sweep = float("-inf")
        while not self._stop.is_set():
            try:
                self._enforce_active_blocks()
                self._scan_host_netstat_ports()
                now = time.monotonic()
                if self._background_scans_enabled and (now - last_lan_sweep) >= 90.0:
                    last_lan_sweep = now
                    self._sweep_lan_game_ports()
            except Exception as exc:
                print(f"[host-sensor] Auto-detect loop warning: {exc}", flush=True)
            if self._stop.wait(1.0):
                break

    def _process_dns_query(self, raw: bytes, client_ip: str) -> bytes | None:
        """Process raw DNS query for both UDP and TCP 53 listeners; return reply bytes or upstream forward."""
        if len(raw) < 12 or raw[2] & 0x80:
            return None
        qname = GameDetectorMixin._extract_dns_qname(raw)
        now_iso = utc_now()
        with self._lock:
            self._dns_queries_total += 1
            if client_ip:
                self._dns_clients[client_ip] = now_iso
                if len(self._dns_clients) > 256:
                    oldest_key = next(iter(self._dns_clients))
                    self._dns_clients.pop(oldest_key, None)
            self._last_dns_client_ip = client_ip
            if qname:
                self._last_dns_domain = qname
            self._last_dns_at = now_iso
            blocks = list(self._active_blocks)
            prev_mode = self._prevention_mode

        if qname:
            if self._network_changes_enabled and GameDetectorMixin._is_doh_canary_domain(qname):
                return GameDetectorMixin._build_dns_nxdomain_reply(raw)

            sig = GameDetectorMixin._match_game_signature(domain=qname)
            action_rule = GameDetectorMixin._should_sinkhole_query(
                client_ip, qname, sig, blocks
            )
            auto_prevent = sig is not None and sig["id"] not in MONITOR_ONLY_IDS and prev_mode in {"auto_block_game", "auto_wifi_cut"}

            if action_rule is not None or auto_prevent:
                with self._lock:
                    self._dns_blocked_total += 1
                sink = GameDetectorMixin._build_dns_sinkhole_reply(raw)
                if action_rule is None and sig is not None and self._should_report(client_ip, sig["id"]):
                    print(
                        f"[host-sensor] REALTIME AUTO-PREVENT {client_ip} -> {qname} [{sig['name']}]",
                        flush=True,
                    )
                    self._submit_live_detection({
                        "ip": client_ip,
                        "gameId": sig["id"],
                        "domain": qname,
                        "autoPrevented": True,
                        "detectionMethod": f"Live DNS Auto-Prevent ({self.dns_host}:{self.dns_port})",
                    })
                elif self._should_report(client_ip, f"blk-{(sig['id'] if sig else 'wifi')}", cooldown=15.0):
                    print(
                        f"[host-sensor] BLOCKED DNS {client_ip} -> {qname} (0.0.0.0 sinkhole)",
                        flush=True,
                    )
                return sink

            if sig:
                if self._should_report(client_ip, sig["id"], cooldown=4.0):
                    print(
                        f"[host-sensor] DNS {client_ip} -> {qname} [{sig['name']}]",
                        flush=True,
                    )
                    self._submit_live_detection({
                        "ip": client_ip,
                        "gameId": sig["id"],
                        "domain": qname,
                        "detectionMethod": f"Live DNS ({self.dns_host}:{self.dns_port})",
                    })

        # Loop-safe upstream forwarding: public domains go directly to 1.1.1.1 / 8.8.8.8 so router DHCP DNS never loops back
        if qname and client_ip not in {self.dns_host, self.hotspot_ip, "127.0.0.1"}:
            with self._lock:
                self._forwarded_dns_domains[qname.lower()] = time.monotonic()
        is_local_name = (not qname) or ("." not in qname) or qname.endswith((".local", ".lan", ".home", ".internal", ".arpa"))
        upstreams = (
            (self.upstream_dns, "1.1.1.1", "8.8.8.8")
            if is_local_name
            else ("1.1.1.1", "8.8.8.8", self.upstream_dns)
        )
        seen_up: set[str] = set()
        for upstream in upstreams:
            if not upstream or upstream in (self.dns_host, self.hotspot_ip) or upstream in seen_up:
                continue
            seen_up.add(upstream)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fwd:
                    fwd.settimeout(1.2)
                    fwd.connect((upstream, 53))
                    fwd.send(raw)
                    resp = fwd.recv(4096)
                if len(resp) < 12 or resp[:2] != raw[:2] or not (resp[2] & 0x80):
                    continue
                with self._lock:
                    self._dns_forwarded_total += 1
                return resp
            except OSError:
                continue
        with self._lock:
            self._dns_forward_failures += 1
        return None

    def _handle_dns_udp_packet(self, sock: socket.socket, raw: bytes, client_addr: tuple[str, int]) -> None:
        reply = self._process_dns_query(raw, client_addr[0])
        if reply:
            try:
                sock.sendto(reply, client_addr)
            except OSError:
                pass

    def _start_dns_worker(self, handler, *args) -> bool:
        if not self._dns_worker_slots.acquire(blocking=False):
            return False

        def run() -> None:
            try:
                handler(*args)
            finally:
                self._dns_worker_slots.release()

        try:
            threading.Thread(target=run, daemon=True).start()
        except RuntimeError:
            self._dns_worker_slots.release()
            return False
        return True

    def _handle_dns_tcp_client(self, conn: socket.socket, client_addr: tuple[str, int]) -> None:
        try:
            conn.settimeout(2.0)
            hdr = bytearray()
            while len(hdr) < 2:
                chunk = conn.recv(2 - len(hdr))
                if not chunk:
                    return
                hdr.extend(chunk)
            msg_len = int.from_bytes(hdr, "big")
            if msg_len <= 0 or msg_len > 4096:
                return
            raw = bytearray()
            while len(raw) < msg_len:
                chunk = conn.recv(msg_len - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) < msg_len:
                return
            reply = self._process_dns_query(bytes(raw), client_addr[0])
            if reply:
                conn.sendall(len(reply).to_bytes(2, "big") + reply)
        except OSError:
            pass
        finally:
            conn.close()

    def _run_dns_udp_listener(self, bind_host: str) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, self.dns_port))
            sock.settimeout(1.0)
            print(f"[host-sensor] Live DNS forwarder listening on {bind_host}:{self.dns_port}/udp -> {self.upstream_dns}:53", flush=True)
        except OSError as exc:
            print(f"[host-sensor] DNS UDP listener bind {bind_host}:{self.dns_port} skipped: {exc}", flush=True)
            sock.close()
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    self._start_dns_worker(self._handle_dns_udp_packet, sock, data, addr)
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            sock.close()

    def _run_dns_tcp_listener(self, bind_host: str) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, self.dns_port))
            sock.listen(32)
            sock.settimeout(1.0)
            print(f"[host-sensor] Live DNS TCP listener active on {bind_host}:{self.dns_port}/tcp", flush=True)
        except OSError as exc:
            print(f"[host-sensor] DNS TCP listener bind {bind_host}:{self.dns_port} skipped: {exc}", flush=True)
            sock.close()
            return

        try:
            while not self._stop.is_set():
                try:
                    conn, addr = sock.accept()
                    if not self._start_dns_worker(self._handle_dns_tcp_client, conn, addr):
                        conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            sock.close()

    def _run_broadcast_game_listener(self, port: int, game_id: str, label: str) -> None:
        """Listen for real-time LAN broadcast game discovery packets (Minecraft Bedrock 19132 / Steam 27036)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.settimeout(1.0)
            print(f"[host-sensor] Real-time LAN {label} listener active on 0.0.0.0:{port}/udp", flush=True)
        except OSError:
            sock.close()
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                client_ip = addr[0]
                if not client_ip or client_ip.startswith("127."):
                    continue
                valid_sig = (
                    (game_id == "minecraft" and (b"MCPE;" in data or (len(data) > 20 and b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe" in data)))
                    or (game_id == "steam" and len(data) >= 8 and data.startswith((b"\xff\xff\xff\xff", b"\x21\x4c\x5f\xa0")))
                )
                if valid_sig and self._should_report(client_ip, game_id, cooldown=5.0):
                    print(
                        f"[host-sensor] LAN Broadcast {client_ip}:{port} -> [{label}]",
                        flush=True,
                    )
                    self._submit_live_detection({
                        "ip": client_ip,
                        "gameId": game_id,
                        "port": port,
                        "matchedIndicator": f"UDP Broadcast :{port} ({label})",
                        "detectionMethod": "Real-Time LAN Broadcast Listener",
                    })
        finally:
            sock.close()

    def _run_syslog_listener(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.syslog_port))
            sock.settimeout(1.0)
            print(f"[host-sensor] Router Syslog listener active on 0.0.0.0:{self.syslog_port}/udp", flush=True)
        except OSError as exc:
            print(f"[host-sensor] Syslog listener bind 0.0.0.0:{self.syslog_port} skipped: {exc}", flush=True)
            sock.close()
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                text = data.decode("utf-8", "ignore")
                sender_ip = addr[0]
                matched_domain = ""
                sig = None
                for dm in re.findall(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){1,5}\b", text):
                    sig = GameDetectorMixin._match_game_signature(domain=dm)
                    if sig:
                        matched_domain = dm.lower()
                        break
                matched_port = None
                if sig is None:
                    pm = re.search(r"(?:DPT|dst_port|port)[=: ]+(\d{2,5})", text, re.I)
                    if pm:
                        sig = GameDetectorMixin._match_game_signature(port=pm.group(1))
                        if sig:
                            matched_port = int(pm.group(1))
                if sig is None:
                    continue

                client_ip = GameDetectorMixin._syslog_game_client_ip(text, sender_ip)
                if not client_ip:
                    continue
                if self._should_report(client_ip, sig["id"], cooldown=4.0):
                    print(
                        f"[host-sensor] Syslog {client_ip} (via {sender_ip}) -> {matched_domain or matched_port} [{sig['name']}]",
                        flush=True,
                    )
                    self._submit_live_detection({
                        "ip": client_ip,
                        "reporterIp": sender_ip,
                        "gameId": sig["id"],
                        "domain": matched_domain,
                        "port": matched_port,
                        "detectionMethod": f"Router Syslog (UDP {self.syslog_port})",
                    })
        finally:
            sock.close()

    def _ensure_dns_listeners(self, bind_ip: str) -> None:
        if not self._dns_forwarding_enabled:
            return
        clean_ip = str(bind_ip or "").strip()
        if not clean_ip:
            return
        with self._lock:
            if clean_ip in self._bound_dns_ips:
                return
            self._bound_dns_ips.add(clean_ip)
        threading.Thread(target=self._run_dns_udp_listener, args=(clean_ip,), daemon=True).start()
        threading.Thread(target=self._run_dns_tcp_listener, args=(clean_ip,), daemon=True).start()

    def serve_forever(self) -> None:
        ws_engine = self._ensure_wireshark_engine()
        ws_engine.start()

        threads = [
            threading.Thread(target=self._run_syslog_listener, daemon=True),
            threading.Thread(target=self._sync_blocks_loop, daemon=True),
            threading.Thread(target=self._auto_detect_loop, daemon=True),
            threading.Thread(
                target=self._run_broadcast_game_listener, args=(19132, "minecraft", "Minecraft LAN"), daemon=True
            ),
            threading.Thread(
                target=self._run_broadcast_game_listener, args=(27036, "steam", "Steam Discovery"), daemon=True
            ),
        ]
        for t in threads:
            t.start()
        if self._detect_processes and sys.platform == "win32":
            threading.Thread(target=self._host_process_loop, daemon=True).start()
        self._ensure_dns_listeners(self.dns_host)
        print(
            f"[host-sensor] Passive capture and syslog enabled. DNS forwarding: {'on' if self._dns_forwarding_enabled else 'off'}.",
            flush=True,
        )
        try:
            self._stop.wait()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            ws_engine.stop()

    def stop(self) -> None:
        self._stop.set()


def main() -> int:
    parser = argparse.ArgumentParser(description="Host DNS & Syslog Game Sensor for Pulse Network Monitor")
    parser.add_argument("--dns-host", default="auto", help="Host LAN IP to bind UDP/TCP port 53 (default: auto)")
    parser.add_argument("--dns-port", type=int, default=53, help="Host DNS UDP/TCP port (default: 53)")
    parser.add_argument("--syslog-port", type=int, default=514, help="Host Syslog UDP port (default: 514)")
    parser.add_argument("--upstream-dns", default="192.168.0.1", help="Upstream DNS server (default: 192.168.0.1)")
    parser.add_argument("--api-url", default="http://127.0.0.1:3000/api/gaming/detect", help="Monitor API endpoint")
    parser.add_argument("--no-process-detection", action="store_true", help="Use when server.py already runs on this Windows host")
    parser.add_argument("--process-only", action="store_true", help="Report this Windows sign-in session to a central monitor")
    args = parser.parse_args()

    if args.process_only:
        if sys.platform != "win32" or args.no_process_detection:
            parser.error("--process-only requires Windows and process detection")
        token = os.environ.get("PULSE_GAME_ENDPOINT_TOKEN", "")
        endpoint = urllib.parse.urlsplit(args.api_url)
        if not token:
            parser.error("Set PULSE_GAME_ENDPOINT_TOKEN to the central monitor's enrollment token")
        if endpoint.scheme not in {"http", "https"} or not endpoint.hostname or endpoint.path.rstrip("/") != "/api/gaming/endpoint":
            parser.error("Set --api-url to the central monitor's /api/gaming/endpoint URL")
        account = getpass.getuser()
        domain = os.environ.get("USERDOMAIN")
        sensor = HostGameSensor(
            dns_host=_detect_local_lan_ip(endpoint.hostname, "127.0.0.1"),
            api_url=args.api_url,
            endpoint_player=f"{domain}\\{account}" if domain else account,
            endpoint_token=token,
        )
        print(f"[game-endpoint] Watching this Windows sign-in session; reports go to {endpoint.hostname}", flush=True)
        try:
            sensor._host_process_loop()
        except KeyboardInterrupt:
            pass
        return 0

    sensor = HostGameSensor(
        dns_host=args.dns_host,
        dns_port=args.dns_port,
        syslog_port=args.syslog_port,
        upstream_dns=args.upstream_dns,
        api_url=args.api_url,
        detect_processes=not args.no_process_detection,
    )
    sensor.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

