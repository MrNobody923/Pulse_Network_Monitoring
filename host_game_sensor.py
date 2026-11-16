"""Windows Host DNS (UDP 53) & Syslog (UDP 514) Game Sensor preserving exact LAN client IPs.

Runs directly on the host OS outside Docker Desktop bridge NAT so incoming DNS queries
and router syslogs keep the real client phone/PC IP (192.168.x.y) before forwarding
game detections to http://127.0.0.1:3000/api/gaming/detect.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from pulse_monitor.game_detector import GameDetectorMixin, SCAN_GAME_PORTS


_PASSIVE_LAUNCHER_DOMAINS = frozenset({
    "steampowered.com",
    "steamcommunity.com",
    "valvesoftware.com",
    "riotcdn.net",
    "api.steampowered.com",
})

_GAME_SERVER_PORTS = frozenset({
    5000, 5001, 5002, 5551, 30090, 30091, 7500, 7501, 10012,
    17500, 20001, 10010, 10011, 5223, 22101, 22102, 39698, 39800,
    9339, 3659, 17502, 8433, 22023, 8393, 8394, 19132, 25565,
    27015, 27036,
})


class HostGameSensor:
    """Listens on host UDP 53 (DNS forwarding), UDP 514 (Syslog), running processes, DNS cache, and LAN ports."""

    def __init__(
        self,
        dns_host: str = "192.168.0.224",
        dns_port: int = 53,
        syslog_port: int = 514,
        upstream_dns: str = "192.168.0.1",
        api_url: str = "http://127.0.0.1:3000/api/gaming/detect",
    ) -> None:
        self.dns_host = dns_host
        self.dns_port = dns_port
        self.syslog_port = syslog_port
        self.upstream_dns = upstream_dns
        self.api_url = api_url
        base_api = api_url.rsplit("/", 1)[0]
        self.blocks_url = base_api + "/blocks"
        self.activity_url = base_api + "/activity"
        self.dismiss_url = base_api + "/dismiss"
        self._lock = threading.Lock()
        self._recent_hits: dict[tuple[str, str], float] = {}
        self._active_blocks: list[dict] = []
        self._flushed_rule_ids: set[str] = set()
        self._active_host_processes: set[str] = set()
        self._seen_dns_cache_domains: set[str] = set()
        self._dns_cache_initialized = False
        self._stop = threading.Event()

    def _is_blocked(self, client_ip: str, game_id: str) -> dict | None:
        with self._lock:
            blocks = list(self._active_blocks)
        for rule in blocks:
            if rule.get("ip") in (client_ip, "*") and (
                rule.get("gameId") in (game_id, "*")
                or rule.get("scope") in {"device_all_games", "device_wifi_cut"}
            ):
                return rule
        return None

    def _sync_blocks_loop(self) -> None:
        while not self._stop.is_set():
            try:
                with urllib.request.urlopen(self.blocks_url, timeout=1.5) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                blocks = payload.get("blocks")
                if isinstance(blocks, list):
                    with self._lock:
                        self._active_blocks = blocks
            except Exception:
                pass
            if self._stop.wait(1.0):
                break

    def _should_report(self, client_ip: str, game_id: str, cooldown: float = 25.0) -> bool:
        now = time.monotonic()
        key = (client_ip, game_id)
        with self._lock:
            prev = self._recent_hits.get(key)
            if prev is not None and (now - prev) < cooldown:
                return False
            self._recent_hits[key] = now
            return True

    def _post_json(self, url: str, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0):
                pass
        except Exception as exc:
            print(f"[host-sensor] POST {url} warning: {exc}", flush=True)

    def _post_detection(self, payload: dict) -> None:
        self._post_json(self.api_url, payload)

    def _post_dismiss(self, client_ip: str, game_id: str) -> None:
        self._post_json(self.dismiss_url, {"ip": client_ip, "gameId": game_id})

    @staticmethod
    def _subprocess_flags() -> int:
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)) if sys.platform == "win32" else 0

    def _scan_host_processes(self) -> None:
        if sys.platform != "win32":
            return
        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=3.0,
                creationflags=self._subprocess_flags(),
            )
            if res.returncode != 0:
                return
        except Exception:
            return

        current_games: dict[str, str] = {}
        for row in csv.reader(res.stdout.splitlines()):
            if not row:
                continue
            proc_name = str(row[0] or "").strip()
            if not proc_name:
                continue
            sig = GameDetectorMixin._match_game_signature(process=proc_name)
            if sig and sig["id"] not in current_games:
                current_games[sig["id"]] = proc_name

        for gid, pname in current_games.items():
            if self._is_blocked(self.dns_host, gid):
                continue
            is_new = gid not in self._active_host_processes
            if is_new or self._should_report(self.dns_host, gid, cooldown=25.0):
                if is_new:
                    print(
                        f"[host-sensor] Process {self.dns_host} -> {pname} [{gid}]",
                        flush=True,
                    )
                self._post_detection({
                    "ip": self.dns_host,
                    "gameId": gid,
                    "process": pname,
                    "matchedIndicator": f"Process {pname}",
                    "detectionMethod": "Auto Process Sensor (Live Open Game)",
                })

        for ended_gid in sorted(self._active_host_processes - set(current_games.keys())):
            print(
                f"[host-sensor] Process ended on {self.dns_host}: {ended_gid}",
                flush=True,
            )
            self._post_dismiss(self.dns_host, ended_gid)

        self._active_host_processes = set(current_games.keys())

    def _scan_host_dns_cache(self) -> None:
        if sys.platform != "win32":
            return
        try:
            res = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=3.0,
                creationflags=self._subprocess_flags(),
            )
            if res.returncode != 0:
                return
        except Exception:
            return

        matched_now: dict[str, dict] = {}
        for line in res.stdout.splitlines():
            if "record name" not in line.lower() and ":" not in line:
                continue
            parts = line.split(":", 1)
            candidate = (parts[1] if len(parts) == 2 else line).strip().lower().rstrip(".")
            if not candidate or "." not in candidate:
                continue
            sig = GameDetectorMixin._match_game_signature(domain=candidate)
            if sig:
                matched_now[candidate] = sig

        current_keys = set(matched_now.keys())
        if not self._dns_cache_initialized:
            self._seen_dns_cache_domains = current_keys
            self._dns_cache_initialized = True
            target_domains = sorted(
                dom for dom in current_keys if dom not in _PASSIVE_LAUNCHER_DOMAINS
            )
        else:
            new_domains = current_keys - self._seen_dns_cache_domains
            self._seen_dns_cache_domains = current_keys
            target_domains = sorted(new_domains)

        for dom in target_domains:
            sig = matched_now[dom]
            if self._is_blocked(self.dns_host, sig["id"]):
                continue
            if self._should_report(self.dns_host, sig["id"], cooldown=25.0):
                print(
                    f"[host-sensor] DNS Cache {self.dns_host} -> {dom} [{sig['name']}]",
                    flush=True,
                )
                self._post_detection({
                    "ip": self.dns_host,
                    "gameId": sig["id"],
                    "domain": dom,
                    "detectionMethod": "Auto DNS Cache Sensor",
                })

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
            if isinstance(d, dict) and str(d.get("ip") or "").strip()
        ]
        if not ips:
            return

        def _probe_ip(target_ip: str) -> tuple[str, int | None]:
            for port in SCAN_GAME_PORTS:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.14)
                        if s.connect_ex((target_ip, int(port))) == 0:
                            return target_ip, int(port)
                except OSError:
                    continue
            return target_ip, None

        with ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
            for ip_key, open_port in pool.map(_probe_ip, ips):
                if open_port is None:
                    continue
                sig = GameDetectorMixin._match_game_signature(port=open_port)
                if not sig or self._is_blocked(ip_key, sig["id"]):
                    continue
                if self._should_report(ip_key, sig["id"], cooldown=25.0):
                    print(
                        f"[host-sensor] Auto Port {ip_key}:{open_port} -> [{sig['name']}]",
                        flush=True,
                    )
                    self._post_detection({
                        "ip": ip_key,
                        "gameId": sig["id"],
                        "port": open_port,
                        "detectionMethod": "Auto LAN Game Port Sensor",
                    })

    def _enforce_active_blocks(self) -> None:
        with self._lock:
            blocks = list(self._active_blocks)
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
                        timeout=3.0,
                        creationflags=self._subprocess_flags(),
                    )
                    self._flushed_rule_ids.update(new_host_ids)
                except Exception:
                    pass
            try:
                res = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    creationflags=self._subprocess_flags(),
                )
                if res.returncode == 0:
                    killed_procs: set[str] = set()
                    for row in csv.reader(res.stdout.splitlines()):
                        if not row:
                            continue
                        proc_name = str(row[0] or "").strip()
                        if not proc_name or proc_name.lower() in killed_procs:
                            continue
                        sig = GameDetectorMixin._match_game_signature(process=proc_name)
                        if sig and self._is_blocked(self.dns_host, sig["id"]):
                            killed_procs.add(proc_name.lower())
                            subprocess.run(
                                ["taskkill", "/F", "/IM", proc_name],
                                capture_output=True,
                                text=True,
                                timeout=3.0,
                                creationflags=self._subprocess_flags(),
                            )
                            print(
                                f"[host-sensor] Terminated blocked game process: {proc_name} [{sig['name']}]",
                                flush=True,
                            )
            except Exception:
                pass

        # Periodic TCP RST burst on blocked client IPs to drop open game sockets
        linger = struct.pack("ii", 1, 0)
        seen_client_ips: set[str] = set()
        for rule in blocks:
            target_ip = str(rule.get("ip") or "").strip()
            if not target_ip or target_ip in ("*", self.dns_host) or target_ip in seen_client_ips:
                continue
            seen_client_ips.add(target_ip)
            for port in SCAN_GAME_PORTS:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rsock:
                        rsock.settimeout(0.05)
                        rsock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                        rsock.connect((target_ip, int(port)))
                except OSError:
                    pass

    def _scan_host_netstat_ports(self) -> None:
        if sys.platform != "win32":
            return
        try:
            res = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=3.0,
                creationflags=self._subprocess_flags(),
            )
            if res.returncode != 0:
                return
        except Exception:
            return

        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[0].upper() != "TCP" or parts[3].upper() != "ESTABLISHED":
                continue
            if ":" not in parts[1] or ":" not in parts[2]:
                continue
            local_ip = parts[1].rsplit(":", 1)[0].strip("[]")
            if local_ip != self.dns_host:
                continue
            try:
                remote_port = int(parts[2].rsplit(":", 1)[1])
            except ValueError:
                continue
            if remote_port not in _GAME_SERVER_PORTS:
                continue
            sig = GameDetectorMixin._match_game_signature(port=remote_port)
            if not sig or self._is_blocked(self.dns_host, sig["id"]):
                continue
            if self._should_report(self.dns_host, sig["id"], cooldown=25.0):
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
        last_lan_sweep = 0.0
        while not self._stop.is_set():
            try:
                self._enforce_active_blocks()
                self._scan_host_processes()
                self._scan_host_dns_cache()
                self._scan_host_netstat_ports()
                now = time.monotonic()
                if (now - last_lan_sweep) >= 12.0:
                    last_lan_sweep = now
                    self._sweep_lan_game_ports()
            except Exception as exc:
                print(f"[host-sensor] Auto-detect loop warning: {exc}", flush=True)
            if self._stop.wait(4.0):
                break

    def _handle_dns_packet(self, sock: socket.socket, raw: bytes, client_addr: tuple[str, int]) -> None:
        qname = GameDetectorMixin._extract_dns_qname(raw)
        client_ip = client_addr[0]
        if qname:
            sig = GameDetectorMixin._match_game_signature(domain=qname)
            with self._lock:
                blocks = list(self._active_blocks)
            sink_rule = GameDetectorMixin._should_sinkhole_query(client_ip, qname, sig, blocks)
            if sink_rule is not None:
                sink = GameDetectorMixin._build_dns_sinkhole_reply(raw)
                if sink:
                    try:
                        sock.sendto(sink, client_addr)
                    except OSError:
                        pass
                log_key = f"blk-{(sig['id'] if sig else 'wifi')}"
                if self._should_report(client_ip, log_key, cooldown=30.0):
                    print(
                        f"[host-sensor] BLOCKED DNS {client_ip} -> {qname} (0.0.0.0 sinkhole)",
                        flush=True,
                    )
                return
            if sig and self._should_report(client_ip, sig["id"]):
                print(
                    f"[host-sensor] DNS {client_ip} -> {qname} [{sig['name']}]",
                    flush=True,
                )
                threading.Thread(
                    target=self._post_detection,
                    args=({
                        "ip": client_ip,
                        "gameId": sig["id"],
                        "domain": qname,
                        "detectionMethod": f"Live DNS ({self.dns_host}:{self.dns_port})",
                    },),
                    daemon=True,
                ).start()

        # Forward DNS query immediately to upstream gateway DNS (or 1.1.1.1 fallback)
        for upstream in (self.upstream_dns, "1.1.1.1"):
            if not upstream:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fwd:
                    fwd.settimeout(1.2)
                    fwd.sendto(raw, (upstream, 53))
                    resp, _ = fwd.recvfrom(4096)
                sock.sendto(resp, client_addr)
                return
            except OSError:
                continue

    def _run_dns_listener(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.dns_host, self.dns_port))
            sock.settimeout(1.0)
            print(f"[host-sensor] Live DNS forwarder listening on {self.dns_host}:{self.dns_port}/udp -> {self.upstream_dns}:53", flush=True)
        except OSError as exc:
            print(f"[host-sensor] DNS listener bind {self.dns_host}:{self.dns_port} skipped: {exc}", flush=True)
            sock.close()
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    threading.Thread(
                        target=self._handle_dns_packet, args=(sock, data, addr), daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
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

                client_ip = sender_ip
                for cand_ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
                    try:
                        ip_obj = ipaddress.ip_address(cand_ip)
                        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_private and not ip_obj.is_loopback and cand_ip != sender_ip:
                            client_ip = cand_ip
                            break
                    except ValueError:
                        continue
                if self._should_report(client_ip, sig["id"]):
                    print(
                        f"[host-sensor] Syslog {client_ip} (via {sender_ip}) -> {matched_domain or matched_port} [{sig['name']}]",
                        flush=True,
                    )
                    threading.Thread(
                        target=self._post_detection,
                        args=({
                            "ip": client_ip,
                            "reporterIp": sender_ip,
                            "gameId": sig["id"],
                            "domain": matched_domain,
                            "port": matched_port,
                            "detectionMethod": f"Router Syslog (UDP {self.syslog_port})",
                        },),
                        daemon=True,
                    ).start()
        finally:
            sock.close()

    def serve_forever(self) -> None:
        t1 = threading.Thread(target=self._run_dns_listener, daemon=True)
        t2 = threading.Thread(target=self._run_syslog_listener, daemon=True)
        t3 = threading.Thread(target=self._sync_blocks_loop, daemon=True)
        t4 = threading.Thread(target=self._auto_detect_loop, daemon=True)
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        print("[host-sensor] Automatic process, DNS-cache & LAN port scanner active", flush=True)
        try:
            while not self._stop.is_set():
                time.sleep(1.0)
        except KeyboardInterrupt:
            self._stop.set()


def main() -> int:
    parser = argparse.ArgumentParser(description="Host DNS & Syslog Game Sensor for Pulse Network Monitor")
    parser.add_argument("--dns-host", default="192.168.0.224", help="Host LAN IP to bind UDP port 53")
    parser.add_argument("--dns-port", type=int, default=53, help="Host DNS UDP port (default: 53)")
    parser.add_argument("--syslog-port", type=int, default=514, help="Host Syslog UDP port (default: 514)")
    parser.add_argument("--upstream-dns", default="192.168.0.1", help="Upstream DNS server (default: 192.168.0.1)")
    parser.add_argument("--api-url", default="http://127.0.0.1:3000/api/gaming/detect", help="Monitor API endpoint")
    args = parser.parse_args()

    sensor = HostGameSensor(
        dns_host=args.dns_host,
        dns_port=args.dns_port,
        syslog_port=args.syslog_port,
        upstream_dns=args.upstream_dns,
        api_url=args.api_url,
    )
    sensor.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

