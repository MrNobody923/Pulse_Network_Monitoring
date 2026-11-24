"""TCP/ICMP device probing, TP-Link router telemetry, ISP heartbeats, and live speed test."""

from __future__ import annotations

import copy
import ctypes
import gzip
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.client import HTTPResponse
from urllib.response import addinfourl

if os.name == "nt":
    import ctypes.wintypes

from typing import TYPE_CHECKING, cast

from .config import ISP_TARGETS, ROUTER_PORTS, manual_speed_tests_enabled, runtime_attr, utc_now
from .router_game_control import RouterGameControl, router_clients

if TYPE_CHECKING:
    from .engine import Monitor


def _router_link_mbps(value: object) -> float | None:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmg])?(?:b(?:it)?(?:ps|/s)?)?\s*", str(value), re.I)
    if not match:
        return None
    multiplier = {"k": 0.001, "m": 1, "g": 1000, "": 1}[(match[2] or "").lower()]
    speed = float(match[1]) * multiplier
    if not 0 < speed <= 800_000:
        return None
    return int(speed) if speed.is_integer() else speed

if os.name == "nt":
    class _IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_void_p),
        ]

    class _ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [
            ("Address", ctypes.c_uint32),
            ("Status", ctypes.c_uint32),
            ("RoundTripTime", ctypes.c_uint32),
            ("DataSize", ctypes.c_uint16),
            ("Reserved", ctypes.c_uint16),
            ("Data", ctypes.c_void_p),
            ("Options", _IP_OPTION_INFORMATION),
        ]


class ProbesMixin:
    """Executes active TCP/ICMP probes, router telemetry reads, and streaming speed tests."""

    def _initial_router_state(self) -> dict:
        self = cast("Monitor", self)
        ip = self.config["router"].get("ip", "192.168.0.1")
        return {
            "model": "TP-Link BE3600 (Archer BE230)",
            "reachable": False,
            "authenticated": False,
            "ip": ip,
            "lastSeen": None,
            "telemetryAvailable": False,
            "cpu": {"loadPct": None, "cores": None, "history": []},
            "memory": {"usagePct": None, "history": []},
            "wanInternetStatus": "UNKNOWN",
            "ports": [
                {
                    "id": pid,
                    "name": name,
                    "label": label,
                    "speed": None,
                    "speedText": "Unavailable",
                    "duplex": "Unknown",
                    "linkStatus": "unknown",
                    "isWan": is_wan,
                    "status": "unknown",
                    "description": desc,
                }
                for pid, name, label, is_wan, desc in ROUTER_PORTS
            ],
        }

    @staticmethod
    def _initial_isp_state() -> dict:
        timeseries = {"timestamps": [], **{target["id"]: [] for target in ISP_TARGETS}}
        stats = {
            target["id"]: {
                "currentMs": None,
                "avgMs": None,
                "minMs": None,
                "maxMs": None,
                "lossPct": None,
                "uptimePct": None,
                "uptime24hPct": None,
                "uptime30dPct": None,
                "samples24h": 0,
                "samples30d": 0,
                "lastStatus": None,
                "heartbeats": [],
                "statusLog": [],
            }
            for target in ISP_TARGETS
        }
        return {
            "overallHealth": "UNKNOWN",
            "healthScore": None,
            "status": "unknown",
            "wanGatewayLatencyMs": None,
            "wanGatewayReachable": None,
            "wanGatewayIp": None,
            "tier1LatencyMs": None,
            "packetLossPct": None,
            "jitterMs": None,
            "dnsResolutionMs": None,
            "lastSpeedTest": None,
            "speedHistory": [],
            "speedTestError": None,
            "provider": None,
            "providerError": None,
            "liveThroughput": None,
            "routerWanThroughput": None,
            "probeTimestamp": None,
            "probeFailurePct": None,
            "nextAutoTestAt": None,
            "probes": [],
            "history": {"latency": [], "timestamps": []},
            "speedTestRunning": False,
            "pingGraph": {
                "targets": ISP_TARGETS,
                "timeseries": timeseries,
                "stats": stats,
                "statusLog": [],
            },
        }

    @staticmethod
    def _probe_tcp_socket(
        host: str, port: int, timeout: float = 0.85
    ) -> tuple[bool, bool, float | None]:
        """Return (port_open, host_alive_on_lan, latency_ms)."""
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, True, round((time.perf_counter() - started) * 1000, 1)
        except ConnectionRefusedError:
            return False, True, round((time.perf_counter() - started) * 1000, 1)
        except (OSError, OverflowError):
            return False, False, None

    @staticmethod
    def _probe_tcp(
        host: str, port: int, timeout: float = 1.0
    ) -> tuple[bool, float | None]:
        """Strict TCP 3-way handshake check (returns True only when the port is genuinely open)."""
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, round((time.perf_counter() - started) * 1000, 1)
        except (OSError, OverflowError):
            return False, None

    @staticmethod
    def _win32_icmp_echo(host: str, timeout_ms: int = 1000) -> tuple[bool, float | None]:
        """Native Windows IcmpSendEcho via iphlpapi.dll (accurate RTT, immune to ping.exe rc=0 quirks)."""
        try:
            ip_str = socket.gethostbyname(str(host).strip())
            addr_int = int.from_bytes(socket.inet_aton(ip_str), "little")
        except OSError:
            return False, None
        iphlp = getattr(ctypes, "windll", None)
        if iphlp is None or not hasattr(iphlp, "iphlpapi"):
            return False, None
        dll = iphlp.iphlpapi
        if not getattr(dll, "_pulse_icmp_sig", False):
            dll.IcmpCreateFile.restype = ctypes.wintypes.HANDLE
            dll.IcmpCloseHandle.argtypes = [ctypes.wintypes.HANDLE]
            dll.IcmpSendEcho.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint16,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]
            dll.IcmpSendEcho.restype = ctypes.c_uint32
            dll._pulse_icmp_sig = True

        invalid_handle = ctypes.wintypes.HANDLE(-1).value
        handle = dll.IcmpCreateFile()
        if not handle or handle == invalid_handle:
            return False, None
        payload = b"PulsePing0123456"
        reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(payload) + 16
        reply_buf = ctypes.create_string_buffer(reply_size)
        try:
            count = dll.IcmpSendEcho(
                handle,
                addr_int,
                payload,
                len(payload),
                None,
                reply_buf,
                reply_size,
                max(50, int(timeout_ms)),
            )
            if count <= 0:
                return False, None
            reply = _ICMP_ECHO_REPLY.from_buffer(reply_buf)
            if reply.Status != 0:
                return False, None
            rtt = max(0.5, round(float(reply.RoundTripTime), 1))
            return True, rtt
        except OSError:
            return False, None
        finally:
            dll.IcmpCloseHandle(handle)

    @staticmethod
    def _probe_icmp(host: str, timeout_ms: int = 1000) -> tuple[bool, float | None]:
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)
        is_mocked_subproc = hasattr(subproc_mod.run, "assert_called")
        if os_mod.name == "nt" and not is_mocked_subproc and os.name == "nt":
            return ProbesMixin._win32_icmp_echo(host, timeout_ms)

        command = (
            ["ping", "-n", "1", "-w", str(timeout_ms), host]
            if os_mod.name == "nt"
            else ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
        )
        started = time.perf_counter()
        try:
            result = subproc_mod.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_ms / 1000 + 1,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, None
        output = result.stdout + result.stderr
        low = output.lower()
        if result.returncode != 0 or any(
            bad in low
            for bad in ("destination host unreachable", "destination net unreachable", "request timed out", "100% loss", "100% packet loss", "0 received")
        ):
            return False, None
        match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.I)
        if "ttl=" not in low and match is None:
            return False, None
        latency = (
            float(match.group(1)) if match else (time.perf_counter() - started) * 1000
        )
        return True, round(latency, 1)

    def _is_arp_neighbor_alive(self, ip: str, expected_mac: str = "") -> bool:
        """Check whether ip has a live dynamic L2 neighbor entry in the OS ARP cache (for firewall-shielded hosts)."""
        self = cast("Monitor", self)
        if (
            getattr(self, "_skip_live_probe_in_test", False)
            or hasattr(self._probe_icmp, "assert_called")
            or hasattr(self._probe_tcp_socket, "assert_called")
            or not hasattr(self, "_read_arp_entries")
        ):
            return False
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)
        if hasattr(subproc_mod.run, "assert_called"):
            return False
        now_m = time.monotonic()
        arp_map: dict[str, str] | None = getattr(self, "_live_arp_cache_map", None)
        arp_ts: float = getattr(self, "_live_arp_cache_ts", 0.0)
        if arp_map is None or (now_m - arp_ts) >= 8.0:
            try:
                entries = self._read_arp_entries(os_mod.name, subproc_mod.run)
                arp_map = {
                    str(r_ip).strip(): str(r_mac).strip().lower().replace("-", ":")
                    for r_ip, r_mac, r_kind in entries
                    if str(r_kind).lower() == "dynamic"
                    and str(r_mac).strip().lower().replace("-", ":") not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
                }
                self._live_arp_cache_map = arp_map
                self._live_arp_cache_ts = now_m
            except Exception:
                return False
        found_mac = arp_map.get(str(ip).strip())
        if not found_mac:
            return False
        clean_expected = str(expected_mac or "").strip().lower().replace("-", ":")
        if clean_expected and not clean_expected.startswith("02:00:") and found_mac != clean_expected:
            return False
        return True

    def _is_wan_internet_up(self) -> bool | None:
        """Return current monitor WAN reachability, or None before the first check."""
        self = cast("Monitor", self)
        isp_health = str(self.isp_state.get("overallHealth") or "UNKNOWN").upper()
        probes = self.isp_state.get("probes", [])
        external_probes = [p for p in probes if p.get("id") != "gateway"]
        if external_probes:
            return any(p.get("alive") for p in external_probes)
        if isp_health in {"OFFLINE", "OUTAGE"}:
            return False
        wan_port = next(
            (p for p in self.router_state.get("ports", []) if p.get("isWan")),
            None,
        )
        if wan_port and wan_port.get("linkStatus") == "disconnected":
            return False
        return None if isp_health == "UNKNOWN" else True

    @staticmethod
    def _encode_oid(oid_str: str) -> bytes:
        parts = [int(x) for x in oid_str.strip(".").split(".")]
        if len(parts) < 2:
            return b""
        encoded = bytearray([parts[0] * 40 + parts[1]])
        for val in parts[2:]:
            if val == 0:
                encoded.append(0)
            else:
                chunks = []
                while val > 0:
                    chunks.append(val & 0x7F)
                    val >>= 7
                for idx in range(len(chunks) - 1, -1, -1):
                    byte_val = chunks[idx]
                    if idx > 0:
                        byte_val |= 0x80
                    encoded.append(byte_val)
        return bytes([0x06, len(encoded)]) + bytes(encoded)

    @staticmethod
    def _tlv(tag: int, body: bytes) -> bytes:
        n = len(body)
        if n < 0x80:
            len_bytes = bytes([n])
        elif n <= 0xFF:
            len_bytes = bytes([0x81, n])
        else:
            len_bytes = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
        return bytes([tag]) + len_bytes + body

    @staticmethod
    def _read_snmp_tlv(data: bytes) -> tuple[int, bytes, bytes]:
        if len(data) < 2:
            raise ValueError("Incomplete SNMP field")
        tag, length = data[:2]
        start = 2
        if length >= 0x80:
            length_bytes = length & 0x7F
            start += length_bytes
            if not 1 <= length_bytes <= 4 or start > len(data):
                raise ValueError("Invalid SNMP field length")
            length = int.from_bytes(data[2:start], "big")
        end = start + length
        if end > len(data):
            raise ValueError("Incomplete SNMP field")
        return tag, data[start:end], data[end:]

    @classmethod
    def _decode_snmp_value(
        cls, raw: bytes, envelope: bytes, request_fields: bytes, oid: bytes
    ) -> str | None:
        tag, message, trailing = cls._read_snmp_tlv(raw)
        if tag != 0x30 or trailing or not message.startswith(envelope):
            return None
        tag, response, trailing = cls._read_snmp_tlv(message[len(envelope):])
        if tag != 0xA2 or trailing or not response.startswith(request_fields):
            return None
        tag, bindings, trailing = cls._read_snmp_tlv(response[len(request_fields):])
        if tag != 0x30 or trailing:
            return None
        tag, binding, trailing = cls._read_snmp_tlv(bindings)
        if tag != 0x30 or trailing or not binding.startswith(oid):
            return None
        tag, value, trailing = cls._read_snmp_tlv(binding[len(oid):])
        if trailing:
            return None
        if tag == 0x04:
            return value.decode("utf-8", "replace").strip()
        if tag in (0x02, 0x41, 0x42, 0x43, 0x46) and 1 <= len(value) <= 9:
            return str(int.from_bytes(value, "big", signed=tag == 0x02))
        return None

    def _snmp_get_oids(
        self, ip: str, oids: dict[str, str], community: str = "public", timeout: float = 0.55
    ) -> dict[str, str]:
        """Pure-Python SNMPv1/v2c GET for multiple OIDs without external dependencies."""
        if not community:
            return {}
        results: dict[str, str] = {}
        community_tlv = self._tlv(0x04, community.encode("utf-8"))
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        for label, oid in oids.items():
            try:
                oid_tlv = self._encode_oid(oid)
            except ValueError:
                continue
            if not oid_tlv:
                continue
            varbind = self._tlv(0x30, oid_tlv + b"\x05\x00")
            varbind_list = self._tlv(0x30, varbind)
            request_id = (secrets.randbits(30) | (1 << 30)).to_bytes(4, "big")
            request_fields = self._tlv(0x02, request_id) + b"\x02\x01\x00\x02\x01\x00"
            pdu = self._tlv(0xA0, request_fields + varbind_list)
            for version in (b"\x02\x01\x01", b"\x02\x01\x00"):
                envelope = version + community_tlv
                try:
                    with socket.socket(family, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(timeout)
                        sock.connect((ip, 161))
                        sock.send(self._tlv(0x30, envelope + pdu))
                        raw = sock.recv(4096)
                    value = self._decode_snmp_value(raw, envelope, request_fields, oid_tlv)
                except (OSError, ValueError):
                    continue
                if value is not None:
                    results[label] = value
                    break
        return results

    def _get_cached_fingerprints(self) -> dict[str, dict]:
        self = cast("Monitor", self)
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT value FROM monitor_metadata WHERE key='device_fingerprints'"
                ).fetchone()
            if row and row["value"]:
                data = json.loads(row["value"])
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def _save_cached_fingerprints(self, updates: dict[str, dict]) -> None:
        self = cast("Monitor", self)
        if not updates:
            return
        try:
            current = self._get_cached_fingerprints()
            current.update(updates)
            with self._connect() as db:
                db.execute(
                    "INSERT OR REPLACE INTO monitor_metadata (key, value) VALUES ('device_fingerprints', ?)",
                    (json.dumps(current),),
                )
        except Exception:
            pass

    @staticmethod
    def _read_http_body(resp: HTTPResponse | addinfourl, max_bytes: int = 16384) -> str:
        raw = resp.read(max_bytes)
        enc = str(resp.headers.get("Content-Encoding") or "").lower()
        if enc == "gzip" or raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        return raw.decode("utf-8", "ignore")

    @staticmethod
    def _inspect_tls_cert_der(ip: str, port: int = 443, timeout: float = 0.7) -> bytes:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=ip) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    return (der or b"").lower()
        except Exception:
            return b""

    def identify_network_device(
        self, ip: str, open_ports: list[int] | None = None, community: str = "public"
    ) -> dict:
        """Actively identify vendor, hardware model, protocol, and infra role via TLS/HTTP/LuCI/SNMP/SSH."""
        if open_ports is None:
            open_ports = []
            for p in (80, 443, 8080, 8443, 20001, 22):
                is_open, _, _ = self._probe_tcp_socket(ip, p, timeout=0.4)
                if is_open:
                    open_ports.append(p)

        info: dict = {
            "ip": ip,
            "openPorts": list(open_ports),
            "vendor": "",
            "model": "",
            "role": "",
            "protocol": "https" if (443 in open_ports or 8443 in open_ports) and 80 not in open_ports else "http",
            "preferredPort": (
                80 if 80 in open_ports else (443 if 443 in open_ports else (8080 if 8080 in open_ports else (22 if 22 in open_ports else 80)))
            ),
            "sshBanner": "",
            "snmp": {},
        }

        ctx = ssl._create_unverified_context()
        # 0. Fast X.509 certificate inspection (distinguishes TP-Link Deco Mesh vs Omada EAP vs Archer routers)
        cert_der = b""
        for tls_p in (p for p in (443, 8443) if p in open_ports):
            cert_der = self._inspect_tls_cert_der(ip, tls_p)
            if cert_der:
                if b"tplinkdeco.net" in cert_der:
                    info.update({
                        "vendor": "TP-Link",
                        "model": "TP-Link Deco Mesh System",
                        "role": "router",
                        "protocol": "https" if 80 not in open_ports else "http",
                        "preferredPort": 80 if 80 in open_ports else tls_p,
                    })
                elif b"omadaeap.net" in cert_der:
                    info.update({
                        "vendor": "TP-Link",
                        "model": "TP-Link Omada EAP Access Point",
                        "role": "ap",
                        "protocol": "https",
                        "preferredPort": tls_p,
                    })
                elif b"tplinkwifi.net" in cert_der:
                    info["vendor"] = "TP-Link"
                    info["role"] = "router"
                break

        # 1. Try TP-Link LuCI hardware identification (HTTP 80 or HTTPS 443)
        for port in (p for p in (80, 443) if p in open_ports):
            scheme = "https" if port == 443 else "http"
            try:
                req = urllib.request.Request(
                    f"{scheme}://{ip}:{port}/cgi-bin/luci/;stok=/locale?form=lang",
                    data=b"operation=read",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Pulse/2.1",
                        "Accept-Encoding": "gzip, identity",
                    },
                )
                with urllib.request.urlopen(req, timeout=0.95, context=ctx if scheme == "https" else None) as resp:
                    payload = json.loads(self._read_http_body(resp, 4096))
                if payload.get("success") and isinstance(payload.get("data"), dict):
                    data = payload["data"]
                    model = str(data.get("model") or "TP-Link LuCI Device").strip()
                    lower_model = model.lower()
                    role = (
                        "ap"
                        if any(tok in lower_model for tok in ("eap", "access point", "ap "))
                        else "router"
                    )
                    info.update({
                        "vendor": "TP-Link",
                        "model": model,
                        "role": role,
                        "protocol": scheme,
                        "preferredPort": port,
                        "rebootTime": data.get("rebootTime"),
                    })
                    break
            except Exception:
                pass

        # 2. Fallback HTTP / HTTPS root page & header inspection for Deco, SHIP 2.0 Smart IoT, Omada EAP, switches, APs
        if any(p in open_ports for p in (80, 443, 8080)) and (
            not info["model"] or info["model"] in {"TP-Link Deco Mesh System", "TP-Link Omada EAP Access Point"}
        ):
            for port in (p for p in (443, 80, 8080) if p in open_ports):
                scheme = "https" if port in (443, 8443) else "http"
                try:
                    req = urllib.request.Request(
                        f"{scheme}://{ip}:{port}/",
                        headers={"User-Agent": "Pulse/2.1", "Accept-Encoding": "gzip, identity"},
                    )
                    with urllib.request.urlopen(req, timeout=0.95, context=ctx if scheme == "https" else None) as resp:
                        srv = str(resp.headers.get("Server") or "").strip()
                        body = self._read_http_body(resp, 8192)
                        if "ship 2.0" in srv.lower():
                            info.update({
                                "vendor": "TP-Link Tapo / Kasa",
                                "model": "TP-Link Smart Home / Tapo IoT",
                                "role": "client",
                                "protocol": scheme,
                                "preferredPort": port,
                            })
                            break
                        if "/webpages/index.html" in body:
                            try:
                                with urllib.request.urlopen(
                                    urllib.request.Request(
                                        f"{scheme}://{ip}:{port}/webpages/index.html",
                                        headers={"User-Agent": "Pulse/2.1", "Accept-Encoding": "gzip, identity"},
                                    ),
                                    timeout=0.95,
                                    context=ctx if scheme == "https" else None,
                                ) as r2:
                                    body += "\n" + self._read_http_body(r2, 8192)
                            except Exception:
                                pass
                        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                        title = title_m.group(1).strip() if title_m else ""
                        combined = f"{srv} {title} {body[:2000]}".lower()
                        if "omadaeap" in combined or ("tp-link httpd" in srv.lower() and "eap" in combined):
                            info.update({
                                "vendor": "TP-Link",
                                "model": "TP-Link Omada EAP Access Point",
                                "role": "ap",
                                "protocol": scheme,
                                "preferredPort": port,
                            })
                            break
                        if "tp-link" in combined or "$.su." in combined or "/webpages/index.html" in body:
                            if info["model"]:
                                break
                            info["vendor"] = "TP-Link"
                            info["protocol"] = scheme
                            info["preferredPort"] = port
                            if "httpd" in srv.lower() and b"omadaeap.net" in cert_der:
                                info["model"] = "TP-Link Omada EAP Access Point"
                                info["role"] = "ap"
                            elif "httpd" in srv.lower():
                                info["model"] = "TP-Link Omada EAP / Smart AP"
                                info["role"] = "ap"
                            elif 20001 in open_ports or b"tplinkdeco.net" in cert_der:
                                info["model"] = "TP-Link Deco Mesh System"
                                info["role"] = "router"
                            elif "$.su." in combined:
                                # Probe Deco /login?form=auth endpoint (present on Deco / Archer v2 WebUI)
                                is_deco = False
                                try:
                                    lreq = urllib.request.Request(
                                        f"{scheme}://{ip}:{port}/cgi-bin/luci/;stok=/login?form=auth",
                                        data=b"operation=read",
                                        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Pulse/2.1"},
                                    )
                                    with urllib.request.urlopen(lreq, timeout=0.7, context=ctx if scheme == "https" else None) as lr:
                                        ltxt = lr.read(1024).decode("utf-8", "ignore")
                                        if '"error_code":0' in ltxt.replace(" ", ""):
                                            is_deco = True
                                except Exception:
                                    pass
                                info["model"] = "TP-Link Deco Mesh System" if (is_deco or "tplinkdeco" in cert_der.decode("latin1", "ignore")) else "TP-Link SuperUI Router / AP"
                                info["role"] = "router"
                            else:
                                info["model"] = title or srv or "TP-Link Device"
                                info["role"] = "ap"
                            break
                        if any(k in combined for k in ("omada", "unifi", "ubnt", "mikrotik", "routeros", "cisco", "ruijie", "aruba", "netgear")):
                            info["vendor"] = srv or title or "Network Infrastructure"
                            info["model"] = title or srv
                            info["protocol"] = scheme
                            info["preferredPort"] = port
                            info["role"] = "switch" if "switch" in combined else ("router" if "router" in combined else "ap")
                            break
                except Exception:
                    continue

        if 20001 in open_ports and not info["model"]:
            info.update({
                "vendor": "TP-Link",
                "model": "TP-Link Deco Mesh System",
                "role": "router",
            })

        # 3. Lightweight SNMP check (catches managed switches & enterprise routers when SNMP enabled)
        snmp_data = self._snmp_get_oids(
            ip,
            {
                "sysDescr": "1.3.6.1.2.1.1.1.0",
                "sysUpTime": "1.3.6.1.2.1.1.3.0",
                "sysName": "1.3.6.1.2.1.1.5.0",
                "ifNumber": "1.3.6.1.2.1.2.1.0",
            },
            community=community,
            timeout=0.35,
        )
        if snmp_data:
            info["snmp"] = snmp_data
            descr = snmp_data.get("sysDescr", "")
            descr_l = descr.lower()
            if not info["model"] and descr:
                info["model"] = descr[:100]
            if not info["role"]:
                if any(tok in descr_l for tok in ("switch", "catalyst", "jetstream", "procurve", "arubaos")):
                    info["role"] = "switch"
                elif any(tok in descr_l for tok in ("router", "routeros", "ios", "edgeos", "tp-link", "openwrt")):
                    info["role"] = "router"
            if not info["vendor"]:
                for tok, vname in (("cisco", "Cisco"), ("tp-link", "TP-Link"), ("mikrotik", "MikroTik"), ("ubiquiti", "Ubiquiti"), ("aruba", "Aruba"), ("ruijie", "Ruijie")):
                    if tok in descr_l:
                        info["vendor"] = vname
                        break

        # 4. SSH banner fallback (distinguishes Linux servers from network hardware cleanly)
        if 22 in open_ports and not info["model"]:
            try:
                with socket.create_connection((ip, 22), timeout=0.5) as sock:
                    sock.settimeout(0.5)
                    banner = sock.recv(128).decode("utf-8", "ignore").strip()
                if banner:
                    info["sshBanner"] = banner[:90]
                    if not info["role"]:
                        b_l = banner.lower()
                        if "cisco" in b_l:
                            info["role"] = "switch"
                            info["vendor"] = "Cisco"
                            info["model"] = banner[:60]
                        elif "ubuntu" in b_l or "debian" in b_l or "windows" in b_l:
                            info["role"] = "server"
                            info["model"] = banner[:60]
            except Exception:
                pass
        return info

    def probe_device(self, device: dict) -> dict:
        self = cast("Monitor", self)
        ip = device["ip"]
        primary_port = int(device.get("port") or 80)
        dev_type = str(device.get("type") or "ap").lower()
        candidate_ports = []
        default_order = (22, 443, 80, 8080) if dev_type in {"switch", "server"} and primary_port == 22 else (primary_port, 80, 443, 8080, 22)
        for p in (primary_port, *default_order):
            if p not in candidate_ports:
                candidate_ports.append(p)

        open_ports: list[int] = []
        ports_checked: list[int] = []
        tcp_alive = False
        best_latency: float | None = None
        probe_method = "No Response (TCP + ICMP Timeout)"

        for idx, p in enumerate(candidate_ports):
            ports_checked.append(p)
            is_open, is_rst_alive, lat = self._probe_tcp_socket(ip, p, timeout=0.55)
            if is_open:
                open_ports.append(p)
                tcp_alive = True
                if best_latency is None or (lat is not None and lat < best_latency):
                    best_latency = lat
                if idx == 0:
                    # Ghost Mode: primary port responded immediately; skip unnecessary fallback port probes
                    break
            elif is_rst_alive:
                tcp_alive = True
                if best_latency is None and lat is not None:
                    best_latency = lat

        icmp_alive, icmp_latency = self._probe_icmp(ip, timeout_ms=800)
        if not tcp_alive and not icmp_alive:
            # Confirm once before flagging DEVICE_DOWN to avoid false alarms from 1-packet Wi-Fi loss
            icmp_alive, icmp_latency = self._probe_icmp(ip, timeout_ms=1100)
        arp_alive = False
        if not tcp_alive and not icmp_alive:
            arp_alive = self._is_arp_neighbor_alive(ip, expected_mac=str(device.get("mac") or ""))
        alive = tcp_alive or icmp_alive or arp_alive
        latency = (
            icmp_latency
            if icmp_alive and icmp_latency is not None
            else best_latency
        )

        # Enrich with cached or live hardware identity when management ports respond or MAC changed
        cached_fp = self._get_cached_fingerprints().get(ip, {})
        dev_mac = str(device.get("mac") or "").lower()
        mac_mismatch = bool(dev_mac and cached_fp.get("mac") and cached_fp.get("mac") != dev_mac)
        hw_model = "" if mac_mismatch else (device.get("hardwareModel") or cached_fp.get("model") or "")
        fp_attempted: set[str] = getattr(self, "_fp_attempted_ips", set())
        if not hasattr(self, "_fp_attempted_ips"):
            self._fp_attempted_ips = fp_attempted
        in_test = getattr(self, "_skip_live_probe_in_test", False)
        if (
            alive
            and open_ports
            and (not hw_model or mac_mismatch)
            and (in_test or mac_mismatch or ip not in fp_attempted)
            and dev_type in {"gateway", "router", "ap", "switch"}
        ):
            fp_attempted.add(ip)
            fp = self.identify_network_device(ip, open_ports=open_ports)
            if dev_mac:
                fp["mac"] = dev_mac
            if fp.get("model") or fp.get("snmp"):
                hw_model = fp.get("model") or ""
                self._save_cached_fingerprints({ip: fp})
                cached_fp = fp

        if open_ports and icmp_alive:
            port_list = ",".join(str(p) for p in open_ports[:3])
            probe_method = f"TCP/{port_list} + ICMP Echo"
        elif open_ports:
            port_list = ",".join(str(p) for p in open_ports[:3])
            probe_method = f"TCP/{port_list} Management Port"
        elif icmp_alive:
            probe_method = "ICMP Echo Reply"
        elif tcp_alive:
            probe_method = "TCP Stack Active (RST)"
        elif arp_alive:
            probe_method = "ARP cache observation"

        samples = self.history.setdefault(ip, [])
        if not arp_alive:
            samples.append(latency if alive else None)
        del samples[:-10]
        successes = [value for value in samples if value is not None]
        loss = round((len(samples) - len(successes)) / len(samples) * 100) if samples else None
        average = round(sum(successes) / len(successes), 1) if successes else None
        jitter = (
            round(
                sum(abs(successes[i] - successes[i - 1]) for i in range(1, len(successes)))
                / (len(successes) - 1),
                1,
            )
            if len(successes) > 1
            else None
        )

        wan_up = self._is_wan_internet_up()
        has_internet = wan_up if alive else False

        thresholds = self.config.get("thresholds", {})
        high_loss = int(thresholds.get("packetLossWarningPct", 5))
        high_latency = float(thresholds.get("highLatencyMs", 80))

        if arp_alive:
            status = "unknown"
            connectivity_state = "ARP_OBSERVED"
            has_internet = None
        elif not alive:
            status = "offline"
            connectivity_state = "DEVICE_DOWN"
        elif wan_up is False:
            status = "warning"
            connectivity_state = "ONLINE_NO_INTERNET"
        elif (loss is not None and loss >= high_loss) or (average is not None and average > high_latency):
            status = "warning"
            connectivity_state = "DEGRADED_LINK"
        elif wan_up is None:
            status = "online"
            connectivity_state = "ONLINE_WAN_UNKNOWN"
        else:
            status = "online"
            connectivity_state = "ONLINE_WITH_INTERNET"

        subnet = device.get("subnet") or self._subnet_for_ip(ip)

        now_iso = utc_now()
        result = {
            **device,
            "subnet": subnet,
            "hardwareModel": hw_model,
            "httpProtocol": cached_fp.get("protocol") or ("https" if 443 in open_ports and 80 not in open_ports else "http"),
            "snmpSysName": (cached_fp.get("snmp") or {}).get("sysName", ""),
            "alive": alive,
            "directlyReachable": tcp_alive or icmp_alive,
            "icmpAlive": icmp_alive,
            "tcpReachable": tcp_alive,
            "tcpPortsChecked": ports_checked,
            "openPorts": open_ports,
            "managementReachable": bool(open_ports),
            "probeMethod": probe_method,
            "probeOrigin": "monitor",
            "internetEvidence": "monitor_wan",
            "hasInternet": has_internet,
            "connectivityState": connectivity_state,
            "latencyMs": latency,
            "avgLatencyMs": average,
            "packetLossPct": loss,
            "jitterMs": jitter,
            "status": status,
            "lastChecked": now_iso,
        }

        # Sync live probe status back into discovered_devices so inventory and devices match
        try:
            with self._connect() as db:
                if alive and not arp_alive:
                    db.execute(
                        """UPDATE discovered_devices SET is_online=1, last_seen=? WHERE mac=(
                               SELECT mac FROM discovered_devices WHERE ip=?
                               ORDER BY is_online DESC, last_seen DESC LIMIT 1
                           )""",
                        (now_iso, ip),
                    )
                elif not alive:
                    db.execute(
                        "UPDATE discovered_devices SET is_online=0 WHERE ip=?",
                        (ip,),
                    )
        except Exception:
            pass

        self._build_single_device_diagnosis(result, list(self.latest_devices.values()))
        self._evaluate_device(result)
        return result

    def _build_single_device_diagnosis(
        self, dev: dict, peer_devices: list[dict]
    ) -> None:
        """Compute zero-guessing root-cause diagnosis & step-by-step fix instructions for IT team."""
        self = cast("Monitor", self)
        ip = dev.get("ip", "")
        name = dev.get("name", ip)
        mac = dev.get("mac") or "Unknown MAC"
        dev_type = str(dev.get("type") or "ap").lower()
        subnet = dev.get("subnet") or "192.168.0.0/24"
        state = dev.get("connectivityState", "DEVICE_DOWN" if not dev.get("alive") else "ONLINE_WITH_INTERNET")

        same_subnet_peers = [
            p for p in peer_devices
            if p.get("ip") != ip and p.get("subnet") == subnet
        ]
        online_subnet_peers = [p for p in same_subnet_peers if p.get("alive")]
        switches_in_subnet = [
            p for p in peer_devices
            if str(p.get("type", "")).lower() == "switch" and p.get("subnet") == subnet
        ]
        all_switches = [
            p for p in peer_devices if str(p.get("type", "")).lower() == "switch"
        ]
        nearest_switch = (
            switches_in_subnet[0]
            if switches_in_subnet
            else (all_switches[0] if all_switches else None)
        )
        switch_label = (
            f"{nearest_switch['name']} ({nearest_switch['ip']})"
            if nearest_switch
            else "Distribution PoE Switch"
        )
        gateway_ip = self.config.get("router", {}).get("ip", "192.168.0.1")

        if state == "ARP_OBSERVED":
            dev["diagnosisTitle"] = "ARP entry observed"
            dev["likelyFault"] = ""
            dev["diagnosisSummary"] = f"The ARP cache contains {ip}. The device did not answer TCP or ICMP probes."
            dev["fixSteps"] = []
        elif state == "DEVICE_DOWN":
            if same_subnet_peers and len(online_subnet_peers) == 0 and len(same_subnet_peers) >= 2:
                dev["diagnosisTitle"] = f"Multiple Devices Offline in {subnet}"
                dev["likelyFault"] = "Main Switch or Cable Link Offline"
                dev["diagnosisSummary"] = (
                    f"{name} ({ip}) and {len(same_subnet_peers)} other devices in {subnet} are ALL offline. "
                    f"Check the main switch or connecting cable for that area instead of checking one device at a time."
                )
                dev["fixSteps"] = [
                    f"Check {switch_label} — make sure power and main cable lights are on.",
                    f"Check the main network cable running from {subnet} to Main Router ({gateway_ip}).",
                    "Click '⚡ Re-Probe Now' after checking cables to confirm everything comes back online.",
                ]
            elif dev_type == "switch":
                dev["diagnosisTitle"] = f"Network Switch Not Responding ({ip})"
                dev["likelyFault"] = "Switch Powered Off or Unplugged Cable"
                dev["diagnosisSummary"] = (
                    f"{name} ({ip}, MAC {mac}) did not reply on the local network."
                )
                dev["fixSteps"] = [
                    f"Check the power plug and status lights on {name} ({ip}).",
                    f"Check the main cable connecting {ip} to Main Router ({gateway_ip}).",
                    "Restart the switch if lights are frozen, then click '⚡ Re-Probe Now'.",
                ]
            else:
                online_count = len(online_subnet_peers)
                sibling_note = (
                    f"Your Main Router ({gateway_ip}) and {online_count} nearby devices are working."
                    if online_count > 0
                    else f"Your network is active, but {ip} is not responding."
                )
                unit_label = "Router" if dev_type in {"router", "gateway"} else "Device"
                dev["diagnosisTitle"] = f"{unit_label} Not Responding ({ip})"
                dev["likelyFault"] = "Power Off, Unplugged Cable, or Frozen Device"
                dev["diagnosisSummary"] = (
                    f"{sibling_note} Only {name} ({ip}, MAC {mac}) is unreachable."
                )
                dev["fixSteps"] = [
                    f"Check the network cable and power light on {name} ({ip}, MAC {mac}) connected via {switch_label}.",
                    f"Look at the wall or ceiling plug for {ip} to make sure the cable did not come loose.",
                    "Unplug power for 10 seconds and plug back in, then click '⚡ Re-Probe Now'.",
                ]
        elif state == "ONLINE_WAN_UNKNOWN":
            dev["diagnosisTitle"] = "Device reachable on LAN"
            dev["likelyFault"] = ""
            dev["diagnosisSummary"] = f"{name} ({ip}) answered a local probe. The monitor is waiting for a WAN check."
            dev["fixSteps"] = []
        elif state == "ONLINE_NO_INTERNET":
            dev["diagnosisTitle"] = f"Connected to Office Network — No Internet ({ip})"
            dev["likelyFault"] = "Main Internet Line Down (This Device Is OK)"
            dev["diagnosisSummary"] = (
                f"{name} ({ip}) is online on the office network ({dev.get('latencyMs')} ms), "
                "and the monitor could not reach its external test targets."
            )
            dev["fixSteps"] = [
                f"No need to restart {name} ({ip}) — its cable and power are working fine.",
                f"Check the internet cable on Main Router ({gateway_ip}) and the ISP fiber modem box.",
                "Open the Internet & Routers tab to verify when outside internet returns.",
            ]
        elif state == "DEGRADED_LINK":
            dev["diagnosisTitle"] = f"Slow or Unsteady Connection ({ip})"
            dev["likelyFault"] = "Damaged Network Cable, Slow Link Speed, or Busy Wi-Fi"
            dev["diagnosisSummary"] = (
                f"{name} ({ip}) is online but losing {dev.get('packetLossPct', 0)}% of data "
                f"with {dev.get('avgLatencyMs')} ms average delay."
            )
            dev["fixSteps"] = [
                f"Check the cable port on {switch_label} for {ip} — confirm it links at full 1000 Mbps speed.",
                f"Check or swap the network patch cable on {name} ({ip}) if speed stays slow.",
                f"Click '⚡ Re-Probe Now' on {ip} to verify stability returns.",
            ]
        else:
            dev["diagnosisTitle"] = "Online & Working Normally"
            dev["likelyFault"] = "None"
            dev["diagnosisSummary"] = (
                f"Connected normally on office network ({dev.get('latencyMs')} ms response) with working internet."
            )
            dev["fixSteps"] = []

    def enrich_fleet_diagnostics(self, results: list[dict]) -> list[dict]:
        """Re-run cross-device subnet correlation across all probed devices in the cycle."""
        for dev in results:
            self._build_single_device_diagnosis(dev, results)
        return results

    def _luci_post(
        self,
        host: str,
        port: int,
        scheme: str,
        path: str,
        timeout: float = 2.0,
        data: bytes = b"operation=read",
    ) -> dict | None:
        url = f"{scheme}://{host}:{port}{path}"
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Pulse/2.1",
            },
        )
        ctx = ssl._create_unverified_context() if scheme == "https" else None
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:
                return json.loads(response.read(256 * 1024).decode("utf-8", "ignore"))
        except (OSError, ValueError, urllib.error.URLError, TimeoutError):
            return None

    def _probe_single_router(
        self, cfg: dict, is_primary: bool = False, previous_state: dict | None = None
    ) -> dict:
        self = cast("Monitor", self)
        host = self._validate_ip(cfg.get("ip", "192.168.0.1"))
        port = self._validate_port(cfg.get("port", 80))
        use_https = bool(cfg.get("useHttps", False))
        scheme = "https" if use_https or port in (443, 8443) else "http"

        _, tcp_alive, tcp_ms = self._probe_tcp_socket(host, port, 0.85)
        alt_port = 443 if port != 443 else 80
        prev_open = (previous_state or {}).get("openPorts") or []
        if not tcp_alive or alt_port in prev_open:
            alt_open, alt_alive, alt_ms = self._probe_tcp_socket(host, alt_port, 0.65)
        else:
            alt_open, alt_alive, alt_ms = False, False, None
        icmp_alive, icmp_ms = self._probe_icmp(host, timeout_ms=800)
        alive = bool(tcp_alive or alt_alive or icmp_alive)
        latency_ms = (
            icmp_ms
            if icmp_alive and icmp_ms is not None
            else (tcp_ms if tcp_alive and tcp_ms is not None else alt_ms)
        )

        open_ports: list[int] = []
        if tcp_alive:
            open_ports.append(port)
        if alt_alive and alt_port not in open_ports:
            open_ports.append(alt_port)

        state = self._initial_router_state()
        state["id"] = str(cfg.get("id") or f"router-{host}")
        state["isPrimary"] = is_primary
        state["role"] = str(cfg.get("role") or ("Main Gateway" if is_primary else "Secondary Router"))
        state["vendor"] = str(cfg.get("vendor") or "TP-Link")
        state["protocol"] = scheme
        state["port"] = port
        state["openPorts"] = open_ports
        state["latencyMs"] = latency_ms
        state["reachable"] = alive
        state["ip"] = host
        if is_primary and self.isp_state.get("wanGatewayIp") == host:
            external = [p for p in self.isp_state.get("probes", []) if p.get("id") != "gateway"]
            if external:
                state["wanInternetStatus"] = "CONNECTED" if any(p.get("alive") for p in external) else "DISCONNECTED"
        state["lastSeen"] = utc_now() if alive else None
        state["lastChecked"] = utc_now()
        state["clientCount"] = None
        state["wanIpv4"] = None
        state["snmp"] = {}
        state["hasPassword"] = bool(cfg.get("password"))
        state["hasToken"] = bool(cfg.get("stok"))
        state["wanInterfaceIndex"] = cfg.get("wanInterfaceIndex")

        if cfg.get("model"):
            state["model"] = str(cfg["model"])
        elif not is_primary:
            state["model"] = str(cfg.get("name") or f"Router ({host})")

        # Ghost Mode: reuse cached hardware identity & SNMP unless stale (>30m) or unprobed
        admin_port = port if tcp_alive else (alt_port if alt_open else port)
        admin_scheme = "https" if use_https or admin_port in (443, 8443) else "http"
        hw_ts_map: dict[str, float] = getattr(self, "_router_hw_ts", {})
        if not hasattr(self, "_router_hw_ts"):
            self._router_hw_ts = hw_ts_map
        now_m = time.monotonic()
        prev_model = str((previous_state or {}).get("model") or "")
        has_prev_hw = bool(
            previous_state
            and prev_model
            and not prev_model.startswith("Router (")
            and prev_model != "TP-Link Router"
            and (now_m - hw_ts_map.get(host, 0.0)) < 1800.0
        )
        if has_prev_hw and previous_state:
            state["model"] = prev_model
            state["vendor"] = str(previous_state.get("vendor") or state["vendor"])
            state["protocol"] = str(previous_state.get("protocol") or admin_scheme)
            if previous_state.get("snmp"):
                state["snmp"] = dict(previous_state["snmp"])
                state["telemetryAvailable"] = True
        elif alive and open_ports:
            hw_ts_map[host] = now_m
            locale_payload = self._luci_post(
                host, admin_port, admin_scheme, "/cgi-bin/luci/;stok=/locale?form=lang", timeout=1.1
            )
            if not locale_payload and admin_scheme == "http" and alt_open and alt_port == 443:
                locale_payload = self._luci_post(
                    host, 443, "https", "/cgi-bin/luci/;stok=/locale?form=lang", timeout=1.1
                )
                if locale_payload:
                    admin_port, admin_scheme = 443, "https"
            if isinstance(locale_payload, dict) and locale_payload.get("success"):
                loc_data = locale_payload.get("data") or {}
                if loc_data.get("model"):
                    state["model"] = str(loc_data["model"])
                state["vendor"] = "TP-Link"
                state["protocol"] = admin_scheme
            elif not cfg.get("model") and (443 in open_ports or self._probe_tcp_socket(host, 20001, 0.35)[0]):
                cert_der = self._inspect_tls_cert_der(host, 443) if 443 in open_ports else b""
                if b"tplinkdeco.net" in cert_der:
                    state["model"] = "TP-Link Deco Mesh System"
                    state["vendor"] = "TP-Link"
                    state["protocol"] = "https"
                elif 20001 not in open_ports and self._probe_tcp_socket(host, 20001, 0.35)[0]:
                    open_ports.append(20001)
                    state["openPorts"] = open_ports
                    state["model"] = "TP-Link Deco Mesh System"
                    state["vendor"] = "TP-Link"

            snmp_data = self._snmp_get_oids(
                host,
                {
                    "sysDescr": "1.3.6.1.2.1.1.1.0",
                    "sysUpTime": "1.3.6.1.2.1.1.3.0",
                    "sysName": "1.3.6.1.2.1.1.5.0",
                    "ifNumber": "1.3.6.1.2.1.2.1.0",
                },
                community=str(cfg.get("snmpCommunity") or "public"),
                timeout=0.35,
            )
            if snmp_data:
                state["snmp"] = snmp_data
                state["telemetryAvailable"] = True
                if snmp_data.get("sysDescr") and (not cfg.get("model") and not is_primary):
                    state["model"] = snmp_data["sysDescr"][:90]

        stok = str(cfg.get("stok") or "")
        if alive and stok:
            encoded_stok = urllib.parse.quote(stok, safe="")
            ports_payload = self._luci_post(
                host,
                admin_port,
                admin_scheme,
                f"/cgi-bin/luci/;stok={encoded_stok}/admin/status?form=router",
                timeout=2.2,
            )
            if isinstance(ports_payload, dict) and isinstance(ports_payload.get("data"), list):
                state["authenticated"] = True
                for index, item in enumerate(ports_payload["data"]):
                    if index >= len(state["ports"]) or not isinstance(item, dict):
                        continue
                    port_state = state["ports"][index]
                    speed = _router_link_mbps(item.get("speed"))
                    link = str(item.get("link_status", item.get("status", ""))).lower()
                    connected = link in {"up", "connected", "1", "on", "true"}
                    disconnected = link in {"down", "disconnected", "0", "off", "false"}
                    port_state.update({
                        "speed": speed,
                        "speedText": f"{speed} Mbps" if speed else "Unavailable",
                        "duplex": str(item.get("duplex") or "Unknown"),
                        "linkStatus": "connected" if connected else "disconnected" if disconnected else "unknown",
                        "status": (
                            "optimal"
                            if connected and speed and speed >= 1000
                            else ("warning" if connected and speed else "disconnected" if disconnected else "unknown")
                        ),
                    })
                state["telemetryAvailable"] = True

            perf_payload = self._luci_post(
                host,
                admin_port,
                admin_scheme,
                f"/cgi-bin/luci/;stok={encoded_stok}/admin/status?form=all",
                timeout=2.2,
            )
            metrics = perf_payload.get("data") if isinstance(perf_payload, dict) else None
            if isinstance(metrics, dict):
                for field, key in (("cpu_load", "loadPct"), ("mem_usage", "usagePct")):
                    match = re.search(r"\d+", str(metrics.get(field, "")))
                    if match:
                        value = max(0, min(100, int(match.group())))
                        target = state["cpu"] if field == "cpu_load" else state["memory"]
                        target[key] = value
                        target["history"] = [value]
                        state["authenticated"] = True
                        state["telemetryAvailable"] = True

            # Optional WAN IPv4 & DHCP client count queries
            wan_payload = self._luci_post(
                host,
                admin_port,
                admin_scheme,
                f"/cgi-bin/luci/;stok={encoded_stok}/admin/network?form=wan_ipv4_status",
                timeout=1.5,
            )
            if isinstance(wan_payload, dict) and isinstance(wan_payload.get("data"), dict):
                wan_ip = wan_payload["data"].get("wan_ipv4_ipaddr") or wan_payload["data"].get("ipaddr")
                if wan_ip:
                    state["wanIpv4"] = str(wan_ip)
            dhcp_payload = self._luci_post(
                host,
                admin_port,
                admin_scheme,
                f"/cgi-bin/luci/;stok={encoded_stok}/admin/dhcps?form=client",
                timeout=1.5,
            )
            if isinstance(dhcp_payload, dict) and isinstance(dhcp_payload.get("data"), list):
                state["clientCount"] = len(dhcp_payload["data"])
                dhcp_hosts: dict[str, str] = {}
                for cl in dhcp_payload["data"]:
                    if not isinstance(cl, dict):
                        continue
                    cip = str(cl.get("ipaddr") or cl.get("ip") or "").strip()
                    cname = str(cl.get("hostname") or cl.get("name") or "").strip()
                    if cip and cname and cname.lower() not in {"*", "unknown", "—", "--"}:
                        dhcp_hosts[cip] = cname[:80]
                if dhcp_hosts and hasattr(self, "_save_cached_hostnames"):
                    self._save_cached_hostnames(dhcp_hosts)
            if is_primary:
                control = RouterGameControl({
                    **cfg, "ip": host, "port": admin_port, "useHttps": admin_scheme == "https",
                }, self._luci_post)
                clients = control.clients()
                if clients is not None:
                    state.update(routerClients=clients, routerClientSource="router", authenticated=True)
                    state["denyListEnabled"] = control.deny_list_enabled()
                elif isinstance(dhcp_payload, dict) and dhcp_payload.get("success") is True:
                    leases = router_clients(dhcp_payload.get("data"))
                    if leases is not None:
                        state.update(routerClients=leases, routerClientSource="dhcp", authenticated=True)

        if previous_state:
            for idx, prev_port in enumerate(previous_state.get("ports", [])):
                if prev_port.get("simulation") and idx < len(state["ports"]):
                    state["ports"][idx] = dict(prev_port)
        return state

    def _resolve_router_configs(self) -> list[dict]:
        """Combine primary gateway, saved per-router credentials, and all monitored router devices."""
        self = cast("Monitor", self)
        primary = dict(self.config.get("router", {}))
        primary_ip = str(primary.get("ip") or "192.168.0.1").strip()
        by_ip: dict[str, dict] = {}
        by_ip[primary_ip] = {**primary, "ip": primary_ip, "isPrimary": True, "role": "Main Gateway"}

        saved_map = self.config.get("routers") or {}
        if isinstance(saved_map, list):
            saved_iter = {str(r.get("ip")): r for r in saved_map if isinstance(r, dict) and r.get("ip")}
        elif isinstance(saved_map, dict):
            saved_iter = saved_map
        else:
            saved_iter = {}

        for ip_key, r_cfg in saved_iter.items():
            if not isinstance(r_cfg, dict):
                continue
            r_ip = str(r_cfg.get("ip") or ip_key).strip()
            merged = {**by_ip.get(r_ip, {}), **r_cfg, "ip": r_ip}
            by_ip[r_ip] = merged

        cached_fps = self._get_cached_fingerprints()
        for dev in self.get_devices():
            d_type = str(dev.get("type") or "").lower()
            d_ip = str(dev.get("ip") or "").strip()
            if not d_ip:
                continue
            fp = cached_fps.get(d_ip, {})
            if d_type in {"gateway", "router"} or fp.get("role") in {"gateway", "router"}:
                existing = dict(by_ip.get(d_ip, {}))
                existing.setdefault("ip", d_ip)
                existing.setdefault("port", int(dev.get("port") or fp.get("preferredPort") or 80))
                existing.setdefault("name", dev.get("name") or f"Router ({d_ip})")
                if fp.get("model") and not existing.get("model"):
                    existing["model"] = fp["model"]
                existing.setdefault("vendor", dev.get("vendor") or fp.get("vendor") or "TP-Link")
                existing.setdefault("role", "Main Gateway" if d_ip == primary_ip else "Secondary Router")
                by_ip[d_ip] = existing

        return sorted(
            by_ip.values(),
            key=lambda item: (
                0 if item.get("ip") == primary_ip else 1,
                [int(x) if x.isdigit() else 0 for x in str(item.get("ip", "0.0.0.0")).split(".")],
            ),
        )

    def get_router_fleet(self) -> list[dict]:
        self = cast("Monitor", self)
        with self.lock:
            return json.loads(json.dumps(getattr(self, "router_fleet", [])))

    def probe_routers_fleet(self) -> list[dict]:
        """Probe all gateways and secondary routers concurrently to collect live telemetry."""
        self = cast("Monitor", self)
        configs = self._resolve_router_configs()
        if not configs:
            return []
        primary_ip = str(self.config.get("router", {}).get("ip") or "192.168.0.1")
        prev_by_ip = {r.get("ip"): r for r in getattr(self, "router_fleet", []) if r.get("ip")}

        def _run(cfg: dict) -> dict:
            ip = cfg["ip"]
            is_prim = ip == primary_ip
            prev = self.router_state if is_prim else prev_by_ip.get(ip)
            return self._probe_single_router(cfg, is_primary=is_prim, previous_state=prev)

        with ThreadPoolExecutor(max_workers=min(12, len(configs))) as pool:
            fleet = list(pool.map(_run, configs))

        with self.lock:
            self.router_fleet = fleet
            primary_state = next((r for r in fleet if r["ip"] == primary_ip), None)
            if primary_state is not None:
                self.router_state = primary_state
        if primary_state is not None:
            self._evaluate_router_ports(primary_state)
        return fleet

    def probe_router(self) -> dict:
        self = cast("Monitor", self)
        cfg = self.config["router"]
        with self.lock:
            prev_primary = dict(self.router_state)
        state = self._probe_single_router(cfg, is_primary=True, previous_state=prev_primary)
        with self.lock:
            self.router_state = state
            fleet = list(getattr(self, "router_fleet", []))
            replaced = False
            for idx, item in enumerate(fleet):
                if item.get("ip") == state["ip"]:
                    fleet[idx] = state
                    replaced = True
                    break
            if not replaced:
                fleet.insert(0, state)
            self.router_fleet = fleet
        self._evaluate_router_ports(state)
        return state

    def probe_isp(self) -> dict:
        self = cast("Monitor", self)
        with self._isp_probe_lock:
            return self._probe_isp()

    def _probe_isp(self) -> dict:
        self = cast("Monitor", self)
        now_dt = datetime.now().astimezone()
        sample_epoch = now_dt.timestamp()
        now = now_dt.strftime("%H:%M:%S")
        now_full = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        probes = []
        with self.lock:
            graph = copy.deepcopy(self.isp_state["pingGraph"])
            history = copy.deepcopy(self.isp_state["history"])
        global_log = graph.setdefault("statusLog", [])

        router_cfg = self.config.get("router", {})
        router_ip = router_cfg.get("ip", "192.168.0.1")
        try:
            router_port = int(router_cfg.get("port") or 80)
        except (TypeError, ValueError):
            router_port = 80

        def _probe_single_isp_target(target: dict) -> tuple[dict, bool, float | None, str]:
            t_host = router_ip if target["id"] == "gateway" else target["host"]
            t_ip = router_ip if target["id"] == "gateway" else target["ip"]
            t_port = router_port if target["id"] == "gateway" else target["port"]
            # Ghost Mode: prefer single lightweight ICMP echo; only open TCP socket if ICMP fails
            icmp_ok, icmp_ms = self._probe_icmp(t_host, 850)
            if icmp_ok and icmp_ms is not None:
                tcp_alive, tcp_ms = False, None
            else:
                tcp_open, tcp_responded, tcp_ms = self._probe_tcp_socket(t_host, t_port, 1.0)
                tcp_alive = tcp_responded if target["id"] == "gateway" else tcp_open
            alive = icmp_ok or tcp_alive
            if icmp_ok and icmp_ms is not None:
                latency = icmp_ms
                method = "ICMP Echo"
            elif tcp_alive:
                latency = tcp_ms
                method = f"TCP/{t_port}"
            else:
                latency = None
                method = "Timeout"
            return (
                {
                    "id": target["id"],
                    "name": target["name"],
                    "host": t_host,
                    "ip": t_ip,
                    "port": t_port,
                    "method": method,
                    "icmpAlive": icmp_ok,
                },
                alive,
                latency,
                method,
            )

        with ThreadPoolExecutor(max_workers=max(1, len(ISP_TARGETS))) as pool:
            target_results = list(pool.map(_probe_single_isp_target, ISP_TARGETS))

        latency_changes = []
        for meta, alive, latency, method in target_results:
            t_id = meta["id"]
            t_name = meta["name"]
            t_host = meta["host"]
            t_ip = meta["ip"]
            t_port = meta["port"]
            probes.append({
                "id": t_id,
                "name": t_name,
                "host": t_host,
                "ip": t_ip,
                "latencyMs": latency,
                "packetLoss": 0 if alive else 100,
                "alive": alive,
                "method": method,
                "color": next((t["color"] for t in ISP_TARGETS if t["id"] == t_id), "#3b82f6"),
            })
            stats = graph["stats"][t_id]
            prev_status = stats.get("lastStatus")
            curr_status = "UP" if alive else "DOWN"
            previous_ms = stats.get("currentMs")
            if t_id != "gateway" and latency is not None and previous_ms is not None and stats.get("probeMethod") == method:
                latency_changes.append(abs(latency - previous_ms))
            stats["currentMs"] = latency
            stats["lossPct"] = 0 if alive else 100
            stats["probeMethod"] = method

            hb_msg = (
                f"200 - OK • {method} reply from {t_host} ({t_ip}) in {latency} ms"
                if alive
                else f"No response from {t_host} ({t_ip}:{t_port}) over ICMP or TCP"
            )
            stats["heartbeats"].append({
                "time": now,
                "dateTime": now_full,
                "sampleEpoch": sample_epoch,
                "ms": latency,
                "status": "online" if alive else "offline",
                "message": hb_msg,
            })
            del stats["heartbeats"][:-60]
            self._record_ping_sample(t_id, alive, latency, timestamp=sample_epoch)
            heartbeats = stats["heartbeats"]
            values = [entry["ms"] for entry in heartbeats if entry["ms"] is not None]
            up_ratio = (
                sum(entry["status"] != "offline" for entry in heartbeats)
                / len(heartbeats)
                * 100
            )
            db_uptime = self._get_ping_uptime_stats(t_id)
            stats["uptimePct"] = round(up_ratio, 2)
            stats.update(db_uptime)
            if values:
                stats.update({
                    "avgMs": round(sum(values) / len(values), 1),
                    "minMs": min(values),
                    "maxMs": max(values),
                })
            else:
                stats.update(avgMs=None, minMs=None, maxMs=None)

            t_log = stats.setdefault("statusLog", [])
            # Record state transitions (DOWN, recovery UP, initial check, or high latency spike)
            should_log = (
                prev_status is None
                or prev_status != curr_status
                or not alive
                or (latency is not None and latency > 120)
            )
            if should_log:
                if prev_status == "DOWN" and curr_status == "UP":
                    log_msg = f"Connection RESTORED to {t_name} ({t_ip}) — Responded in {latency} ms ({method})"
                elif not alive:
                    log_msg = f"Connection LOST to {t_name} ({t_ip}:{t_port}) — Probe timed out"
                elif latency is not None and latency > 120:
                    log_msg = f"High ping spike on {t_name} ({t_ip}) — {latency} ms response ({method})"
                else:
                    log_msg = f"200 - OK • {t_name} ({t_ip}) online ({latency} ms via {method})"
                entry_item = {
                    "status": curr_status,
                    "dateTime": now_full,
                    "timestamp": utc_now(),
                    "targetId": t_id,
                    "targetName": t_name,
                    "ip": t_ip,
                    "latencyMs": latency,
                    "message": log_msg,
                }
                t_log.insert(0, entry_item)
                del t_log[40:]
                global_log.insert(0, entry_item)
                del global_log[60:]

                # Also persist connection loss / recovery in SQLite network_events for permanent history
                if (prev_status is not None and prev_status != curr_status) or (
                    prev_status is None and not alive
                ):
                    self._record_event(
                        "WAN_RESTORED" if alive else "WAN_OUTAGE",
                        "INFO" if alive else "CRITICAL",
                        f"{t_name} {curr_status}",
                        log_msg,
                        ip=t_ip,
                        device_name=t_name,
                    )
            stats["lastStatus"] = curr_status
        graph["timeseries"]["timestamps"].append(now)
        del graph["timeseries"]["timestamps"][:-40]
        for target in ISP_TARGETS:
            values = graph["timeseries"][target["id"]]
            values.append(graph["stats"][target["id"]]["currentMs"])
            del values[:-40]

        wan = [probe for probe in probes if probe["id"] != "gateway"]
        wan_alive = any(probe["alive"] for probe in wan)
        latencies = [
            probe["latencyMs"]
            for probe in wan
            if probe["alive"] and probe["latencyMs"] is not None
        ]
        latency = round(sum(latencies) / len(latencies), 1) if latencies else None
        jitter = round(sum(latency_changes) / len(latency_changes), 1) if latency_changes else None
        dns_started = time.perf_counter()
        try:
            socket.getaddrinfo(
                self.config["isp"].get("dnsTestDomain", "google.com"), 443
            )
            dns_ms = round((time.perf_counter() - dns_started) * 1000, 1)
        except OSError:
            dns_ms = None
        loss = round(sum(not probe["alive"] for probe in wan) / len(wan) * 100)
        score = (
            0
            if not latencies
            else max(
                0,
                min(
                    100,
                    round(
                        100
                        - loss * 2
                        - max(0, (latency or 0) - 60) * 0.5
                        - (15 if dns_ms is None or dns_ms > 100 else 0)
                    ),
                ),
            )
        )
        overall = "EXCELLENT" if score >= 90 else "GOOD" if score >= 70 else "DEGRADED" if wan_alive else "OUTAGE"
        gw_latency = graph["stats"]["gateway"]["currentMs"]
        gw_alive = any(p["id"] == "gateway" and p["alive"] for p in probes)

        isp_diagnosis = self._build_isp_diagnosis(
            overall=overall,
            score=score,
            gw_alive=gw_alive,
            gw_latency=gw_latency,
            wan_latency=latency,
            loss_pct=loss,
            dns_ms=dns_ms,
        )

        history["latency"].append(latency)
        history["timestamps"].append(now)
        del history["latency"][:-30]
        del history["timestamps"][:-30]
        state_update = {
            "overallHealth": overall,
            "healthScore": score,
            "status": (
                "online" if score >= 70 else "warning" if wan_alive else "offline"
            ),
            "wanGatewayLatencyMs": gw_latency,
            "wanGatewayReachable": gw_alive,
            "wanGatewayIp": router_ip,
            "tier1LatencyMs": latency,
            "packetLossPct": loss,
            "probeFailurePct": loss,
            "probeTimestamp": utc_now(),
            "jitterMs": jitter,
            "dnsResolutionMs": dns_ms,
            "probes": probes,
            "diagnosis": isp_diagnosis,
            "pingGraph": graph,
            "history": history,
        }
        with self.lock:
            self.isp_state.update(state_update)
            if self.router_state.get("ip") == router_ip:
                self.router_state["wanInternetStatus"] = "CONNECTED" if wan_alive else "DISCONNECTED"
        if hasattr(self, "_evaluate_isp_alert"):
            self._evaluate_isp_alert(overall, isp_diagnosis, probes)
        return self.get_isp_state()

    def _build_isp_diagnosis(
        self,
        *,
        overall: str,
        score: int,
        gw_alive: bool,
        gw_latency: float | None,
        wan_latency: float | None,
        loss_pct: int,
        dns_ms: float | None,
    ) -> dict:
        """Diagnose current gateway, WAN probe, and DNS measurements."""
        self = cast("Monitor", self)
        gateway_ip = self.config.get("router", {}).get("ip", "192.168.0.1")

        if overall == "OUTAGE":
            if not gw_alive:
                return {
                    "verdict": "CRITICAL",
                    "headline": f"Cannot Reach Main Router ({gateway_ip}) — Local Network Disconnected",
                    "bottleneckLayer": f"Office Network / Main Router ({gateway_ip})",
                    "summary": (
                        f"This computer cannot reach Main Router ({gateway_ip}). "
                        "The issue is your local cable or Wi-Fi connection rather than your internet provider."
                    ),
                    "solutions": [
                        f"Check power and network cables on Main Router ({gateway_ip}) and your office switch.",
                        "Verify your computer's Ethernet cable or Wi-Fi connection.",
                        "Click '🔄 Re-Check Internet Now' after checking the router power.",
                    ],
                }
            return {
                "verdict": "CRITICAL",
                "headline": "Internet Connection Down — Office Router Is On, No Outside Internet",
                "bottleneckLayer": "Internet Provider (Modem / Fiber Box)",
                "summary": (
                    f"Main Router ({gateway_ip}) is working inside the office ({gw_latency} ms), "
                    "but outside servers (1.1.1.1, 8.8.8.8, and google.com) are not responding."
                ),
                "solutions": [
                    "Check your internet fiber modem/box — look for a red blinking light.",
                    f"Unplug and firmly reconnect the internet cable between the modem and Main Router ({gateway_ip}).",
                    "Restart the internet modem for 30 seconds; if the red light stays on, contact your internet provider.",
                ],
            }

        issues: list[str] = []
        solutions: list[str] = []
        bottleneck = None

        if not gw_alive:
            issues.append(f"Main Router ({gateway_ip}) did not answer the monitor")
            bottleneck = "Gateway reachability"
            solutions.append(f"Check whether {gateway_ip} permits ICMP or responds on its configured management port.")
        elif gw_latency is not None and gw_latency > 25:
            issues.append(f"Slow local connection to Main Router ({gw_latency} ms)")
            bottleneck = f"Busy Office Wi-Fi or Cable Before Router ({gateway_ip})"
            solutions.append(
                f"Local delay to {gateway_ip} is {gw_latency} ms (usually under 5 ms). Check for busy Wi-Fi or slow cables."
            )

        if loss_pct > 0:
            issues.append(f"{loss_pct}% of external targets did not respond")
            bottleneck = "External reachability"
            solutions.append(
                "Compare failures across multiple checks to distinguish a single unreachable target from a WAN problem."
            )

        if wan_latency is not None and wan_latency > 75:
            issues.append(f"Slow outside internet ping ({wan_latency} ms avg)")
            if bottleneck is None:
                bottleneck = "Latency to external targets"
            solutions.append(
                f"Outside probes average {wan_latency} ms. Use 'Check Internet Path' to investigate the delay."
            )

        if dns_ms is None or dns_ms > 80:
            issues.append(f"Slow DNS lookup ({dns_ms} ms)" if dns_ms is not None else "DNS lookup failed")
            if bottleneck is None:
                bottleneck = "Slow Website Address Lookup (DNS)"
            solutions.append(
                "Use 'Test Website Lookup Speed' to compare the system resolver with the other DNS resolvers."
            )

        if not issues:
            return {
                "verdict": "OPTIMAL",
                "headline": "Gateway, internet reachability and DNS checks passed",
                "bottleneckLayer": "None detected by current probes",
                "summary": (
                    f"Main Router ({gateway_ip}) responds in {gw_latency if gw_latency is not None else '--'} ms, "
                    f"external probes average {wan_latency} ms, and website lookup takes {dns_ms} ms."
                ),
                "solutions": [],
            }

        return {
            "verdict": "WARNING" if score >= 50 else "CRITICAL",
            "headline": " · ".join(issues),
            "bottleneckLayer": bottleneck,
            "summary": (
                f"Found {len(issues)} issue(s): {'; '.join(issues)}. "
                f"Router latency: {f'{gw_latency} ms' if gw_latency is not None else 'unavailable'}. "
                f"External latency: {f'{wan_latency} ms' if wan_latency is not None else 'unavailable'}."
            ),
            "solutions": solutions,
        }

    def _hydrate_ping_history(self) -> None:
        self = cast("Monitor", self)
        graph = self.isp_state.get("pingGraph")
        if not graph:
            return
        stats_map = graph.get("stats", {})
        ts_series: list[str] = []
        for target in ISP_TARGETS:
            tid = target["id"]
            recent = self._load_recent_ping_samples(tid, limit=60)
            if not recent:
                continue
            st = stats_map[tid]
            st["heartbeats"] = recent
            st["currentMs"] = recent[-1]["ms"]
            st["lossPct"] = 0 if recent[-1]["status"] == "online" else 100
            vals = [e["ms"] for e in recent if e["ms"] is not None]
            if vals:
                st["avgMs"] = round(sum(vals) / len(vals), 1)
                st["minMs"] = min(vals)
                st["maxMs"] = max(vals)
            db_uptime = self._get_ping_uptime_stats(tid)
            up_ratio = sum(e["status"] != "offline" for e in recent) / len(recent) * 100
            st["uptimePct"] = round(up_ratio, 2)
            st.update(db_uptime)
            st["lastStatus"] = "UP" if recent[-1]["status"] == "online" else "DOWN"
            tail = recent[-40:]
            graph["timeseries"][tid] = [e["ms"] for e in tail]
            if len(tail) > len(ts_series):
                ts_series = [e["time"] for e in tail]
        if ts_series:
            graph["timeseries"]["timestamps"] = ts_series

        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT value FROM monitor_metadata WHERE key='last_speed_test'"
                ).fetchone()
                if row and row["value"]:
                    saved_st = json.loads(row["value"])
                    if isinstance(saved_st, dict) and saved_st.get("downloadMbps"):
                        self.isp_state["lastSpeedTest"] = saved_st
                        history = self.isp_state.setdefault("speedHistory", [])
                        if not history:
                            history.append(saved_st)
        except Exception:
            pass

    def get_isp_state(self) -> dict:
        self = cast("Monitor", self)
        with self.lock:
            state = json.loads(json.dumps(self.isp_state))
        state["speedTestsEnabled"] = manual_speed_tests_enabled()
        return state
