"""Wireshark / TShark & Npcap (wpcap.dll) live packet inspection and PCAP/PCAPNG engine for Pulse Game Detector."""

from __future__ import annotations

import ctypes
import ctypes.util
import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Iterable
from pathlib import Path


def find_wireshark_binaries(custom_tshark_path: str = "") -> dict:
    """Locate Wireshark / TShark / Dumpcap binaries and Npcap wpcap.dll on the host."""
    candidates: list[str] = []
    if custom_tshark_path and custom_tshark_path.strip():
        candidates.append(custom_tshark_path.strip())
    which_tshark = shutil.which("tshark")
    if which_tshark:
        candidates.append(which_tshark)
    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ])

    tshark_path = next((p for p in candidates if p and os.path.isfile(p)), "")
    dumpcap_candidates = [shutil.which("dumpcap") or ""]
    wireshark_candidates = [shutil.which("wireshark") or ""]
    if tshark_path:
        base_dir = os.path.dirname(tshark_path)
        dumpcap_candidates.insert(0, os.path.join(base_dir, "dumpcap.exe" if os.name == "nt" else "dumpcap"))
        wireshark_candidates.insert(0, os.path.join(base_dir, "Wireshark.exe" if os.name == "nt" else "wireshark"))
    elif os.name == "nt":
        dumpcap_candidates.extend([
            r"C:\Program Files\Wireshark\dumpcap.exe",
            r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
        ])
        wireshark_candidates.extend([
            r"C:\Program Files\Wireshark\Wireshark.exe",
            r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
        ])

    dumpcap_path = next((p for p in dumpcap_candidates if p and os.path.isfile(p)), "")
    wireshark_path = next((p for p in wireshark_candidates if p and os.path.isfile(p)), "")

    wpcap_path = ""
    if os.name == "nt":
        for p in (
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\wpcap.dll",
        ):
            if os.path.isfile(p):
                wpcap_path = p
                break
    else:
        wpcap_path = ctypes.util.find_library("pcap") or ""

    return {
        "tsharkInstalled": bool(tshark_path),
        "tsharkPath": tshark_path,
        "dumpcapInstalled": bool(dumpcap_path),
        "dumpcapPath": dumpcap_path,
        "wiresharkGuiInstalled": bool(wireshark_path),
        "wiresharkGuiPath": wireshark_path,
        "npcapAvailable": bool(wpcap_path),
        "wpcapPath": wpcap_path,
    }


def build_wireshark_display_filter(game_signatures: list[dict] | None = None) -> str:
    """Build a ready-to-paste Wireshark Display Filter matching Pulse's game catalog."""
    if game_signatures is None:
        from .game_detector import GAME_SIGNATURES
        game_signatures = GAME_SIGNATURES

    domains: list[str] = []
    exact_domains: list[str] = []
    ports: set[int] = set()
    for g in game_signatures:
        for d in g.get("domains", ()):
            target = exact_domains if g.get("exactDomainsOnly") else domains
            if d not in target:
                target.append(d)
        for p in g.get("ports", ()):
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                pass

    clauses: list[str] = []
    for field in ("dns.qry.name", "tls.handshake.extensions_server_name"):
        checks = [f'{field} contains "{d}"' for d in domains]
        checks.extend(f'{field} == "{d}"' for d in exact_domains)
        if checks:
            clauses.append(f"({' or '.join(checks)})")
    if ports:
        port_list = " ".join(str(p) for p in sorted(ports))
        clauses.append(f"(udp.port in {{{port_list}}} or tcp.port in {{{port_list}}})")
    return " or ".join(clauses) if clauses else "dns or tls.handshake.type == 1"


def extract_dns_qname_payload(payload: bytes, is_tcp: bool = False) -> str:
    """Extract the queried DNS hostname cleanly from raw UDP/TCP DNS payload."""
    if not payload or len(payload) < 12:
        return ""
    if is_tcp and len(payload) >= 14:
        try:
            tcp_len = struct.unpack("!H", payload[:2])[0]
            if tcp_len == len(payload) - 2:
                payload = payload[2:]
        except struct.error:
            return ""
    if len(payload) < 12:
        return ""
    try:
        qdcount = struct.unpack("!H", payload[4:6])[0]
    except struct.error:
        return ""
    if qdcount < 1 or qdcount > 16:
        return ""
    pos = 12
    labels: list[str] = []
    total_len = 0
    while pos < len(payload) and len(labels) < 20:
        length = payload[pos]
        if length == 0:
            break
        if length >= 0xC0 or length > 63:
            return ""
        pos += 1
        if pos + length > len(payload):
            return ""
        lbl = payload[pos : pos + length].decode("ascii", "ignore").lower()
        if not lbl:
            return ""
        labels.append(lbl)
        total_len += len(lbl) + 1
        if total_len > 253:
            return ""
        pos += length
    if not labels:
        return ""
    qname = ".".join(labels).strip(".")
    if qname.endswith((".in-addr.arpa", ".ip6.arpa")):
        return ""
    return qname


def extract_tls_sni(payload: bytes) -> str:
    """Extract Server Name Indication (tls.handshake.extensions_server_name) from TLS ClientHello."""
    if not payload or len(payload) < 48:
        return ""
    # TLS Handshake record (0x16), SSL 3.0 / TLS 1.x version (0x03 0x00..0x04), ClientHello (0x01)
    if payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return ""
    try:
        pos = 43  # 5 record + 4 handshake header + 2 client version + 32 client random
        if pos >= len(payload):
            return ""
        sess_len = payload[pos]
        pos += 1 + sess_len
        if pos + 2 > len(payload):
            return ""
        cipher_len = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2 + cipher_len
        if pos >= len(payload):
            return ""
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_total = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2
        end_ext = min(len(payload), pos + ext_total)
        while pos + 4 <= end_ext:
            ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            ext_end = pos + ext_len
            if ext_end > end_ext:
                break
            if ext_type == 0x0000 and ext_len >= 5:
                list_len = struct.unpack("!H", payload[pos : pos + 2])[0]
                spos = pos + 2
                send = min(ext_end, spos + list_len)
                while spos + 3 <= send:
                    name_type = payload[spos]
                    name_len = struct.unpack("!H", payload[spos + 1 : spos + 3])[0]
                    spos += 3
                    if spos + name_len > send:
                        break
                    if name_type == 0x00 and 3 <= name_len <= 253:
                        host = payload[spos : spos + name_len].decode("ascii", "ignore").strip().lower()
                        if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]", host):
                            return host
                    spos += name_len
            pos = ext_end
    except (struct.error, IndexError):
        return ""
    return ""


def extract_http_host(payload: bytes) -> str:
    """Extract http.host header cleanly from cleartext HTTP request payloads."""
    if not payload or len(payload) < 12:
        return ""
    head = payload[:1024]
    if not head.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"CONNECT ", b"OPTIONS ")):
        return ""
    text = head.decode("ascii", "ignore")
    m = re.search(r"(?:^|\r\n)Host:\s*([A-Za-z0-9.-]{3,253})(?::\d+)?\s*(?:\r\n|$)", text, re.I)
    if m:
        return m.group(1).strip().lower()
    return ""


def unwrap_tzsp_packet(payload: bytes) -> tuple[bytes | None, int]:
    """Unwrap TaZmen Sniffer Protocol (TZSP, UDP 37008) encapsulated router/AP packet frames."""
    if not payload or len(payload) < 6 or payload[0] != 0x01:
        return None, 1
    try:
        encap = struct.unpack("!H", payload[2:4])[0]
    except struct.error:
        return None, 1
    # Map TZSP encap protocol to libpcap DLT (1 = Ethernet, 105 = IEEE 802.11)
    dlt = 1 if encap == 0x0001 else (105 if encap == 0x0012 else 1)
    pos = 4
    for _ in range(32):
        if pos >= len(payload):
            return None, dlt
        tag = payload[pos]
        pos += 1
        if tag == 0x00:  # Padding
            continue
        if tag == 0x01:  # End of tagged fields
            return payload[pos:], dlt
        if pos >= len(payload):
            return None, dlt
        tag_len = payload[pos]
        pos += 1 + tag_len
    return None, dlt


_RFC1918_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA_V6 = ipaddress.ip_network("fc00::/7")


def _is_usable_client_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        if ip_str.endswith(".255"):
            return False
        return any(addr in net for net in _RFC1918_V4)
    return addr in _ULA_V6


def _match_sig_helper(domain: str = "", port: int | None = None, matcher=None) -> dict | None:
    if matcher is not None:
        return matcher(domain=domain, port=port)
    from .game_detector import GameDetectorMixin
    return GameDetectorMixin._match_game_signature(domain=domain, port=port)


def _get_game_ports_set() -> frozenset[int]:
    from .game_detector import _NETSTAT_GAME_PORTS
    return _NETSTAT_GAME_PORTS


def dissect_raw_packet(
    raw: bytes,
    dlt: int = 1,
    ts_epoch: float | None = None,
    matcher=None,
    game_ports: frozenset[int] | None = None,
    infra_ips: set[str] | None = None,
    self_ips: set[str] | None = None,
    _depth: int = 0,
) -> dict | None:
    """Dissect Ethernet/Loopback/Raw IPv4/IPv6 packet and match Wireshark DPI signatures."""
    if not raw or len(raw) < 20 or _depth > 2:
        return None
    if ts_epoch is None:
        ts_epoch = time.time()
    infra = infra_ips or set()
    self_set = self_ips or set()
    ports_set = game_ports if game_ports is not None else _get_game_ports_set()

    offset = 0
    eth_type = 0
    if dlt == 1:  # Ethernet (DLT_EN10MB)
        if len(raw) < 14:
            return None
        eth_type = struct.unpack("!H", raw[12:14])[0]
        offset = 14
        while eth_type in (0x8100, 0x88A8) and offset + 4 <= len(raw):
            eth_type = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
            offset += 4
    elif dlt == 0:  # Npcap / BSD Loopback (DLT_NULL)
        if len(raw) < 4:
            return None
        family = struct.unpack("<I", raw[:4])[0]
        offset = 4
        if family == 2:
            eth_type = 0x0800
        elif family in (24, 28, 30):
            eth_type = 0x86DD
        else:
            return None
    elif dlt == 113:  # Linux cooked capture (SLL)
        if len(raw) < 16:
            return None
        eth_type = struct.unpack("!H", raw[14:16])[0]
        offset = 16
    elif dlt == 101:  # Raw IP (DLT_RAW)
        offset = 0
        ver = raw[0] >> 4
        eth_type = 0x0800 if ver == 4 else (0x86DD if ver == 6 else 0)
    else:
        return None

    src_ip = ""
    dst_ip = ""
    proto = 0
    l4_offset = 0
    ip_end = len(raw)
    if eth_type == 0x0800:
        if offset + 20 > len(raw):
            return None
        v_ihl = raw[offset]
        if (v_ihl >> 4) != 4:
            return None
        ihl = (v_ihl & 0x0F) * 4
        total_len = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
        if ihl < 20 or total_len < ihl or offset + ihl > len(raw):
            return None
        ip_end = min(len(raw), offset + total_len)
        proto = raw[offset + 9]
        src_ip = socket.inet_ntop(socket.AF_INET, raw[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntop(socket.AF_INET, raw[offset + 16 : offset + 20])
        l4_offset = offset + ihl
    elif eth_type == 0x86DD:
        if offset + 40 > len(raw):
            return None
        if (raw[offset] >> 4) != 6:
            return None
        payload_len = struct.unpack("!H", raw[offset + 4 : offset + 6])[0]
        ip_end = min(len(raw), offset + 40 + payload_len)
        proto = raw[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, raw[offset + 8 : offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, raw[offset + 24 : offset + 40])
        l4_offset = offset + 40
    else:
        return None

    if proto not in (6, 17):
        return None

    sport = 0
    dport = 0
    tcp_flags = 0
    app_payload = b""
    if proto == 17:
        if l4_offset + 8 > ip_end:
            return None
        sport, dport, ulen, _csum = struct.unpack("!HHHH", raw[l4_offset : l4_offset + 8])
        udp_end = min(ip_end, l4_offset + ulen) if ulen >= 8 else ip_end
        app_payload = raw[l4_offset + 8 : udp_end]
        if dport == 37008 and app_payload:
            inner, inner_dlt = unwrap_tzsp_packet(app_payload)
            if inner:
                res = dissect_raw_packet(
                    inner,
                    dlt=inner_dlt,
                    ts_epoch=ts_epoch,
                    matcher=matcher,
                    game_ports=ports_set,
                    infra_ips=infra,
                    self_ips=self_set,
                    _depth=_depth + 1,
                )
                if res:
                    res["detectionMethod"] = "Wireshark TZSP Stream"
                    res["reporterIp"] = src_ip
                return res
            return None
    else:
        if l4_offset + 20 > ip_end:
            return None
        sport, dport = struct.unpack("!HH", raw[l4_offset : l4_offset + 4])
        data_off = ((raw[l4_offset + 12] >> 4) & 0x0F) * 4
        if data_off < 20 or l4_offset + data_off > ip_end:
            return None
        tcp_flags = raw[l4_offset + 13]
        app_payload = raw[l4_offset + data_off : ip_end]

    # Determine LAN client endpoint accurately
    src_client = _is_usable_client_ip(src_ip)
    dst_client = _is_usable_client_ip(dst_ip)
    client_ip = ""
    remote_ip = ""
    if 53 in (sport, dport) or 5353 in (sport, dport):
        if dport in (53, 5353) and src_client:
            client_ip, remote_ip = src_ip, dst_ip
        elif sport in (53, 5353) and dst_client:
            client_ip, remote_ip = dst_ip, src_ip
    elif src_client and not dst_client:
        client_ip, remote_ip = src_ip, dst_ip
    elif dst_client and not src_client:
        client_ip, remote_ip = dst_ip, src_ip
    elif src_client and dst_client:
        if dport in (443, 8443, 80, 8080, 19132, 27036) or (src_ip not in infra and dst_ip in infra):
            client_ip, remote_ip = src_ip, dst_ip
        elif sport in (443, 8443, 80, 8080) or (dst_ip not in infra and src_ip in infra):
            client_ip, remote_ip = dst_ip, src_ip
        else:
            client_ip, remote_ip = src_ip, dst_ip

    if not client_ip or client_ip in infra:
        return None

    # 1. DNS Wire QNAME inspection
    if 53 in (sport, dport):
        dns_offset = 2 if proto == 6 else 0
        if dport != 53 or len(app_payload) <= dns_offset + 2 or app_payload[dns_offset + 2] & 0x80:
            return None
        qname = extract_dns_qname_payload(app_payload, is_tcp=(proto == 6))
        if qname:
            sig = _match_sig_helper(domain=qname, matcher=matcher)
            if sig:
                return {
                    "tsEpoch": ts_epoch,
                    "ip": client_ip,
                    "remoteIp": remote_ip,
                    "gameId": sig["id"],
                    "gameName": sig["name"],
                    "domain": qname,
                    "port": dport if client_ip == src_ip else sport,
                    "protocol": "DNS",
                    "matchedIndicator": f"DNS Wire: {qname}",
                    "detectionMethod": "Wireshark DNS Wire",
                    "isDnsQuery": dport == 53,
                    "srcIp": src_ip,
                    "dstIp": dst_ip,
                }
        return None

    # 2. TLS ClientHello SNI inspection (captures encrypted HTTPS game sessions)
    if proto == 6 and dport in (443, 8443) and len(app_payload) >= 48 and app_payload[0] == 0x16:
        sni = extract_tls_sni(app_payload)
        if sni:
            sig = _match_sig_helper(domain=sni, matcher=matcher)
            if sig:
                return {
                    "tsEpoch": ts_epoch,
                    "ip": client_ip,
                    "remoteIp": remote_ip,
                    "gameId": sig["id"],
                    "gameName": sig["name"],
                    "domain": sni,
                    "port": dport,
                    "protocol": "TLS SNI",
                    "matchedIndicator": f"TLS SNI: {sni}",
                    "detectionMethod": "Wireshark TLS SNI",
                    "srcIp": src_ip,
                    "dstIp": dst_ip,
                }

    # 3. HTTP Host header inspection
    if proto == 6 and dport in (80, 8080) and app_payload:
        http_host = extract_http_host(app_payload)
        if http_host:
            sig = _match_sig_helper(domain=http_host, matcher=matcher)
            if sig:
                return {
                    "tsEpoch": ts_epoch,
                    "ip": client_ip,
                    "remoteIp": remote_ip,
                    "gameId": sig["id"],
                    "gameName": sig["name"],
                    "domain": http_host,
                    "port": dport,
                    "protocol": "HTTP",
                    "matchedIndicator": f"HTTP Host: {http_host}",
                    "detectionMethod": "Wireshark HTTP Host",
                    "srcIp": src_ip,
                    "dstIp": dst_ip,
                }

    # 4. LAN Game Broadcast payloads (Minecraft Bedrock 19132 / Steam 27036)
    if proto == 17 and dport == 19132 and (
        b"MCPE;" in app_payload or (len(app_payload) > 20 and b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe" in app_payload)
    ):
        sig = _match_sig_helper(port=19132, matcher=matcher)
        if sig:
            return {
                "tsEpoch": ts_epoch,
                "ip": client_ip,
                "remoteIp": remote_ip,
                "gameId": sig["id"],
                "gameName": sig["name"],
                "port": 19132,
                "protocol": "UDP",
                "matchedIndicator": "UDP Broadcast :19132 (Minecraft LAN)",
                "detectionMethod": "Wireshark LAN Broadcast",
                "srcIp": src_ip,
                "dstIp": dst_ip,
            }

    if proto == 17 and dport == 27036 and len(app_payload) >= 8 and app_payload.startswith((b"\xff\xff\xff\xff", b"\x21\x4c\x5f\xa0")):
        sig = _match_sig_helper(port=27036, matcher=matcher)
        if sig:
            return {
                "tsEpoch": ts_epoch,
                "ip": client_ip,
                "remoteIp": remote_ip,
                "gameId": sig["id"],
                "gameName": sig["name"],
                "port": 27036,
                "protocol": "UDP",
                "matchedIndicator": "UDP Broadcast :27036 (Steam Discovery)",
                "frameSourceMac": raw[6:12].hex(":") if dlt == 1 else "",
                "detectionMethod": "Wireshark LAN Broadcast",
                "srcIp": src_ip,
                "dstIp": dst_ip,
            }

    # 5. Active Game Port Flows — match remote service/game port only (never client ephemeral source ports!),
    # ignore LAN traffic involving monitor host self_ips (prevents active port-scan echoes),
    # and strictly exclude TCP RST (0x04), FIN (0x01), bare SYN (0x02), and known router/AP infra IPs!
    is_external_flow = not (src_client and dst_client)
    if not is_external_flow and (src_ip in self_set or dst_ip in self_set):
        return None
    lan_game_ports = (19132, 27015, 27036)
    flow_client_ip = client_ip
    flow_remote_ip = remote_ip
    if not is_external_flow:
        if sport in lan_game_ports:
            flow_client_ip, flow_remote_ip = src_ip, dst_ip
        elif dport in lan_game_ports:
            flow_client_ip, flow_remote_ip = dst_ip, src_ip
    if flow_client_ip in infra:
        return None
    remote_port = dport if flow_client_ip == src_ip else sport
    if proto == 6:
        if (tcp_flags & 0x05) != 0 or (tcp_flags & 0x12) == 0x02:
            return None
        if is_external_flow:
            # Only inspect the remote server port on WAN flows (never client ephemeral ports)
            match_port = remote_port if remote_port in ports_set else None
        else:
            match_port = (
                sport
                if sport in lan_game_ports
                else (dport if dport in lan_game_ports else None)
            )
        if match_port is not None:
            if app_payload:
                sig = _match_sig_helper(port=match_port, matcher=matcher)
                if sig:
                    return {
                        "tsEpoch": ts_epoch,
                        "ip": flow_client_ip,
                        "remoteIp": flow_remote_ip,
                        "gameId": sig["id"],
                        "gameName": sig["name"],
                        "port": match_port,
                        "protocol": "TCP",
                        "matchedIndicator": f"TCP Flow :{match_port}",
                        "detectionMethod": "Wireshark Packet Flow",
                        "srcIp": src_ip,
                        "dstIp": dst_ip,
                    }
    elif proto == 17 and app_payload:
        if is_external_flow:
            match_port = (
                remote_port
                if (remote_port in ports_set and remote_port != 27036)
                else None
            )
        else:
            match_port = 27015 if 27015 in (sport, dport) else None
        if match_port is not None:
            sig = _match_sig_helper(port=match_port, matcher=matcher)
            if sig:
                return {
                    "tsEpoch": ts_epoch,
                    "ip": flow_client_ip,
                    "remoteIp": flow_remote_ip,
                    "gameId": sig["id"],
                    "gameName": sig["name"],
                    "port": match_port,
                    "protocol": "UDP",
                    "matchedIndicator": f"UDP Flow :{match_port}",
                    "detectionMethod": "Wireshark Packet Flow",
                    "srcIp": src_ip,
                    "dstIp": dst_ip,
                }

    return None


def parse_pcap_or_pcapng(raw_bytes: bytes) -> list[tuple[float, int, bytes]]:
    """Parse standard libpcap (.pcap) or Wireshark (.pcapng) bytes into (ts_epoch, dlt, raw_frame) tuples."""
    if not raw_bytes or len(raw_bytes) < 24:
        raise ValueError("Capture file is too short to be a valid .pcap or .pcapng file")

    magic = raw_bytes[:4]
    # 1. Classic libpcap format
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        ns_res = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        endian = "<" if little else ">"
        _m, _maj, _min, _tz, _sf, _snap, linktype = struct.unpack(endian + "IHHiIII", raw_bytes[:24])
        pos = 24
        packets: list[tuple[float, int, bytes]] = []
        while pos < len(raw_bytes):
            if pos + 16 > len(raw_bytes):
                raise ValueError("Capture ends in an incomplete .pcap packet header")
            ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(endian + "IIII", raw_bytes[pos : pos + 16])
            pos += 16
            if pos + incl_len > len(raw_bytes):
                raise ValueError("Capture ends in an incomplete .pcap packet")
            ts = float(ts_sec) + (ts_sub / 1_000_000_000.0 if ns_res else ts_sub / 1_000_000.0)
            packets.append((ts, int(linktype), raw_bytes[pos : pos + incl_len]))
            pos += incl_len
        return packets

    # 2. Wireshark Next Generation (.pcapng)
    if magic == b"\x0a\x0d\x0d\x0a":
        if len(raw_bytes) < 28:
            raise ValueError("Truncated pcapng Section Header Block")
        endian = "<"
        pos = 0
        if_dlts: list[int] = []
        packets = []
        while pos < len(raw_bytes):
            if pos + 12 > len(raw_bytes):
                raise ValueError("Capture ends in an incomplete .pcapng block header")
            if raw_bytes[pos : pos + 4] == magic:
                bom = raw_bytes[pos + 8 : pos + 12]
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("Unsupported pcapng byte-order magic")
            blk_type, blk_len = struct.unpack(endian + "II", raw_bytes[pos : pos + 8])
            end = pos + blk_len
            if blk_len < 12 or blk_len % 4 or end > len(raw_bytes):
                raise ValueError("Invalid or incomplete .pcapng block")
            if struct.unpack_from(endian + "I", raw_bytes, end - 4)[0] != blk_len:
                raise ValueError("Mismatched .pcapng block lengths")
            body = raw_bytes[pos + 8 : pos + blk_len - 4]
            if blk_type == 0x0A0D0D0A:  # SHB resets interface list per section
                if len(body) < 16:
                    raise ValueError("Incomplete .pcapng section header")
                if_dlts = []
            elif blk_type == 0x00000001 and len(body) >= 8:  # Interface Description Block (IDB)
                link_type = struct.unpack(endian + "H", body[:2])[0]
                if_dlts.append(int(link_type))
            elif blk_type == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block (EPB)
                iface_id, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack(endian + "IIIII", body[:20])
                dlt = if_dlts[iface_id] if iface_id < len(if_dlts) else 1
                pkt = body[20 : 20 + cap_len]
                ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                if len(pkt) == cap_len:
                    packets.append((ts, dlt, pkt))
            elif blk_type == 0x00000003 and len(body) >= 4:  # Simple Packet Block (SPB)
                dlt = if_dlts[0] if if_dlts else 1
                pkt = body[4:]
                packets.append((time.time(), dlt, pkt))
            pos += blk_len
        return packets

    raise ValueError("Unrecognized capture format (expected .pcap or .pcapng)")


class PcapRingRecorder:
    """Thread-safe bounded libpcap (.pcap) recorder compatible with Wireshark."""

    GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def __init__(self, path: str | Path, max_bytes: int = 4 * 1024 * 1024) -> None:
        self.path = Path(path)
        self.max_bytes = max(256 * 1024, int(max_bytes))
        self._lock = threading.Lock()
        self._packets_written = 0
        self._ensure_header()

    def _ensure_header(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() or self.path.stat().st_size < 24:
            self.path.write_bytes(self.GLOBAL_HEADER)

    def write_packet(self, raw_frame: bytes, ts_epoch: float | None = None, dlt: int = 1) -> None:
        if not raw_frame or dlt != 1:
            return
        if ts_epoch is None:
            ts_epoch = time.time()
        sec = max(0, int(ts_epoch))
        usec = max(0, min(999999, int((ts_epoch - sec) * 1_000_000)))
        cap_len = min(len(raw_frame), 65535)
        rec = struct.pack("<IIII", sec, usec, cap_len, len(raw_frame)) + raw_frame[:cap_len]
        with self._lock:
            self._ensure_header()
            try:
                cur_size = self.path.stat().st_size
                if cur_size + len(rec) > self.max_bytes:
                    # Keep the most recent tail slice aligned by rotating safely
                    prev_path = self.path.with_suffix(".prev.pcap")
                    try:
                        if prev_path.exists():
                            prev_path.unlink()
                        self.path.replace(prev_path)
                    except OSError:
                        pass
                    self.path.write_bytes(self.GLOBAL_HEADER)
                with self.path.open("ab") as fh:
                    fh.write(rec)
                self._packets_written += 1
            except OSError:
                pass

    def file_bytes(self) -> int:
        try:
            return int(self.path.stat().st_size) if self.path.exists() else 0
        except OSError:
            return 0


class _WinTimeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _WinPcapPktHdr(ctypes.Structure):
    _fields_ = [("ts", _WinTimeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]


def _load_wpcap(wpcap_path: str) -> ctypes.CDLL:
    if not wpcap_path or not os.path.isfile(wpcap_path):
        raise FileNotFoundError(wpcap_path)
    dll = ctypes.CDLL(wpcap_path)
    dll.pcap_findalldevs.restype = ctypes.c_int
    dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_char_p]
    dll.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    dll.pcap_open_live.restype = ctypes.c_void_p
    dll.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    dll.pcap_next_ex.restype = ctypes.c_int
    dll.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_WinPcapPktHdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    dll.pcap_datalink.restype = ctypes.c_int
    dll.pcap_datalink.argtypes = [ctypes.c_void_p]
    dll.pcap_close.argtypes = [ctypes.c_void_p]
    return dll


def list_npcap_interfaces(wpcap_path: str = "", tshark_path: str = "") -> list[dict]:
    """List capture adapters via Npcap wpcap.dll (or TShark -D fallback) without noisy virtual interfaces first."""
    results: list[dict] = []
    if wpcap_path and os.path.isfile(wpcap_path):
        try:
            dll = _load_wpcap(wpcap_path)
            errbuf = ctypes.create_string_buffer(256)
            alldevs = ctypes.POINTER(_PcapIf)()
            if dll.pcap_findalldevs(ctypes.byref(alldevs), errbuf) == 0:
                cur = alldevs
                idx = 1
                while cur:
                    node = cur.contents
                    name = (node.name or b"").decode("utf-8", "ignore")
                    desc = (node.description or b"").decode("utf-8", "ignore") or name
                    low = f"{desc} {name}".lower()
                    is_loop = "loopback" in low
                    is_virtual_noise = any(
                        tok in low
                        for tok in ("wan miniport", "hyper-v", "tailscale", "vmware", "virtualbox", "npcap loopback")
                    )
                    is_preferred = (not is_loop and not is_virtual_noise) and any(
                        tok in low for tok in ("wi-fi", "wireless", "802.11", "ethernet", "gb", "pcie", "wi-fi direct")
                    )
                    results.append({
                        "index": idx,
                        "name": name,
                        "description": desc,
                        "flags": int(node.flags),
                        "loopback": is_loop,
                        "preferred": is_preferred,
                    })
                    idx += 1
                    cur = node.next
                dll.pcap_freealldevs(alldevs)
        except Exception:
            results = []

    if not results and tshark_path and os.path.isfile(tshark_path):
        try:
            proc = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                m = re.match(r"^\s*(\d+)\.\s+([^\s]+)(?:\s+\((.+)\))?", line)
                if m:
                    name = m.group(2)
                    desc = m.group(3) or name
                    low = desc.lower()
                    is_loop = "loopback" in low
                    is_preferred = not is_loop and not any(
                        tok in low for tok in ("wan miniport", "hyper-v", "tailscale")
                    )
                    results.append({
                        "index": int(m.group(1)),
                        "name": name,
                        "description": desc,
                        "flags": 0,
                        "loopback": is_loop,
                        "preferred": is_preferred,
                    })
        except Exception:
            pass
    return results


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


def build_wireshark_bpf_filters(game_ports: Iterable[int]) -> list[str]:
    """Return kernel BPF filter candidates (strict TLS-handshake-only first, then port-based fallback)."""
    extra_ports = sorted({int(p) for p in game_ports if int(p) not in (53, 80, 443, 8080, 8443, 37008)})
    game_terms = " or ".join(f"port {p}" for p in extra_ports)
    suffix = f" or {game_terms}" if game_terms else ""
    strict = (
        "(port 53 or udp port 37008 or tcp port 80 or tcp port 8080 "
        "or (ip and (tcp port 443 or tcp port 8443) and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) "
        "or (ip6 proto 6 and (tcp port 443 or tcp port 8443) and ip6[(40 + ((ip6[52:1] & 0xf0) >> 2)):1] = 0x16)"
        f"{suffix}) and not (ip and tcp and (tcp[13] & 0x12 = 0x02))"
    )
    fallback_syn = (
        "(port 53 or udp port 37008 or tcp port 80 or tcp port 8080 "
        "or (ip and (tcp port 443 or tcp port 8443) and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) "
        "or (ip6 and (tcp port 443 or tcp port 8443))"
        f"{suffix}) and not (ip and tcp and (tcp[13] & 0x12 = 0x02))"
    )
    fallback = (
        "port 53 or udp port 37008 or tcp port 80 or tcp port 8080 or tcp port 443 or tcp port 8443"
        f"{suffix}"
    )
    return [strict, fallback_syn, fallback]


def _apply_wpcap_bpf_filter(dll, handle: int, game_ports: Iterable[int]) -> bool:
    """Compile and attach a kernel BPF capture filter on wpcap handle; return True if applied."""
    try:
        if not getattr(dll, "_pulse_bpf_bound", False):
            dll.pcap_compile.restype = ctypes.c_int
            dll.pcap_compile.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_BpfProgram),
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_uint32,
            ]
            dll.pcap_setfilter.restype = ctypes.c_int
            dll.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
            dll.pcap_freecode.restype = None
            dll.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
            dll._pulse_bpf_bound = True
    except (AttributeError, OSError):
        return False

    for expr in build_wireshark_bpf_filters(game_ports):
        prog = _BpfProgram()
        try:
            if dll.pcap_compile(ctypes.c_void_p(handle), ctypes.byref(prog), expr.encode("ascii"), 1, 0xFFFFFFFF) == 0:
                try:
                    if dll.pcap_setfilter(ctypes.c_void_p(handle), ctypes.byref(prog)) == 0:
                        return True
                finally:
                    dll.pcap_freecode(ctypes.byref(prog))
        except Exception:
            continue
    return False


class WiresharkCaptureEngine:
    """Real-time Wireshark/TShark + Npcap deep packet sniffer and TZSP stream inspector."""

    def __init__(
        self,
        on_detection,
        pcap_path: str | Path = "data/wireshark_live.pcap",
        tzsp_port: int = 37008,
        custom_tshark_path: str = "",
        is_forwarded_dns_fn=None,
        infra_ips: set[str] | None = None,
        self_ips: set[str] | None = None,
    ) -> None:
        self.on_detection = on_detection
        self.tzsp_port = int(tzsp_port)
        self.is_forwarded_dns_fn = is_forwarded_dns_fn
        self.infra_ips = {str(x).strip() for x in (infra_ips or set()) if str(x).strip()}
        self.self_ips = {str(x).strip() for x in (self_ips or set()) if str(x).strip()}
        self._custom_tshark_path = str(custom_tshark_path or "").strip()
        self.binaries = find_wireshark_binaries(self._custom_tshark_path)
        self.interfaces = list_npcap_interfaces(
            self.binaries.get("wpcapPath", ""), self.binaries.get("tsharkPath", "")
        )
        self.recorder = PcapRingRecorder(pcap_path)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._active_interfaces: set[str] = set()
        self._enabled = True
        self._selected_interfaces: list[str] = self._pick_default_interfaces()
        self._engine_name = (
            "tshark"
            if self.binaries.get("tsharkInstalled")
            else ("npcap-wpcap" if self.binaries.get("npcapAvailable") else "tzsp-only")
        )
        self._packets_captured = 0
        self._packets_matched = 0
        self._dns_matches = 0
        self._tls_sni_matches = 0
        self._http_matches = 0
        self._port_matches = 0
        self._last_hit_at: str | None = None
        self._last_packet_at: float = 0.0
        self._recent_hits: list[dict] = []
        self._workers: list[threading.Thread] = []
        self._tshark_procs: list[subprocess.Popen] = []
        self._recent_hit_cooldown: dict[tuple[str, str, str], float] = {}
        self._tzsp_active = False

    def _pick_default_interfaces(self) -> list[str]:
        preferred = [x for x in self.interfaces if x.get("preferred")]
        if preferred:
            preferred.sort(
                key=lambda x: (
                    "wi-fi direct" in (x.get("description") or "").lower(),
                    int(x.get("index") or 0),
                )
            )
            return [x["name"] for x in preferred[:4]]
        non_loop = [x["name"] for x in self.interfaces if not x.get("loopback")]
        return non_loop[:2]

    def configure(self, enabled: bool | None = None, selected_interfaces: list[str] | None = None, custom_tshark_path: str | None = None) -> None:
        restart_needed = False
        with self._lock:
            if custom_tshark_path is not None:
                clean_tshark = str(custom_tshark_path or "").strip()
                if clean_tshark != self._custom_tshark_path:
                    self._custom_tshark_path = clean_tshark
                    self.binaries = find_wireshark_binaries(clean_tshark)
                    self._engine_name = (
                        "tshark"
                        if self.binaries.get("tsharkInstalled")
                        else ("npcap-wpcap" if self.binaries.get("npcapAvailable") else "tzsp-only")
                    )
                    restart_needed = True
            if selected_interfaces is not None:
                valid = {x["name"] for x in self.interfaces}
                cleaned = [s for s in selected_interfaces if s in valid] or self._pick_default_interfaces()
                if cleaned != self._selected_interfaces:
                    self._selected_interfaces = cleaned
                    restart_needed = True
            if enabled is not None and bool(enabled) != self._enabled:
                self._enabled = bool(enabled)
                restart_needed = True
        if restart_needed and not self._stop.is_set():
            self.restart_capture_workers()

    def _emit_hit(self, hit: dict, raw_frame: bytes | None = None, dlt: int = 1) -> None:
        client_ip = str(hit.get("ip") or "").strip()
        game_id = str(hit.get("gameId") or "").strip()
        domain = str(hit.get("domain") or "").strip()
        if not client_ip or not game_id:
            return

        if hit.get("protocol") == "DNS" and self.is_forwarded_dns_fn and self.is_forwarded_dns_fn(client_ip, domain):
            return

        if raw_frame and dlt == 1:
            self.recorder.write_packet(raw_frame, ts_epoch=hit.get("tsEpoch"), dlt=dlt)

        now_m = time.monotonic()
        dedup_key = (client_ip, game_id, str(hit.get("matchedIndicator") or ""))
        with self._lock:
            self._packets_matched += 1
            proto = str(hit.get("protocol") or "")
            if proto == "DNS":
                self._dns_matches += 1
            elif proto == "TLS SNI":
                self._tls_sni_matches += 1
            elif proto == "HTTP":
                self._http_matches += 1
            else:
                self._port_matches += 1
            from .config import utc_now
            hit_ts = utc_now()
            self._last_hit_at = hit_ts
            entry = {
                "timestamp": hit_ts,
                "ip": client_ip,
                "remoteIp": hit.get("remoteIp", ""),
                "frameSourceMac": hit.get("frameSourceMac", ""),
                "gameId": game_id,
                "gameName": hit.get("gameName", ""),
                "protocol": proto,
                "matchedIndicator": hit.get("matchedIndicator", ""),
                "detectionMethod": hit.get("detectionMethod", "Wireshark Live Capture"),
                "port": hit.get("port"),
                "domain": domain,
            }
            self._recent_hits.insert(0, entry)
            self._recent_hits = self._recent_hits[:30]
            prev = self._recent_hit_cooldown.get(dedup_key)
            if prev is not None and (now_m - prev) < 3.5:
                return
            self._recent_hit_cooldown[dedup_key] = now_m

        if self.on_detection:
            self.on_detection({
                "ip": client_ip,
                "reporterIp": hit.get("reporterIp", ""),
                "gameId": game_id,
                "domain": domain,
                "port": hit.get("port"),
                "matchedIndicator": hit.get("matchedIndicator", ""),
                "detectionMethod": hit.get("detectionMethod", "Wireshark Packet Capture"),
            })

    def _run_wpcap_interface(self, iface_name: str, worker_stop: threading.Event) -> None:
        wpcap_path = self.binaries.get("wpcapPath", "")
        if not wpcap_path:
            return
        try:
            dll = _load_wpcap(wpcap_path)
        except Exception:
            return
        errbuf = ctypes.create_string_buffer(256)
        handle = dll.pcap_open_live(iface_name.encode("utf-8", "ignore"), 65535, 1, 250, errbuf)
        if not handle:
            print(f"[wireshark-npcap] Cannot open {iface_name}: {errbuf.value.decode(errors='replace')}", flush=True)
            return
        dlt = int(dll.pcap_datalink(handle))
        hdr_ptr = ctypes.POINTER(_WinPcapPktHdr)()
        pkt_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        from .game_detector import GameDetectorMixin, _NETSTAT_GAME_PORTS

        bpf_ok = _apply_wpcap_bpf_filter(dll, handle, _NETSTAT_GAME_PORTS)
        with self._lock:
            self._active_interfaces.add(iface_name)
        print(f"[wireshark-npcap] Capturing live packets on {iface_name} (dlt={dlt}, bpf={bpf_ok})", flush=True)
        try:
            while not self._stop.is_set() and not worker_stop.is_set():
                res = dll.pcap_next_ex(handle, ctypes.byref(hdr_ptr), ctypes.byref(pkt_ptr))
                if res == 1:
                    hdr = hdr_ptr.contents
                    caplen = min(int(hdr.caplen), 65535)
                    if caplen <= 0:
                        continue
                    raw = ctypes.string_at(pkt_ptr, caplen)
                    ts_epoch = float(hdr.ts.tv_sec) + (float(hdr.ts.tv_usec) / 1_000_000.0)
                    with self._lock:
                        self._packets_captured += 1
                        self._last_packet_at = time.time()
                    # Record DNS/TLS ClientHello/HTTP packets cleanly so downloaded .pcap includes all discovery context
                    hit = dissect_raw_packet(
                        raw,
                        dlt=dlt,
                        ts_epoch=ts_epoch,
                        matcher=GameDetectorMixin._match_game_signature,
                        game_ports=_NETSTAT_GAME_PORTS,
                        infra_ips=self.infra_ips,
                        self_ips=self.self_ips,
                    )
                    if hit:
                        self._emit_hit(hit, raw_frame=raw, dlt=dlt)
                elif res == 0:
                    continue
                else:
                    break
        finally:
            with self._lock:
                if not worker_stop.is_set():
                    self._active_interfaces.discard(iface_name)
            try:
                dll.pcap_close(ctypes.c_void_p(handle))
            except Exception:
                pass

    def _run_tshark_interface(self, iface_name: str, worker_stop: threading.Event) -> None:
        tshark_path = self.binaries.get("tsharkPath", "")
        if not tshark_path or not os.path.isfile(tshark_path):
            return
        cmd = [
            tshark_path,
            "-l",
            "-n",
            "-Q",
            "-i",
            iface_name,
            "-f",
            "ip or ip6",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.flags",
            "-e",
            "tcp.len",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.flags.response",
            "-e",
            "tls.handshake.extensions_server_name",
            "-e",
            "http.host",
        ]
        cflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)) if sys.platform == "win32" else 0
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=cflags,
            )
        except OSError:
            return
        with self._lock:
            self._tshark_procs.append(proc)
            self._active_interfaces.add(iface_name)
        print(f"[wireshark-tshark] Live dissector running on {iface_name}", flush=True)
        from .game_detector import GameDetectorMixin, _NETSTAT_GAME_PORTS

        try:
            while not self._stop.is_set() and not worker_stop.is_set():
                line = proc.stdout.readline() if proc.stdout else ""
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                    continue
                parts = line.rstrip("\r\n").split("|")
                if len(parts) < 15:
                    continue
                (ts_s, ip4_s, ip4_d, ip6_s, ip6_d, u_sp, u_dp, t_sp, t_dp,
                 t_flags, tcp_len, dns_q, dns_response, tls_sni, http_h) = parts[:15]
                src_ip = ip4_s or ip6_s
                dst_ip = ip4_d or ip6_d
                with self._lock:
                    self._packets_captured += 1
                    self._last_packet_at = time.time()
                sport = int(u_sp or t_sp or 0)
                dport = int(u_dp or t_dp or 0)
                src_ok = _is_usable_client_ip(src_ip)
                dst_ok = _is_usable_client_ip(dst_ip)
                if not src_ok and not dst_ok:
                    continue
                client_ip = src_ip if (src_ok and (not dst_ok or dport in (53, 443, 8443, 80, 8080))) else (dst_ip if dst_ok else "")
                if not client_ip:
                    continue
                remote_ip = dst_ip if client_ip == src_ip else src_ip
                try:
                    ts_epoch = float(ts_s)
                except ValueError:
                    ts_epoch = time.time()

                if dns_q and (dport != 53 or dns_response != "0"):
                    continue
                domain = (dns_q or tls_sni or http_h or "").strip().lower()
                if domain:
                    if not src_ok or src_ip in self.infra_ips:
                        continue
                    sig = GameDetectorMixin._match_game_signature(domain=domain)
                    if sig:
                        proto = "DNS" if dns_q else ("TLS SNI" if tls_sni else "HTTP")
                        method = (
                            "TShark DNS Wire"
                            if dns_q
                            else ("TShark TLS SNI" if tls_sni else "TShark HTTP Host")
                        )
                        self._emit_hit({
                            "tsEpoch": ts_epoch,
                            "ip": src_ip,
                            "remoteIp": dst_ip,
                            "gameId": sig["id"],
                            "gameName": sig["name"],
                            "domain": domain,
                            "port": dport or sport,
                            "protocol": proto,
                            "matchedIndicator": f"{proto}: {domain}",
                            "detectionMethod": method,
                        })
                        continue

                is_external_flow = not (src_ok and dst_ok)
                if not is_external_flow and (src_ip in self.self_ips or dst_ip in self.self_ips):
                    continue
                flow_client = client_ip
                flow_remote = remote_ip
                if not is_external_flow:
                    if sport in (19132, 27015, 27036):
                        flow_client, flow_remote = src_ip, dst_ip
                    elif dport in (19132, 27015, 27036):
                        flow_client, flow_remote = dst_ip, src_ip
                remote_port = dport if flow_client == src_ip else sport
                if is_external_flow:
                    port_cand = remote_port if remote_port in _NETSTAT_GAME_PORTS and (not u_sp or remote_port != 27036) else None
                else:
                    lan_ports = (27015,) if u_sp else (19132, 27015, 27036)
                    port_cand = next((port for port in (sport, dport) if port in lan_ports), None)
                if port_cand is not None and flow_client not in self.infra_ips:
                    if t_sp or t_dp:
                        try:
                            f_val = int(t_flags, 16) if t_flags.startswith("0x") else int(t_flags)
                            if int(tcp_len or 0) <= 0 or (f_val & 0x05) != 0 or (f_val & 0x12) == 0x02:
                                continue
                        except ValueError:
                            continue
                    sig = GameDetectorMixin._match_game_signature(port=port_cand)
                    if sig:
                        self._emit_hit({
                            "tsEpoch": ts_epoch,
                            "ip": flow_client,
                            "remoteIp": flow_remote,
                            "gameId": sig["id"],
                            "gameName": sig["name"],
                            "port": port_cand,
                            "protocol": "UDP" if u_sp else "TCP",
                            "matchedIndicator": f"{'UDP' if u_sp else 'TCP'} Flow :{port_cand}",
                            "detectionMethod": "TShark Packet Flow",
                        })
        finally:
            with self._lock:
                if proc in self._tshark_procs:
                    self._tshark_procs.remove(proc)
                if not worker_stop.is_set():
                    self._active_interfaces.discard(iface_name)
            try:
                proc.terminate()
            except Exception:
                pass

    def _run_tzsp_listener(self, worker_stop: threading.Event) -> None:
        """Listen for router/AP TZSP packet mirror streams on UDP 37008."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.tzsp_port))
            sock.settimeout(1.0)
            with self._lock:
                self._tzsp_active = True
            print(f"[wireshark-tzsp] Router TZSP mirror listener active on 0.0.0.0:{self.tzsp_port}/udp", flush=True)
        except OSError:
            sock.close()
            return

        from .game_detector import GameDetectorMixin, _NETSTAT_GAME_PORTS

        try:
            while not self._stop.is_set() and not worker_stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                inner, dlt = unwrap_tzsp_packet(data)
                if not inner:
                    continue
                with self._lock:
                    self._packets_captured += 1
                    self._last_packet_at = time.time()
                hit = dissect_raw_packet(
                    inner,
                    dlt=dlt,
                    ts_epoch=time.time(),
                    matcher=GameDetectorMixin._match_game_signature,
                    game_ports=_NETSTAT_GAME_PORTS,
                    infra_ips=self.infra_ips,
                    self_ips=self.self_ips,
                )
                if hit:
                    hit["reporterIp"] = addr[0]
                    hit["detectionMethod"] = "Wireshark TZSP Stream"
                    self._emit_hit(hit, raw_frame=inner, dlt=dlt)
        finally:
            with self._lock:
                self._tzsp_active = False
            sock.close()

    def restart_capture_workers(self) -> None:
        self._stop_capture_workers()
        self._start_capture_workers()

    def _stop_capture_workers(self) -> None:
        wstop = getattr(self, "_worker_stop", None)
        if wstop is not None:
            wstop.set()
        with self._lock:
            procs = list(self._tshark_procs)
            self._tshark_procs.clear()
            self._active_interfaces.clear()
        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass
        for t in getattr(self, "_workers", []):
            if t.is_alive():
                t.join(timeout=1.0)
        self._workers = []

    def _start_capture_workers(self) -> None:
        self._worker_stop = threading.Event()
        with self._lock:
            enabled = self._enabled
            ifaces = list(self._selected_interfaces)
            use_tshark = bool(self.binaries.get("tsharkInstalled"))
            use_wpcap = bool(self.binaries.get("npcapAvailable"))
        if not enabled:
            return

        for iface in ifaces:
            if use_tshark:
                t = threading.Thread(target=self._run_tshark_interface, args=(iface, self._worker_stop), daemon=True)
                t.start()
                self._workers.append(t)
            elif use_wpcap:
                t = threading.Thread(target=self._run_wpcap_interface, args=(iface, self._worker_stop), daemon=True)
                t.start()
                self._workers.append(t)

        tzsp_t = threading.Thread(target=self._run_tzsp_listener, args=(self._worker_stop,), daemon=True)
        tzsp_t.start()
        self._workers.append(tzsp_t)

    def start(self) -> None:
        self._stop.clear()
        self._start_capture_workers()

    def stop(self) -> None:
        self._stop.set()
        self._stop_capture_workers()

    def status_snapshot(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "active": bool(self._active_interfaces or self._tzsp_active),
                "activeInterfaceCount": len(self._active_interfaces),
                "engine": self._engine_name,
                "tsharkInstalled": bool(self.binaries.get("tsharkInstalled")),
                "tsharkPath": self.binaries.get("tsharkPath", ""),
                "dumpcapInstalled": bool(self.binaries.get("dumpcapInstalled")),
                "wiresharkGuiInstalled": bool(self.binaries.get("wiresharkGuiInstalled")),
                "npcapAvailable": bool(self.binaries.get("npcapAvailable")),
                "tzspActive": bool(self._tzsp_active),
                "tzspPort": self.tzsp_port,
                "interfaces": list(self.interfaces),
                "selectedInterfaces": list(self._selected_interfaces),
                "packetsCaptured": self._packets_captured,
                "packetsMatched": self._packets_matched,
                "dnsMatches": self._dns_matches,
                "tlsSniMatches": self._tls_sni_matches,
                "httpMatches": self._http_matches,
                "portMatches": self._port_matches,
                "pcapPath": str(self.recorder.path),
                "pcapBytes": self.recorder.file_bytes(),
                "lastHitAt": self._last_hit_at,
                "recentHits": list(self._recent_hits),
                "displayFilter": build_wireshark_display_filter(),
            }
