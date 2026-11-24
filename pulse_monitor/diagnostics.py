"""Network diagnostic tools: Traceroute, DNS Benchmark, and One-Click Full Diagnostics."""

from __future__ import annotations

import http.client
import ipaddress
import math
import os
import re
import socket
import ssl
import struct
import subprocess
import time

from typing import TYPE_CHECKING, cast

from .config import runtime_attr, utc_now, validate_device_ip, validate_host, validate_port

if TYPE_CHECKING:
    from .engine import Monitor


def _trace_address(text: str) -> str | None:
    for token in text.split():
        token = token.strip("[](),")
        if token.count(":") == 1:
            token = token.removesuffix(":")
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


class DiagnosticsMixin:
    """Provides interactive network engineering diagnostic utilities."""

    def get_device_connection(self, value: object, *, check_now: bool = False) -> dict:
        """Inspect one listed device without changing its monitoring or management settings."""
        self = cast("Monitor", self)
        ip = validate_device_ip(value)
        address = ipaddress.ip_address(ip)
        device = next((item for item in self.get_devices() if item.get("ip") == ip), None)
        with self._connect() as db:
            observed = db.execute(
                """SELECT suggested_name, arp_type, last_seen FROM discovered_devices
                   WHERE ip=? ORDER BY is_online DESC, last_seen DESC LIMIT 1""",
                (ip,),
            ).fetchone()
        if device is None and (observed is None or not self._is_real_lan_client_ip(ip)):
            raise LookupError("Device is not in the monitored or discovered inventory")

        fingerprint = self._get_cached_fingerprints().get(ip, {})
        latest = self.latest_devices.get(ip, {}) if device else {}
        router = next((item for item in self.get_router_fleet() if item.get("ip") == ip), {})
        protocol = router.get("protocol") or fingerprint.get("protocol")
        known_port = router.get("port") or fingerprint.get("preferredPort")
        probe_port = (device or {}).get("port") or (known_port if protocol in ("http", "https") else None)
        port = validate_port(probe_port) if probe_port is not None else None
        management_port = validate_port(known_port) if known_port and protocol in ("http", "https") else None
        if management_port is None and port in (80, 443, 8080, 8443):
            management_port = port
            protocol = "https" if port in (443, 8443) else "http"
        host = f"[{ip}]" if address.version == 6 else ip
        management_url = f"{protocol}://{host}:{management_port}/" if management_port else None

        result: dict = {
            "ip": ip,
            "name": (device or {}).get("name") or (observed["suggested_name"] if observed else ip),
            "monitored": device is not None,
            "lastObservedAt": observed["last_seen"] if observed else None,
            "observationSource": observed["arp_type"] if observed else None,
            "lastMonitorCheckAt": latest.get("lastChecked"),
            "managementUrl": management_url,
            "tcpPort": port,
        }
        if check_now:
            responds, icmp_ms = self._probe_icmp(ip, timeout_ms=800)
            result["icmp"] = {"status": "reply" if responds else "no_reply", "latencyMs": icmp_ms}
            if port is not None:
                opened, answered, tcp_ms = self._probe_tcp_socket(ip, port, timeout=0.85)
                result["tcp"] = {
                    "status": "open" if opened else "refused" if answered else "no_reply",
                    "latencyMs": tcp_ms,
                }
            if management_port is not None:
                if management_port == port and result["tcp"]["status"] != "open":
                    result["http"] = {"status": "tcp_unavailable"}
                else:
                    result["http"] = self._check_management_http(ip, management_port, protocol == "https")
            result["checkedAt"] = utc_now()
        return result

    @staticmethod
    def _check_management_http(ip: str, port: int, https: bool) -> dict:
        connection_type = http.client.HTTPSConnection if https else http.client.HTTPConnection
        connection = connection_type(ip, port, timeout=1.25)
        started = time.perf_counter()
        try:
            connection.request("HEAD", "/", headers={"Connection": "close"})
            with connection.getresponse() as response:
                return {
                    "status": "reply",
                    "statusCode": response.status,
                    "latencyMs": round((time.perf_counter() - started) * 1000, 1),
                }
        except ssl.SSLCertVerificationError:
            return {"status": "certificate_untrusted"}
        except (OSError, http.client.HTTPException):
            return {"status": "no_reply"}
        finally:
            connection.close()

    def read_device_snmp(self, value: object, community: object) -> dict:
        """Read basic information from a listed device using a one-time community."""
        self = cast("Monitor", self)
        if not isinstance(community, str) or not 1 <= len(community) <= 128 or not community.isprintable():
            raise ValueError("Enter a printable SNMP community of 1 to 128 characters")
        ip = self.get_device_connection(value)["ip"]
        data = self._snmp_get_oids(ip, {
            "name": ".1.3.6.1.2.1.1.5.0",
            "description": ".1.3.6.1.2.1.1.1.0",
            "uptime": ".1.3.6.1.2.1.1.3.0",
            "interfaceCount": ".1.3.6.1.2.1.2.1.0",
        }, community=community, timeout=0.55)
        values: dict[str, str | int | float] = {
            key: data[key][:512] for key in ("name", "description") if data.get(key)
        }
        uptime = data.get("uptime", "")
        if len(uptime) <= 10 and uptime.isdecimal() and uptime.isascii() and int(uptime) <= 0xFFFFFFFF:
            values["uptimeSeconds"] = int(uptime) / 100
        interface_count = data.get("interfaceCount", "")
        if len(interface_count) <= 10 and interface_count.isdecimal() and interface_count.isascii() and int(interface_count) <= 0x7FFFFFFF:
            values["interfaceCount"] = int(interface_count)
        return {"status": "reply" if values else "no_data", "values": values, "checkedAt": utc_now()}

    @staticmethod
    def _validate_host(host: object) -> str:
        return validate_host(host)

    def traceroute(self, host: object, max_hops: object) -> dict:
        self = cast("Monitor", self)
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)
        destination = self._validate_host(host or "google.com")
        hops_value = max_hops or 15
        try:
            if not isinstance(hops_value, (str, int, float)):
                raise ValueError("Expected a numeric hop count")
            hops_limit = max(1, min(20, int(hops_value)))
        except (ValueError, OverflowError) as exc:
            raise ValueError("maxHops must be between 1 and 20") from exc
        timeout = 1.0
        command = (
            ["tracert", "-d", "-h", str(hops_limit), "-w", "800", destination]
            if os_mod.name == "nt"
            else ["traceroute", "-n", "-m", str(hops_limit), "-w", "1", destination]
        )
        started = time.perf_counter()
        try:
            result = subproc_mod.run(
                command,
                capture_output=True,
                text=True,
                timeout=hops_limit * timeout * 3 + 5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "host": destination,
                "destinationIp": None,
                "hops": [],
                "totalHops": 0,
                "durationMs": round((time.perf_counter() - started) * 1000),
                "error": str(exc),
            }
        hops = []
        destination_ip = _trace_address(destination)
        gateway_ip = _trace_address(str(self.config.get("router", {}).get("ip") or ""))
        for line in result.stdout.splitlines():
            match = re.match(r"\s*(\d+)\s+(.+)$", line)
            if not match:
                if destination_ip is None and not hops:
                    destination_ip = _trace_address(line)
                continue
            hop_num, detail = int(match.group(1)), match.group(2).strip()
            hop_ip = _trace_address(detail)
            samples = re.findall(r"(<\s*)?(\d+(?:\.\d+)?)\s*ms\b", detail, re.I)
            times = [float(value) for _, value in samples]
            avg = round(sum(times) / len(times), 1) if times else None
            latency_display = None
            if times and any(less_than for less_than, _ in samples):
                upper_bound = math.ceil((sum(times) / len(times)) * 10) / 10
                latency_display = f"<{upper_bound:g} ms"

            if hop_ip is None:
                role_type, role = "unknown", "Unknown hop"
            elif ipaddress.ip_address(hop_ip).is_loopback:
                role_type, role = "local", "Local host (loopback)"
            elif hop_ip == gateway_ip:
                role_type, role = "local", "Configured gateway"
            elif hop_ip == destination_ip:
                role_type, role = "destination", "Destination"
            else:
                role_type, role = "transit", "Transit node"
            hops.append({
                "hop": hop_num,
                "ip": hop_ip or "*",
                "latencyMs": avg,
                "latencyDisplay": latency_display,
                "rtts": times,
                "status": "success" if avg is not None else "timeout",
                "role": {"type": role_type, "label": role},
            })
        return {
            "host": destination,
            "destinationIp": destination_ip,
            "hops": hops,
            "totalHops": len(hops),
            "durationMs": round((time.perf_counter() - started) * 1000),
        }

    def dns_benchmark(self, domain: object) -> dict:
        domain = self._validate_host(domain or "google.com")
        resolvers = [
            ("System DNS", "system", "OS-configured resolver"),
            ("Cloudflare Anycast", "1.1.1.1", "Cloudflare DNS resolver"),
            ("Google Public DNS", "8.8.8.8", "Google Public DNS resolver"),
            ("Quad9 Secure Anycast", "9.9.9.9", "Quad9 DNS resolver"),
        ]
        results = []
        for name, server, desc in resolvers:
            started = time.perf_counter()
            try:
                if server == "system":
                    addresses = sorted({
                        entry[4][0]
                        for entry in socket.getaddrinfo(domain, None, socket.AF_INET)
                    })
                else:
                    addresses = self._dns_udp_query(domain, server)
                elapsed = round((time.perf_counter() - started) * 1000, 1)
                results.append({
                    "name": name,
                    "ip": server,
                    "desc": desc,
                    "latencyMs": elapsed,
                    "addresses": addresses,
                    "status": "success",
                })
            except (OSError, ValueError, TimeoutError) as exc:
                results.append({
                    "name": name,
                    "ip": server,
                    "desc": desc,
                    "latencyMs": None,
                    "addresses": [],
                    "status": "error",
                    "error": str(exc),
                })
        return {"domain": domain, "timestamp": utc_now(), "results": results}

    @staticmethod
    def _dns_udp_query(domain: str, server: str) -> list[str]:
        transaction_id = int.from_bytes(os.urandom(2), "big")
        question = b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in domain.rstrip(".").split(".")
        )
        packet = (
            struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
            + question
            + b"\x00"
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.5)
            sock.sendto(packet, (server, 53))
            response, _ = sock.recvfrom(4096)
        if len(response) < 12:
            raise OSError("Invalid DNS response")
        response_id, flags, questions, answers, _, _ = struct.unpack(
            "!HHHHHH", response[:12]
        )
        if response_id != transaction_id or not flags & 0x8000 or flags & 0x000F:
            raise OSError("DNS resolver returned an error")
        offset = 12
        for _ in range(questions):
            while offset < len(response) and response[offset] != 0:
                length = response[offset]
                offset += 1 + (2 if length & 0xC0 == 0xC0 else length)
            offset += 5
        addresses = []
        for _ in range(answers):
            if offset + 12 > len(response):
                break
            if response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0:
                    offset += 1 + response[offset]
                offset += 1
            record_type, _, _, data_len = struct.unpack(
                "!HHIH", response[offset : offset + 10]
            )
            offset += 10
            record = response[offset : offset + data_len]
            offset += data_len
            if record_type == 1 and data_len == 4:
                addresses.append(socket.inet_ntoa(record))
        return addresses

    def run_diagnostics(self) -> dict:
        self = cast("Monitor", self)
        started = time.perf_counter()
        results = [device for device in self.probe_all_devices() if not device.get("archived")]
        router = self.probe_router()
        isp = self.probe_isp()
        findings = []
        recommendations = []
        if not router["reachable"]:
            findings.append({
                "stage": "GATEWAY_ROUTER",
                "status": "CRITICAL",
                "title": "Main Router Unreachable",
                "detail": f"Cannot connect to {router['ip']}:{self.config['router']['port']}.",
            })
            recommendations.append(
                "Check gateway power, cable, IP address, and management port."
            )
        offline = [device for device in results if not device["alive"]]
        observed = [device for device in results if device["alive"] and device.get("directlyReachable") is False]
        degraded = [device for device in results if device.get("connectivityState") == "DEGRADED_LINK"]
        online_count = len(results) - len(offline) - len(observed)
        for device in observed:
            findings.append({
                "stage": "COMPANY_DEVICES",
                "status": "WARNING",
                "title": f"Direct reachability unverified: {device['name']}",
                "detail": f"The ARP cache contains {device['ip']}, but TCP and ICMP probes received no response.",
            })
        for device in offline:
            findings.append({
                "stage": "COMPANY_DEVICES",
                "status": "CRITICAL" if device.get("critical") else "WARNING",
                "title": f"Device Offline: {device['name']}",
                "detail": f"{device['ip']} did not respond to TCP or ICMP probes.",
            })
            recommendations.append(
                f"Check power, cabling, and network configuration for {device['name']}."
            )
        for device in degraded:
            measurements = [
                f"{device[key]}{unit}"
                for key, unit in (("avgLatencyMs", " ms average response time"), ("packetLossPct", "% probe loss"))
                if device.get(key) is not None
            ]
            findings.append({
                "stage": "COMPANY_DEVICES",
                "status": "WARNING",
                "title": f"Slow or unstable response: {device['name']}",
                "detail": f"{device['ip']}: {', '.join(measurements)}." if measurements
                else f"A link warning was reported for {device['ip']}.",
            })
        if degraded:
            recommendations.append("Compare the slow devices with nearby devices and check their Ethernet or Wi-Fi link.")
        measured_ports = [
            port for port in router["ports"] if not port.get("simulation")
            and port.get("linkStatus") in {"connected", "disconnected"}
        ]
        for port in measured_ports:
            wan_down = port.get("isWan") and port["linkStatus"] == "disconnected"
            if wan_down or port.get("status") == "warning":
                findings.append({
                    "stage": "ROUTER_PORTS",
                    "status": "CRITICAL" if wan_down else "WARNING",
                    "title": f"Router link: {port['name']}",
                    "detail": "The router reports the WAN link down." if wan_down
                    else f"The router reports {port.get('speedText', 'unknown speed')} and {port.get('duplex', 'unknown duplex')}.",
                })
        if len(measured_ports) < len(router["ports"]):
            findings.append({
                "stage": "ROUTER_PORTS",
                "status": "UNAVAILABLE",
                "title": "Router port telemetry incomplete",
                "detail": f"The router reported physical link state for {len(measured_ports)} of {len(router['ports'])} ports.",
            })
        if isp["overallHealth"] == "OUTAGE":
            findings.append({
                "stage": "ISP_WAN",
                "status": "CRITICAL",
                "title": "External Internet Unreachable",
                "detail": "None of the configured external targets answered ICMP or accepted a TCP connection.",
            })
            recommendations.append(
                "Verify the ISP modem/ONT and contact your ISP if the outage continues."
            )
        elif isp["overallHealth"] == "DEGRADED":
            findings.append({
                "stage": "ISP_WAN",
                "status": "WARNING",
                "title": f"Internet health: {isp['overallHealth']}",
                "detail": f"Health score {isp['healthScore']}/100."
                + (f" DNS response {isp['dnsResolutionMs']} ms." if isp.get("dnsResolutionMs") is not None else ""),
            })
        if not findings:
            findings.append({
                "stage": "NETWORK",
                "status": "OPTIMAL",
                "title": "Network probes are healthy",
                "detail": "The gateway, monitored devices, and external connectivity responded to probes.",
            })
        severities = {item["status"] for item in findings}
        verdict = "CRITICAL" if "CRITICAL" in severities else "DEGRADED" if "WARNING" in severities else "HEALTHY"
        diag_report = {
            "timestamp": utc_now(),
            "durationMs": round((time.perf_counter() - started) * 1000),
            "overallVerdict": verdict,
            "summaryHeadline": {
                "HEALTHY": "Network probes completed without detected issues",
                "DEGRADED": "Some monitored targets need attention",
                "CRITICAL": "A critical network connectivity issue was detected",
            }[verdict],
            "metrics": {
                "routerReachable": router["reachable"],
                "routerModel": router["model"],
                "routerCpuPct": router["cpu"]["loadPct"],
                "routerMemPct": router["memory"]["usagePct"],
                "activeDuplexes": sum(p.get("status") == "optimal" for p in measured_ports),
                "totalPorts": len(router["ports"]),
                "portsVerified": len(measured_ports),
                "devicesMonitored": len(results),
                "devicesOnline": online_count,
                "devicesOffline": len(offline),
                "devicesObservedOnly": len(observed),
                "devicesDegraded": len(degraded),
                "ispLatencyMs": isp["tier1LatencyMs"],
                "ispHealthScore": isp["healthScore"],
                "ispDownloadMbps": (isp.get("lastSpeedTest") or {}).get("downloadMbps"),
                "ispUploadMbps": (isp.get("lastSpeedTest") or {}).get("uploadMbps"),
            },
            "findings": findings,
            "recommendations": recommendations
            or [
                "Continue monitoring; current checks did not detect a connectivity problem."
            ],
        }
        self._record_event(
            "DIAGNOSTICS_RUN",
            "CRITICAL" if verdict == "CRITICAL" else ("WARNING" if verdict == "DEGRADED" else "INFO"),
            f"Full Diagnostics: {verdict}",
            f"Router {'UP' if router['reachable'] else 'DOWN'} · Devices {online_count}/{len(results)} directly reachable · ISP {isp['overallHealth']} ({isp['tier1LatencyMs'] or '--'} ms).",
            ip=router.get("ip") or "",
            device_name="Full Diagnostics",
        )
        return diag_report

