"""Network diagnostic tools: Traceroute, DNS Benchmark, and One-Click Full Diagnostics."""

from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from .config import runtime_attr, utc_now, validate_host


class DiagnosticsMixin:
    """Provides interactive network engineering diagnostic utilities."""

    @staticmethod
    def _validate_host(host: object) -> str:
        return validate_host(host)

    def traceroute(self, host: object, max_hops: object) -> dict:
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)
        destination = self._validate_host(host or "google.com")
        try:
            hops_limit = max(1, min(20, int(max_hops or 15)))
        except (TypeError, ValueError) as exc:
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
        destination_ip = None
        for line in result.stdout.splitlines():
            match = re.match(r"\s*(\d+)\s+(.+)$", line)
            if not match:
                continue
            hop_num, detail = int(match.group(1)), match.group(2).strip()
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", detail)
            hop_ip = ip_match.group(1) if ip_match else "*"
            times = [
                float(value)
                for value in re.findall(r"(\d+(?:\.\d+)?)\s*ms", detail, re.I)
            ]
            avg = round(sum(times) / len(times), 1) if times else None
            role = (
                "Local Gateway Router"
                if hop_num == 1
                else (
                    "Destination Server"
                    if hop_ip != "*" and hop_num > 3
                    else "Internet Node"
                )
            )
            hops.append({
                "hop": hop_num,
                "ip": hop_ip,
                "latencyMs": avg,
                "rtts": times,
                "status": "success" if avg is not None else "timeout",
                "role": {
                    "type": "local" if hop_num == 1 else "transit",
                    "label": role,
                },
            })
            if hop_ip != "*":
                destination_ip = hop_ip
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
        started = time.perf_counter()
        devices = self.get_devices()
        with ThreadPoolExecutor(max_workers=min(12, max(1, len(devices)))) as pool:
            results = list(pool.map(self.probe_device, devices)) if devices else []
        router = self.probe_router()
        isp = self.probe_isp()
        findings = []
        recommendations = []
        verdict = "HEALTHY"
        if not router["reachable"]:
            verdict = "CRITICAL"
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
        if offline and verdict != "CRITICAL":
            verdict = "DEGRADED"
        if isp["overallHealth"] == "OUTAGE":
            verdict = "CRITICAL"
            findings.append({
                "stage": "ISP_WAN",
                "status": "CRITICAL",
                "title": "External Internet Unreachable",
                "detail": "None of the configured Tier-1 targets responded to a TCP probe.",
            })
            recommendations.append(
                "Verify the ISP modem/ONT and contact your ISP if the outage continues."
            )
        elif isp["overallHealth"] == "DEGRADED":
            if verdict == "HEALTHY":
                verdict = "DEGRADED"
            findings.append({
                "stage": "ISP_WAN",
                "status": "WARNING",
                "title": f"Internet health: {isp['overallHealth']}",
                "detail": f"Health score {isp['healthScore']}/100; DNS response {isp['dnsResolutionMs']} ms.",
            })
        if not findings:
            findings.append({
                "stage": "NETWORK",
                "status": "OPTIMAL",
                "title": "Network probes are healthy",
                "detail": "The gateway, monitored devices, and external connectivity responded to probes.",
            })
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
                "activeDuplexes": sum(p["status"] == "optimal" for p in router["ports"]),
                "totalPorts": len(router["ports"]),
                "devicesMonitored": len(devices),
                "devicesOnline": sum(d["alive"] for d in results),
                "devicesOffline": len(offline),
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
            f"Router {'UP' if router['reachable'] else 'DOWN'} · Devices {sum(d['alive'] for d in results)}/{len(devices)} online · ISP {isp['overallHealth']} ({isp['tier1LatencyMs'] or '--'} ms).",
            ip=router.get("ip") or "",
            device_name="Full Diagnostics",
        )
        return diag_report

