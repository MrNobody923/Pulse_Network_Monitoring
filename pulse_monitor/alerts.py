"""Alert evaluation, deduplication, resolution, and incident statistics."""

from __future__ import annotations

import uuid
from datetime import datetime

from .config import utc_now


class AlertsMixin:
    """Evaluates device, performance, and router port telemetry for alert generation."""

    def _evaluate_device(self, result: dict) -> None:
        key = result["ip"]
        current = bool(result["alive"])
        previous = self.device_status.get(key)
        self.device_status[key] = current
        if current and previous is None:
            outage_alert = self.active_alerts.pop(f"dev-{key}", None)
            if outage_alert:
                self._resolve_alert(
                    f"dev-{key}",
                    outage_alert,
                    f"{result['name']} ({key}) is responding again.",
                    "DEVICE_ONLINE",
                    result,
                )
            self._evaluate_performance(result)
            return
        if previous is not None and current == previous:
            if current:
                self._evaluate_performance(result)
            else:
                existing_outage = self.active_alerts.get(f"dev-{key}")
                if existing_outage is not None:
                    existing_outage["consecutiveFailures"] = (
                        int(existing_outage.get("consecutiveFailures") or 1) + 1
                    )
                    existing_outage["lastChecked"] = result.get("lastChecked", utc_now())
                    if existing_outage.get("deviceName") != result.get("name"):
                        existing_outage["deviceName"] = result["name"]
                        existing_outage["title"] = f"{result['name']} ({key}) is DOWN / Unreachable"
            return

        outage_key = f"dev-{key}"
        if current:
            previous_alert = self.active_alerts.pop(outage_key, None)
            if previous_alert:
                self._resolve_alert(
                    outage_key,
                    previous_alert,
                    f"{result['name']} ({key}) is responding again.",
                    "DEVICE_ONLINE",
                    result,
                )
            self._evaluate_performance(result)
        else:
            title = f"{result['name']} ({key}) is DOWN / Unreachable"
            kind = "DEVICE_OFFLINE"
            severity = "CRITICAL" if result.get("critical") else "WARNING"
            diag_summary = result.get("diagnosisSummary") or (
                f"{result['name']} ({key}) stopped responding to TCP management ports and ICMP echo probes."
            )
            message = diag_summary
            if outage_key not in self.active_alerts:
                alert = self._make_alert(
                    outage_key, severity, title, message, key, result.get("port", 80)
                )
                alert.update({
                    "deviceName": result["name"],
                    "mac": result.get("mac", ""),
                    "subnet": result.get("subnet", ""),
                    "location": result.get("location", ""),
                    "likelyFault": result.get("likelyFault", "PoE Power Loss / Unplugged Cable"),
                    "rootCause": diag_summary,
                    "remediation": result.get("fixSteps") or [
                        f"Check the PoE switch port and RJ45 Ethernet cable feeding {result['name']} ({key}).",
                        "Verify the device status LED and power-cycle the PoE port if needed.",
                    ],
                })
                self.active_alerts[outage_key] = alert
                self.save_alert(alert)
                self._record_event(
                    kind,
                    severity,
                    title,
                    message,
                    result.get("mac", ""),
                    key,
                    result["name"],
                )
                self.broadcast("new_alert", alert)
            performance_alert = self.active_alerts.pop(f"perf-{key}", None)
            if performance_alert:
                self._resolve_alert(
                    f"perf-{key}",
                    performance_alert,
                    f"{result['name']} ({key}) is now offline; the outage alert is active.",
                    "DEVICE_OFFLINE",
                    result,
                    event_title="Performance alert replaced by offline outage",
                )

    def _evaluate_performance(self, result: dict) -> None:
        key = f"perf-{result['ip']}"
        thresholds = self.config.get("thresholds", {})
        high_loss = int(thresholds.get("packetLossWarningPct", 5))
        high_latency = float(thresholds.get("highLatencyMs", 80))
        degraded = (
            result.get("packetLossPct", 0) >= high_loss
            or (
                result.get("avgLatencyMs") is not None
                and result["avgLatencyMs"] > high_latency
            )
        )
        existing = self.active_alerts.get(key)
        if degraded and existing is None:
            message = (
                f"{result['name']} ({result['ip']}) has {result.get('packetLossPct', 0)}% packet loss "
                f"and {result.get('avgLatencyMs')} ms average latency."
            )
            alert = self._make_alert(
                key,
                "WARNING",
                f"Latency / packet loss on {result['name']}",
                message,
                result["ip"],
                result.get("port", 80),
            )
            alert.update({
                "type": "HIGH_LATENCY_PACKET_LOSS",
                "errorCode": "WARN_PACKET_LOSS_LATENCY_SPIKE",
                "metrics": {
                    "measuredLatency": result.get("avgLatencyMs"),
                    "packetLoss": result.get("packetLossPct"),
                    "jitter": result.get("jitterMs"),
                },
                "rootCause": "Network congestion, wireless interference, or an intermediate link issue.",
                "solution": "Check the device's wireless signal, switch link, and network load.",
            })
            self.active_alerts[key] = alert
            self.save_alert(alert)
            self._record_event(
                "DEVICE_DEGRADED",
                "WARNING",
                alert["title"],
                message,
                result.get("mac", ""),
                result["ip"],
                result["name"],
            )
            self.broadcast("new_alert", alert)
        elif degraded and existing:
            existing["lastChecked"] = result["lastChecked"]
            if existing.get("deviceName") != result.get("name"):
                existing["deviceName"] = result["name"]
                existing["title"] = f"Latency / packet loss on {result['name']}"
            existing["consecutiveFailures"] = int(existing.get("consecutiveFailures") or 1) + 1
            existing["metrics"].update({
                "measuredLatency": result.get("avgLatencyMs"),
                "packetLoss": result.get("packetLossPct"),
                "jitter": result.get("jitterMs"),
            })
        elif existing:
            self.active_alerts.pop(key, None)
            self._resolve_alert(
                key,
                existing,
                f"Latency and packet loss on {result['name']} returned to normal.",
                "DEVICE_HEALTHY",
                result,
            )

    def evaluate_router_ports(self, state: dict | None = None) -> None:
        self._evaluate_router_ports(state or self.router_state)

    def _evaluate_router_ports(self, state: dict) -> None:
        curr_reachable = bool(state.get("reachable"))
        prev_reachable = getattr(self, "_last_router_reachable", None)
        if (prev_reachable is not None and prev_reachable != curr_reachable) or (
            prev_reachable is None and not curr_reachable
        ):
            r_ip = state.get("ip", "")
            r_model = state.get("model") or "Main Gateway Router"
            self._record_event(
                "ROUTER_ONLINE" if curr_reachable else "ROUTER_OFFLINE",
                "INFO" if curr_reachable else "CRITICAL",
                f"{r_model} {'Online' if curr_reachable else 'Unreachable'}",
                (
                    f"Main Gateway Router ({r_ip}) is reachable again."
                    if curr_reachable
                    else f"Main Gateway Router ({r_ip}) stopped responding to TCP and ICMP probes."
                ),
                ip=r_ip,
                device_name=r_model,
            )
        self._last_router_reachable = curr_reachable

        for port in state.get("ports", []):
            key = f"port-{port['id']}"
            issue = port.get("status") == "warning" or (
                port.get("isWan") and port.get("linkStatus") == "disconnected"
            )
            existing = self.active_alerts.get(key)
            if issue and existing is None:
                wan_outage = bool(
                    port.get("isWan") and port.get("linkStatus") == "disconnected"
                )
                title = (
                    "Internet WAN port disconnected"
                    if wan_outage
                    else f"Router port issue: {port['name']}"
                )
                message = (
                    "The router reports no physical link on its Internet WAN port."
                    if wan_outage
                    else f"{port['name']} reports {port.get('speedText', 'a degraded link')} / {port.get('duplex', 'unknown duplex')}."
                )
                alert = self._make_alert(
                    key,
                    "CRITICAL" if wan_outage else "WARNING",
                    title,
                    message,
                    state.get("ip", ""),
                    int(self.config["router"].get("port", 80)),
                )
                alert.update({
                    "type": "WAN_DISCONNECTED" if wan_outage else "DUPLEX_MISMATCH",
                    "category": "router",
                    "errorCode": "ERR_ROUTER_PORT_LINK",
                    "target": f"{state.get('ip', '')} / {port['name']}",
                    "metrics": {
                        "port": port["name"],
                        "speed": port.get("speedText"),
                        "duplex": port.get("duplex"),
                        "linkStatus": port.get("linkStatus"),
                    },
                    "rootCause": "A damaged or disconnected cable, wall jack, or connected device may be causing this link state.",
                    "solution": "Check both ends of the cable and verify the connected device's network port.",
                })
                self.active_alerts[key] = alert
                self.save_alert(alert)
                self._record_event(
                    "ROUTER_PORT_ISSUE",
                    alert["severity"],
                    title,
                    message,
                    ip=state.get("ip", ""),
                    device_name=port["name"],
                )
                self.broadcast("new_alert", alert)
            elif (
                not issue
                and existing
                and port.get("status") in {"optimal", "disconnected"}
            ):
                if port.get("status") == "disconnected" and not port.get("isWan"):
                    continue
                self.active_alerts.pop(key, None)
                self._resolve_alert(
                    key,
                    existing,
                    f"{port['name']} link returned to normal.",
                    "ROUTER_PORT_RECOVERED",
                    {"ip": state.get("ip", ""), "name": port["name"], "mac": ""},
                )

    def _resolve_alert(
        self,
        key: str,
        alert: dict,
        message: str,
        event_type: str,
        result: dict,
        event_title: str = "Monitored device recovered",
    ) -> None:
        resolved = dict(alert)
        resolved.update({
            "status": "RESOLVED",
            "severity": "RESOLVED",
            "resolvedAt": utc_now(),
            "message": message,
        })
        self.save_alert(resolved)
        self._record_event(
            event_type,
            "INFO",
            event_title,
            message,
            result.get("mac", ""),
            result["ip"],
            result["name"],
        )
        self.broadcast(
            "resolved_alert",
            {
                "key": key,
                "title": alert.get("title", "Network issue resolved"),
                "message": message,
                "severity": "RESOLVED",
            },
        )

    @staticmethod
    def _make_alert(
        key: str,
        severity: str,
        title: str,
        message: str,
        ip: str = "",
        port: int = 80,
    ) -> dict:
        now = utc_now()
        return {
            "id": f"alt-{uuid.uuid4().hex[:12]}",
            "key": key,
            "incidentId": f"INC-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": now,
            "firstSeen": now,
            "lastChecked": now,
            "status": "ACTIVE",
            "severity": severity,
            "type": "DEVICE_OFFLINE",
            "category": "device",
            "errorCode": "ERR_HOST_UNREACHABLE",
            "target": f"{ip}:{port}",
            "ip": ip,
            "port": port,
            "title": title,
            "message": message,
            "metrics": {},
            "rootCause": "The device may be powered off, disconnected, or blocked by a network firewall.",
            "impact": "Monitoring probes cannot currently reach this device.",
            "remediation": [
                "Check the device power and network link.",
                "Verify its IP address and firewall rules.",
            ],
            "cliCommand": f"Test-NetConnection -ComputerName {ip} -Port {port}",
            "solution": "Check the device power, cable, and network configuration.",
            "consecutiveFailures": 1,
            "notes": [],
        }

    def _evaluate_isp_alert(
        self, overall: str, diagnosis: dict, probes: list[dict]
    ) -> None:
        key = "isp-wan"
        existing = self.active_alerts.get(key)
        prev_health = getattr(self, "_last_logged_isp_health", None)
        is_outage = overall == "OUTAGE"
        target_ip = self.config.get("router", {}).get("ip", "192.168.0.1")
        if is_outage:
            gw_probe = next((p for p in probes if p.get("id") == "gateway"), {})
            title = diagnosis.get("headline") or "Internet WAN Connection Down"
            message = diagnosis.get("summary") or "External internet probes failed."
            if existing is None:
                alert = self._make_alert(key, "CRITICAL", title, message, target_ip, 443)
                alert.update({
                    "type": "ISP_OUTAGE",
                    "category": "isp",
                    "errorCode": "ERR_WAN_OUTAGE",
                    "target": "External Internet (1.1.1.1 / 8.8.8.8)",
                    "likelyFault": diagnosis.get("bottleneckLayer") or "ISP WAN Link",
                    "remediation": diagnosis.get("solutions") or [],
                    "metrics": {"gatewayAlive": gw_probe.get("alive")},
                })
                self.active_alerts[key] = alert
                self.save_alert(alert)
                self._record_event(
                    "ISP_OUTAGE",
                    "CRITICAL",
                    title,
                    message,
                    ip=target_ip,
                    device_name="ISP Internet Uplink",
                )
                self.broadcast("new_alert", alert)
            else:
                existing["consecutiveFailures"] = int(existing.get("consecutiveFailures") or 1) + 1
                existing["lastChecked"] = utc_now()
                existing["title"] = title
                existing["message"] = message
        elif overall == "DEGRADED" and prev_health not in {"DEGRADED", "OUTAGE"}:
            self._record_event(
                "ISP_DEGRADED",
                "WARNING",
                diagnosis.get("headline") or "Internet connection degraded",
                diagnosis.get("summary") or "High internet latency or packet loss detected.",
                ip=target_ip,
                device_name="ISP Internet Uplink",
            )
        elif existing is not None and overall in {"EXCELLENT", "GOOD"}:
            self.active_alerts.pop(key, None)
            self._resolve_alert(
                key,
                existing,
                "Internet connection and external DNS/ping targets recovered.",
                "WAN_RESTORED",
                {
                    "ip": target_ip,
                    "name": "ISP Internet Uplink",
                    "mac": "",
                },
                event_title="Internet connection recovered",
            )
        elif prev_health == "DEGRADED" and overall in {"EXCELLENT", "GOOD"}:
            self._record_event(
                "WAN_RESTORED",
                "INFO",
                "Internet quality stabilized",
                diagnosis.get("summary") or "Internet latency and packet loss returned to normal.",
                ip=target_ip,
                device_name="ISP Internet Uplink",
            )
        self._last_logged_isp_health = overall

    def get_alerts(self, limit: int = 100) -> list[dict]:
        with self.lock:
            return [dict(alert) for alert in list(self.config.get("alerts", []))[:limit]]

    def get_active_alerts(self) -> list[dict]:
        with self.lock:
            return [dict(alert) for alert in self.active_alerts.values()]

    @staticmethod
    def _is_today_iso(ts_str: object) -> bool:
        if not ts_str:
            return False
        try:
            dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")).astimezone()
            return dt.date() == datetime.now().astimezone().date()
        except ValueError:
            return False

    def get_alert_stats(self) -> dict:
        active = self.get_active_alerts()
        history = self.get_alerts(100)
        resolved_all = [a for a in history if a.get("severity") == "RESOLVED"]
        resolved_today = sum(
            self._is_today_iso(a.get("resolvedAt") or a.get("timestamp"))
            for a in resolved_all
        )
        return {
            "activeCount": len(active),
            "criticalCount": sum(a.get("severity") == "CRITICAL" for a in active),
            "warningCount": sum(a.get("severity") == "WARNING" for a in active),
            "acknowledgedCount": sum(a.get("status") == "ACKNOWLEDGED" for a in active),
            "resolvedCount": resolved_today,
            "resolvedTotal": len(resolved_all),
            "totalTracked": len(history),
        }

    def save_alert(self, alert: dict) -> None:
        with self.lock:
            alerts = self.config.setdefault("alerts", [])
            existing_index = next(
                (
                    index
                    for index, item in enumerate(alerts)
                    if item.get("id") == alert.get("id")
                ),
                None,
            )
            if existing_index is None:
                alerts.insert(0, alert)
            else:
                alerts[existing_index] = alert
            self.config["alerts"] = self.config["alerts"][:50]
            self.save_config()

