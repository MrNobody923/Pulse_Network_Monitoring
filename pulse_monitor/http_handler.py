"""Django dashboard, REST API, and sensor request handlers."""

from __future__ import annotations

import csv
import hmac
import io
import ipaddress
import json
import os
import queue
import re
import socket
import time
import urllib.parse
from typing import TYPE_CHECKING

from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.views import View

from .config import API_VERSION, ROOT, utc_now
from .game_detector import ANDROID_APP_DETECTION, MANAGED_PROCESS_DETECTION
from .runtime import PORT, DashboardServer, _active_monitor, run_server
from .views import render_page

if TYPE_CHECKING:
    from .engine import Monitor


__all__ = ["DashboardServer", "MAX_BODY_BYTES", "PORT", "PUBLIC_DIR", "RequestHandler", "run_server"]

PUBLIC_DIR = ROOT / "public"
MAX_BODY_BYTES = 1_000_000


RESOURCE_ROUTES = (
    (r"api/devices/[^/]+/probe", ["post"]),
    (r"api/alerts/[^/]+/(?:retest|acknowledge|feedback|dismiss)", ["post"]),
    (r"api/topology/node/[^/]+/position", ["post"]),
    (r"api/topology/node/[^/]+", ["put", "delete"]),
    (r"api/topology/link/[^/]+", ["delete"]),
    (r"api/devices/[^/]+", ["put", "delete"]),
)


def _safe_key(value: str) -> str:
    return urllib.parse.unquote(value)


class RequestHandler(View):
    """Serve the existing dashboard and sensor API through Django."""

    resource = False

    def dispatch(self, request, *args, **kwargs):
        request.get_host()
        self.headers = request.headers
        self.client_address = (request.META.get("REMOTE_ADDR", ""),)
        target = request.META.get("RAW_URI") or request.get_full_path()
        path, separator, query = target.partition("?")
        self.route_path = path.removesuffix("/") or "/"
        if self.resource or "%2f" in self.route_path.lower():
            for pattern, methods in RESOURCE_ROUTES:
                if re.fullmatch("/" + pattern, self.route_path):
                    self.http_method_names = methods
                    break
            else:
                return JsonResponse({"error": "Not found"}, status=404)
        self.path = self.route_path + separator + query
        result = super().dispatch(request, *args, **kwargs)
        return self.response if result is None else result

    http_method_names = ["get", "post", "put", "delete"]

    def http_method_not_allowed(self, request, *args, **kwargs):
        return JsonResponse(
            {"error": "Method not allowed"}, status=405,
            headers={"Allow": ", ".join(self._allowed_methods())},
        )

    def _json_body(self, max_bytes: int = MAX_BODY_BYTES) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length < 0 or length > max_bytes:
            raise ValueError(f"Request body must be smaller than {max_bytes // (1024 * 1024) or 1} MB")
        raw = self.request.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must contain valid JSON") from exc
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object")
        return body

    def _allow_write_request(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None and self.headers.get("Sec-Fetch-Site") != "cross-site":
            return True
        if origin and self.headers.get("Sec-Fetch-Site") != "cross-site":
            try:
                parsed = urllib.parse.urlsplit(origin)
            except ValueError:
                pass
            else:
                if parsed.scheme in {"http", "https"} and parsed.netloc.lower() == self.headers.get("Host", "").lower():
                    return True
        self._send_error_json("Cross-origin writes are forbidden", 403)
        return False

    def _allow_local_dashboard(self, error: str = "Device controls require the local dashboard") -> bool:
        try:
            host = urllib.parse.urlsplit("//" + self.headers.get("Host", "")).hostname
            local_host = host == "localhost" or ipaddress.ip_address(host or "").is_loopback
            if local_host and ipaddress.ip_address(self.client_address[0]).is_loopback:
                return True
        except ValueError:
            pass
        self._send_error_json(error, 403)
        return False

    def _send_json(self, payload: object, status: int = 200) -> None:
        self.response = JsonResponse(
            payload, status=status, safe=False,
            content_type="application/json; charset=utf-8",
            json_dumps_params={"ensure_ascii": False, "separators": (",", ":")},
            headers={"Cache-Control": "no-store"},
        )

    def _send_static_file(self, rel_path: str, content_type: str) -> bool:
        target = (PUBLIC_DIR / rel_path).resolve()
        if (
            not target.is_relative_to(PUBLIC_DIR.resolve())
            or not target.is_file()
        ):
            return False
        self.response = HttpResponse(target.read_bytes(), content_type=content_type,
                                     headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        return True

    def _send_page(
        self, path: str, message: str = "", filter_by: str = "all"
    ) -> None:
        if path in {"/", "/index.html"} and self._send_static_file(
            "index.html", "text/html; charset=utf-8"
        ):
            return
        mon = _active_monitor()
        self.response = HttpResponse(
            render_page(mon, path, message, filter_by), content_type="text/html; charset=utf-8",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    def _form_body(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Form body must be smaller than 1 MB")
        raw = self.request.read(length).decode("utf-8")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=30)
        return {key: values[-1] for key, values in parsed.items()}

    def _redirect(self, message: str = "", path: str = "/") -> None:
        parsed = urllib.parse.urlsplit("/")
        # Forms return to one of the local dashboard pages.
        page, _, query_string = path.partition("?")
        if page in {"/", "/index.html", "/devices", "/events"}:
            parsed = urllib.parse.urlsplit(page + "?" + query_string)
        query = urllib.parse.parse_qs(parsed.query)
        if message:
            query["message"] = [message]
        encoded_query = urllib.parse.urlencode(
            {k: v[-1] for k, v in query.items() if v}
        )
        location = parsed.path + ("?" + encoded_query if encoded_query else "")
        self.response = HttpResponse(status=303, headers={"Location": location})

    def _send_error_json(self, message: str, status: int) -> None:
        self._send_json({"error": message}, status)

    def _send_history_csv(self, rows: list[dict]) -> None:
        output = io.StringIO(newline="")
        fields = [
            "timestamp",
            "severity",
            "category",
            "eventType",
            "deviceName",
            "ip",
            "mac",
            "title",
            "message",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({
                field: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value
                for field, value in row.items()
            })
        raw = output.getvalue().encode("utf-8-sig")
        self.response = HttpResponse(
            raw,
            content_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="vertex-sentry-history-logs.csv"',
                "Cache-Control": "no-store",
            },
        )

    def _send_csv(self, rows: list[dict]) -> None:
        output = io.StringIO(newline="")
        fields = [
            "mac",
            "ip",
            "vendor",
            "name",
            "firstSeen",
            "lastSeen",
            "authorized",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({
                field: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value
                for field, value in row.items()
            })
        raw = output.getvalue().encode("utf-8-sig")
        self.response = HttpResponse(
            raw, content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="pulse-network-inventory.csv"'},
        )

    def get(self, request) -> None:
        mon = _active_monitor()
        path = urllib.parse.unquote(self.route_path)
        try:
            if path in {"/", "/index.html", "/devices", "/events"}:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                filter_by = query.get("filter", ["all"])[0]
                if filter_by not in {
                    "all",
                    "connected",
                    "favorites",
                    "new",
                    "down",
                    "offline",
                    "disconnected",
                    "archived",
                }:
                    filter_by = "all"
                self._send_page(path, query.get("message", [""])[0], filter_by)
            elif path.startswith("/css/") and path.endswith(".css"):
                if not self._send_static_file(
                    path.lstrip("/"), "text/css; charset=utf-8"
                ):
                    self._send_error_json("Not found", 404)
            elif path.startswith("/js/") and path.endswith(".js"):
                if not self._send_static_file(
                    path.lstrip("/"), "application/javascript; charset=utf-8"
                ):
                    self._send_error_json("Not found", 404)
            elif path == "/manifest.json":
                if not self._send_static_file(
                    "manifest.json", "application/manifest+json; charset=utf-8"
                ):
                    self._send_error_json("Not found", 404)
            elif path in {"/api/health", "/api/v1/health"}:
                self._send_json({
                    "ok": True,
                    "service": "pulse-network-monitor",
                    "apiVersion": API_VERSION,
                    "timestamp": utc_now(),
                })
            elif path in {"/api/mobile/summary", "/api/summary", "/api/v1/summary"}:
                self._send_json(mon.get_mobile_summary())
            elif path in {"/vertex-sentry.png", "/vertex-sentry-192.png", "/favicon.ico"}:
                asset = "vertex-sentry-192.png" if path == "/favicon.ico" else path.lstrip("/")
                if not self._send_static_file(asset, "image/png"):
                    self._send_error_json("Not found", 404)
            elif path == "/api/status":
                self._send_json(mon.snapshot())
            elif path == "/api/events":
                self._stream_events(mon)
            elif path == "/api/router/duplex":
                self._send_json(mon.router_state)
            elif path == "/api/routers":
                self._send_json({
                    "primaryIp": mon.config["router"].get("ip", "192.168.0.1"),
                    "routers": mon.get_router_fleet(),
                })
            elif path == "/api/devices":
                self._send_json(mon.get_devices())
            elif path == "/api/devices/connection":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                self._send_device_connection(mon, query.get("ip", [""])[0])
            elif path == "/api/devices/history":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                try:
                    self._send_json(mon.get_device_history(query.get("deviceId", [""])[0], query.get("mac", [""])[0]))
                except LookupError as exc:
                    self._send_error_json(str(exc), 404)
            elif path == "/api/alerts":
                self._send_json({
                    "active": mon.get_active_alerts(),
                    "history": mon.get_alerts(100),
                    "stats": mon.get_alert_stats(),
                })
            elif path == "/api/operations":
                self._send_json(mon.get_operations())
            elif path == "/api/operations/notifications":
                self._send_json(mon.get_notification_settings())
            elif path == "/api/operations/incident":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                try:
                    self._send_json(mon.get_incident(query.get("key", [""])[0]))
                except LookupError as exc:
                    self._send_error_json(str(exc), 404)
            elif path == "/api/operations/switch-ports":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                self._send_json(mon.get_switch_ports(query.get("deviceId", [""])[0]))
            elif path == "/api/network/ping-history":
                self._send_json(mon.get_isp_state().get("pingGraph", {}))
            elif path == "/api/isp/live":
                self._send_json(mon.get_live_isp_telemetry())
            elif path == "/api/network/inventory":
                self._send_json({
                    "inventory": mon.get_inventory(),
                    "events": mon.get_events(50),
                })
            elif path == "/api/network/inventory/profile":
                self._send_json({"profiles": mon.get_device_profiles()})
            elif path == "/api/network/events":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                limit = int(query.get("limit", ["50"])[0])
                self._send_json(mon.get_events(limit))
            elif path == "/api/network/history":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                self._send_json(mon.get_history_logs(
                    category=query.get("category", ["all"])[0],
                    severity=query.get("severity", ["all"])[0],
                    days=int(query.get("days", ["0"])[0] or 0),
                    search=query.get("q", [""])[0],
                    limit=int(query.get("limit", ["50"])[0] or 50),
                    offset=int(query.get("offset", ["0"])[0] or 0),
                ))
            elif path == "/api/network/history/export":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                data = mon.get_history_logs(
                    category=query.get("category", ["all"])[0],
                    severity=query.get("severity", ["all"])[0],
                    days=int(query.get("days", ["0"])[0] or 0),
                    search=query.get("q", [""])[0],
                    limit=500,
                    offset=0,
                )
                self._send_history_csv(data["items"])
            elif path == "/api/network/inventory/export":
                self._send_csv([{**row, "mac": row["observedMac"]} for row in mon.get_inventory()])
            elif path == "/api/tools/port-scan/catalog":
                self._send_json(mon.get_portscan_catalog())
            elif path == "/api/topology":
                self._send_json(mon.get_topology())
            elif path == "/api/gaming/activity":
                self._send_json(mon.get_game_activity())
            elif path == "/api/gaming/blocks":
                self._send_json({
                    "blocks": mon.get_game_blocks(),
                    "policy": mon.get_gaming_policy(),
                })
            elif path == "/api/gaming/wireshark/status":
                self._send_json(mon.get_wireshark_status())
            elif path == "/api/gaming/wireshark/capture.pcap":
                raw_pcap = mon.get_wireshark_capture_bytes()
                self.response = HttpResponse(
                    raw_pcap, content_type="application/vnd.tcpdump.pcap",
                    headers={"Cache-Control": "no-store", "Content-Disposition": 'attachment; filename="pulse-game-capture.pcap"'},
                )
            else:
                self._send_error_json("Not found", 404)
        except (ValueError, RuntimeError) as exc:
            self._send_error_json(str(exc), 400)
        except (OSError, TimeoutError) as exc:
            print(f"[http] GET {path} failed: {exc}", flush=True)
            self._send_error_json("The requested network operation failed", 502)
        except Exception as exc:
            print(f"[http] GET {path} failed unexpectedly: {exc}", flush=True)
            self._send_error_json("Internal server error", 500)

    def _stream_events(self, mon: Monitor) -> None:
        subscriber: queue.Queue[dict | None] = queue.Queue(maxsize=200)
        with mon.lock:
            stream_available = len(mon.event_subscribers) < 24
            if stream_available:
                mon.event_subscribers.add(subscriber)
        if not stream_available:
            self._send_error_json("Event stream capacity reached", 503)
            return

        def events():
            try:
                # Prime the generator so closing an unread response also frees the slot.
                yield b""
                snapshot = json.dumps(mon.snapshot(), separators=(",", ":"))
                yield f"event: snapshot\ndata: {snapshot}\n\n"
                while True:
                    try:
                        event = subscriber.get(timeout=15)
                    except queue.Empty:
                        yield b": keep-alive\n\n"
                        continue
                    if event is None:
                        return
                    payload = json.dumps(event["data"], separators=(",", ":"))
                    yield f"event: {event['event']}\ndata: {payload}\n\n"
            finally:
                with mon.lock:
                    mon.event_subscribers.discard(subscriber)

        stream = events()
        next(stream)
        self.response = StreamingHttpResponse(
            stream, content_type="text/event-stream; charset=utf-8",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def post(self, request) -> None:
        if not self._allow_write_request():
            return
        mon = _active_monitor()
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/actions/"):
            self._handle_dashboard_action(mon, path)
            return
        try:
            body = self._json_body(
                max_bytes=16 * 1024 * 1024 if path == "/api/gaming/wireshark/analyze" else MAX_BODY_BYTES
            )
            if path == "/api/devices" or path.startswith(("/api/devices/", "/api/network/", "/api/router/", "/api/routers/")):
                self._handle_network_post(mon, path, body)
            elif path == "/api/alerts/acknowledge-all":
                now = utc_now()
                tech = str(body.get("technician") or "Network Administrator")[:120]
                for alert in list(mon.active_alerts.values()):
                    alert["status"] = "ACKNOWLEDGED"
                    alert["acknowledgedBy"] = tech
                    alert["acknowledgedAt"] = now
                    mon.save_alert(alert)
                self._send_json({"success": True, "active": mon.get_active_alerts()})
            elif path == "/api/speedtest/run":
                self._send_json(mon.run_speedtest(target=body if isinstance(body, dict) else None))
            elif path == "/api/operations/maintenance":
                self._send_json(mon.create_maintenance(body), 201)
            elif path == "/api/operations/maintenance/cancel":
                mon.cancel_maintenance(str(body.get("id") or ""))
                self._send_json({"success": True})
            elif path == "/api/operations/notifications":
                if self._allow_local_dashboard("Notification settings require the local dashboard"):
                    self._send_json(mon.save_notification_settings(body))
            elif path == "/api/operations/notifications/test":
                if self._allow_local_dashboard("Test notifications require the local dashboard"):
                    self._send_json(mon.test_notification_channels())
            elif path == "/api/operations/switch-ports":
                if self._allow_local_dashboard("Run switch SNMP checks from the local dashboard"):
                    self._send_json(mon.sample_switch_ports(str(body.get("deviceId") or ""), body))
            elif path == "/api/isp/probe":
                isp_state = mon.probe_isp()
                self._send_json({"success": True, "isp": isp_state})
                mon.broadcast(
                    "telemetry",
                    {
                        "timestamp": utc_now(),
                        "router": mon.router_state,
                        "isp": isp_state,
                        "devices": mon._hydrated_devices(),
                        "activeAlerts": mon.get_active_alerts(),
                        "alertStats": mon.get_alert_stats(),
                    },
                )
            elif path == "/api/diagnostics/run":
                self._send_json(mon.run_diagnostics())
            elif path == "/api/tools/traceroute":
                self._send_json(
                    mon.traceroute(body.get("host"), body.get("maxHops", 15))
                )
            elif path == "/api/tools/dns-benchmark":
                self._send_json(mon.dns_benchmark(body.get("domain")))
            elif path == "/api/tools/port-check":
                host = mon._validate_host(body.get("host", ""))
                port = mon._validate_port(body.get("port"))
                try:
                    resolved_ip = socket.gethostbyname(host)
                except OSError as exc:
                    raise ValueError(f"Could not resolve target host '{host}': {exc}") from exc
                detail = mon.check_tcp_port(resolved_ip, port)
                error = None
                if not detail["open"]:
                    error = {
                        "connection-refused": "Connection refused",
                        "timeout": "Connection timed out",
                        "connection-error": "Connection could not be established",
                    }.get(detail["reason"], f"Nmap reported the port as {detail['state']}")
                self._send_json({
                    "host": host,
                    "ip": resolved_ip,
                    "port": port,
                    "open": detail["open"],
                    "state": detail["state"],
                    "reason": detail["reason"],
                    "observedService": detail["observedService"],
                    "serviceSource": detail["serviceSource"],
                    "reviewSource": detail["reviewSource"],
                    "latencyMs": detail["latencyMs"],
                    "service": detail["service"],
                    "category": detail["category"],
                    "riskLevel": detail["riskLevel"],
                    "atRisk": detail["atRisk"],
                    "banner": detail["banner"],
                    "summary": detail["summary"],
                    "exposureRisk": detail["exposureRisk"],
                    "remediation": detail["remediation"],
                    "error": error,
                    "timestamp": utc_now(),
                })
            elif path == "/api/tools/port-scan":
                self._send_json(
                    mon.run_port_scan(
                        body.get("host"),
                        body.get("profile", "quick_audit"),
                        body.get("customPorts", ""),
                        body.get("timeoutMs", 650),
                    )
                )
            elif path == "/api/alerts/clear":
                with mon.lock:
                    mon.config["alerts"] = []
                    mon.save_config()
                self._send_json({"success": True})
            elif path == "/api/alerts/test-drill":
                self._test_drill(mon, body)
            elif path == "/api/topology/node":
                self._send_json(mon.add_topology_node(body), 201)
            elif path == "/api/topology/link":
                self._send_json(mon.add_topology_link(body), 201)
            elif path == "/api/topology/import-monitored":
                self._send_json(mon.import_monitored_to_topology())
            elif path == "/api/topology/auto-layout":
                self._send_json(mon.auto_layout_topology())
            elif path == "/api/topology/clear":
                self._send_json(mon.clear_topology())
            elif path == "/api/topology/pdu-ping":
                self._send_json(
                    mon.ping_topology_pdu(body.get("sourceId"), body.get("targetId"))
                )
            elif path.startswith("/api/gaming/"):
                self._handle_gaming_post(mon, path, body)
            else:
                pos_match = re.fullmatch(
                    r"/api/topology/node/([^/]+)/position", path
                )
                match = re.fullmatch(
                    r"/api/alerts/([^/]+)/(retest|acknowledge|feedback|dismiss)", path
                )
                if pos_match:
                    self._send_json(
                        mon.move_topology_node(_safe_key(pos_match.group(1)), body)
                    )
                elif match:
                    self._alert_action(
                        mon, _safe_key(match.group(1)), match.group(2), body
                    )
                else:
                    self._send_error_json("Not found", 404)
        except (ValueError, RuntimeError) as exc:
            self._send_error_json(str(exc), 400)
        except (OSError, TimeoutError) as exc:
            print(f"[http] POST {path} failed: {exc}", flush=True)
            self._send_error_json("The requested network operation failed", 502)
        except Exception as exc:
            print(f"[http] POST {path} failed unexpectedly: {exc}", flush=True)
            self._send_error_json("Internal server error", 500)

    def _handle_network_post(self, mon: Monitor, path: str, body: dict) -> None:
        if path == "/api/devices":
            created = mon.add_device(body)
            self._send_json(created, 201)
            mon.broadcast(
                "telemetry",
                {
                    "timestamp": utc_now(),
                    "router": mon.router_state,
                    "isp": mon.get_isp_state(),
                    "devices": mon._hydrated_devices(),
                    "activeAlerts": mon.get_active_alerts(),
                    "alertStats": mon.get_alert_stats(),
                },
            )
        elif path == "/api/devices/connection":
            self._send_device_connection(mon, body.get("ip"), check_now=True)
        elif path == "/api/devices/upstream":
            try:
                mon.set_device_upstream(str(body.get("deviceId") or ""), str(body.get("upstreamDeviceId") or ""))
            except LookupError as exc:
                self._send_error_json(str(exc), 404)
            else:
                active = mon.get_active_alerts()
                mon.broadcast("alert_updated", {"deviceId": body.get("deviceId")})
                self._send_json({"success": True, "activeAlerts": active})
        elif path == "/api/devices/connection/snmp":
            if self._allow_local_dashboard("Enter the SNMP community from the local dashboard"):
                try:
                    self._send_json(mon.read_device_snmp(body.get("ip"), body.get("community")))
                except LookupError as exc:
                    self._send_error_json(str(exc), 404)
        elif path == "/api/devices/probe-all":
            results = mon.probe_all_devices()
            self._send_json({
                "success": True,
                "devices": results,
                "activeAlerts": mon.get_active_alerts(),
                "inventory": mon.get_inventory(),
            })
            mon.broadcast(
                "telemetry",
                {
                    "timestamp": utc_now(),
                    "router": mon.router_state,
                    "isp": mon.get_isp_state(),
                    "devices": results,
                    "activeAlerts": mon.get_active_alerts(),
                    "alertStats": mon.get_alert_stats(),
                },
            )
        elif path == "/api/network/sync-infrastructure":
            sync_res = mon.sync_infrastructure_devices()
            results = mon.probe_all_devices()
            self._send_json({
                "success": True,
                "sync": sync_res,
                "devices": results,
                "inventory": mon.get_inventory(),
                "activeAlerts": mon.get_active_alerts(),
            })
            mon.broadcast(
                "telemetry",
                {
                    "timestamp": utc_now(),
                    "router": mon.router_state,
                    "isp": mon.get_isp_state(),
                    "devices": results,
                    "activeAlerts": mon.get_active_alerts(),
                    "alertStats": mon.get_alert_stats(),
                },
            )
        elif re.fullmatch(r"/api/devices/[^/]+/probe", path):
            device_id = _safe_key(path.split("/")[-2])
            device = next(
                (item for item in mon.get_devices() if item["id"] == device_id),
                None,
            )
            if device is None:
                self._send_error_json("Device not found", 404)
                return
            result = mon.probe_device(device)
            mon.latest_devices[result["ip"]] = result
            mon.enrich_fleet_diagnostics(list(mon.latest_devices.values()))
            self._send_json(result)
            mon.broadcast(
                "telemetry",
                {
                    "timestamp": utc_now(),
                    "router": mon.router_state,
                    "isp": mon.get_isp_state(),
                    "devices": mon._hydrated_devices(),
                    "activeAlerts": mon.get_active_alerts(),
                    "alertStats": mon.get_alert_stats(),
                },
            )
        elif path in {"/api/router/access/block", "/api/router/access/restore"}:
            if not self._allow_local_dashboard():
                return
            result = (
                mon.block_gateway_device(body) if path.endswith("/block")
                else mon.restore_gateway_device(body.get("ruleId"))
            )
            self._send_json(result)
        elif path == "/api/router/refresh":
            router = mon.probe_router()
            fleet = mon.get_router_fleet()
            mon.broadcast("router_update", {**router, "fleet": fleet})
            self._send_json({"router": router, "routers": fleet})
        elif path in {"/api/router/config", "/api/routers/config"}:
            target_ip = mon.update_router_config(
                body,
                select_primary=path == "/api/router/config" and body.get("isPrimary") is not False,
            )
            fleet = mon.probe_routers_fleet()
            matched_router = next(
                (r for r in fleet if r.get("ip") == target_ip),
                mon.router_state,
            )
            mon.broadcast(
                "router_update",
                {**mon.router_state, "fleet": fleet},
            )
            self._send_json({"success": True, "router": matched_router, "routers": fleet})
        elif path == "/api/router/simulate":
            self._simulate_port(mon, body)
        elif path == "/api/network/import-devices":
            self._import_devices(mon, body)
        elif path == "/api/network/discover":
            self._send_json(mon.discover_devices())
        elif path == "/api/network/inventory/authorize":
            mac = body.get("mac", "")
            updated = mon.authorize_device(mac)
            if not updated:
                self._send_error_json("Discovered device not found", 404)
            else:
                inventory = mon.get_inventory()
                mon.broadcast("inventory_update", {"inventory": inventory})
                self._send_json({"success": True, "inventory": inventory})
        elif path == "/api/network/inventory/review":
            if not isinstance(body.get("ignored"), bool):
                raise ValueError("Choose whether to ignore this device")
            if not mon.set_device_review_ignored(body.get("mac", ""), body["ignored"]):
                self._send_error_json("Pending device review not found", 404)
            else:
                inventory = mon.get_inventory()
                mon.broadcast("inventory_update", {"inventory": inventory})
                self._send_json({"success": True, "inventory": inventory})
        elif path == "/api/network/inventory/favorite":
            fav = mon.toggle_favorite(str(body.get("asset_key", "")))
            self._send_json({
                "success": True,
                "favorite": fav,
                "inventory": mon.get_inventory(),
                "devices": mon._hydrated_devices(),
            })
        elif path == "/api/network/inventory/archive":
            archived = mon.toggle_archive(str(body.get("asset_key", "")))
            self._send_json({
                "success": True,
                "archived": archived,
                "inventory": mon.get_inventory(),
                "devices": mon.get_devices(),
            })
        elif path == "/api/network/inventory/profile":
            res = mon.set_device_profile(str(body.get("mac") or ""), body)
            inventory = mon.get_inventory()
            mon.broadcast("inventory_update", {"inventory": inventory})
            self._send_json({**res, "inventory": inventory})
        elif path == "/api/network/events/clear":
            self._send_json(mon.clear_events())
        else:
            self._send_error_json("Not found", 404)

    def _send_device_connection(self, mon: Monitor, ip: object, *, check_now: bool = False) -> None:
        try:
            self._send_json(mon.get_device_connection(ip, check_now=check_now))
        except LookupError as exc:
            self._send_error_json(str(exc), 404)

    def _handle_gaming_post(self, mon: Monitor, path: str, body: dict) -> None:
        if path == "/api/gaming/detect":
            if str(body.get("detectionMethod") or "").strip() == ANDROID_APP_DETECTION:
                raise ValueError("Android app reports use the local Android sensor endpoint")
            result = mon.record_game_detection(body, include_activity=body.get("includeActivity") is not False)
            self._send_json(result, 201)
        elif path == "/api/gaming/android":
            if self._allow_local_dashboard("Android game reports require a local sensor"):
                self._send_json(mon.report_android_game_activity(body))
        elif path == "/api/gaming/endpoint":
            self._handle_game_endpoint(mon, body)
        elif path == "/api/gaming/scan":
            self._send_json(mon.scan_lan_for_games(include_topology_refresh=True))
        elif path == "/api/gaming/clear":
            self._send_json(mon.clear_game_activity())
        elif path == "/api/gaming/dismiss":
            if body.get("id"):
                self._send_json(mon.dismiss_game_session(body.get("id", "")))
            else:
                self._send_json(
                    mon.mark_game_session_ended_by_ip_game(
                        body.get("ip", ""), body.get("gameId", "")
                    )
                )
        elif path == "/api/gaming/block":
            if not self._allow_local_dashboard():
                return
            if body.get("scope") in ("device_throttle", "device_wifi_cut"):
                body["routerOnly"] = True
            self._send_json(mon.block_game_session(body))
        elif path == "/api/gaming/unblock":
            if not self._allow_local_dashboard():
                return
            result = mon.unblock_game_rule(body.get("ruleId") or body.get("id") or "")
            self._send_json(result, 200 if result["success"] else 409)
        elif path == "/api/gaming/policy":
            self._send_json(mon.set_gaming_policy(body))
        elif path == "/api/gaming/sensor-heartbeat":
            self._send_json(mon.record_gaming_sensor_heartbeat(body))
        elif path == "/api/gaming/setup-router-dns":
            self._send_json(mon.configure_router_game_dns())
        elif path == "/api/gaming/wireshark/analyze":
            self._send_json(mon.analyze_wireshark_capture(body))
        elif path == "/api/gaming/wireshark/config":
            self._send_json(mon.set_wireshark_config(body))
        else:
            self._send_error_json("Not found", 404)

    def _handle_game_endpoint(self, mon: Monitor, body: dict) -> None:
        token = os.environ.get("PULSE_GAME_ENDPOINT_TOKEN", "")
        auth = self.headers.get("Authorization", "").encode("utf-8")
        if not token or not hmac.compare_digest(auth, f"Bearer {token}".encode("utf-8")):
            self._send_error_json("Endpoint enrollment token is required", 403)
            return

        peer_ip = self.client_address[0]
        ip = str(body.get("ip") or peer_ip) if ipaddress.ip_address(peer_ip).is_loopback else peer_ip
        if not mon._is_real_lan_client_ip(ip):
            raise ValueError("Endpoint must be in a monitored LAN subnet")
        if body.get("heartbeat") is True:
            mon.note_game_endpoint(ip)
            self._send_json({"success": True})
            return
        player = body.get("player")
        if (
            not isinstance(player, str) or not player.strip() or len(player) > 128
            or any(not char.isprintable() for char in player)
        ):
            raise ValueError("A Windows account name is required")
        player = player.strip().casefold()

        if body.get("ended") is True:
            signature = mon._match_game_signature(game_id=body.get("gameId"))
            if signature is None:
                raise ValueError("Unrecognized game")
            result = mon.mark_game_session_ended_by_ip_game(
                ip, signature["id"], player=player, include_activity=False,
            )
        else:
            process = body.get("process")
            if not isinstance(process, str) or mon._match_game_signature(process=process) is None:
                raise ValueError("Unrecognized game process")
            result = mon.record_game_detection({
                "ip": ip,
                "process": process,
                "detectionMethod": MANAGED_PROCESS_DETECTION,
                "skipAutoPrevent": True,
            }, player=player, include_activity=False)
        mon.note_game_endpoint(ip)
        self._send_json({"success": result["success"]})

    def _handle_dashboard_action(self, mon: Monitor, path: str) -> None:
        return_to = "/devices"
        try:
            form = self._form_body()
            return_to = form.get("return_to") or "/devices"
            if path == "/actions/discover":
                result = mon.discover_devices()
                self._redirect(
                    f"LAN scan complete: {result['totalDiscovered']} devices seen across "
                    f"{', '.join(result['networks'])}.",
                    return_to,
                )
            elif path == "/actions/favorite":
                favorite = mon.toggle_favorite(form.get("asset_key", ""))
                self._redirect(
                    "Device added to favourites."
                    if favorite
                    else "Device removed from favourites.",
                    return_to,
                )
            elif path == "/actions/archive":
                archived = mon.toggle_archive(form.get("asset_key", ""))
                self._redirect(
                    "Device archived."
                    if archived
                    else "Device restored from the archive.",
                    return_to,
                )
            elif path == "/actions/authorize":
                if not mon.authorize_device(form.get("mac", "")):
                    raise ValueError("Discovered device not found")
                self._redirect("Device marked as reviewed.", return_to)
            elif path == "/actions/add-device":
                mon.add_device({
                    "name": form.get("name", ""),
                    "ip": form.get("ip", ""),
                    "port": form.get("port", 80),
                    "type": form.get("type", "device"),
                })
                self._redirect("Device added to monitoring.", return_to)
            else:
                self._send_error_json("Not found", 404)
        except (ValueError, RuntimeError) as exc:
            self._redirect(str(exc), return_to)
        except (OSError, TimeoutError) as exc:
            print(f"[http] Dashboard action {path} failed: {exc}", flush=True)
            self._redirect("The requested network operation failed.", return_to)

    def put(self, request) -> None:
        if not self._allow_write_request():
            return
        mon = _active_monitor()
        path = urllib.parse.urlsplit(self.path).path
        topo_match = re.fullmatch(r"/api/topology/node/([^/]+)", path)
        if topo_match:
            try:
                updates = self._json_body()
                self._send_json(
                    mon.update_topology_node(_safe_key(topo_match.group(1)), updates)
                )
            except ValueError as exc:
                self._send_error_json(str(exc), 400)
            return
        match = re.fullmatch(r"/api/devices/([^/]+)", path)
        if not match:
            self._send_error_json("Not found", 404)
            return
        try:
            updates = self._json_body()
            updated = mon.update_device(_safe_key(match.group(1)), updates)
            if updated is None:
                self._send_error_json("Device not found", 404)
            else:
                self._send_json(updated)
        except ValueError as exc:
            self._send_error_json(str(exc), 400)

    def delete(self, request) -> None:
        if not self._allow_write_request():
            return
        mon = _active_monitor()
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        topo_node_match = re.fullmatch(r"/api/topology/node/([^/]+)", path)
        if topo_node_match:
            try:
                query = urllib.parse.parse_qs(parsed.query)
                del_mon = query.get("deleteMonitored", ["false"])[0].lower() == "true"
                self._send_json(
                    mon.delete_topology_node(_safe_key(topo_node_match.group(1)), del_mon)
                )
            except ValueError as exc:
                self._send_error_json(str(exc), 404)
            return
        topo_link_match = re.fullmatch(r"/api/topology/link/([^/]+)", path)
        if topo_link_match:
            try:
                self._send_json(
                    mon.delete_topology_link(_safe_key(topo_link_match.group(1)))
                )
            except ValueError as exc:
                self._send_error_json(str(exc), 404)
            return
        match = re.fullmatch(r"/api/devices/([^/]+)", path)
        if not match:
            self._send_error_json("Not found", 404)
            return
        deleted = mon.delete_device(_safe_key(match.group(1)))
        if deleted:
            mon.broadcast(
                "telemetry",
                {
                    "timestamp": utc_now(),
                    "devices": mon._hydrated_devices(),
                    "routers": mon.get_router_fleet() if hasattr(mon, "get_router_fleet") else [],
                    "activeAlerts": mon.get_active_alerts(),
                    "alertStats": mon.get_alert_stats(),
                },
            )
        self._send_json({"success": deleted})

    def _import_devices(self, mon: Monitor, body: dict) -> None:
        items = body.get("devices")
        if not isinstance(items, list) or not items:
            raise ValueError("No devices provided")
        added = []
        errors = []
        for item in items[:200]:
            if not isinstance(item, dict) or not item.get("ip"):
                continue
            try:
                added.append(
                    mon.add_device({
                        "name": item.get("suggestedName")
                        or item.get("name")
                        or f"Device {item['ip']}",
                        "ip": item["ip"],
                        "type": item.get("type") or "device",
                        "port": item.get("port") or 80,
                        "location": item.get("location") or "Office",
                        "critical": bool(item.get("critical", False)),
                        "mac": item.get("mac", ""),
                    })
                )
            except ValueError as exc:
                errors.append({"ip": item.get("ip"), "error": str(exc)})
        if not added and errors:
            self._send_json(
                {"success": False, "count": 0, "devices": [], "errors": errors}, 409
            )
            return
        self._send_json({
            "success": True,
            "count": len(added),
            "devices": added,
            "errors": errors,
        })

    def _simulate_port(self, mon: Monitor, body: dict) -> None:
        try:
            index = int(body["portIndex"])
            speed = int(body.get("speed", 1000))
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError("portIndex and speed must be integers") from exc
        target_ip = str(body.get("ip") or mon.router_state.get("ip") or "").strip()
        with mon.lock:
            target_router = next(
                (r for r in getattr(mon, "router_fleet", []) if r.get("ip") == target_ip),
                mon.router_state,
            )
            if not 0 <= index < len(target_router["ports"]) or speed < 0:
                raise ValueError("Invalid router port simulation values")
            port = target_router["ports"][index]
            connected = body.get("linkStatus") != "disconnected"
            port.update({
                "speed": speed,
                "speedText": f"{speed} Mbps" if connected else "Unavailable",
                "duplex": str(body.get("duplex") or "Unknown"),
                "linkStatus": "connected" if connected else "disconnected",
                "status": (
                    "disconnected"
                    if not connected
                    else (
                        "warning"
                        if speed < 1000
                        or "half" in str(body.get("duplex", "")).lower()
                        else "optimal"
                    )
                ),
                "simulation": True,
            })
            if target_router.get("ip") == mon.router_state.get("ip"):
                mon.router_state["ports"][index] = dict(port)
        mon.evaluate_router_ports(target_router)
        self._send_json({"success": True, "port": port})
        mon.broadcast("router_update", {**mon.router_state, "fleet": mon.get_router_fleet()})

    def _test_drill(self, mon: Monitor, body: dict) -> None:
        now = utc_now()
        drill_type = str(body.get("type") or "DUPLEX_COLLISION")
        is_outage = drill_type == "AP_OUTAGE"
        key = f"drill-{int(time.time() * 1000)}"
        alert = mon._make_alert(
            key,
            "CRITICAL",
            "🧪 [DRILL SIMULATION] Access Point Power Loss"
            if is_outage
            else "🧪 [DRILL SIMULATION] Duplex Collision Mismatch",
            "SIMULATION DRILL: This is a test alert and does not indicate a real network issue.",
            "192.168.0.45" if is_outage else "",
        )
        alert.update({
            "isDrill": True,
            "timestamp": now,
            "firstSeen": now,
            "notes": [
                {
                    "id": "note-0",
                    "author": "Drill System",
                    "text": "Simulation initiated to test alert handling.",
                    "timestamp": now,
                }
            ],
            "remediation": [
                "Acknowledge this simulation alert or dismiss it when finished."
            ],
        })
        mon.active_alerts[key] = alert
        mon.save_alert(alert)
        mon.broadcast("new_alert", alert)
        self._send_json({"success": True, "alert": alert})

    def _alert_action(
        self, mon: Monitor, key: str, action: str, body: dict
    ) -> None:
        alert = mon.active_alerts.get(key)
        if alert is None:
            if action == "dismiss":
                self._send_json({"success": True, "alreadyDismissed": True})
                return
            self._send_error_json("Alert not found or already resolved", 404)
            return
        if action == "acknowledge":
            alert["status"] = "ACKNOWLEDGED"
            alert["acknowledgedBy"] = str(
                body.get("technician") or "Network Administrator"
            )[:120]
            alert["acknowledgedAt"] = utc_now()
            mon.save_alert(alert)
            self._send_json({"success": True, "alert": alert})
            mon.broadcast("alert_updated", alert)
        elif action == "feedback":
            note = str(body.get("note") or "").strip()
            if not note:
                raise ValueError("Note text cannot be empty")
            added = {
                "id": f"note-{int(time.time() * 1000)}",
                "author": str(body.get("author") or "Technician")[:120],
                "text": note[:2000],
                "timestamp": utc_now(),
            }
            alert.setdefault("notes", []).append(added)
            mon.save_alert(alert)
            self._send_json({"success": True, "note": added, "alert": alert})
            mon.broadcast("alert_updated", alert)
        elif action == "dismiss":
            dismissed = mon.active_alerts.pop(key, None)
            if dismissed is not None:
                dismissed["status"] = "DISMISSED"
                mon.save_alert(dismissed)
            self._send_json({"success": dismissed is not None})
            mon.broadcast("alert_dismissed", {"key": key})
        else:
            if alert.get("isDrill"):
                raise ValueError("Simulation alerts use test data.")
            ip = alert.get("ip") or mon.config["router"]["ip"]
            port = int(alert.get("port") or 80)
            resolved_now = False
            if key.startswith("port-"):
                router_state = mon.probe_router()
                mon.broadcast("router_update", router_state)
                still_active = key in mon.active_alerts
                resolved_now = not still_active
                port_row = next(
                    (p for p in router_state.get("ports", []) if f"port-{p.get('id')}" == key),
                    {},
                )
                port_unknown = port_row.get("linkStatus") not in {"connected", "disconnected"}
                result = {
                    "alive": router_state.get("reachable", False),
                    "latencyMs": None,
                    "method": "Router Port Check",
                    "status": "UNKNOWN" if port_unknown else "HEALTHY" if resolved_now else str(port_row.get("status") or "UNKNOWN").upper(),
                    "feedback": (
                        "The router did not report the port's current link state."
                        if port_unknown
                        else f"{port_row.get('name', 'Router port')} returned to normal."
                        if resolved_now
                        else f"Issue persists ({port_row.get('speedText', 'Unavailable')} / {port_row.get('duplex', 'Unknown')})."
                    ),
                    "testedAt": utc_now(),
                }
            elif key == "isp-wan" or alert.get("category") == "isp":
                isp_state = mon.probe_isp()
                still_active = key in mon.active_alerts
                resolved_now = not still_active
                result = {
                    "alive": isp_state.get("overallHealth") != "OUTAGE",
                    "latencyMs": isp_state.get("tier1LatencyMs"),
                    "method": "Internet TCP/ICMP Check",
                    "status": str(isp_state.get("overallHealth") or "UNKNOWN"),
                    "feedback": (
                        f"Internet reachable ({isp_state.get('tier1LatencyMs')} ms avg ping)."
                        if resolved_now
                        else "External internet targets are still unreachable."
                    ),
                    "testedAt": utc_now(),
                }
            else:
                dev = next((d for d in mon.get_devices() if d.get("ip") == ip), None) or {
                    "id": f"retest-{ip}",
                    "name": alert.get("deviceName") or ip,
                    "ip": ip,
                    "type": "ap",
                    "port": port,
                    "critical": alert.get("severity") == "CRITICAL",
                    "mac": alert.get("mac", ""),
                }
                probe_res = mon.probe_device(dev)
                mon.latest_devices[ip] = probe_res
                observed_only = probe_res.get("connectivityState") == "ARP_OBSERVED"
                alive = bool(probe_res.get("alive")) and not observed_only
                latency = probe_res.get("latencyMs")
                method = probe_res.get("probeMethod") or "TCP + ICMP"
                still_active = key in mon.active_alerts
                resolved_now = not still_active
                result = {
                    "alive": alive,
                    "latencyMs": latency,
                    "method": method,
                    "status": (
                        "UNCONFIRMED"
                        if observed_only
                        else "ONLINE"
                        if alive and probe_res.get("status") == "online"
                        else ("DEGRADED" if alive else "OFFLINE")
                    ),
                    "feedback": (
                        "ARP entry observed. TCP and ICMP received no reply."
                        if observed_only
                        else f"Responded in {latency} ms via {method}."
                        if alive
                        else f"No response on TCP ports or ICMP ping ({method})."
                    ),
                    "testedAt": probe_res.get("lastChecked") or utc_now(),
                }
                mon.broadcast(
                    "telemetry",
                    {
                        "timestamp": utc_now(),
                        "router": mon.router_state,
                        "isp": mon.get_isp_state(),
                        "devices": mon._hydrated_devices(),
                        "activeAlerts": mon.get_active_alerts(),
                        "alertStats": mon.get_alert_stats(),
                    },
                )

            if key in mon.active_alerts:
                alert["lastProbeResult"] = result
                alert["lastChecked"] = result["testedAt"]
                mon.save_alert(alert)
            self._send_json({
                "success": True,
                "alert": alert,
                "probeResult": result,
                "resolved": resolved_now,
            })
            if not resolved_now:
                mon.broadcast("alert_updated", alert)
