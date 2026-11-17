"""HTTP server, REST API routes, SSE streaming, and static asset serving."""

from __future__ import annotations

import csv
import io
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import API_VERSION, ROOT, utc_now
from .views import render_page


PUBLIC_DIR = ROOT / "public"
MAX_BODY_BYTES = 1_000_000
PORT = int(os.environ.get("PORT", "3000"))


def _safe_key(value: str) -> str:
    return urllib.parse.unquote(value)


def _active_monitor():
    """Return the active monitor instance (supports unittest.mock.patch on `server.monitor`)."""
    srv_mod = sys.modules.get("server")
    if srv_mod is not None and hasattr(srv_mod, "monitor"):
        return srv_mod.monitor
    from . import monitor as default_monitor

    return default_monitor


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request: object, client_address: object) -> None:
        _, exc, _ = sys.exc_info()
        if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "PulseNetworkMonitor/2.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[http] {self.address_string()} - {fmt % args}", flush=True)

    def _json_body(self, max_bytes: int = MAX_BODY_BYTES) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length < 0 or length > max_bytes:
            raise ValueError(f"Request body must be smaller than {max_bytes // (1024 * 1024) or 1} MB")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must contain valid JSON") from exc
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object")
        return body

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_json(self, payload: object, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(raw)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _send_static_file(self, rel_path: str, content_type: str) -> bool:
        target = (PUBLIC_DIR / rel_path).resolve()
        if (
            not str(target).startswith(str(PUBLIC_DIR.resolve()))
            or not target.is_file()
        ):
            return False
        raw = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)
        return True

    def _send_page(
        self, path: str, message: str = "", filter_by: str = "all"
    ) -> None:
        if path in {"/", "/index.html"} and self._send_static_file(
            "index.html", "text/html; charset=utf-8"
        ):
            return
        mon = _active_monitor()
        raw = render_page(mon, path, message, filter_by).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _form_body(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Form body must be smaller than 1 MB")
        raw = self.rfile.read(length).decode("utf-8")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=30)
        return {key: values[-1] for key, values in parsed.items()}

    def _redirect(self, message: str = "", path: str = "/") -> None:
        if not path.startswith("/") or path.startswith("//"):
            path = "/"
        parsed = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(parsed.query)
        if message:
            query["message"] = [message]
        encoded_query = urllib.parse.urlencode(
            {k: v[-1] for k, v in query.items() if v}
        )
        location = parsed.path + ("?" + encoded_query if encoded_query else "")
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_error_json(self, message: str, status: int) -> None:
        self._send_json({"error": message}, status)

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
        writer.writerows(rows)
        raw = output.getvalue().encode("utf-8-sig")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header(
            "Content-Disposition",
            'attachment; filename="pulse-network-inventory.csv"',
        )
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _path_parts(self) -> list[str]:
        path = urllib.parse.urlsplit(self.path).path
        return [urllib.parse.unquote(part) for part in path.split("/") if part]

    def do_GET(self) -> None:
        mon = _active_monitor()
        parts = self._path_parts()
        path = "/" + "/".join(parts)
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
            elif path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
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
            elif path == "/api/alerts":
                self._send_json({
                    "active": mon.get_active_alerts(),
                    "history": mon.get_alerts(100),
                    "stats": mon.get_alert_stats(),
                })
            elif path == "/api/network/ping-history":
                self._send_json(mon.get_isp_state().get("pingGraph", {}))
            elif path == "/api/network/discover":
                self._send_json(mon.discover_devices())
            elif path == "/api/network/inventory":
                self._send_json({
                    "inventory": mon.get_inventory(),
                    "events": mon.get_events(50),
                })
            elif path == "/api/network/events":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                limit = int(query.get("limit", ["50"])[0])
                self._send_json(mon.get_events(limit))
            elif path == "/api/network/inventory/export":
                self._send_csv(mon.get_inventory())
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
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Disposition", 'attachment; filename="pulse-game-capture.pcap"')
                self.send_header("Content-Length", str(len(raw_pcap)))
                self.send_header("Cache-Control", "no-store")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(raw_pcap)
            else:
                self._send_error_json("Not found", 404)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass
        except (ValueError, RuntimeError) as exc:
            self._send_error_json(str(exc), 400)
        except (OSError, TimeoutError) as exc:
            print(f"[http] GET {path} failed: {exc}", flush=True)
            self._send_error_json("The requested network operation failed", 502)
        except Exception as exc:
            print(f"[http] GET {path} failed unexpectedly: {exc}", flush=True)
            self._send_error_json("Internal server error", 500)

    def _stream_events(self, mon: object) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self._send_cors_headers()
        self.end_headers()
        subscriber: queue.Queue = queue.Queue(maxsize=200)
        with mon.lock:
            mon.event_subscribers.add(subscriber)
        try:
            snapshot = json.dumps(mon.snapshot(), separators=(",", ":"))
            self.wfile.write(f"event: snapshot\ndata: {snapshot}\n\n".encode("utf-8"))
            self.wfile.flush()
            while True:
                try:
                    event = subscriber.get(timeout=15)
                    if event is None:
                        break
                    payload = json.dumps(event["data"], separators=(",", ":"))
                    self.wfile.write(
                        f"event: {event['event']}\ndata: {payload}\n\n".encode("utf-8")
                    )
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with mon.lock:
                mon.event_subscribers.discard(subscriber)

    def do_POST(self) -> None:
        mon = _active_monitor()
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/actions/"):
            self._handle_dashboard_action(mon, path)
            return
        try:
            body = self._json_body(
                max_bytes=16 * 1024 * 1024 if path == "/api/gaming/wireshark/analyze" else MAX_BODY_BYTES
            )
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
            elif path in {"/api/router/config", "/api/routers/config"}:
                router_ip_default = mon.config["router"].get("ip", "192.168.0.1")
                target_ip = mon._validate_ip(body.get("ip") or router_ip_default)
                routers_map = mon.config.setdefault("routers", {})
                if not isinstance(routers_map, dict):
                    routers_map = {}
                    mon.config["routers"] = routers_map
                r_entry = dict(routers_map.get(target_ip, {}))
                r_entry["ip"] = target_ip
                if body.get("port") is not None and str(body.get("port")).strip():
                    r_entry["port"] = mon._validate_port(body["port"])
                if "useHttps" in body:
                    r_entry["useHttps"] = bool(body["useHttps"])
                if "stok" in body:
                    r_entry["stok"] = str(body["stok"])[:256]
                if "password" in body:
                    r_entry["password"] = str(body["password"])[:256]
                if "username" in body:
                    r_entry["username"] = str(body["username"])[:128]
                if "snmpCommunity" in body:
                    r_entry["snmpCommunity"] = str(body["snmpCommunity"] or "public")[:64]
                if "name" in body and str(body["name"]).strip():
                    r_entry["name"] = str(body["name"]).strip()[:120]
                if "role" in body and str(body["role"]).strip():
                    r_entry["role"] = str(body["role"]).strip()[:60]
                routers_map[target_ip] = r_entry

                is_primary_update = target_ip == router_ip_default or (
                    path == "/api/router/config" and body.get("isPrimary") is not False
                )
                if is_primary_update:
                    config = mon.config["router"]
                    config["ip"] = target_ip
                    for k in ("port", "stok", "password", "username", "snmpCommunity", "useHttps"):
                        if k in r_entry:
                            config[k] = r_entry[k]

                mon.save_config()
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
                    self._send_json({"success": True, "inventory": mon.get_inventory()})
            elif path == "/api/network/inventory/favorite":
                fav = mon.toggle_favorite(str(body.get("asset_key", "")))
                self._send_json({
                    "success": True,
                    "favorite": fav,
                    "inventory": mon.get_inventory(),
                    "devices": mon.get_devices(),
                })
            elif path == "/api/network/inventory/archive":
                archived = mon.toggle_archive(str(body.get("asset_key", "")))
                self._send_json({
                    "success": True,
                    "archived": archived,
                    "inventory": mon.get_inventory(),
                    "devices": mon.get_devices(),
                })
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
                mon.broadcast("speedtest_status", {"status": "running"})
                self._send_json(mon.run_speedtest())
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
                detail = mon._scan_single_port(host, port, 1.5)
                self._send_json({
                    "host": host,
                    "port": port,
                    "open": detail["open"],
                    "latencyMs": detail["latencyMs"],
                    "service": detail["service"],
                    "category": detail["category"],
                    "riskLevel": detail["riskLevel"],
                    "atRisk": detail["atRisk"],
                    "banner": detail["banner"],
                    "summary": detail["summary"],
                    "exposureRisk": detail["exposureRisk"],
                    "remediation": detail["remediation"],
                    "error": None if detail["open"] else "Connection timed out or was refused",
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
                mon.config["alerts"] = []
                mon.save_config()
                self._send_json({"success": True})
            elif path == "/api/network/events/clear":
                self._send_json(mon.clear_events())
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
            elif path == "/api/gaming/detect":
                self._send_json(mon.record_game_detection(body), 201)
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
                self._send_json(mon.block_game_session(body))
            elif path == "/api/gaming/unblock":
                self._send_json(
                    mon.unblock_game_rule(body.get("ruleId") or body.get("id") or "")
                )
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
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass
        except (ValueError, RuntimeError) as exc:
            self._send_error_json(str(exc), 400)
        except (OSError, TimeoutError) as exc:
            print(f"[http] POST {path} failed: {exc}", flush=True)
            self._send_error_json("The requested network operation failed", 502)
        except Exception as exc:
            print(f"[http] POST {path} failed unexpectedly: {exc}", flush=True)
            self._send_error_json("Internal server error", 500)

    def _handle_dashboard_action(self, mon: object, path: str) -> None:
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

    def do_PUT(self) -> None:
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

    def do_DELETE(self) -> None:
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

    def _import_devices(self, mon: object, body: dict) -> None:
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

    def _simulate_port(self, mon: object, body: dict) -> None:
        try:
            index = int(body.get("portIndex"))
            speed = int(body.get("speed", 1000))
        except (TypeError, ValueError) as exc:
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

    def _test_drill(self, mon: object, body: dict) -> None:
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
        self, mon: object, key: str, action: str, body: dict
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
                result = {
                    "alive": router_state.get("reachable", False),
                    "latencyMs": None,
                    "method": "Router Port Check",
                    "status": "HEALTHY" if resolved_now else str(port_row.get("status") or "UNKNOWN").upper(),
                    "feedback": (
                        f"{port_row.get('name', 'Router port')} returned to normal."
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
                alive = bool(probe_res.get("alive"))
                latency = probe_res.get("latencyMs")
                method = probe_res.get("probeMethod") or "TCP + ICMP"
                still_active = key in mon.active_alerts
                resolved_now = not still_active
                result = {
                    "alive": alive,
                    "latencyMs": latency,
                    "method": method,
                    "status": (
                        "ONLINE"
                        if alive and probe_res.get("status") == "online"
                        else ("DEGRADED" if alive else "OFFLINE")
                    ),
                    "feedback": (
                        f"Responded in {latency} ms via {method}."
                        if alive
                        else f"No response on TCP ports or ICMP ping ({method})."
                    ),
                    "testedAt": utc_now(),
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
                alert["lastChecked"] = utc_now()
                mon.save_alert(alert)
            self._send_json({
                "success": True,
                "alert": alert,
                "probeResult": result,
                "resolved": resolved_now,
            })
            if not resolved_now:
                mon.broadcast("alert_updated", alert)


def run_server(port: int = PORT) -> None:
    mon = _active_monitor()
    server = DashboardServer(("0.0.0.0", port), RequestHandler)
    mon.start()

    def _open_browser() -> None:
        time.sleep(1.0)
        try:
            import webbrowser
            if os.environ.get("PULSE_NO_BROWSER") != "1" and not os.path.exists("/.dockerenv"):
                webbrowser.open(f"http://localhost:{port}")
        except Exception:
            pass

    threading.Thread(target=_open_browser, daemon=True, name="browser-opener").start()

    print("=======================================================", flush=True)
    print("  PULSE NETWORK MONITORING SYSTEM (Python)", flush=True)
    print(f"  Local Web Dashboard: http://localhost:{port}", flush=True)
    try:
        lan_ip = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.168.0.1", 80))
            lan_ip = s.getsockname()[0]
        if lan_ip and not lan_ip.startswith("127."):
            print(f"  Mobile / LAN API URL: http://{lan_ip}:{port}", flush=True)
    except OSError:
        pass
    device_poll_sec = max(5, min(20, int(mon.config.get("devicePollIntervalSec") or 15)))
    print(
        "  LAN discovery: live ARP/infra sync every 45s + full LAN sweep every 5m",
        flush=True,
    )
    print(f"  Monitored device probes: TCP/ICMP every {device_poll_sec} seconds", flush=True)
    print("=======================================================", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Pulse Network Monitor...", flush=True)
    finally:
        mon.stop()
        server.server_close()

