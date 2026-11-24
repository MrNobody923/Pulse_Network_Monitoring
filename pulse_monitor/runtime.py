"""Start and stop the Django listener and the monitor workers as one service."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, cast

from django.core.servers.basehttp import ThreadedWSGIServer, WSGIRequestHandler
from django.core.wsgi import get_wsgi_application

if TYPE_CHECKING:
    from .engine import Monitor


PORT = int(os.environ.get("PORT", "3000"))


def _active_monitor() -> Monitor:
    """Return the active monitor instance (supports unittest.mock.patch on `server.monitor`)."""
    srv_mod = sys.modules.get("server")
    if srv_mod is not None and hasattr(srv_mod, "monitor"):
        return cast("Monitor", srv_mod.monitor)
    from . import monitor as default_monitor

    return default_monitor


class DashboardServer(ThreadedWSGIServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs) -> None:
        self._request_slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple) -> None:
        _, exc, _ = sys.exc_info()
        if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout)):
            return
        super().handle_error(request, client_address)


class DashboardTransport(WSGIRequestHandler):
    timeout = 15

    def get_environ(self):
        environ = super().get_environ()
        # Some inventory and alert keys contain escaped path separators.
        environ["RAW_URI"] = self.path
        return environ


def run_server(port: int = PORT) -> None:
    mon = _active_monitor()
    bind_host = os.environ.get("PULSE_BIND_HOST", "127.0.0.1")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pulse_monitor.django_settings")
    application = get_wsgi_application()
    server = DashboardServer((bind_host, port), DashboardTransport)
    server.set_app(application)
    port = server.server_port
    sensor = None
    sensor_thread = None

    def _open_browser() -> None:
        time.sleep(1.0)
        try:
            import webbrowser
            if os.environ.get("PULSE_NO_BROWSER") != "1" and not os.path.exists("/.dockerenv"):
                webbrowser.open(f"http://localhost:{port}")
        except Exception:
            pass

    print("=======================================================", flush=True)
    print("  VERTEX SENTRY", flush=True)
    print(f"  Local Web Dashboard: http://localhost:{port}", flush=True)
    print(f"  HTTP listener: {bind_host}:{port}", flush=True)
    device_poll_sec = max(5, min(20, int(mon.config.get("devicePollIntervalSec") or 15)))
    scan_status = "enabled" if os.environ.get("PULSE_ENABLE_BACKGROUND_SCANS") == "1" else "off"
    print(f"  Background LAN sweeps: {scan_status}", flush=True)
    print(f"  Monitored device probes: core every {device_poll_sec}s, AP/server every 30s, clients every 60s", flush=True)
    print("=======================================================", flush=True)
    try:
        mon.start()
        if sys.platform == "win32" and os.environ.get("PULSE_HOST_GAME_SENSOR") != "0":
            from host_game_sensor import HostGameSensor

            api_host = "127.0.0.1" if bind_host in {"", "0.0.0.0"} else bind_host
            sensor = HostGameSensor(
                upstream_dns=mon.config.get("router", {}).get("ip") or "192.168.0.1",
                api_url=f"http://{api_host}:{port}/api/gaming/detect",
                detect_processes=False,
            )
            sensor_thread = threading.Thread(target=sensor.serve_forever, daemon=True, name="host-game-sensor")
            sensor_thread.start()
        threading.Thread(target=_open_browser, daemon=True, name="browser-opener").start()
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Vertex Sentry...", flush=True)
    finally:
        if sensor is not None:
            sensor.stop()
        if sensor_thread is not None:
            sensor_thread.join(timeout=3.0)
        mon.stop()
        server.server_close()

