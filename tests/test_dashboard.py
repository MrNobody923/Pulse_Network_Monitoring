import unittest
from django.http.request import HttpHeaders
from unittest.mock import Mock
from pulse_monitor.http_handler import RequestHandler


class DashboardRequestTests(unittest.TestCase):
    def test_game_device_controls_require_loopback_peer_and_host(self):
        handler = RequestHandler.__new__(RequestHandler)
        handler._send_error_json = Mock()
        handler.client_address = ("127.0.0.1",)
        handler.headers = HttpHeaders({"HTTP_HOST": "localhost:3000"})
        self.assertTrue(handler._allow_local_dashboard())
        handler.headers = HttpHeaders({"HTTP_HOST": "external.example:3000"})
        self.assertFalse(handler._allow_local_dashboard())
        handler.client_address = ("192.168.1.20",)
        handler.headers = HttpHeaders({"HTTP_HOST": "localhost:3000"})
        self.assertFalse(handler._allow_local_dashboard())

    def test_inventory_filters_and_scan_mode_follow_snapshot(self):
        from pulse_monitor.views import render_page

        monitor = Mock()
        snapshot = {
            "devices": [
                {"ip": "192.0.2.1", "name": "Waiting probe", "status": "unknown"},
                {"ip": "192.0.2.2", "name": "Down probe", "status": "offline"},
                {"ip": "192.0.2.3", "name": "Slow probe", "status": "warning"},
            ],
            "networkInventory": [], "config": {"backgroundScansEnabled": False},
        }
        monitor.snapshot.return_value = snapshot
        page = render_page(monitor, "/devices", filter_by="offline")
        self.assertIn("Down probe", page)
        self.assertNotIn("Waiting probe", page)
        self.assertIn("Offline (1)", page)
        self.assertIn("LAN discovery: On demand", page)
        snapshot["config"]["backgroundScansEnabled"] = True
        page = render_page(monitor, "/devices")
        self.assertIn("LAN discovery: Daily", page)
        self.assertIn('class="pill warning">DEGRADED', page)

    def test_dashboard_writes_accept_only_same_origin_browser_requests(self):
        handler = RequestHandler.__new__(RequestHandler)
        handler._send_error_json = Mock()
        handler.headers = HttpHeaders({"HTTP_HOST": "monitor.example:3000"})
        self.assertTrue(handler._allow_write_request())
        handler.headers = HttpHeaders({"HTTP_HOST": "monitor.example:3000", "HTTP_ORIGIN": "http://monitor.example:3000"})
        self.assertTrue(handler._allow_write_request())
        handler.headers = HttpHeaders({"HTTP_HOST": "monitor.example:3000", "HTTP_ORIGIN": "http://other.example:3000"})
        self.assertFalse(handler._allow_write_request())
        handler._send_error_json.assert_called_once_with("Cross-origin writes are forbidden", 403)

    def test_fallback_device_rows_keep_the_saved_favourite_key(self):
        from pulse_monitor.views import dashboard_rows, render_table

        ip = "192.168.0.20"
        mac = "02:aa:bb:cc:dd:ee"
        rows = dashboard_rows({
            "devices": [{"name": "Office AP", "ip": ip, "status": "unknown", "alive": True, "directlyReachable": False}],
            "networkInventory": [{"ip": ip, "mac": mac, "favorite": True, "favoriteKey": f"ip:{ip}"}],
        })
        self.assertFalse(rows[0]["online"])
        self.assertIn(f'action="/actions/favorite"><input type="hidden" name="asset_key" value="ip:{ip}"', render_table(rows))
        self.assertIn(f'action="/actions/archive"><input type="hidden" name="asset_key" value="mac:{mac}"', render_table(rows))
