import os
import threading
import unittest
import urllib.parse
from unittest.mock import Mock, patch

import django
from django.test import Client


class DjangoDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pulse_monitor.django_settings")
        django.setup()

    def setUp(self):
        self.client = Client(HTTP_HOST="localhost:3000")
        self.monitor = Mock()
        self.monitor.lock = threading.Lock()
        self.monitor.event_subscribers = set()
        self.monitor.snapshot.return_value = {"online": True}
        active = patch("pulse_monitor.http_handler._active_monitor", return_value=self.monitor)
        active.start()
        self.addCleanup(active.stop)

    def test_dashboard_api_and_write_guards(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/api/status").json(), {"online": True})
        self.assertEqual(self.client.get("/api/unknown").status_code, 404)
        self.assertEqual(self.client.patch("/api/status").status_code, 405)
        self.assertEqual(self.client.post("/api/gaming/android", "{}", content_type="application/json",
                                         HTTP_ORIGIN="https://other.example").status_code, 403)
        self.assertEqual(self.client.post("/api/gaming/android", "{}", content_type="application/json",
                                         REMOTE_ADDR="192.168.0.7").status_code, 403)
        self.assertEqual(self.client.post("/api/gaming/android", "{", content_type="application/json").status_code, 400)

    def test_stream_releases_subscriber_on_disconnect(self):
        for read_snapshot in (False, True):
            response = self.client.get("/api/events")
            self.assertTrue(response.streaming)
            self.assertEqual(len(self.monitor.event_subscribers), 1)
            if read_snapshot:
                self.assertEqual(next(iter(response.streaming_content)), b'event: snapshot\ndata: {"online":true}\n\n')
            response.close()
            self.assertFalse(self.monitor.event_subscribers)

    def test_named_routes_take_precedence_over_device_ids(self):
        for path, allow in (
            ("/api/devices/history", "GET"),
            ("/api/devices/connection/", "GET, POST"),
            ("/api/devices/probe-all", "POST"),
        ):
            with self.subTest(path=path):
                response = self.client.delete(path)
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response.headers["Allow"], allow)
        self.monitor.delete_device.assert_not_called()
        self.assertEqual(self.client.post("/api/typo", "invalid", content_type="application/json").status_code, 404)

    def test_device_resource_keys_and_trailing_slashes(self):
        self.monitor.update_device.return_value = {"ok": True}
        for segment, expected in (("node%2Fprobe", "node/probe"), ("name%252Fid", "name%2Fid")):
            path = "/api/devices/" + segment + "/"
            response = self.client.put(path, "{}", content_type="application/json", RAW_URI=path)
            self.assertEqual(response.status_code, 200)
            self.monitor.update_device.assert_called_with(expected, {})
        self.assertEqual(self.client.put("/api/devices/unexpected/path").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/health/").status_code, 200)

    def test_workspace_bookmarks_and_form_return_location(self):
        for workspace in ("gaming", "internet", "router", "topology"):
            response = self.client.get(f"/{workspace}/")
            expected = "internet" if workspace == "router" else workspace
            self.assertEqual(response.headers["Location"], f"/#{expected}")
        for destination, expected in (("/devices?filter=down", "/devices?filter=down&"), ("/api/status", "/?")):
            response = self.client.post("/actions/favorite/",
                                        "asset_key=item&return_to=" + urllib.parse.quote(destination, safe=""),
                                        content_type="application/x-www-form-urlencoded")
            self.assertEqual(response.status_code, 303)
            self.assertTrue(response.headers["Location"].startswith(expected))


if __name__ == "__main__":
    from pathlib import Path

    # Discovery adds the repository root to the import path, including on a direct file run.
    tests_dir = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(
        str(tests_dir), pattern="test_django_http.py", top_level_dir=str(tests_dir.parent)
    )
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
