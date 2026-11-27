import time
from unittest.mock import patch
import monitor as monitor_module
from tests.support import MonitorTestCase


class NetworkHealthTests(MonitorTestCase):
    def test_alerts_group_only_confirmed_current_upstream_outages(self):
        router = self.monitor.add_device({"name": "Test router", "ip": "192.168.60.1", "type": "router"})
        switch = self.monitor.add_device({"name": "Test switch", "ip": "192.168.60.2", "type": "switch"})
        client = self.monitor.add_device({"name": "Test client", "ip": "192.168.60.3", "type": "device"})
        self.monitor.set_device_upstream(switch["id"], router["id"])
        self.monitor.set_device_upstream(client["id"], switch["id"])
        with self.assertRaisesRegex(ValueError, "form a loop"):
            self.monitor.set_device_upstream(router["id"], switch["id"])
        self.assertEqual(monitor_module.Monitor().get_device_history(client["id"], "")["upstreamDeviceId"], switch["id"])

        def set_probe(device, state):
            result = {
                **device, "alive": state != "DEVICE_DOWN", "connectivityState": state,
                "lastChecked": monitor_module.utc_now(),
            }
            self.monitor.latest_devices[device["ip"]] = result
            self.monitor._evaluate_device(result)

        def upstream_ip(device):
            incident = next(item for item in self.monitor.get_active_alerts() if item["ip"] == device["ip"]).get("upstreamIncident")
            return incident["ip"] if incident is not None else None

        for device in (router, switch, client):
            set_probe(device, "DEVICE_DOWN")
        self.assertEqual(upstream_ip(client), router["ip"])
        self.assertEqual(upstream_ip(switch), router["ip"])
        incident = self.monitor.get_incident(f"dev-{router['ip']}")
        self.assertEqual(incident["deviceId"], router["id"])
        self.assertEqual({alert["ip"] for alert in incident["affected"]}, {switch["ip"], client["ip"]})
        set_probe(router, "ONLINE_WITH_INTERNET")
        self.assertEqual(upstream_ip(client), switch["ip"])
        self.assertIsNone(upstream_ip(switch))
        outage = self.monitor.active_alerts[f"dev-{client['ip']}"]
        first_seen = outage["firstSeen"]
        outage["firstSeen"] = "2000-01-01T12:00:00Z"
        self.assertIsNone(upstream_ip(client))
        outage["firstSeen"] = first_seen
        set_probe(switch, "ARP_OBSERVED")
        self.assertIsNone(upstream_ip(client))
        self.assertEqual(len(self.monitor.get_active_alerts()), 2)

    def test_maintenance_keeps_incident_data_and_deduplicates_notifications(self):
        from datetime import datetime, timedelta, timezone

        device = self.monitor.add_device({"name": "Office switch", "ip": "192.168.50.3"})
        ip = device["ip"]
        alert = self.monitor._make_alert(f"dev-{ip}", "WARNING", "Switch no reply", "TCP and ICMP timed out", ip)
        now = datetime.now(timezone.utc)
        alert["firstSeen"] = (now - timedelta(seconds=90)).isoformat()
        self.monitor.active_alerts[alert["key"]] = alert
        window = self.monitor.create_maintenance({
            "deviceId": device["id"], "reason": "Patch",
            "startsAt": (now - timedelta(minutes=1)).isoformat(),
            "endsAt": (now + timedelta(minutes=15)).isoformat(),
        })
        self.monitor._collect_incident_notifications()
        self.assertEqual(self.monitor.get_operations()["notifications"], [])
        self.assertEqual(len(self.monitor.get_active_alerts()), 1)
        self.monitor.cancel_maintenance(window["id"])
        with patch.object(self.monitor, "_alert_email_enabled", return_value=True):
            self.monitor._collect_incident_notifications()
            self.monitor._collect_incident_notifications()
            with patch.object(self.monitor, "_send_incident_email") as send:
                self.monitor._deliver_incident_notifications()
                self.monitor._deliver_incident_notifications()
                send.assert_called_once()
            self.monitor.active_alerts.clear()
            self.monitor.save_alert({**alert, "status": "RESOLVED"})
            self.monitor._collect_incident_notifications()
            self.monitor._collect_incident_notifications()
        notices = self.monitor.get_operations()["notifications"]
        self.assertEqual({(row["kind"], row["delivery"]) for row in notices}, {("outage", "sent"), ("recovered", "pending")})
        self.assertEqual(len(notices), 2)

    def test_device_outage_is_deduplicated_and_recovery_is_persisted(self):
        device = {
            "id": "test-ap", "name": "Test AP", "ip": "192.168.10.40",
            "port": 80, "critical": True, "mac": "",
        }
        offline = {
            **device, "alive": False, "status": "offline", "packetLossPct": 100,
            "avgLatencyMs": None, "jitterMs": 0, "lastChecked": "2026-01-01T00:00:00Z",
        }
        self.monitor._evaluate_device(offline)
        self.monitor._evaluate_device(offline)
        self.assertEqual(len(self.monitor.get_active_alerts()), 1)

        online = {
            **device, "alive": True, "status": "online", "packetLossPct": 0,
            "avgLatencyMs": 4, "jitterMs": 0, "lastChecked": "2026-01-01T00:00:10Z",
        }
        self.monitor._evaluate_device(online)
        self.assertEqual(self.monitor.get_active_alerts(), [])
        self.assertEqual(self.monitor.get_alerts(1)[0]["severity"], "RESOLVED")

    def test_latency_alert_clears_after_probe_recovers(self):
        device = {
            "id": "test-ap", "name": "Test AP", "ip": "192.168.10.41",
            "port": 80, "critical": False, "mac": "",
        }
        slow = {
            **device, "alive": True, "status": "warning", "packetLossPct": 10,
            "avgLatencyMs": 130, "jitterMs": 20, "lastChecked": "2026-01-01T00:00:00Z",
        }
        self.monitor._evaluate_device(slow)
        self.assertEqual(self.monitor.get_active_alerts()[0]["type"], "HIGH_LATENCY_PACKET_LOSS")
        self.monitor._evaluate_device({**slow, "avgLatencyMs": 92.3, "packetLossPct": 0})
        self.assertIn("92.3 ms", self.monitor.get_active_alerts()[0]["message"])
        self.assertIn("0% probe loss", self.monitor.get_active_alerts()[0]["message"])

        recovered = {
            **device, "alive": True, "status": "online", "packetLossPct": 0,
            "avgLatencyMs": 4, "jitterMs": 1, "lastChecked": "2026-01-01T00:00:10Z",
        }
        self.monitor._evaluate_device(recovered)
        self.assertEqual(self.monitor.get_active_alerts(), [])
        self.assertEqual(self.monitor.get_alerts(1)[0]["severity"], "RESOLVED")

    def test_full_diagnostics_reports_slow_devices_and_unavailable_ports(self):
        router = self.monitor._initial_router_state()
        router["reachable"] = True
        router["ports"][0].update(status="optimal", linkStatus="connected", simulation=True)
        samples = [
            {"name": "Slow AP", "ip": "192.168.0.20", "alive": True,
             "connectivityState": "DEGRADED_LINK", "avgLatencyMs": 125, "packetLossPct": 0},
            {"name": "Retired AP", "ip": "192.168.0.21", "alive": False, "critical": True, "archived": True},
        ]
        with (
            patch.object(self.monitor, "probe_all_devices", return_value=samples),
            patch.object(self.monitor, "probe_router", return_value=router),
            patch.object(self.monitor, "probe_isp", return_value={**self.monitor.isp_state, "overallHealth": "GOOD"}),
        ):
            report = self.monitor.run_diagnostics()
        self.assertEqual(report["overallVerdict"], "DEGRADED")
        self.assertEqual(report["metrics"]["devicesDegraded"], 1)
        self.assertEqual(report["metrics"]["portsVerified"], 0)
        self.assertTrue(any("125 ms" in finding["detail"] for finding in report["findings"]))
        self.assertFalse(any("Retired AP" in finding["title"] for finding in report["findings"]))

    def test_alerts_distinguish_arp_only_and_archived_devices(self):
        device = self.monitor.add_device({
            "name": "Maintenance AP", "ip": "192.168.25.89", "type": "ap", "critical": True,
        })
        self.monitor._evaluate_device({**device, "alive": False})
        self.assertEqual(self.monitor.get_active_alerts()[0]["severity"], "CRITICAL")
        self.monitor._evaluate_device({**device, "alive": True, "connectivityState": "ARP_OBSERVED"})
        alert = self.monitor.get_active_alerts()[0]
        self.assertTrue(alert["verificationUnavailable"])
        self.assertEqual(alert["severity"], "WARNING")
        self.assertIn("ARP entry", alert["message"])
        self.monitor._evaluate_device({**device, "alive": False})
        self.assertEqual(self.monitor.get_active_alerts()[0]["severity"], "CRITICAL")
        self.monitor.toggle_archive(f"ip:{device['ip']}")
        self.assertEqual(self.monitor.get_active_alerts(), [])
        self.assertTrue(self.monitor.get_alerts())

    def test_unknown_router_ports_do_not_raise_false_alerts(self):
        state = self.monitor._initial_router_state()
        self.monitor.evaluate_router_ports(state)
        self.assertEqual(self.monitor.get_active_alerts(), [])

        state["ports"][2].update({
            "speed": 100, "speedText": "100 Mbps", "duplex": "Half Duplex",
            "linkStatus": "connected", "status": "warning",
        })
        self.monitor.evaluate_router_ports(state)
        self.assertEqual(self.monitor.get_active_alerts()[0]["type"], "DUPLEX_MISMATCH")

        state["ports"][2].update({
            "speed": 1000, "speedText": "1000 Mbps", "duplex": "Full Duplex",
            "linkStatus": "connected", "status": "optimal",
        })
        self.monitor.evaluate_router_ports(state)
        self.assertEqual(self.monitor.get_active_alerts(), [])

    def test_wan_outage_flag_and_good_isp_diagnostics(self):
        self.monitor.isp_state["overallHealth"] = "OUTAGE"
        self.assertFalse(self.monitor._is_wan_internet_up())

        self.monitor.config["router"]["ip"] = "192.168.55.1"
        probed_hosts = []

        def fake_sock(host, port, timeout=1.2):
            probed_hosts.append((host, port))
            return True, True, 12.0

        with patch.object(self.monitor, "_probe_tcp_socket", side_effect=fake_sock), patch.object(
            self.monitor, "_probe_icmp", return_value=(False, None)
        ):
            isp_res = self.monitor.probe_isp()
        self.assertIn(("192.168.55.1", 80), probed_hosts)
        gw_probe = next(p for p in isp_res["probes"] if p["id"] == "gateway")
        self.assertEqual(gw_probe["ip"], "192.168.55.1")

        # Verify real ICMP echo latency takes priority for genuine internet ping when ICMP replies
        with patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 45.0)), patch.object(
            self.monitor, "_probe_icmp", return_value=(True, 18.2)
        ):
            icmp_isp = self.monitor.probe_isp()
        cf_probe = next(p for p in icmp_isp["probes"] if p["id"] == "cloudflare")
        self.assertEqual(cf_probe["latencyMs"], 18.2)
        self.assertEqual(cf_probe["method"], "ICMP Echo")

        good_isp = {**isp_res, "overallHealth": "GOOD", "healthScore": 85, "dnsResolutionMs": 20.0}
        with patch.object(
            self.monitor,
            "probe_device",
            side_effect=lambda d: {**d, "alive": True, "status": "online"},
        ), patch.object(
            self.monitor,
            "probe_router",
            return_value={**self.monitor.router_state, "reachable": True, "ip": "192.168.55.1"},
        ), patch.object(self.monitor, "probe_isp", return_value=good_isp):
            diag = self.monitor.run_diagnostics()
        self.assertEqual(diag["overallVerdict"], "HEALTHY")

    def test_saved_bandwidth_benchmark_does_not_degrade_current_probe_diagnosis(self):
        benchmark = {"timestamp": "2026-01-01T12:00:00Z", "downloadMbps": 30.9, "uploadMbps": 26.3}
        self.monitor.isp_state["lastSpeedTest"] = benchmark
        with (
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 12.0)),
            patch.object(self.monitor, "_probe_icmp", return_value=(True, 12.0)),
            patch("pulse_monitor.probes.socket.getaddrinfo", return_value=[]),
        ):
            isp = self.monitor.probe_isp()
        self.assertEqual(isp["lastSpeedTest"], benchmark)
        self.assertEqual(isp["diagnosis"]["verdict"], "OPTIMAL")
        self.assertIn("reachability", isp["diagnosis"]["headline"])
        self.assertNotIn("Mbps", isp["diagnosis"]["summary"])

    def test_ping_uptime_persists_in_sqlite_and_mobile_summary_returns_contract(self) -> None:
        with patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 8.5)):
            isp_res = self.monitor.probe_isp()
        self.assertEqual(isp_res["pingGraph"]["stats"]["cloudflare"]["samples24h"], 1)
        self.assertEqual(isp_res["pingGraph"]["stats"]["cloudflare"]["uptime24hPct"], 100.0)

        reloaded = monitor_module.Monitor()
        self.assertEqual(
            len(reloaded.get_isp_state()["pingGraph"]["stats"]["cloudflare"]["heartbeats"]),
            1,
        )

        summary = reloaded.get_mobile_summary()
        self.assertEqual(summary["apiVersion"], monitor_module.API_VERSION)
        self.assertIn("health", summary)
        self.assertIn("counts", summary)
        self.assertIn("isp", summary)

    def test_ping_uptime_stays_unknown_outside_the_sample_window(self) -> None:
        fresh = self.monitor.get_isp_state()["pingGraph"]["stats"]["cloudflare"]
        self.assertIsNone(fresh["uptime24hPct"])
        self.assertIsNone(fresh["uptime30dPct"])
        yesterday = time.time() - 2 * 86400
        self.monitor._record_ping_sample("cloudflare", True, 15, timestamp=yesterday)
        self.monitor._record_ping_sample("cloudflare", False, None, timestamp=yesterday + 1)

        stats = monitor_module.Monitor().get_isp_state()["pingGraph"]["stats"]["cloudflare"]
        self.assertIsNone(stats["uptime24hPct"])
        self.assertEqual(stats["samples24h"], 0)
        self.assertEqual(stats["uptime30dPct"], 50.0)
        self.assertIsNone(stats["currentMs"])
        self.assertEqual(stats["lossPct"], 100)

    def test_isp_reports_degraded_when_only_one_external_target_responds(self) -> None:
        def tcp_probe(host, _port, _timeout):
            if host == "1.1.1.1":
                return True, True, 20.0
            return False, True, 2.0

        with (
            patch.object(self.monitor, "_probe_icmp", return_value=(False, None)),
            patch.object(self.monitor, "_probe_tcp_socket", side_effect=tcp_probe),
            patch("pulse_monitor.probes.socket.getaddrinfo", return_value=[]),
        ):
            first = self.monitor.probe_isp()
            self.assertIsNone(first["jitterMs"])
            self.assertEqual(first["overallHealth"], "DEGRADED")
            self.assertTrue(self.monitor._is_wan_internet_up())
            self.assertNotIn("isp-wan", self.monitor.active_alerts)
            self.assertEqual(sum(p["alive"] for p in first["probes"] if p["id"] != "gateway"), 1)
            self.assertEqual(self.monitor.probe_isp()["jitterMs"], 0.0)

    def test_alerts_track_consecutive_failures_and_isp_outages(self) -> None:
        dev = {
            "id": "test-sw", "name": "Test Switch", "ip": "192.168.10.44",
            "port": 80, "critical": True, "mac": "",
        }
        offline = {
            **dev, "alive": False, "status": "offline", "packetLossPct": 100,
            "avgLatencyMs": None, "jitterMs": 0, "lastChecked": "2026-01-01T00:00:00Z",
        }
        self.monitor._evaluate_device(offline)
        self.monitor._evaluate_device(offline)
        alert = self.monitor.active_alerts["dev-192.168.10.44"]
        self.assertEqual(alert["consecutiveFailures"], 2)

        with patch.object(self.monitor, "_probe_tcp_socket", return_value=(False, False, None)), patch.object(
            self.monitor, "_probe_icmp", return_value=(False, None)
        ):
            self.monitor.probe_isp()
        self.assertIn("isp-wan", self.monitor.active_alerts)
        self.assertEqual(self.monitor.active_alerts["isp-wan"]["category"], "isp")
        event_types = [e["eventType"] for e in self.monitor.get_events(50)]
        self.assertIn("ISP_OUTAGE", event_types)

        with patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 9.0)):
            self.monitor.probe_isp()
        self.assertNotIn("isp-wan", self.monitor.active_alerts)
        self.assertEqual(self.monitor.get_alert_stats()["resolvedCount"], 1)
        event_types = [e["eventType"] for e in self.monitor.get_events(50)]
        self.assertIn("WAN_RESTORED", event_types)

        # Router online/offline transitions log to network_events
        r_down = self.monitor._initial_router_state()
        r_down["reachable"] = False
        self.monitor.evaluate_router_ports(r_down)
        r_up = self.monitor._initial_router_state()
        r_up["reachable"] = True
        self.monitor.evaluate_router_ports(r_up)
        event_types = [e["eventType"] for e in self.monitor.get_events(50)]
        self.assertIn("ROUTER_OFFLINE", event_types)
        self.assertIn("ROUTER_ONLINE", event_types)

        # Device add / remove log to network_events
        added = self.monitor.add_device({"name": "Branch Switch", "ip": "192.168.10.45"})
        self.assertTrue(self.monitor.delete_device(added["id"]))
        event_types = [e["eventType"] for e in self.monitor.get_events(50)]
        self.assertIn("DEVICE_ADDED", event_types)
        self.assertIn("DEVICE_REMOVED", event_types)

        snap = self.monitor.snapshot()
        self.assertTrue(len(snap["networkEvents"]) >= 5)
        cleared_ev = self.monitor.clear_events()
        self.assertTrue(cleared_ev["success"])
        self.assertEqual(self.monitor.get_events(20), [])

    @patch.dict("os.environ", {})
    def test_manual_speed_test_runs_by_default_without_starting_a_schedule(self):
        import os

        os.environ.pop("PULSE_ALLOW_SPEED_TESTS", None)
        self.monitor.config["isp"]["speedTestIntervalMinutes"] = 5
        self.assertTrue(self.monitor.get_isp_state()["speedTestsEnabled"])
        self.assertEqual(self.monitor._speedtest_interval_sec(), 0)
        self.monitor.isp_state["provider"] = {"provider": "Test ISP"}
        with (
            patch.object(self.monitor, "_measure_latency", return_value=(12.0, 2.0)),
            patch.object(self.monitor, "_run_transfer_phase", side_effect=[30.0, 20.0]),
        ):
            result = self.monitor.run_speedtest()
        self.assertEqual(result["downloadMbps"], 30.0)
        self.assertEqual(result["uploadMbps"], 20.0)
        self.assertEqual(result["provider"], "Test ISP")
        self.assertEqual(self.monitor.get_isp_state()["lastSpeedTest"], result)
        with patch.dict(os.environ, {"PULSE_ALLOW_SPEED_TESTS": "1"}):
            self.assertEqual(self.monitor._speedtest_interval_sec(), 300)

    def test_speed_test_failure_preserves_last_complete_result(self):
        previous = {"timestamp": "2026-01-02T00:00:00Z", "downloadMbps": 30.0, "uploadMbps": 20.0}
        self.monitor.isp_state["lastSpeedTest"] = previous
        with patch.object(self.monitor, "_measure_latency", side_effect=PermissionError("socket denied")):
            with self.assertRaisesRegex(RuntimeError, "Latency test blocked.*speed.cloudflare.com"):
                self.monitor.run_speedtest()
        state = self.monitor.get_isp_state()
        self.assertEqual(state["lastSpeedTest"], previous)
        self.assertFalse(state["speedTestRunning"])
        self.assertIn("Allow outbound HTTPS", state["speedTestError"])
