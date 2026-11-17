import json
import ipaddress
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import monitor as monitor_module


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        data_dir = Path(self.temp_dir.name)
        self.patches = [
            patch.object(monitor_module, "DATA_DIR", data_dir),
            patch.object(monitor_module, "CONFIG_FILE", data_dir / "config.json"),
            patch.object(monitor_module, "DATABASE_FILE", data_dir / "network.db"),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(self.temp_dir.cleanup)
        self.addCleanup(self._stop_patches)
        self.monitor = monitor_module.Monitor()

    def _stop_patches(self):
        for item in reversed(self.patches):
            item.stop()

    @staticmethod
    def discovered_device(ip="192.168.10.20"):
        return {
            "ip": ip,
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": "Unknown vendor",
            "suggestedName": f"Unknown vendor ({ip})",
            "arpType": "dynamic",
        }

    def test_inventory_remembers_first_seen_and_flags_unreviewed_assets(self):
        item = self.discovered_device()
        self.monitor._upsert_inventory(item)
        first = self.monitor.get_inventory()[0]
        self.assertFalse(first["authorized"])

        self.monitor._upsert_inventory(item)
        second = self.monitor.get_inventory()[0]
        self.assertEqual(second["firstSeen"], first["firstSeen"])
        self.assertEqual(len(self.monitor.get_events()), 1)
        self.assertEqual(self.monitor.get_events()[0]["eventType"], "NEW_DEVICE")

    def test_ip_change_is_recorded_and_mac_remains_the_asset_identity(self):
        self.monitor._upsert_inventory(self.discovered_device())
        self.monitor._upsert_inventory(self.discovered_device("192.168.10.21"))

        inventory = self.monitor.get_inventory()
        events = self.monitor.get_events()
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["ip"], "192.168.10.21")
        self.assertEqual(inventory[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(events[0]["eventType"], "IP_CHANGED")

    def test_authorization_persists(self):
        self.monitor._upsert_inventory(self.discovered_device())
        self.assertTrue(self.monitor.authorize_device("AA-BB-CC-DD-EE-FF"))
        self.assertTrue(self.monitor.get_inventory()[0]["authorized"])

    def test_favourite_persists_and_can_be_removed(self):
        self.monitor._upsert_inventory(self.discovered_device())
        key = "mac:aa:bb:cc:dd:ee:ff"
        self.assertTrue(self.monitor.toggle_favorite(key))
        self.assertTrue(self.monitor.get_inventory()[0]["favorite"])
        reloaded = monitor_module.Monitor()
        self.assertTrue(reloaded.get_inventory()[0]["favorite"])
        self.assertFalse(reloaded.toggle_favorite(key))
        self.assertFalse(self.monitor.get_inventory()[0]["favorite"])

    def test_archive_persists_and_can_be_restored(self):
        self.monitor._upsert_inventory(self.discovered_device())
        key = "mac:aa:bb:cc:dd:ee:ff"
        self.assertTrue(self.monitor.toggle_archive(key))
        self.assertTrue(self.monitor.get_inventory()[0]["archived"])

        reloaded = monitor_module.Monitor()
        self.assertTrue(reloaded.get_inventory()[0]["archived"])
        self.assertFalse(reloaded.toggle_archive(key))
        self.assertFalse(self.monitor.get_inventory()[0]["archived"])

    def test_monitored_device_can_be_archived_by_ip(self):
        device = self.monitor.add_device({
            "name": "Office AP", "ip": "192.168.10.31",
        })
        self.assertTrue(self.monitor.toggle_archive(f"ip:{device['ip']}"))
        self.assertTrue(self.monitor.get_devices()[-1]["archived"])

    def test_daily_scan_timestamp_persists_and_controls_schedule(self):
        self.assertTrue(self.monitor._daily_discovery_due())
        with self.monitor._connect() as db:
            db.execute(
                "INSERT INTO monitor_metadata (key, value) VALUES ('last_discovery_at', ?)",
                (monitor_module.datetime.now().astimezone().isoformat(),),
            )
        self.assertFalse(self.monitor._daily_discovery_due())
        self.assertIsNotNone(self.monitor.last_discovery_at())

    def test_lan_network_discovery_filters_to_small_private_physical_subnets(self):
        output = json.dumps([
            {"ip": "192.168.10.8", "prefix": 24, "name": "Wi-Fi"},
            {"ip": "10.0.0.8", "prefix": 16, "name": "Ethernet"},
            {"ip": "172.20.1.4", "prefix": 24, "name": "VMware Network"},
            {"ip": "169.254.1.4", "prefix": 16, "name": "Ethernet"},
        ])
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch.object(monitor_module.os, "name", "nt"), patch.object(
            monitor_module.subprocess, "run", return_value=completed
        ):
            networks = self.monitor._local_lan_networks()
        self.assertEqual(networks, [ipaddress.ip_network("192.168.10.0/24")])

    def test_device_configuration_survives_restart_and_rejects_duplicate_ip(self):
        device = self.monitor.add_device({
            "name": "Office AP", "ip": "192.168.10.30", "port": 443,
        })
        self.assertEqual(device["port"], 443)
        with self.assertRaisesRegex(ValueError, "already uses"):
            self.monitor.add_device({"name": "Another AP", "ip": "192.168.10.30"})
        reloaded = monitor_module.Monitor()
        self.assertEqual(reloaded.get_devices()[-1]["name"], "Office AP")
        saved = json.loads((Path(self.temp_dir.name) / "config.json").read_text())
        self.assertEqual(saved["devices"][-1]["ip"], "192.168.10.30")

    def test_invalid_mac_and_ip_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "valid IP"):
            self.monitor.add_device({"name": "Bad", "ip": "not-an-ip"})
        with self.assertRaisesRegex(ValueError, "valid MAC"):
            self.monitor.authorize_device("not-a-mac")

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

        recovered = {
            **device, "alive": True, "status": "online", "packetLossPct": 0,
            "avgLatencyMs": 4, "jitterMs": 1, "lastChecked": "2026-01-01T00:00:10Z",
        }
        self.monitor._evaluate_device(recovered)
        self.assertEqual(self.monitor.get_active_alerts(), [])
        self.assertEqual(self.monitor.get_alerts(1)[0]["severity"], "RESOLVED")

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

    def test_topology_crud_cables_problem_correlation_and_pdu_ping(self) -> None:
        self.monitor._upsert_inventory(self.discovered_device("192.168.10.20"))
        with patch.object(
            self.monitor,
            "_probe_tcp_socket",
            side_effect=lambda ip, port, timeout=0.65: (
                (ip == "192.168.10.1"),
                (ip == "192.168.10.1"),
                2.5 if ip == "192.168.10.1" else None,
            ),
        ), patch.object(
            self.monitor,
            "_probe_icmp",
            side_effect=lambda ip, timeout_ms=800: (
                (ip == "192.168.10.1"),
                2.1 if ip == "192.168.10.1" else None,
            ),
        ):
            gw = self.monitor.add_topology_node({
                "name": "HQ Core Router",
                "ip": "192.168.10.1",
                "nodeType": "gateway",
            })
            sw = self.monitor.add_topology_node({
                "name": "Distribution Switch 1",
                "ip": "192.168.10.2",
                "nodeType": "switch",
                "connectToId": gw["node"]["id"],
                "cableType": "fiber",
            })
            ap = self.monitor.add_topology_node({
                "name": "Floor 2 AP",
                "ip": "192.168.10.30",
                "nodeType": "ap",
                "connectToId": sw["node"]["id"],
                "cableType": "copper",
            })

            topo = self.monitor.get_topology()
            self.assertEqual(topo["summary"]["totalNodes"], 3)
            self.assertEqual(topo["summary"]["totalLinks"], 2)
            self.assertEqual(topo["summary"]["online"], 1)
            self.assertEqual(topo["summary"]["down"], 2)
            self.assertEqual(topo["summary"]["problemCount"], 2)
            self.assertTrue(len(topo["logs"]) >= 3)

            # Packet Tracer PDU ping traces through Switch to AP and identifies downed intermediate Switch
            pdu = self.monitor.ping_topology_pdu(gw["node"]["id"], ap["node"]["id"])
            self.assertFalse(pdu["reachable"])
            self.assertEqual(pdu["failedAtNodeId"], sw["node"]["id"])
            self.assertEqual(len(pdu["pathNodeIds"]), 3)

            self.monitor.move_topology_node(ap["node"]["id"], {"x": 640, "y": 420})
            self.monitor.auto_layout_topology()
            link_id = topo["links"][0]["id"]
            self.monitor.delete_topology_link(link_id)
            self.monitor.delete_topology_node(ap["node"]["id"], delete_monitored=True)
            final_topo = self.monitor.get_topology()
            self.assertEqual(final_topo["summary"]["totalNodes"], 2)

            cleared = self.monitor.clear_topology()
            self.assertTrue(cleared["success"])
            self.assertEqual(cleared["removedNodes"], 2)
            self.assertEqual(cleared["topology"]["summary"]["totalNodes"], 0)
            self.assertEqual(cleared["topology"]["summary"]["totalLinks"], 0)

    def test_overview_and_lan_asset_cards_and_list_view_render(self):
        import server as server_module

        self.monitor._upsert_inventory(self.discovered_device("192.168.10.20"))
        with patch.object(server_module, "monitor", self.monitor):
            overview_html = server_module._render_page("/", "", "all")
            devices_html = server_module._render_page("/devices", "", "offline")

        for label in (
            "All devices",
            "Connected currently",
            "Favourites",
            "New devices",
            "Down",
            "Disconnected",
            "Archived devices",
            "Overall users &amp; devices",
            "Down devices",
            "Offline",
        ):
            self.assertIn(label, overview_html)
            self.assertIn(label, devices_html)
        self.assertIn("Device (List View)", overview_html)
        self.assertIn("192.168.10.20", overview_html)

    def test_port_scan_detects_open_and_at_risk_ports(self) -> None:
        def fake_probe_tcp(host: str, port: int, timeout: float = 0.65) -> tuple[bool, float | None]:
            if port in {23, 80, 443, 445}:
                return True, 3.2
            return False, None

        with patch.object(self.monitor, "_probe_tcp", side_effect=fake_probe_tcp), patch.object(
            self.monitor, "_grab_service_banner", return_value="TestBanner/1.0"
        ):
            report = self.monitor.run_port_scan(
                "127.0.0.1", profile="custom", custom_ports="22-23, 80, 443, 445"
            )

        self.assertEqual(report["counts"]["totalScanned"], 5)
        self.assertEqual(report["counts"]["open"], 4)
        self.assertEqual(report["counts"]["atRisk"], 3)
        self.assertEqual(report["counts"]["critical"], 2)  # 23 (Telnet) & 445 (SMB)
        open_port_nums = [p["port"] for p in report["openPorts"]]
        self.assertEqual(open_port_nums, [23, 80, 443, 445])
        self.assertIn("23/tcp", report["nmapTranscript"])

    def test_port_scan_nmap_xml_enrichment_and_service_risk_inference(self) -> None:
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -p 2323,445,8443,9999 -oX - 127.0.0.1" version="7.993">
  <host>
    <status state="up" reason="syn-ack"/>
    <os><osmatch name="Linux 5.15" accuracy="96"/></os>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.17.0"><cpe>cpe:/a:samba:samba:4.17.0</cpe></service>
      </port>
      <port protocol="tcp" portid="2323">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" product="BusyBox telnetd"/>
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open" reason="syn-ack"/>
        <service name="http" tunnel="ssl" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="filtered" reason="admin-prohibited"/>
        <service name="abyss"/>
      </port>
    </ports>
    <times srtt="1400"/>
  </host>
</nmaprun>"""

        def fake_probe_tcp(host: str, port: int, timeout: float = 0.65) -> tuple[bool, float | None]:
            if port in {445, 2323, 8443}:
                return True, 1.4
            return False, None

        mock_proc = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=sample_xml, stderr="")
        with patch.object(self.monitor, "_find_nmap_binary", return_value="nmap"), patch.object(
            self.monitor, "_probe_tcp", side_effect=fake_probe_tcp
        ), patch.object(
            self.monitor, "_grab_service_banner", return_value=""
        ), patch(
            "pulse_monitor.port_scanner.subprocess.run", return_value=mock_proc
        ):
            report = self.monitor.run_port_scan(
                "127.0.0.1", profile="custom", custom_ports="445, 2323, 8443, 9999"
            )

        by_port = {p["port"]: p for p in report["allPorts"]}
        self.assertEqual(report["nmapVersion"], "7.993")
        self.assertEqual(report["osGuess"], "Linux 5.15 (96%)")
        self.assertEqual(by_port[2323]["riskLevel"], "CRITICAL")
        self.assertTrue(by_port[2323]["atRisk"])
        self.assertIn("BusyBox telnetd", by_port[2323]["banner"])
        self.assertIn("Samba smbd 4.17.0", by_port[445]["banner"])
        self.assertEqual(by_port[445]["cpe"], "cpe:/a:samba:samba:4.17.0")
        self.assertEqual(by_port[9999]["state"], "filtered")
        self.assertEqual(report["counts"]["filtered"], 1)
        catalog = self.monitor.get_portscan_catalog()
        self.assertTrue(catalog["nmapAvailable"])
        self.assertEqual(len(catalog["history"]), 1)
        self.assertIn(report["reportId"], catalog["reports"])

        # Busy lock rejects overlapping scan cleanly
        lock = self.monitor._get_portscan_lock()
        lock.acquire()
        try:
            with self.assertRaises(RuntimeError):
                self.monitor.run_port_scan("127.0.0.1", profile="quick_audit")
        finally:
            lock.release()

    def test_sync_infrastructure_enrolls_discovered_aps_and_switches_and_diagnoses_downed_ap(self) -> None:
        self.monitor._upsert_inventory({
            "ip": "192.168.0.65",
            "mac": "00:16:96:ed:df:59",
            "vendor": "Cisco",
            "suggestedName": "Cisco (192.168.0.65)",
            "arpType": "dynamic",
        })
        self.monitor._upsert_inventory({
            "ip": "192.168.0.56",
            "mac": "68:7f:f0:1c:fe:6c",
            "vendor": "TP-Link",
            "suggestedName": "TP-Link (192.168.0.56)",
            "arpType": "dynamic",
        })
        self.monitor._upsert_inventory({
            "ip": "192.168.0.248",
            "mac": "4c:23:38:06:28:e7",
            "vendor": "TP-Link",
            "suggestedName": "TP-Link (192.168.0.248)",
            "arpType": "dynamic",
        })

        sync_res = self.monitor.sync_infrastructure_devices()
        self.assertEqual(sync_res["synced"], 3)
        monitored_ips = {d["ip"] for d in self.monitor.get_devices()}
        self.assertIn("192.168.0.65", monitored_ips)
        self.assertIn("192.168.0.56", monitored_ips)
        self.assertIn("192.168.0.248", monitored_ips)
        # Placeholder IPs not in discovered_devices are removed
        self.assertNotIn("192.168.0.10", monitored_ips)

        def fake_tcp_socket(host: str, port: int, timeout: float = 0.65):
            if host == "192.168.0.248":
                return False, False, None
            return (port == 80), True, 2.4

        def fake_icmp(host: str, timeout_ms: int = 800):
            if host == "192.168.0.248":
                return False, None
            return True, 1.8

        with patch.object(self.monitor, "_probe_tcp_socket", side_effect=fake_tcp_socket), patch.object(
            self.monitor, "_probe_icmp", side_effect=fake_icmp
        ):
            results = self.monitor.probe_all_devices()

        by_ip = {r["ip"]: r for r in results}
        down_ap = by_ip["192.168.0.248"]
        self.assertFalse(down_ap["alive"])
        self.assertEqual(down_ap["connectivityState"], "DEVICE_DOWN")
        self.assertIn("192.168.0.65", " ".join(down_ap["fixSteps"]))
        self.assertTrue(by_ip["192.168.0.56"]["alive"])
        self.assertEqual(by_ip["192.168.0.56"]["connectivityState"], "ONLINE_WITH_INTERNET")

    def test_slash22_does_not_misclassify_dot1_clients_and_cleans_dhcp_ip_change_alerts(self) -> None:
        # Simulate real /22 subnet detection (192.168.0.0/22 with single gateway 192.168.0.1)
        self.monitor._discovered_networks = [ipaddress.ip_network("192.168.0.0/22")]
        self.monitor._discovered_gateways = {"192.168.0.1"}

        self.monitor._upsert_inventory({
            "ip": "192.168.0.1",
            "mac": "68:7f:f0:1d:06:e0",
            "vendor": "TP-Link",
            "suggestedName": "Subnet Gateway (192.168.0.1)",
            "arpType": "dynamic",
        })
        # Client phone on .2.1 inside the /22 subnet must NOT become a Subnet Gateway Router
        self.monitor._upsert_inventory({
            "ip": "192.168.2.1",
            "mac": "36:eb:2b:ae:36:8f",
            "vendor": "Unknown vendor",
            "suggestedName": "Unknown vendor (192.168.2.1)",
            "arpType": "dynamic",
        })
        # Real TP-Link AP initially at 192.168.0.152
        self.monitor._upsert_inventory({
            "ip": "192.168.0.152",
            "mac": "4c:23:38:3b:20:55",
            "vendor": "TP-Link",
            "suggestedName": "TP-Link (192.168.0.152)",
            "arpType": "dynamic",
        })

        self.monitor.sync_infrastructure_devices()
        by_mac = {d.get("mac"): d for d in self.monitor.get_devices() if d.get("mac")}
        self.assertNotIn("36:eb:2b:ae:36:8f", by_mac)
        self.assertEqual(by_mac["4c:23:38:3b:20:55"]["subnet"], "192.168.0.0/22")

        # Raise an outage alert on the AP's old IP 192.168.0.152
        self.monitor._evaluate_device({
            **by_mac["4c:23:38:3b:20:55"],
            "alive": False,
            "status": "offline",
            "packetLossPct": 100,
            "avgLatencyMs": None,
            "jitterMs": 0,
            "lastChecked": "2026-01-01T00:00:00Z",
        })
        self.assertEqual(len(self.monitor.get_active_alerts()), 1)

        # AP changes DHCP IP to 192.168.1.18 -> name updates and stale old-IP alert clears
        self.monitor._upsert_inventory({
            "ip": "192.168.1.18",
            "mac": "4c:23:38:3b:20:55",
            "vendor": "TP-Link",
            "suggestedName": "TP-Link (192.168.1.18)",
            "arpType": "dynamic",
        })
        self.monitor.sync_infrastructure_devices()
        updated_ap = next(d for d in self.monitor.get_devices() if d.get("mac") == "4c:23:38:3b:20:55")
        self.assertEqual(updated_ap["ip"], "192.168.1.18")
        self.assertIn(".1.18", updated_ap["name"])
        self.assertEqual(self.monitor.get_active_alerts(), [])

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

    def test_multi_router_fleet_and_docker_env_subnet_discovery(self) -> None:
        # Verified client OUIs must NOT be misclassified as APs or switches
        self.assertEqual(self.monitor._vendor_for_oui("4c2338")[1], "client")
        self.assertEqual(self.monitor._vendor_for_oui("d0577e")[1], "client")
        self.assertEqual(self.monitor._vendor_for_oui("001696")[1], "client")
        self.assertEqual(self.monitor._vendor_for_oui("687ff0"), ("TP-Link", "router"))

        # Add secondary router to monitored devices + per-router config
        self.monitor.config["devices"] = [
            d for d in self.monitor.config["devices"] if d.get("ip") != "192.168.0.56"
        ]
        self.monitor.add_device({
            "name": "TP-Link BE3600 Router · .0.56",
            "ip": "192.168.0.56",
            "type": "router",
            "port": 80,
        })

        def fake_luci(host, port, scheme, path, timeout=2.0):
            if "locale?form=lang" in path:
                return {"success": True, "data": {"model": "BE3600 Dual-Band Wi-Fi 7 Router" if host == "192.168.0.1" else "AX3000 4-Stream Wi-Fi 6 Router"}}
            return None

        with patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 3.5)), patch.object(
            self.monitor, "_probe_icmp", return_value=(True, 2.2)
        ), patch.object(self.monitor, "_luci_post", side_effect=fake_luci), patch.object(
            self.monitor, "_snmp_get_oids", return_value={}
        ):
            fleet = self.monitor.probe_routers_fleet()

        ips = [r["ip"] for r in fleet]
        self.assertIn("192.168.0.1", ips)
        self.assertIn("192.168.0.56", ips)
        sec = next(r for r in fleet if r["ip"] == "192.168.0.56")
        self.assertEqual(sec["model"], "AX3000 4-Stream Wi-Fi 6 Router")
        self.assertTrue(sec["reachable"])
        self.assertIn("routers", self.monitor.snapshot())

        # Docker bridged container environment override resolves subnet cleanly on Linux
        with patch.object(monitor_module.os, "name", "posix"), patch.dict(
            monitor_module.os.environ,
            {"PULSE_LAN_SUBNETS": "192.168.0.0/22", "PULSE_ROUTER_IP": "192.168.0.1"},
            clear=False,
        ):
            nets = self.monitor._local_lan_networks()
        self.assertEqual(nets, [ipaddress.ip_network("192.168.0.0/22")])

    def test_automatic_game_detection_process_online_devices_and_expiry(self) -> None:
        self.monitor._skip_live_probe_in_test = True

        # Process signature matching for PC & emulator games
        roblox_sig = self.monitor._match_game_signature(process="RobloxPlayerBeta.exe")
        self.assertIsNotNone(roblox_sig)
        self.assertEqual(roblox_sig["id"], "roblox")
        val_sig = self.monitor._match_game_signature(process="valorant.exe")
        self.assertIsNotNone(val_sig)
        self.assertEqual(val_sig["id"], "valorant")

        # Online mobile + PC clients vs printer should populate onlineDevices automatically
        self.monitor._upsert_inventory({
            "ip": "192.168.0.1",
            "mac": "68:7f:f0:1d:06:e0",
            "vendor": "TP-Link",
            "suggestedName": "Main Gateway (192.168.0.1)",
            "arpType": "dynamic",
        })
        self.monitor._upsert_inventory({
            "ip": "192.168.1.77",
            "mac": "02:aa:bb:cc:dd:ee",
            "vendor": "Apple",
            "suggestedName": "iPhone-Staff (Apple)",
            "arpType": "dynamic",
        })
        self.monitor._upsert_inventory({
            "ip": "192.168.0.99",
            "mac": "00:11:22:33:44:55",
            "vendor": "Epson",
            "suggestedName": "Office Printer (Epson)",
            "arpType": "dynamic",
        })

        det = self.monitor.record_game_detection({
            "ip": "192.168.1.77",
            "domain": "mobilelegends.com",
            "detectionMethod": "Live DNS (192.168.0.224:53)",
        })
        self.assertTrue(det["success"])
        proc_det = self.monitor.record_game_detection({
            "ip": self.monitor.HOST_DNS_IP,
            "process": "RobloxPlayerBeta.exe",
            "detectionMethod": "Auto Process Sensor (Live Open Game)",
        })
        self.assertEqual(proc_det["detection"]["gameId"], "roblox")

        activity = self.monitor.get_game_activity(50)
        self.assertTrue(activity["autoScanActive"])
        online_by_ip = {d["ip"]: d for d in activity["onlineDevices"]}
        self.assertNotIn("192.168.0.1", online_by_ip)
        self.assertNotIn("192.168.0.99", online_by_ip)
        self.assertIn("192.168.1.77", online_by_ip)
        self.assertIn(self.monitor.HOST_DNS_IP, online_by_ip)
        self.assertTrue(online_by_ip["192.168.1.77"]["isMobile"])
        self.assertEqual(online_by_ip["192.168.1.77"]["activeGames"][0]["gameId"], "mlbb")
        self.assertEqual(online_by_ip[self.monitor.HOST_DNS_IP]["activeGames"][0]["gameId"], "roblox")

        # Ending a host game process immediately transitions the session out of active state
        self.monitor.mark_game_session_ended_by_ip_game(self.monitor.HOST_DNS_IP, "roblox")
        after_end = self.monitor.get_game_activity(50)
        host_dev = next(d for d in after_end["onlineDevices"] if d["ip"] == self.monitor.HOST_DNS_IP)
        self.assertEqual(host_dev["activeGames"], [])

        # Stale mobile game sessions automatically expire after max_idle_seconds
        with self.monitor._connect() as db:
            db.execute(
                "UPDATE game_activity_logs SET timestamp=? WHERE ip='192.168.1.77' AND game_id='mlbb'",
                ("2020-01-01T00:00:00+00:00",),
            )
        expired_count = self.monitor.expire_stale_game_sessions(max_idle_seconds=180)
        self.assertEqual(expired_count, 1)
        after_expire = self.monitor.get_game_activity(50)
        self.assertEqual(after_expire["summary"]["activeCount"], 0)

    def test_per_user_game_and_wifi_cutoff_enforcement(self) -> None:
        self.monitor._skip_live_probe_in_test = True
        self.monitor._upsert_inventory({
            "ip": "192.168.1.77",
            "mac": "02:aa:bb:cc:dd:ee",
            "vendor": "Apple",
            "suggestedName": "iPhone-Staff (Apple)",
            "arpType": "dynamic",
        })
        det = self.monitor.record_game_detection({
            "ip": "192.168.1.77",
            "domain": "mobilelegends.com",
            "detectionMethod": "Live DNS (192.168.0.224:53)",
        })
        session_id = det["detection"]["id"]

        # 1. Per-user Game + Wi-Fi shutoff blocks all traffic for targeted user ONLY
        res_cut = self.monitor.block_game_session({
            "sessionId": session_id,
            "ip": "192.168.1.77",
            "gameId": "mlbb",
            "scope": "device_wifi_cut",
            "cutWifi": True,
        })
        rule_id = res_cut["ruleId"]
        blocks = self.monitor.get_game_blocks()
        self.assertEqual(len(blocks), 1)
        ml_sig = self.monitor._match_game_signature(domain="mobilelegends.com")
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "mobilelegends.com", ml_sig, blocks))
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "connectivitycheck.gstatic.com", None, blocks))
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "google.com", None, blocks))
        # Other company users remain completely unaffected
        self.assertIsNone(self.monitor._should_sinkhole_query("192.168.1.88", "mobilelegends.com", ml_sig, blocks))
        self.assertIsNone(self.monitor._should_sinkhole_query("192.168.1.88", "google.com", None, blocks))

        # 2. Verify DNS sinkhole reply carries 0.0.0.0 with TTL=1s
        qname = b"\x0dmobilelegends\x03com\x00"
        raw_q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
        reply = self.monitor._build_dns_sinkhole_reply(raw_q)
        self.assertEqual(reply[-4:], b"\x00\x00\x00\x00")
        self.assertEqual(int.from_bytes(reply[-10:-6], "big"), 1)

        self.monitor.unblock_game_rule(rule_id)
        self.assertEqual(self.monitor.get_game_blocks(), [])

        # 3. Single-game block (cutWifi=False) only sinkholes that game + relay domains
        res_game = self.monitor.block_game_session({
            "ip": "192.168.1.77",
            "gameId": "mlbb",
            "scope": "device_game",
            "cutWifi": False,
        })
        blocks2 = self.monitor.get_game_blocks()
        relay_sig = self.monitor._match_game_signature(domain="cdn.moonton.net")
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "cdn.moonton.net", relay_sig, blocks2))
        self.assertIsNone(self.monitor._should_sinkhole_query("192.168.1.77", "google.com", None, blocks2))
        self.monitor.unblock_game_rule(res_game["ruleId"])

    def test_realtime_game_prevention_and_sensor_telemetry(self) -> None:
        self.monitor._skip_live_probe_in_test = True

        # 1. Subdomain matching catches live mobile regions without TikTok CDN false positives
        self.assertIsNotNone(self.monitor._match_game_signature(domain="sea-api-02.youngjoygame.com"))
        self.assertIsNotNone(self.monitor._match_game_signature(domain="dl.codm.garena.com"))
        self.assertIsNone(self.monitor._match_game_signature(domain="byteoversea.com"))

        # 2. DoH canary NXDOMAIN detection (prevents mobile browsers/Private Relay DNS bypass)
        self.assertTrue(self.monitor._is_doh_canary_domain("use-application-dns.net"))
        self.assertTrue(self.monitor._is_doh_canary_domain("mask.icloud.com"))
        nxd_q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04mask\x06icloud\x03com\x00\x00\x01\x00\x01"
        nxd_reply = self.monitor._build_dns_nxdomain_reply(nxd_q)
        self.assertEqual(nxd_reply[0:4], b"\xab\xcd\x81\x83")  # RCODE=3 NXDOMAIN

        # 3. Sensor heartbeat populates live readiness & synchronizes policy
        hb = self.monitor.record_gaming_sensor_heartbeat({
            "dnsHost": "192.168.0.224",
            "dnsQueriesTotal": 42,
            "dnsClients": {"192.168.1.77": "2026-11-16T12:00:00Z"},
            "lastDnsClientIp": "192.168.1.77",
            "lastDnsDomain": "api.mobilelegends.com",
        })
        self.assertTrue(hb["success"])

        # 4. Auto-prevention mode immediately blocks opened games at detection time
        pol_res = self.monitor.set_gaming_policy({"preventionMode": "auto_block_game"})
        self.assertTrue(pol_res["policy"]["autoPreventEnabled"])
        auto_det = self.monitor.record_game_detection({
            "ip": "192.168.1.77",
            "domain": "sea-api-02.youngjoygame.com",
            "detectionMethod": "Live DNS Auto-Prevent (192.168.0.224:53)",
        })
        self.assertTrue(auto_det["autoPrevented"])
        self.assertTrue(auto_det["blocked"])
        blocks = self.monitor.get_game_blocks()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["gameId"], "mlbb")
        self.assertEqual(blocks[0]["ip"], "192.168.1.77")

        activity = self.monitor.get_game_activity(50)
        self.assertEqual(activity["policy"]["preventionMode"], "auto_block_game")
        self.assertTrue(activity["sensorStatus"]["sensorOnline"])
        self.assertTrue(activity["sensorStatus"]["dnsInterceptReady"])
        self.assertEqual(activity["sensorStatus"]["dnsClientsCount"], 1)

        self.monitor.unblock_game_rule(auto_det["ruleId"])
        self.monitor.set_gaming_policy({"preventionMode": "alert_only"})

        # 5. Whole-topology scan sweeps >120 online devices + topology endpoints and fetches game hits
        for idx in range(132):
            self.monitor._upsert_inventory({
                "ip": f"192.168.2.{10 + idx}",
                "mac": f"02:11:22:33:{idx // 256:02x}:{idx % 256:02x}",
                "vendor": "Apple",
                "suggestedName": f"Staff-Phone-{idx}",
                "arpType": "dynamic",
            })
        topo_ap = self.monitor.add_topology_node({
            "name": "Floor 2 AP",
            "ip": "192.168.2.1",
            "nodeType": "ap",
        })["node"]
        topo_phone = self.monitor.add_topology_node({
            "name": "Gaming-Phone-22",
            "ip": "192.168.2.99",
            "nodeType": "device",
        })["node"]
        self.monitor.add_topology_link({
            "sourceId": topo_ap["id"],
            "targetId": topo_phone["id"],
            "cableType": "wireless",
        })

        def fake_game_probe(ip: str, port: int, timeout: float = 0.06):
            if ip == "192.168.2.99" and port == 19132:
                return True, True, 2.0
            return False, False, None

        with patch.object(self.monitor, "_probe_tcp_socket", side_effect=fake_game_probe):
            scan_res = self.monitor.scan_lan_for_games(include_topology_refresh=True)

        self.assertTrue(scan_res["success"])
        self.assertGreaterEqual(scan_res["scannedDevices"], 132)
        self.assertGreaterEqual(scan_res["topologyNodesScanned"], 2)
        self.assertEqual(scan_res["detectedCount"], 1)
        self.assertEqual(scan_res["detections"][0]["ip"], "192.168.2.99")
        self.assertEqual(scan_res["detections"][0]["gameId"], "minecraft")
        # Scanning devices must never auto-block users
        self.assertEqual(self.monitor.get_game_blocks(), [])

        # 6. Explicit manual block with device_throttle drops user connection to unplayable rate
        thr_res = self.monitor.block_game_session({
            "ip": "192.168.2.99",
            "gameId": "minecraft",
            "scope": "device_throttle",
            "cutWifi": False,
        })
        self.assertTrue(thr_res["success"])
        self.assertEqual(thr_res["scope"], "device_throttle")
        self.assertIn("enforcementDetails", thr_res)
        self.assertTrue(thr_res["enforcementDetails"]["requiresSetup"])
        thr_blocks = self.monitor.get_game_blocks()
        self.assertEqual(len(thr_blocks), 1)
        self.assertEqual(thr_blocks[0]["scope"], "device_throttle")
        mc_sig = self.monitor._match_game_signature(game_id="minecraft")
        act_game, _ = self.monitor._classify_dns_query_action("192.168.2.99", "minecraft.net", mc_sig, thr_blocks)
        act_web, _ = self.monitor._classify_dns_query_action("192.168.2.99", "youtube.com", None, thr_blocks)
        act_other, _ = self.monitor._classify_dns_query_action("192.168.2.50", "youtube.com", None, thr_blocks)
        self.assertEqual(act_game, "sinkhole")
        self.assertEqual(act_web, "throttle")
        self.assertEqual(act_other, "allow")
        self.monitor.unblock_game_rule(thr_res["ruleId"])
        self.assertEqual(self.monitor.get_game_blocks(), [])

    def test_game_signature_accuracy_dedup_and_dns_wire(self) -> None:
        self.monitor._skip_live_probe_in_test = True

        # 1. Generic system/Apple/Java/CDN ports & domains must NOT trigger false positives
        self.assertIsNone(self.monitor._match_game_signature(port=5223))
        self.assertIsNone(self.monitor._match_game_signature(port=5000))
        self.assertIsNone(self.monitor._match_game_signature(port=49152))
        self.assertIsNone(self.monitor._match_game_signature(domain="img.myqcloud.com"))
        self.assertIsNone(self.monitor._match_game_signature(domain="cdn.tencent-cloud.net"))
        self.assertIsNone(self.monitor._match_game_signature(domain="notcodm.example.com"))
        self.assertIsNone(self.monitor._match_game_signature(domain="garena.com"))
        self.assertIsNone(self.monitor._match_game_signature(process="javaw.exe"))
        self.assertIsNone(self.monitor._match_game_signature(process="Windows10Universal.exe"))

        # 2. Real mobile/PC signatures & DoH canaries match accurately
        self.assertEqual(self.monitor._match_game_signature(domain="sea-api-02.youngjoygame.com")["id"], "mlbb")
        self.assertEqual(self.monitor._match_game_signature(domain="dl.codm.garena.com")["id"], "codm")
        self.assertEqual(self.monitor._match_game_signature(domain="fortnite.com")["id"], "fortnite")
        self.assertEqual(self.monitor._match_game_signature(process="FortniteClient-Win64-Shipping.exe")["id"], "fortnite")
        self.assertTrue(self.monitor._is_doh_canary_domain("chrome.cloudflare-dns.com"))

        # 3. Updating while blocked only updates the latest row, never corrupting older timestamps
        with self.monitor._connect() as db:
            db.execute(
                """INSERT INTO game_activity_logs
                   (id, timestamp, ip, mac, device_name, vendor, device_type, game_id, game_name, is_active, is_blocked)
                   VALUES (?, ?, ?, '', 'Phone-Test', 'Apple', 'Mobile', 'mlbb', 'Mobile Legends: Bang Bang', 0, 0)""",
                ("game-hist-1", "2026-01-01T00:00:00Z", "192.168.1.90"),
            )
            db.execute(
                """INSERT INTO game_activity_logs
                   (id, timestamp, ip, mac, device_name, vendor, device_type, game_id, game_name, is_active, is_blocked)
                   VALUES (?, ?, ?, '', 'Phone-Test', 'Apple', 'Mobile', 'mlbb', 'Mobile Legends: Bang Bang', 1, 0)""",
                ("game-hist-2", "2026-01-02T00:00:00Z", "192.168.1.90"),
            )
        blk = self.monitor.block_game_session({
            "ip": "192.168.1.90",
            "gameId": "mlbb",
            "scope": "device_throttle",
            "cutWifi": False,
        })
        self.monitor.record_game_detection({
            "ip": "192.168.1.90",
            "domain": "api.mobilelegends.com",
            "detectionMethod": "Live DNS",
        })
        with self.monitor._connect() as db:
            ts1 = db.execute("SELECT timestamp FROM game_activity_logs WHERE id='game-hist-1'").fetchone()["timestamp"]
            ts2 = db.execute("SELECT timestamp FROM game_activity_logs WHERE id='game-hist-2'").fetchone()["timestamp"]
        self.assertEqual(ts1, "2026-01-01T00:00:00Z")
        self.assertNotEqual(ts2, "2026-01-02T00:00:00Z")
        self.monitor.unblock_game_rule(blk["ruleId"])

        # 4. Wire-level HostGameSensor DNS handler handles DoH NXDOMAIN & device_throttle cleanly
        from host_game_sensor import HostGameSensor

        sensor = HostGameSensor(dns_host="127.0.0.1", dns_port=0, syslog_port=0)
        doh_pkt = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04mask\x06icloud\x03com\x00\x00\x01\x00\x01"
        doh_resp = sensor._process_dns_query(doh_pkt, "192.168.1.90")
        self.assertIsNotNone(doh_resp)
        self.assertEqual(doh_resp[0:4], b"\xaa\xbb\x81\x83")

        sensor._apply_policy_and_blocks({
            "policy": {"preventionMode": "alert_only"},
            "blocks": [{"id": "r1", "ip": "192.168.1.90", "gameId": "*", "scope": "device_throttle", "cutWifi": False}],
        })
        mlbb_pkt = b"\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api\x0dmobilelegends\x03com\x00\x00\x01\x00\x01"
        mlbb_resp = sensor._process_dns_query(mlbb_pkt, "192.168.1.90")
        self.assertIsNotNone(mlbb_resp)
        self.assertEqual(mlbb_resp[-4:], b"\x00\x00\x00\x00")


    def test_win32_icmp_fallback_rejects_unreachable_with_zero_returncode(self):
        from unittest.mock import MagicMock

        unreachable_proc = MagicMock(
            returncode=0,
            stdout="\nPinging 192.168.0.212 with 32 bytes of data:\nReply from 192.168.0.24: Destination host unreachable.\n\nPackets: Sent = 1, Received = 1, Lost = 0 (0% loss),\n",
            stderr="",
        )
        with patch("pulse_monitor.probes.os.name", "nt"), patch(
            "pulse_monitor.probes.subprocess.run", return_value=unreachable_proc
        ):
            alive, latency = monitor_module.Monitor._probe_icmp("192.168.0.212", 1000)
        self.assertFalse(alive)
        self.assertIsNone(latency)

        reachable_proc = MagicMock(
            returncode=0,
            stdout="\nPinging 192.168.1.195 with 32 bytes of data:\nReply from 192.168.1.195: bytes=32 time=7ms TTL=128\n",
            stderr="",
        )
        with patch("pulse_monitor.probes.os.name", "nt"), patch(
            "pulse_monitor.probes.subprocess.run", return_value=reachable_proc
        ):
            alive_ok, latency_ok = monitor_module.Monitor._probe_icmp("192.168.1.195", 1000)
        self.assertTrue(alive_ok)
        self.assertEqual(latency_ok, 7.0)

    def test_deco_omada_ship_iot_classification_and_manual_ap_persistence(self):
        import ipaddress
        from unittest.mock import MagicMock

        # 1. Identify TP-Link Deco Mesh via TLS CN (tplinkdeco.net), Omada EAP via omadaeap.net, and SHIP 2.0 Smart IoT
        fake_resp = MagicMock()
        fake_resp.headers = {"Server": "SHIP 2.0"}
        fake_resp.read.return_value = b"<html><body><center>200 OK</center></body></html>"
        fake_resp.__enter__.return_value = fake_resp
        fake_resp.__exit__.return_value = False

        with patch.object(
            self.monitor, "_inspect_tls_cert_der", return_value=b"CN=tplinkdeco.net"
        ), patch("urllib.request.urlopen", side_effect=OSError("no root html")):
            deco_fp = self.monitor.identify_network_device("192.168.2.134", open_ports=[443, 20001])
        self.assertEqual(deco_fp["role"], "router")
        self.assertIn("Deco", deco_fp["model"])

        with patch.object(
            self.monitor, "_inspect_tls_cert_der", return_value=b"CN=omadaeap.net"
        ), patch("urllib.request.urlopen", side_effect=OSError("no root html")):
            omada_fp = self.monitor.identify_network_device("192.168.0.203", open_ports=[443])
        self.assertEqual(omada_fp["role"], "ap")
        self.assertIn("Omada", omada_fp["model"])

        with patch.object(self.monitor, "_inspect_tls_cert_der", return_value=b""), patch(
            "urllib.request.urlopen", return_value=fake_resp
        ):
            iot_fp = self.monitor.identify_network_device("192.168.2.81", open_ports=[80])
        self.assertEqual(iot_fp["role"], "client")

        # 2. Seed discovered LAN rows + fingerprints + manual AP (192.168.1.195), then run sync_infrastructure_devices()
        for ip, mac, vendor, sugg in [
            ("192.168.2.134", "98:03:8e:c3:be:0c", "TP-Link Deco Mesh", "TP-Link Deco Mesh (.2.134)"),
            ("192.168.2.81", "50:3d:d1:11:22:33", "TP-Link Systems Inc.", "TP-Link Tapo IoT"),
            ("192.168.0.203", "c0:3a:55:44:55:66", "TP-Link Systems Inc.", "Smart Switch (.0.203)"),
            ("192.168.1.195", "40:c7:3c:12:3f:8b", "Intel Corporate", "Intel Corporate (192.168.1.195)"),
        ]:
            self.monitor._upsert_inventory(
                {"mac": mac, "ip": ip, "vendor": vendor, "suggestedName": sugg, "arpType": "dynamic"},
                scan_id="test-scan",
            )
        with self.monitor._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO monitor_metadata (key, value) VALUES ('device_fingerprints', ?)",
                (
                    json.dumps({
                        "192.168.2.134": {**deco_fp, "mac": "98:03:8e:c3:be:0c"},
                        "192.168.2.81": {**iot_fp, "mac": "50:3d:d1:11:22:33"},
                        "192.168.0.203": {**omada_fp, "mac": "c0:3a:55:44:55:66"},
                    }),
                ),
            )
            db.commit()

        manual_ap = self.monitor.add_device({
            "name": "Deployed Access Point · .1.195",
            "ip": "192.168.1.195",
            "type": "ap",
            "manual": True,
        })
        self.assertEqual(manual_ap["mac"], "40:c7:3c:12:3f:8b")

        with patch.object(
            self.monitor, "_known_local_networks", return_value=[ipaddress.ip_network("192.168.0.0/22")]
        ), patch.object(
            self.monitor, "_known_local_gateways", return_value={"192.168.0.1"}
        ):
            self.monitor.sync_infrastructure_devices()

        devices_by_ip = {d["ip"]: d for d in self.monitor.get_devices()}
        self.assertIn("192.168.2.134", devices_by_ip)
        self.assertEqual(devices_by_ip["192.168.2.134"]["type"], "router")
        self.assertIn("192.168.0.203", devices_by_ip)
        self.assertEqual(devices_by_ip["192.168.0.203"]["type"], "ap")
        self.assertNotIn("192.168.2.81", devices_by_ip)
        self.assertNotIn("192.168.2.81", self.monitor.config.get("routers", {}))
        self.assertIn("192.168.1.195", devices_by_ip)
        self.assertTrue(devices_by_ip["192.168.1.195"].get("manual"))


    def test_wireshark_tls_sni_tzsp_pcapng_and_syn_probe_rejection(self):
        import base64
        import socket
        import struct
        from pulse_monitor.wireshark_capture import (
            PcapRingRecorder,
            build_wireshark_display_filter,
            dissect_raw_packet,
            extract_tls_sni,
            parse_pcap_or_pcapng,
        )

        def build_eth_ipv4(src_ip: str, dst_ip: str, proto: int, l4_payload: bytes) -> bytes:
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            total_len = 20 + len(l4_payload)
            ip_hdr = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                total_len,
                1,
                0,
                64,
                proto,
                0,
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip),
            )
            return eth + ip_hdr + l4_payload

        def build_udp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
            udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
            return build_eth_ipv4(src_ip, dst_ip, 17, udp + payload)

        def build_tcp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, payload: bytes) -> bytes:
            tcp = struct.pack("!HHIIHHHH", sport, dport, 100, 0, (5 << 12) | flags, 65535, 0, 0)
            return build_eth_ipv4(src_ip, dst_ip, 6, tcp + payload)

        # 1. TLS ClientHello with SNI = api.mobilelegends.com
        host_b = b"api.mobilelegends.com"
        sni_ext_data = struct.pack("!HBH", len(host_b) + 3, 0, len(host_b)) + host_b
        sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
        ch_body = (
            b"\x03\x03"
            + (b"\x11" * 32)
            + b"\x00"
            + struct.pack("!HH", 2, 0x1301)
            + b"\x01\x00"
            + struct.pack("!H", len(sni_ext))
            + sni_ext
        )
        hs = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
        tls_rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
        self.assertEqual(extract_tls_sni(tls_rec), "api.mobilelegends.com")

        tls_frame = build_tcp_frame("192.168.1.90", "203.0.113.10", 51234, 443, 0x18, tls_rec)
        tls_hit = dissect_raw_packet(tls_frame, dlt=1)
        self.assertIsNotNone(tls_hit)
        self.assertEqual(tls_hit["ip"], "192.168.1.90")
        self.assertEqual(tls_hit["gameId"], "mlbb")
        self.assertEqual(tls_hit["protocol"], "TLS SNI")
        self.assertEqual(tls_hit["detectionMethod"], "Wireshark TLS SNI")

        # 2. Outbound SYN-only & 60-byte padded Ethernet RST+ACK TCP scanner probes must NEVER trigger false game detections
        syn_probe = build_tcp_frame("192.168.0.224", "192.168.0.243", 38910, 7500, 0x02, b"")
        self.assertIsNone(dissect_raw_packet(syn_probe, dlt=1))
        rst_ack_padded = build_tcp_frame("192.168.0.243", "192.168.0.224", 7500, 38910, 0x14, b"") + (b"\x00" * 6)
        self.assertEqual(len(rst_ack_padded), 60)
        self.assertIsNone(dissect_raw_packet(rst_ack_padded, dlt=1))

        # Private-to-private TP-Link Deco mesh chatter on port 20001 must NOT be misclassified as PUBG Mobile
        deco_mesh_udp = build_udp_frame("192.168.0.224", "192.168.2.134", 54000, 20001, b"\x00\x01\x02\x03")
        self.assertIsNone(dissect_raw_packet(deco_mesh_udp, dlt=1))

        # Ephemeral client source port matching a game port (e.g. QUIC UDP 39800 -> 443) must NOT false-trigger Free Fire
        quic_ephemeral = build_udp_frame("192.168.2.130", "142.250.199.10", 39800, 443, b"\xc0\x00\x00\x01")
        self.assertIsNone(dissect_raw_packet(quic_ephemeral, dlt=1))

        # Known gateway/router IP must NOT be reported as a client player via port fallback
        gw_udp = build_udp_frame("192.168.0.1", "47.90.10.20", 51234, 39698, b"\x01\x02\x03")
        self.assertIsNone(dissect_raw_packet(gw_udp, dlt=1, infra_ips={"192.168.0.1"}))

        # Monitor self_ips scanning another LAN host on :27015 must NOT trigger a self-detection echo
        self_scan_tcp = build_tcp_frame("192.168.0.224", "192.168.1.63", 54321, 27015, 0x18, b"\x00\x01")
        self.assertIsNone(dissect_raw_packet(self_scan_tcp, dlt=1, self_ips={"192.168.0.224"}))

        # Non-self LAN host serving Steam :27036 to another peer attributes the host running :27036
        lan_steam = build_tcp_frame("192.168.3.160", "192.168.1.50", 27036, 51111, 0x18, b"\xaa\xbb")
        lan_steam_hit = dissect_raw_packet(lan_steam, dlt=1, self_ips={"192.168.0.224"})
        self.assertIsNotNone(lan_steam_hit)
        self.assertEqual(lan_steam_hit["ip"], "192.168.3.160")
        self.assertEqual(lan_steam_hit["gameId"], "steam")

        # Genuine outbound UDP game traffic (client -> remote Free Fire server :39800) DOES match
        real_ff = build_udp_frame("192.168.2.130", "47.90.10.20", 51234, 39800, b"\x01\x02\x03")
        ff_hit = dissect_raw_packet(real_ff, dlt=1)
        self.assertIsNotNone(ff_hit)
        self.assertEqual(ff_hit["ip"], "192.168.2.130")
        self.assertEqual(ff_hit["gameId"], "freefire")

        # Established TCP data flow to public server on game port 7500 DOES match
        tcp_flow = build_tcp_frame("192.168.1.88", "203.0.113.20", 55555, 7500, 0x18, b"\xaa\xbb\xcc\xdd")
        flow_hit = dissect_raw_packet(tcp_flow, dlt=1)
        self.assertIsNotNone(flow_hit)
        self.assertEqual(flow_hit["ip"], "192.168.1.88")
        self.assertEqual(flow_hit["gameId"], "codm")

        # 3. DNS Wire query wrapped inside Router TZSP (UDP 37008)
        dns_q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x08gamejoin\x06roblox\x03com\x00\x00\x01\x00\x01"
        inner_dns_frame = build_udp_frame("192.168.2.55", "1.1.1.1", 54321, 53, dns_q)
        tzsp_payload = b"\x01\x00\x00\x01\x01" + inner_dns_frame
        tzsp_outer = build_udp_frame("192.168.0.1", "192.168.0.224", 40000, 37008, tzsp_payload)
        tzsp_hit = dissect_raw_packet(tzsp_outer, dlt=1)
        self.assertIsNotNone(tzsp_hit)
        self.assertEqual(tzsp_hit["ip"], "192.168.2.55")
        self.assertEqual(tzsp_hit["gameId"], "roblox")
        self.assertEqual(tzsp_hit["detectionMethod"], "Wireshark TZSP Stream")

        # 4. .pcap and .pcapng binary capture parsing + live analysis ingestion (never auto-blocking)
        pcap_bytes = (
            PcapRingRecorder.GLOBAL_HEADER
            + struct.pack("<IIII", 1700000000, 0, len(tls_frame), len(tls_frame))
            + tls_frame
        )
        self.assertEqual(len(parse_pcap_or_pcapng(pcap_bytes)), 1)

        def pad4(b: bytes) -> bytes:
            return b + (b"\x00" * ((4 - (len(b) % 4)) % 4))

        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb = struct.pack("<II", 0x0A0D0D0A, len(shb_body) + 12) + shb_body + struct.pack("<I", len(shb_body) + 12)
        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb = struct.pack("<II", 0x00000001, len(idb_body) + 12) + idb_body + struct.pack("<I", len(idb_body) + 12)
        epb_pkt = pad4(inner_dns_frame)
        epb_body = struct.pack("<IIIII", 0, 0, 1000, len(inner_dns_frame), len(inner_dns_frame)) + epb_pkt
        epb = struct.pack("<II", 0x00000006, len(epb_body) + 12) + epb_body + struct.pack("<I", len(epb_body) + 12)
        pcapng_bytes = shb + idb + epb
        self.assertEqual(len(parse_pcap_or_pcapng(pcapng_bytes)), 1)

        res = self.monitor.analyze_wireshark_capture({
            "filename": "office_mirror.pcapng",
            "dataBase64": base64.b64encode(pcapng_bytes).decode("ascii"),
            "ingest": True,
        })
        self.assertEqual(res["packetsParsed"], 1)
        self.assertEqual(res["uniqueMatches"], 1)
        self.assertEqual(res["detectionsLogged"], 1)
        self.assertEqual(len(res["gameActivity"]["blocks"]), 0)
        self.assertEqual(res["gameActivity"]["logs"][0]["gameId"], "roblox")

        # 5. Config & heartbeat telemetry round-trip + Display filter sanity
        filt = build_wireshark_display_filter()
        self.assertIn("dns.qry.name", filt)
        self.assertIn("tls.handshake.extensions_server_name", filt)
        self.assertIn("udp.port in", filt)

        cfg_res = self.monitor.set_wireshark_config({"enabled": False})
        self.assertFalse(cfg_res["wiresharkStatus"]["enabled"])
        hb = self.monitor.record_gaming_sensor_heartbeat({
            "pid": 1234,
            "wireshark": {"active": False, "engine": "npcap-wpcap", "packetsCaptured": 99, "packetsMatched": 2},
        })
        self.assertFalse(hb["wireshark"]["enabled"])
        self.assertEqual(self.monitor.get_game_activity()["wiresharkStatus"]["packetsCaptured"], 99)


if __name__ == "__main__":
    unittest.main()
