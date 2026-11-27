import json
import ipaddress
import subprocess
from pathlib import Path
from unittest.mock import patch
import monitor as monitor_module
from tests.support import MonitorTestCase


class InventoryTests(MonitorTestCase):
    def test_sync_preserves_operator_devices_at_old_sample_addresses(self):
        self.assertFalse(self.monitor.get_devices())
        device = self.monitor.add_device({"ip": "192.168.0.10", "name": "Warehouse printer"})
        self.monitor.sync_infrastructure_devices()
        self.assertIn(device["id"], [item["id"] for item in self.monitor.get_devices()])

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

    def test_subnet_discovery_distinguishes_echo_replies_from_arp_observations(self):
        from pulse_monitor.config import inferred_inventory_mac

        arp_ip, routed_ip = "10.20.10.12", "10.20.20.12"
        mac = "aa:bb:cc:dd:ee:01"
        previous = self.discovered_device(routed_ip)
        previous["mac"] = "00:22:33:44:55:66"
        self.monitor._upsert_inventory(previous)
        subnets = [ipaddress.IPv4Network("10.20.10.0/24"), ipaddress.IPv4Network("10.20.20.0/24")]
        with (
            patch.object(self.monitor, "_local_lan_networks", return_value=subnets),
            patch.object(self.monitor, "_ping_sweep_hosts", return_value=[routed_ip]),
            patch.object(self.monitor, "_read_arp_entries", return_value=[(arp_ip, mac, "dynamic")]),
            patch.object(self.monitor, "_resolve_hostnames_bulk", return_value={}),
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(False, False, None)),
            patch.object(self.monitor, "sync_infrastructure_devices", return_value={}),
        ):
            result = self.monitor.discover_devices()
        self.assertEqual(result["coverage"], [
            {"subnet": "10.20.10.0/24", "addressesProbed": 254, "icmpReplies": 0, "addressesObserved": 1},
            {"subnet": "10.20.20.0/24", "addressesProbed": 254, "icmpReplies": 1, "addressesObserved": 1},
        ])
        self.assertEqual(self.monitor.get_discovery_coverage()["lastScan"], result["coverage"])
        self.assertEqual(self.monitor.get_discovery_coverage()["lastScanAt"], result["timestamp"])
        devices = {item["ip"]: item for item in result["inventory"] if item["isOnline"]}
        self.assertEqual(devices[arp_ip]["observedMac"], mac)
        self.assertEqual(devices[routed_ip]["observedMac"], "")
        self.assertEqual(devices[routed_ip]["mac"], inferred_inventory_mac(routed_ip))

        self.assertTrue(self.monitor.toggle_favorite(f"mac:{inferred_inventory_mac(routed_ip)}"))
        self.monitor._upsert_inventory(self.discovered_device(routed_ip))
        rows = [row for row in self.monitor.get_inventory() if row["ip"] == routed_ip]
        online = [row for row in rows if row["isOnline"]]
        self.assertEqual(len(online), 1)
        self.assertEqual(online[0]["observedMac"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(online[0]["favorite"])

    def test_hostname_cache_requires_matching_hardware(self):
        ip = "192.168.1.45"
        self.monitor._save_cached_hostnames({ip: "OfficePrinter"}, {ip: "00:11:22:33:44:55"})
        self.assertEqual(self.monitor._get_cached_hostnames({ip: "00:11:22:33:44:55"}), {ip: "OfficePrinter"})
        self.assertEqual(self.monitor._get_cached_hostnames({ip: "12:34:56:78:90:ab"}), {})

    def test_arp_observation_does_not_create_latency_or_loss_samples(self):
        device = {"id": "arp-client", "name": "ARP client", "ip": "10.20.10.12", "type": "device"}
        self.monitor._evaluate_device({**device, "alive": False})
        with (
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(False, False, None)),
            patch.object(self.monitor, "_probe_icmp", return_value=(False, None)),
            patch.object(self.monitor, "_is_arp_neighbor_alive", return_value=True),
        ):
            result = self.monitor.probe_device(device)
        self.assertEqual(result["probeMethod"], "ARP cache observation")
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["directlyReachable"])
        self.assertIn(f"dev-{device['ip']}", self.monitor.active_alerts)
        self.assertIsNone(result["latencyMs"])
        self.assertIsNone(result["packetLossPct"])
        self.assertEqual(self.monitor.history[device["ip"]], [])

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

    def test_favourite_saved_by_ip_can_be_removed_after_discovery(self):
        item = self.discovered_device()
        ip = item["ip"]
        ip_key = f"ip:{ip}"
        self.monitor.add_device({"name": "Office AP", "ip": ip, "type": "ap"})
        self.assertTrue(self.monitor.toggle_favorite(ip_key))
        device = next(device for device in self.monitor.get_devices() if device["ip"] == ip)
        self.monitor.latest_devices[ip] = {**device, "status": "online"}
        self.monitor._upsert_inventory(item)

        inventory = self.monitor.get_inventory()[0]
        self.assertEqual(inventory["favoriteKey"], ip_key)
        self.assertFalse(self.monitor.toggle_favorite(inventory["favoriteKey"]))
        self.assertFalse(self.monitor.get_inventory()[0]["favorite"])
        hydrated = next(device for device in self.monitor._hydrated_devices() if device["ip"] == ip)
        self.assertFalse(hydrated["favorite"])
        self.assertEqual(hydrated["status"], "online")

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

    def test_history_follows_mac_and_monitored_id_across_address_reuse(self):
        first = self.discovered_device("192.168.10.20")
        second = {**first, "mac": "aa:bb:cc:dd:ee:12"}
        self.monitor._upsert_inventory(first)
        self.monitor._upsert_inventory(second)
        self.monitor._upsert_inventory({**first, "ip": "192.168.10.21"})
        old = self.monitor.get_device_history("", first["mac"])
        new = self.monitor.get_device_history("", second["mac"])
        self.assertEqual(old["ip"], "192.168.10.21")
        self.assertEqual(
            [event["eventType"] for event in old["events"]],
            ["IP_CHANGED", "ADDRESS_REASSIGNED", "NEW_DEVICE"],
        )
        self.assertEqual([event["eventType"] for event in new["events"]], ["NEW_DEVICE"])
        self.assertTrue(all(event["mac"] == second["mac"] for event in new["events"]))
        device = self.monitor.add_device({"name": "Managed host", "ip": "192.168.10.50"})
        self.monitor.update_device(device["id"], {"ip": "192.168.10.51"})
        history = self.monitor.get_device_history(device["id"], second["mac"])
        self.assertEqual(history["ip"], "192.168.10.51")
        self.assertEqual([event["eventType"] for event in history["events"]], ["MONITORED_IP_CHANGED", "DEVICE_ADDED"])

    def test_inventory_review_ignore_is_reversible_and_persists(self):
        device = self.discovered_device()
        self.monitor._upsert_inventory(device)
        self.assertTrue(self.monitor.set_device_review_ignored(device["mac"], True))
        self.monitor._upsert_inventory({**device, "ip": "192.168.10.21"})
        reloaded = monitor_module.Monitor()
        self.assertTrue(reloaded.get_inventory()[0]["reviewIgnored"])
        self.assertFalse(reloaded.get_inventory()[0]["authorized"])
        self.assertTrue(reloaded.set_device_review_ignored(device["mac"], False))
        self.assertFalse(reloaded.get_inventory()[0]["reviewIgnored"])
        self.assertTrue(reloaded.authorize_device(device["mac"]))
        self.assertFalse(reloaded.set_device_review_ignored(device["mac"], True))

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
        self.assertEqual(by_ip["192.168.0.56"]["connectivityState"], "ONLINE_WAN_UNKNOWN")
        self.assertIsNone(by_ip["192.168.0.56"]["hasInternet"])

    def test_slash22_does_not_misclassify_dot1_clients_and_cleans_dhcp_ip_change_alerts(self) -> None:
        # Simulate real /22 subnet detection (192.168.0.0/22 with single gateway 192.168.0.1)
        self.monitor._discovered_networks = [ipaddress.IPv4Network("192.168.0.0/22")]
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
