from pathlib import Path
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from pulse_monitor.wireshark_capture import WiresharkCaptureEngine
from tests.support import MonitorTestCase


def _build_eth_ipv4_tcp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\x01\xaa\xbb\xcc\xdd\xee\x02\x08\x00"
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1,
        0,
        (5 << 4),
        0x02,
        65535,
        0,
        0,
    )
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return eth + ip_header + tcp_header + payload


class AccuracyUpgradesTests(MonitorTestCase):
    def test_flapping_protection_debounces_single_offline_miss(self):
        self.monitor.config["thresholds"]["offlineConfirmCount"] = 2
        device = self.monitor.add_device(
            {
                "name": "Office AP 1",
                "ip": "192.168.10.50",
                "type": "ap",
                "location": "Floor 2",
                "critical": True,
            }
        )
        # First offline probe should be suppressed (debounced)
        self.monitor._evaluate_device({**device, "alive": False})
        self.assertEqual(self.monitor.get_active_alerts(), [])
        self.assertEqual(self.monitor._pending_offline_counts.get("192.168.10.50"), 1)

        # Second consecutive offline probe should trigger the alert
        self.monitor._evaluate_device({**device, "alive": False})
        active = self.monitor.get_active_alerts()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["type"], "DEVICE_OFFLINE")

        # Recovery should clear alert and reset debounce counter
        self.monitor._evaluate_device({**device, "alive": True, "latencyMs": 3.0})
        self.assertEqual(self.monitor.get_active_alerts(), [])
        self.assertEqual(self.monitor._pending_offline_counts.get("192.168.10.50", 0), 0)

    def test_external_notification_settings_and_test_delivery(self):
        saved = self.monitor.save_notification_settings(
            {
                "enabled": True,
                "webhookUrl": "https://hooks.example.test/services/abc",
                "telegramBotToken": "123456:TESTTOKEN",
                "telegramChatId": "-100999888",
                "offlineConfirmCount": 3,
            }
        )
        self.assertTrue(saved["success"])
        ns = saved["notificationSettings"]
        self.assertTrue(ns["enabled"])
        self.assertEqual(ns["offlineConfirmCount"], 3)
        self.assertEqual(self.monitor.config["thresholds"]["offlineConfirmCount"], 3)

        ops = self.monitor.get_operations()
        self.assertTrue(ops["webhookEnabled"])
        self.assertTrue(ops["telegramEnabled"])
        self.assertEqual(ops["notificationSettings"]["offlineConfirmCount"], 3)

        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.__enter__.return_value = fake_resp
        fake_resp.__exit__.return_value = False
        with patch("pulse_monitor.operations.urllib.request.urlopen", return_value=fake_resp) as mock_open:
            res = self.monitor.test_notification_channels()
        self.assertTrue(res["success"])
        self.assertEqual(res["results"].get("webhook"), "sent")
        self.assertEqual(res["results"].get("telegram"), "sent")
        self.assertEqual(mock_open.call_count, 2)

    def test_passive_top_talkers_and_encrypted_dns_detection(self):
        engine = WiresharkCaptureEngine(
            on_detection=lambda _m: None,
            pcap_path=Path(self.temp_dir.name) / "test_passive.pcap",
        )
        now = 1_700_000_000.0
        # Simulated DoT (:853) frame from LAN client 192.168.10.42 -> 1.1.1.1:853
        dot_frame = _build_eth_ipv4_tcp_frame("192.168.10.42", "1.1.1.1", 51234, 853, b"x" * 200)
        # Simulated DoH (:443) frame from LAN client 192.168.10.43 -> 8.8.8.8:443
        doh_frame = _build_eth_ipv4_tcp_frame("192.168.10.43", "8.8.8.8", 51235, 443, b"y" * 500)

        engine._record_passive_frame_metrics(dot_frame, 1, now)
        engine._record_passive_frame_metrics(doh_frame, 1, now + 0.5)

        with patch("pulse_monitor.wireshark_capture.time.time", return_value=now + 1.0):
            snap = engine.status_snapshot()

        talkers = {t["ip"]: t for t in snap["topTalkers"]}
        self.assertIn("192.168.10.42", talkers)
        self.assertIn("192.168.10.43", talkers)
        self.assertGreater(talkers["192.168.10.43"]["txBytes"], talkers["192.168.10.42"]["txBytes"])

        enc = {c["ip"]: c for c in snap["encryptedDnsClients"]}
        self.assertIn("192.168.10.42", enc)
        self.assertEqual(enc["192.168.10.42"]["protocol"], "DoT :853")
        self.assertIn("192.168.10.43", enc)
        self.assertEqual(enc["192.168.10.43"]["protocol"], "DoH :443")

    def test_device_role_tagging_and_ap_client_association(self):
        mac = "aa:bb:cc:dd:ee:44"
        self.monitor._upsert_inventory(
            {
                "ip": "192.168.10.88",
                "mac": mac,
                "vendor": "TP-Link Technologies",
                "suggestedName": "TP-Link (192.168.10.88)",
                "arpType": "dynamic",
            }
        )
        # Tag device as staff_pc with custom name
        profile_res = self.monitor.set_device_profile(
            mac, {"customName": "Finance Laptop", "role": "staff_pc", "notes": "Accounting desk"}
        )
        self.assertTrue(profile_res["success"])
        profile = profile_res["profile"]
        self.assertEqual(profile["role"], "staff_pc")
        self.assertEqual(profile["customName"], "Finance Laptop")

        # Save AP association for this client MAC
        self.monitor.save_ap_client_associations(
            {
                mac: {
                    "apIp": "192.168.10.2",
                    "apName": "Floor 2 Deco AP",
                    "band": "5 GHz",
                    "rssi": -54,
                    "source": "tp-link-stok",
                }
            }
        )

        inv = {item["mac"]: item for item in self.monitor.get_inventory()}
        entry = inv[mac]
        self.assertEqual(entry["name"], "Finance Laptop")
        self.assertEqual(entry["role"], "staff_pc")
        self.assertEqual(entry["apAssociation"]["apName"], "Floor 2 Deco AP")
        self.assertEqual(entry["apAssociation"]["band"], "5 GHz")

        # Non-infra role (staff_pc) must be excluded from automatic infrastructure enrollment
        sync_res = self.monitor.sync_infrastructure_devices()
        self.assertEqual(sync_res.get("added", 0), 0)
        self.assertFalse(any(d.get("ip") == "192.168.10.88" for d in self.monitor.get_devices()))

    def test_arp_parser_resolves_same_subnet_conflicts_and_filters_multicast(self):
        from unittest.mock import Mock

        arp_out = "\n".join([
            "Interface: 172.27.3.1 --- 0x9",
            "  Internet Address      Physical Address      Type",
            "  192.168.0.50          aa-aa-aa-aa-aa-aa     static",
            "Interface: 192.168.0.109 --- 0x4",
            "  Internet Address      Physical Address      Type",
            "  192.168.0.50          68-7f-f0-1d-06-e0     dynamic",
            "  192.168.0.255         ff-ff-ff-ff-ff-ff     static",
            "  224.0.0.22            01-00-5e-00-00-16     static",
        ])
        fake_run = Mock(return_value=Mock(returncode=0, stdout=arp_out, stderr=""))
        entries = self.monitor._read_arp_entries("nt", fake_run)
        self.assertEqual(entries, [("192.168.0.50", "68:7f:f0:1d:06:e0", "dynamic")])

    def test_inventory_prevents_duplicate_online_ips_and_promotes_inferred_macs(self):
        from pulse_monitor.config import inferred_inventory_mac

        ip = "192.168.10.77"
        fake_mac = inferred_inventory_mac(ip)
        self.monitor._upsert_inventory({
            "ip": ip, "mac": fake_mac, "vendor": "LAN Host",
            "suggestedName": f"LAN Host ({ip})", "arpType": "icmp",
        })
        self.monitor.toggle_favorite(f"mac:{fake_mac}")
        inv_before = {item["mac"]: item for item in self.monitor.get_inventory()}
        self.assertEqual(inv_before[fake_mac]["observedMac"], "")

        # Real MAC arrives for same IP -> fake 02:00: row deleted and favorite migrated
        real_mac_1 = "aa:bb:cc:11:22:33"
        self.monitor._upsert_inventory({
            "ip": ip, "mac": real_mac_1, "vendor": "TP-Link",
            "suggestedName": "Office PC", "arpType": "dynamic",
        })
        inv_after = {item["mac"]: item for item in self.monitor.get_inventory()}
        self.assertNotIn(fake_mac, inv_after)
        self.assertIn(real_mac_1, inv_after)
        self.assertEqual(inv_after[real_mac_1]["observedMac"], real_mac_1)
        self.assertTrue(inv_after[real_mac_1]["favorite"])

        # DHCP reassigns same IP to a second real MAC -> first MAC must become offline (no duplicate online IPs)
        real_mac_2 = "aa:bb:cc:44:55:66"
        self.monitor._upsert_inventory({
            "ip": ip, "mac": real_mac_2, "vendor": "Intel",
            "suggestedName": "New Laptop", "arpType": "dynamic",
        })
        online_on_ip = [item["mac"] for item in self.monitor.get_inventory() if item["ip"] == ip and item["isOnline"]]
        self.assertEqual(online_on_ip, [real_mac_2])

    def test_unified_history_logs_filtering_and_pagination(self):
        self.monitor._record_event(
            "DEVICE_OFFLINE", "CRITICAL", "AP Down", "Floor 2 AP unreachable",
            mac="aa:bb:cc:11:22:33", ip="192.168.10.2", device_name="Floor 2 AP",
        )
        self.monitor._record_event(
            "NEW_DEVICE", "WARNING", "New device joined", "Staff phone joined LAN",
            mac="aa:bb:cc:44:55:66", ip="192.168.10.99", device_name="Staff Phone",
        )
        self.monitor._record_event(
            "NETWORK_SCAN", "INFO", "LAN Scan", "Completed daily scan",
        )

        all_logs = self.monitor.get_history_logs(limit=2, offset=0)
        self.assertEqual(all_logs["total"], 3)
        self.assertEqual(len(all_logs["items"]), 2)
        self.assertTrue(all_logs["hasMore"])
        self.assertEqual(all_logs["stats"]["critical"], 1)
        self.assertEqual(all_logs["stats"]["warning"], 1)
        self.assertEqual(all_logs["stats"]["info"], 1)

        alerts_only = self.monitor.get_history_logs(category="alerts", severity="CRITICAL")
        self.assertEqual(alerts_only["total"], 1)
        self.assertEqual(alerts_only["items"][0]["ip"], "192.168.10.2")

        search_hit = self.monitor.get_history_logs(search="192.168.10.99")
        self.assertEqual(search_hit["total"], 1)
        self.assertEqual(search_hit["items"][0]["deviceName"], "Staff Phone")

        # Insert a detected game session and verify detailed game history log output
        with self.monitor._connect() as db:
            db.execute(
                """INSERT INTO game_activity_logs
                   (id, timestamp, ip, player, mac, device_name, vendor, device_type,
                    game_id, game_name, game_category, game_icon, connected_to,
                    router_ip, zone_label, matched_indicator, detection_method, is_active)
                   VALUES ('sess-1', '2026-11-24T06:00:00Z', '192.168.10.55', 'vincent',
                           'aa:bb:cc:77:88:99', 'Staff Android', 'Samsung', 'mobile',
                           'mlbb', 'Mobile Legends: Bang Bang', 'MOBA', '🎮', 'Floor 2 AP',
                           '192.168.10.1', 'Main Office', 'api.mobilelegends.com', 'Wireshark TLS SNI', 1)"""
            )
        gaming_logs = self.monitor.get_history_logs(category="gaming")
        self.assertEqual(gaming_logs["total"], 1)
        g = gaming_logs["items"][0]
        self.assertEqual(g["eventType"], "GAME_DETECTED")
        self.assertIn("Mobile Legends: Bang Bang", g["title"])
        self.assertIn("api.mobilelegends.com", g["message"])
        self.assertIn("Wireshark TLS SNI", g["message"])
        self.assertEqual(g["gameDetails"]["player"], "vincent")
        self.assertEqual(g["gameDetails"]["connectedTo"], "Floor 2 AP")

    def test_lan_target_speedtest_measures_router_and_rejects_invalid_ip(self):
        with (
            patch.object(self.monitor, "_probe_icmp", return_value=(True, 1.4)),
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(False, False, None)),
        ):
            res = self.monitor.run_speedtest(
                target={"targetType": "router", "targetIp": "192.168.10.1", "targetName": "Main Router"}
            )
        self.assertEqual(res["targetType"], "router")
        self.assertEqual(res["targetIp"], "192.168.10.1")
        self.assertEqual(res["targetName"], "Main Router")
        self.assertEqual(res["pingMs"], 1.4)
        self.assertEqual(res["packetLossPct"], 0.0)
        self.assertIn("Latency Only", res["rating"])

        with self.assertRaises(RuntimeError):
            self.monitor.run_speedtest(
                target={"targetType": "device", "targetIp": "127.0.0.1", "targetName": "Loopback"}
            )


if __name__ == "__main__":
    unittest.main()
