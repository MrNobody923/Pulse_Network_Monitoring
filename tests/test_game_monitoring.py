from http.client import HTTPMessage
from unittest.mock import Mock, patch
from tests.support import MonitorTestCase


class GameMonitoringTests(MonitorTestCase):
    def test_lan_discovery_does_not_identify_an_app_or_the_ip_inventory_owner(self):
        ip = "192.168.1.45"
        self.monitor._upsert_inventory(self.discovered_device(ip))
        payload = {"ip": ip, "gameId": "steam", "detectionMethod": "Real-Time LAN Broadcast Listener"}
        result = self.monitor.record_game_detection(payload, include_activity=False)
        self.assertEqual(result["hintType"], "lan_discovery")
        self.assertIsNone(result["detection"])
        self.monitor.record_game_detection({**payload, "detectionMethod": "Live DNS"}, include_activity=False)
        with self.monitor._connect() as db:
            db.execute("UPDATE game_activity_logs SET detection_method=? WHERE ip=?", (payload["detectionMethod"], ip))
        row = self.monitor.get_game_activity()["logs"][0]
        self.assertEqual(row["deviceName"], "Unverified device")
        self.assertEqual((row["mac"], row["connectedTo"], row["isActive"]), ("", "", False))

    def test_automatic_game_detection_process_online_devices_and_expiry(self) -> None:
        self.monitor._skip_live_probe_in_test = True

        # Process signature matching for PC & emulator games
        roblox_sig = self.monitor._match_game_signature(process="RobloxPlayerBeta.exe")
        assert roblox_sig is not None
        self.assertEqual(roblox_sig["id"], "roblox")
        val_sig = self.monitor._match_game_signature(process="valorant.exe")
        assert val_sig is not None
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
            "domain": "api.mobilelegends.com",
            "detectionMethod": "Live DNS (192.168.0.224:53)",
        })
        self.assertTrue(det["success"])
        proc_det = self.monitor.record_game_detection({
            "ip": self.monitor.HOST_DNS_IP,
            "process": "RobloxPlayerBeta.exe",
            "detectionMethod": "Auto Process Sensor (Live Open Game)",
        })
        self.assertEqual(proc_det["detection"]["gameId"], "roblox")

        with patch.dict("os.environ", {"PULSE_ENABLE_BACKGROUND_SCANS": "0"}):
            activity = self.monitor.get_game_activity(50)
        self.assertFalse(activity["autoScanActive"])
        with patch.dict("os.environ", {"PULSE_ENABLE_BACKGROUND_SCANS": "1"}):
            self.assertTrue(self.monitor.get_game_activity(50)["autoScanActive"])
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

    @patch.dict("os.environ", {"PULSE_ALLOW_NETWORK_CHANGES": "1"})
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
            "domain": "api.mobilelegends.com",
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
        ml_sig = self.monitor._match_game_signature(domain="api.mobilelegends.com")
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "api.mobilelegends.com", ml_sig, blocks))
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "connectivitycheck.gstatic.com", None, blocks))
        self.assertIsNotNone(self.monitor._should_sinkhole_query("192.168.1.77", "google.com", None, blocks))
        # Other company users remain completely unaffected
        self.assertIsNone(self.monitor._should_sinkhole_query("192.168.1.88", "api.mobilelegends.com", ml_sig, blocks))
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

    @patch.dict("os.environ", {"PULSE_ALLOW_NETWORK_CHANGES": "1"})
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
            "dnsForwardedTotal": 39,
            "dnsForwardFailures": 3,
            "dnsClients": {
                "192.168.1.77": "2026-11-16T12:00:00Z",
                "127.0.0.1": "2026-11-16T12:00:00Z",
                "192.168.0.224": "2026-11-16T12:00:00Z",
            },
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
        self.assertEqual(activity["sensorStatus"]["dnsForwardFailures"], 3)

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
        self.assertEqual(scan_res["detectedCount"], 0)
        self.assertEqual(scan_res["openPortHits"], 1)
        self.assertEqual(scan_res["gameActivity"]["summary"]["activeCount"], 0)
        self.assertEqual(self.monitor.get_game_blocks(), [])
        self.monitor.record_game_detection({"ip": "192.168.2.99", "domain": "minecraft.net", "skipAutoPrevent": True})

        throttle_request = {
            "ip": "192.168.2.99",
            "gameId": "minecraft",
            "scope": "device_throttle",
            "cutWifi": False,
        }
        failed = self.monitor.block_game_session(throttle_request)
        self.assertFalse(failed["success"])
        self.assertTrue(failed["enforcementDetails"]["requiresSetup"])
        self.assertEqual(self.monitor.get_game_blocks(), [])
        self.assertEqual(self.monitor.get_game_activity()["summary"]["activeCount"], 1)

        with patch.object(self.monitor, "_enforce_router_client_block", return_value=["192.168.0.1"]):
            thr_res = self.monitor.block_game_session(throttle_request)
        self.assertTrue(thr_res["success"])
        thr_blocks = self.monitor.get_game_blocks()
        self.assertEqual(len(thr_blocks), 1)
        self.assertEqual(thr_blocks[0]["throttleRouters"], ["192.168.0.1"])
        mc_sig = self.monitor._match_game_signature(game_id="minecraft")
        self.assertIsNone(self.monitor._should_sinkhole_query("192.168.2.99", "minecraft.net", mc_sig, thr_blocks))
        self.assertFalse(self.monitor.unblock_game_rule(thr_res["ruleId"])["success"])
        self.assertEqual(self.monitor.get_game_blocks(), thr_blocks)
        with patch.object(self.monitor, "_enforce_router_client_block", return_value=["192.168.0.1"]) as restore:
            self.assertTrue(self.monitor.unblock_game_rule(thr_res["ruleId"])["success"])
        self.assertEqual(restore.call_args.kwargs["router_targets"], ["192.168.0.1"])
        self.assertEqual(self.monitor.get_game_blocks(), [])

    def test_open_port_reports_and_legacy_hints_do_not_count_as_live_games(self):
        ip = "192.168.1.77"
        result = self.monitor.record_game_detection({
            "ip": ip, "port": 27015, "detectionMethod": "Auto LAN Game Port Sensor",
        })
        self.assertTrue(result["portHint"])
        self.assertIsNone(result["detection"])
        self.assertEqual(result["gameActivity"]["logs"], [])
        existing = self.monitor.record_game_detection({"ip": ip, "domain": "minecraft.net"})["detection"]
        with self.monitor._connect() as db:
            db.execute(
                "UPDATE game_activity_logs SET detection_method=? WHERE id=?",
                ("Whole-Topology Port Scan", existing["id"]),
            )
        reported = self.monitor.get_game_activity()
        self.assertTrue(reported["logs"][0]["portHint"])
        self.assertEqual(reported["summary"]["activeCount"], 0)
        self.assertEqual(reported["summary"]["totalCount"], 0)
        with self.assertRaisesRegex(ValueError, "open port"):
            self.monitor.block_game_session({"sessionId": existing["id"], "scope": "device_wifi_cut"})
        cached = self.monitor.record_game_detection({
            "ip": ip, "domain": "minecraft.net", "detectionMethod": "Auto DNS Cache Sensor",
        })
        self.assertEqual(cached["hintType"], "dns_cache")
        self.assertIsNone(cached["detection"])
        new_game = self.monitor.record_game_detection({"ip": ip, "domain": "minecraft.net"})["detection"]
        self.assertIsNotNone(new_game)
        self.assertNotEqual(new_game["id"], existing["id"])

    def test_dismissed_process_session_stays_dismissed_until_game_reopens(self) -> None:
        from pulse_monitor.game_detector import host_game_processes

        ip = self.monitor.HOST_DNS_IP
        games = host_game_processes(ip, ["RobloxPlayerLauncher.exe", "HD-Player.exe", "cs2.exe"])
        self.assertEqual(list(games), [(ip, "steam")])
        payload = games[(ip, "steam")]
        session = self.monitor.record_game_detection(payload)["detection"]
        self.monitor.dismiss_game_session(session["id"])
        heartbeat = self.monitor.record_game_detection(payload)
        self.assertIsNone(heartbeat["detection"])
        self.assertEqual(len(heartbeat["gameActivity"]["logs"]), 1)
        self.assertTrue(heartbeat["gameActivity"]["logs"][0]["isDismissed"])
        self.assertEqual(heartbeat["gameActivity"]["summary"]["activeCount"], 0)
        self.monitor.mark_game_session_ended_by_ip_game(ip, "steam")
        reopened = self.monitor.record_game_detection(payload)["detection"]
        self.assertNotEqual(reopened["id"], session["id"])
        self.assertTrue(reopened["isActive"])

    def test_steam_client_tracks_process_lifecycle_without_treating_traffic_as_a_launch(self) -> None:
        from pulse_monitor.game_detector import STEAM_CLIENT_ID, host_game_processes

        self.monitor._skip_live_probe_in_test = True
        ip = self.monitor.HOST_DNS_IP
        self.assertFalse(host_game_processes(ip, ["steamwebhelper.exe", "SteamService.exe"]))
        payload = host_game_processes(ip, ["Steam.exe", "steam.exe"])[(ip, STEAM_CLIENT_ID)]
        self.assertEqual(self.monitor._match_game_signature(port=27036)["id"], "steam")
        traffic = self.monitor.record_game_detection({"ip": ip, "domain": "api.steampowered.com"})["detection"]
        self.assertEqual(traffic["gameId"], "steam")
        with self.assertRaisesRegex(ValueError, "steam.exe process report"):
            self.monitor.record_game_detection({"ip": ip, "gameId": STEAM_CLIENT_ID})

        policy = {**self.monitor.get_gaming_policy(), "autoPreventEnabled": True, "autoCutWifi": True}
        with patch.object(self.monitor, "get_gaming_policy", return_value=policy), patch.object(
            self.monitor, "block_game_session"
        ) as restrict, patch.object(self.monitor, "_match_active_block_rule") as find_rule:
            session = self.monitor.record_game_detection(payload)["detection"]
            repeated = self.monitor.record_game_detection(payload)["detection"]
            restrict.assert_not_called()
            find_rule.assert_not_called()
        self.assertEqual(session["id"], repeated["id"])
        self.assertEqual(session["gameName"], "Steam Client")
        self.assertEqual(session["matchedIndicator"], "Process steam.exe")
        self.assertEqual(session["detectionMethod"], "Windows client process")
        with self.assertRaisesRegex(ValueError, "monitoring only"):
            self.monitor.block_game_session({"sessionId": session["id"], "scope": "device_throttle"})

        stopped = self.monitor.mark_game_session_ended_by_ip_game(ip, STEAM_CLIENT_ID)["gameActivity"]
        self.assertEqual({row["gameId"] for row in stopped["logs"] if row["isActive"]}, {"steam"})
        reopened = self.monitor.record_game_detection(payload)["detection"]
        self.assertNotEqual(session["id"], reopened["id"])

    def test_riot_and_supercell_titles_use_distinct_signals(self) -> None:
        from pulse_monitor.game_detector import RIOT_CLIENT_ID, host_game_processes

        self.monitor._skip_live_probe_in_test = True
        ip = self.monitor.HOST_DNS_IP
        games = host_game_processes(ip, [
            "RiotClientServices.exe", "LeagueClientUx.exe", "League of Legends.exe",
            "VALORANT-Win64-Shipping.exe", "RobloxPlayerBeta.exe", "LoR.exe",
        ])
        self.assertEqual(
            {game_id for _, game_id in games}, {RIOT_CLIENT_ID, "lol", "valorant", "roblox", "runeterra"},
        )
        for domain, game_id in (
            ("wildrift.leagueoflegends.com", "wildrift_website"),
            ("game.clashofclans.com", "clashofclans"),
            ("game.clashroyaleapp.com", "clashroyale"),
            ("game.brawlstarsgame.com", "brawlstars"),
            ("haydaygame.com", "hayday"),
        ):
            with self.subTest(domain=domain):
                self.assertEqual(self.monitor._match_game_signature(domain=domain)["id"], game_id)
        for domain in (
            "auth.riotgames.com", "riotcdn.net", "teamfighttactics.leagueoflegends.com",
            "accounts.supercell.com", "supercellid.com", "haydaygame.com.example.org",
        ):
            with self.subTest(domain=domain):
                self.assertIsNone(self.monitor._match_game_signature(domain=domain))
        self.assertIsNone(self.monitor._match_game_signature(port=9339))

        with self.assertRaisesRegex(ValueError, "RiotClientServices.exe process report"):
            self.monitor.record_game_detection({"ip": ip, "gameId": RIOT_CLIENT_ID})
        riot = self.monitor.record_game_detection(games[ip, RIOT_CLIENT_ID])["detection"]
        self.assertEqual(riot["detectionMethod"], "Windows client process")
        with self.assertRaisesRegex(ValueError, "monitoring only"):
            self.monitor.block_game_session({"sessionId": riot["id"], "scope": "device_throttle"})
        self.monitor.record_game_detection(games[ip, "lol"])
        updated = self.monitor.mark_game_session_ended_by_ip_game(ip, RIOT_CLIENT_ID)["gameActivity"]
        self.assertEqual({row["gameId"] for row in updated["logs"] if row["isActive"]}, {"lol"})

    def test_riot_website_alerts_as_monitoring_only_activity(self) -> None:
        from pulse_monitor.game_detector import RIOT_WEBSITE_ID
        from pulse_monitor.wireshark_capture import build_wireshark_display_filter

        self.monitor._skip_live_probe_in_test = True
        match = self.monitor._match_game_signature
        self.assertEqual(match(domain="WWW.RIOTGAMES.COM.")["id"], RIOT_WEBSITE_ID)
        self.assertEqual(match(domain="riotgames.com")["id"], RIOT_WEBSITE_ID)
        for domain in ("auth.riotgames.com", "support.riotgames.com", "riotgames.com.example.org"):
            with self.subTest(domain=domain):
                self.assertIsNone(match(domain=domain))
        display_filter = build_wireshark_display_filter()
        self.assertIn('dns.qry.name == "riotgames.com"', display_filter)
        self.assertIn('tls.handshake.extensions_server_name == "www.riotgames.com"', display_filter)
        self.assertNotIn('contains "riotgames.com"', display_filter)

        ip = self.monitor.HOST_DNS_IP
        payload = {"ip": ip, "domain": "www.riotgames.com", "detectionMethod": "Wireshark TLS SNI"}
        policy = {**self.monitor.get_gaming_policy(), "autoPreventEnabled": True}
        with (
            patch.object(self.monitor, "get_gaming_policy", return_value=policy),
            patch.object(self.monitor, "block_game_session") as restrict,
            patch.object(self.monitor, "broadcast") as broadcast,
        ):
            result = self.monitor.record_game_detection(payload)["detection"]
            restrict.assert_not_called()
            broadcast.assert_any_call("game_detected", {"detection": result})
            self.assertTrue(any(
                event == "new_alert" and "Riot Games website observed" in alert["title"]
                for (event, alert), _ in broadcast.call_args_list
            ))
        self.assertEqual(result["gameId"], RIOT_WEBSITE_ID)
        self.assertEqual(result["gameCategory"], "Website")
        with self.assertRaisesRegex(ValueError, "monitoring only"):
            self.monitor.block_game_session({"sessionId": result["id"], "scope": "device_throttle"})
        with self.assertRaisesRegex(ValueError, "matching website hostname"):
            self.monitor.record_game_detection({**payload, "domain": "auth.riotgames.com", "gameId": RIOT_WEBSITE_ID})

    def test_mobile_legends_website_and_game_create_distinct_detections(self) -> None:
        from pulse_monitor.game_detector import MLBB_WEBSITE_ID

        self.monitor._skip_live_probe_in_test = True
        match = self.monitor._match_game_signature
        for domain in ("mobilelegends.com", "WWW.MOBILELEGENDS.COM.", "play.mobilelegends.com"):
            with self.subTest(domain=domain):
                self.assertEqual(match(domain=domain)["id"], MLBB_WEBSITE_ID)
        self.assertIsNone(match(domain="www.mobilelegends.com.example.org"))
        self.assertEqual(match(domain="api.mobilelegends.com")["id"], "mlbb")
        self.assertEqual(match(domain="sea-api-02.youngjoygame.com")["id"], "mlbb")

        ip = self.monitor.HOST_DNS_IP
        payload = {"ip": ip, "detectionMethod": "Wireshark DNS Wire"}
        website = self.monitor.record_game_detection({**payload, "domain": "www.mobilelegends.com"})["detection"]
        game = self.monitor.record_game_detection({**payload, "domain": "api.mobilelegends.com"})["detection"]
        self.assertEqual(website["gameCategory"], "Website")
        self.assertEqual(website["gameId"], MLBB_WEBSITE_ID)
        self.assertEqual(game["gameId"], "mlbb")
        self.assertNotEqual(website["id"], game["id"])
        with self.assertRaisesRegex(ValueError, "monitoring only"):
            self.monitor.block_game_session({"sessionId": website["id"], "scope": "device_throttle"})

    def test_supercell_website_alerts_are_distinct_from_game_traffic(self) -> None:
        self.monitor._skip_live_probe_in_test = True
        match = self.monitor._match_game_signature
        for domain, signature in (
            ("www.supercell.com", "supercell_website"),
            ("clashofclans.com", "clashofclans_website"),
            ("www.clashroyale.com", "clashroyale_website"),
            ("brawlstars.com", "brawlstars_website"),
            ("www.hayday.com", "hayday_website"),
            ("boombeach.supercell.com", "boombeach_website"),
            ("mo.co", "moco_website"),
            ("squadbusters.supercell.com", "squadbusters_website"),
        ):
            with self.subTest(domain=domain):
                self.assertEqual(match(domain=domain)["id"], signature)
        for domain in ("accounts.supercell.com", "supercellid.com", "brawlstars.com.example.org"):
            with self.subTest(domain=domain):
                self.assertIsNone(match(domain=domain))
        self.assertIsNone(match(port=9339))

        payload = {"ip": self.monitor.HOST_DNS_IP, "detectionMethod": "Wireshark DNS Wire"}
        website = self.monitor.record_game_detection({**payload, "domain": "clashofclans.com"})["detection"]
        game = self.monitor.record_game_detection({**payload, "domain": "game.clashofclans.com"})["detection"]
        self.assertEqual(website["gameCategory"], "Website")
        self.assertEqual(website["gameId"], "clashofclans_website")
        self.assertEqual(game["gameId"], "clashofclans")
        self.assertNotEqual(website["id"], game["id"])
        with self.assertRaisesRegex(ValueError, "monitoring only"):
            self.monitor.block_game_session({"sessionId": website["id"], "scope": "device_throttle"})

    def test_wild_rift_public_site_reports_website_activity(self) -> None:
        self.monitor._skip_live_probe_in_test = True
        detection = self.monitor.record_game_detection({
            "ip": self.monitor.HOST_DNS_IP,
            "domain": "WILDRIFT.LEAGUEOFLEGENDS.COM.",
            "detectionMethod": "Wireshark TLS SNI",
        })["detection"]
        self.assertEqual(detection["gameId"], "wildrift_website")
        self.assertEqual(detection["gameCategory"], "Website")
        self.assertIsNone(self.monitor._match_game_signature(domain="wildrift.leagueoflegends.com.example.org"))
        with self.assertRaisesRegex(ValueError, "monitoring only"):
            self.monitor.block_game_session({"sessionId": detection["id"], "scope": "device_throttle"})

    def test_android_foreground_reports_confirm_and_end_game_sessions(self) -> None:
        from android_game_sensor import foreground_game_package
        from pulse_monitor.game_detector import ANDROID_APP_DETECTION
        from pulse_monitor.http_handler import RequestHandler

        heading = "ACTIVITY MANAGER TOP-RESUMED (dumpsys activity top-resumed)\n"
        package = "com.riotgames.league.wildrift"
        fixture = f"{heading}packageName={package} processName={package}\nstate=RESUMED\n"
        self.assertEqual(foreground_game_package(fixture), package)
        self.assertIsNone(foreground_game_package(fixture.replace("RESUMED\n", "PAUSED\n")))
        self.assertIsNone(foreground_game_package(heading + "packageName=com.android.chrome processName=com.android.chrome\n"))
        with self.assertRaisesRegex(RuntimeError, "top-resumed Android activity"):
            foreground_game_package("unknown command")

        self.monitor._skip_live_probe_in_test = True
        ip = "192.168.0.28"
        handler = RequestHandler.__new__(RequestHandler)
        handler.headers = {"Host": "127.0.0.1:3000"}
        handler.client_address = (ip, 51234)
        handler._send_error_json = Mock()
        handler._send_json = Mock()
        report = {"ip": ip, "package": "com.mobile.legends"}
        handler._handle_gaming_post(self.monitor, "/api/gaming/android", report)
        handler._send_error_json.assert_called_once_with("Android game reports require a local sensor", 403)
        handler._send_json.assert_not_called()
        handler.client_address = ("127.0.0.1", 51234)
        with self.assertRaisesRegex(ValueError, "local Android sensor"):
            handler._handle_gaming_post(self.monitor, "/api/gaming/detect", {
                "ip": ip, "gameId": "mlbb", "detectionMethod": ANDROID_APP_DETECTION,
            })

        network = {"ip": ip, "domain": "api.mobilelegends.com", "detectionMethod": "Wireshark DNS Wire"}
        inferred = self.monitor.record_game_detection(network)["detection"]
        handler._handle_gaming_post(self.monitor, "/api/gaming/android", report)
        confirmed = handler._send_json.call_args.args[0]["detection"]
        self.assertEqual(confirmed["detectionMethod"], ANDROID_APP_DETECTION)
        self.assertEqual(confirmed["gameId"], "mlbb")
        self.assertNotEqual(confirmed["id"], inferred["id"])
        self.assertEqual(self.monitor.report_android_game_activity(report)["detection"]["id"], confirmed["id"])
        self.assertIsNone(self.monitor.record_game_detection(network)["detection"])
        activity = self.monitor.get_game_activity()
        self.assertEqual({row["id"] for row in activity["logs"] if row["isActive"]}, {confirmed["id"]})
        handler._handle_gaming_post(self.monitor, "/api/gaming/android", {**report, "ended": True})
        self.assertEqual(self.monitor.get_game_activity()["summary"]["activeCount"], 0)
        with self.assertRaisesRegex(ValueError, "Unrecognized Android game package"):
            self.monitor.report_android_game_activity({**report, "package": "com.android.chrome"})
        with self.assertRaisesRegex(ValueError, "monitored LAN subnet"):
            self.monitor.report_android_game_activity({**report, "ip": "127.0.0.1"})

    def test_host_sensor_retries_process_reports_and_ends_previous_ip(self) -> None:
        from host_game_sensor import HostGameSensor

        sensor = HostGameSensor(dns_host="192.168.0.20")
        with patch.object(sensor, "_post_detection", side_effect=[False, True, True]) as detect, patch.object(
            sensor, "_post_dismiss", side_effect=[False, True]
        ) as dismiss:
            sensor._scan_host_processes(["RobloxPlayerBeta.exe"])
            sensor._scan_host_processes(["RobloxPlayerBeta.exe"])
            sensor._scan_host_processes(["RobloxPlayerBeta.exe"])
            self.assertEqual(detect.call_count, 2)
            sensor.dns_host = "192.168.0.21"
            sensor._scan_host_processes(["RobloxPlayerBeta.exe"])
            sensor._scan_host_processes(["RobloxPlayerBeta.exe"])
        self.assertEqual(detect.call_args.args[0]["ip"], "192.168.0.21")
        self.assertEqual(dismiss.call_count, 2)
        dismiss.assert_called_with("192.168.0.20", "roblox")

    @patch.dict("os.environ", {"PULSE_ENABLE_BACKGROUND_SCANS": "1", "PULSE_ALLOW_NETWORK_CHANGES": "1"})
    def test_companion_sensor_runs_background_detectors_with_a_qos_rule(self) -> None:
        from host_game_sensor import HostGameSensor

        sensor = HostGameSensor(dns_host="192.168.0.20")
        sensor._apply_policy_and_blocks({
            "policy": {"preventionMode": "alert_only", "restrictionsEnabled": True},
            "blocks": [{"id": "qos", "ip": sensor.dns_host, "gameId": "*", "scope": "device_throttle"}],
        })
        with (
            patch("host_game_sensor.list_windows_processes") as processes,
            patch.object(sensor, "_scan_host_netstat_ports") as netstat,
            patch.object(sensor, "_sweep_lan_game_ports") as sweep,
            patch.object(sensor._stop, "wait", return_value=True),
        ):
            sensor._auto_detect_loop()
        processes.assert_not_called()
        netstat.assert_called_once_with()
        sweep.assert_called_once_with()

    def test_host_sensor_uses_selected_bind_address_and_sibling_api_urls(self):
        from host_game_sensor import HostGameSensor, _detect_local_lan_ip

        with patch("host_game_sensor.socket.socket", side_effect=OSError):
            self.assertEqual(_detect_local_lan_ip(), "")

        sensor = HostGameSensor(dns_host="127.0.0.1", api_url="http://localhost:3000/api/gaming/detect/")
        with (
            patch.object(sensor, "_ensure_dns_listeners") as bind,
            patch.object(sensor, "_ensure_wireshark_engine"),
            patch("host_game_sensor.threading.Thread"),
            patch.object(sensor._stop, "wait"),
        ):
            sensor.serve_forever()
        bind.assert_called_once_with("127.0.0.1")
        self.assertEqual(sensor.heartbeat_url, "http://localhost:3000/api/gaming/sensor-heartbeat")

    def test_managed_endpoints_identify_accounts_across_subnets(self) -> None:
        import os
        from unittest.mock import Mock
        from pulse_monitor.http_handler import RequestHandler

        self.monitor._skip_live_probe_in_test = True
        handler = RequestHandler.__new__(RequestHandler)
        handler.headers = HTTPMessage()
        handler.client_address = ("10.20.40.12", 49152)
        handler._send_json = Mock()
        handler._send_error_json = Mock()
        body = {"player": "COMPANY\\Alice", "process": "RobloxPlayerBeta.exe"}
        with patch.dict(os.environ, {
            "PULSE_GAME_ENDPOINT_TOKEN": "test-enrollment",
            "PULSE_LAN_SUBNETS": "10.20.40.0/24,172.27.18.0/24",
        }):
            handler._handle_game_endpoint(self.monitor, body)
            handler._send_error_json.assert_called_once_with("Endpoint enrollment token is required", 403)
            handler.headers["Authorization"] = "Bearer test-enrollment"
            with patch("pulse_monitor.game_detector.time.monotonic", return_value=200.0):
                handler._handle_game_endpoint(self.monitor, {"heartbeat": True, "ip": "10.20.40.99"})
                idle = self.monitor.get_game_activity()
                self.assertEqual(idle["coverage"]["subnets"], ["10.20.40.0/24", "172.27.18.0/24"])
                self.assertEqual(idle["coverage"]["endpointIps"], ["10.20.40.12"])
                self.assertFalse(idle["logs"])
            with patch("pulse_monitor.game_detector.time.monotonic", return_value=291.0):
                self.assertFalse(self.monitor.get_game_activity()["coverage"]["endpointIps"])
            handler._handle_game_endpoint(self.monitor, body)
            handler._handle_game_endpoint(self.monitor, {**body, "player": "COMPANY\\Eve"})
            handler.client_address = ("172.27.18.40", 49153)
            handler._handle_game_endpoint(self.monitor, {**body, "player": "COMPANY\\Bob"})
            activity = self.monitor.get_game_activity(limit=1)
            self.assertEqual(activity["summary"]["activeCount"], 3)
            self.assertEqual({row["player"] for row in activity["logs"]}, {"company\\alice", "company\\bob", "company\\eve"})
            self.assertIn("172.27.18.40", {device["ip"] for device in activity["onlineDevices"]})

            handler.client_address = ("10.20.40.12", 49152)
            handler._handle_game_endpoint(self.monitor, {
                "player": body["player"], "gameId": "roblox", "ended": True,
            })
            self.assertEqual(self.monitor.get_game_activity()["summary"]["activeCount"], 2)
            handler._handle_game_endpoint(self.monitor, {**body, "process": "steam.exe"})
            handler._send_json.assert_called_with({"success": True})
            steam = next(row for row in self.monitor.get_game_activity()["logs"] if row["gameId"] == "steam_client")
            self.assertEqual(steam["ip"], "10.20.40.12")
            self.assertEqual(steam["player"], "company\\alice")
            self.assertEqual(steam["gameId"], "steam_client")
            self.assertEqual(steam["detectionMethod"], "Managed Windows client process")
            handler._handle_game_endpoint(self.monitor, {
                "player": body["player"], "gameId": "steam_client", "ended": True,
            })
            self.assertEqual(self.monitor.get_game_activity()["summary"]["activeCount"], 2)
            handler.client_address = ("10.20.55.12", 49152)
            with self.assertRaisesRegex(ValueError, "monitored LAN subnet"):
                handler._handle_game_endpoint(self.monitor, body)
            self.assertEqual(
                self.monitor._parse_syslog_game_text("gateway DST=10.20.40.1 SRC=172.27.18.40 DPT=25565", "10.20.40.1"),
                ("172.27.18.40", "", 25565),
            )
            self.assertIsNone(self.monitor._parse_syslog_game_text("router online minecraft.net", "10.20.40.1"))

    @patch.dict("os.environ", {"PULSE_ALLOW_NETWORK_CHANGES": "1"})
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
        self.assertEqual((self.monitor._match_game_signature(domain="sea-api-02.youngjoygame.com") or {}).get("id"), "mlbb")
        self.assertEqual((self.monitor._match_game_signature(domain="dl.codm.garena.com") or {}).get("id"), "codm")
        self.assertEqual((self.monitor._match_game_signature(domain="fortnite.com") or {}).get("id"), "fortnite")
        self.assertEqual((self.monitor._match_game_signature(process="FortniteClient-Win64-Shipping.exe") or {}).get("id"), "fortnite")
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
            "scope": "device_game",
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

        # 4. Verify wire-level DoH NXDOMAIN and the targeted game DNS rule.
        from host_game_sensor import HostGameSensor

        sensor = HostGameSensor(dns_host="127.0.0.1", dns_port=0, syslog_port=0)
        doh_pkt = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04mask\x06icloud\x03com\x00\x00\x01\x00\x01"
        doh_resp = sensor._process_dns_query(doh_pkt, "192.168.1.90")
        assert doh_resp is not None
        self.assertEqual(doh_resp[0:4], b"\xaa\xbb\x81\x83")

        sensor._apply_policy_and_blocks({
            "policy": {"preventionMode": "alert_only", "restrictionsEnabled": True},
            "blocks": [{"id": "r1", "ip": "192.168.1.90", "gameId": "mlbb", "scope": "device_game", "cutWifi": False}],
        })
        mlbb_pkt = b"\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api\x0dmobilelegends\x03com\x00\x00\x01\x00\x01"
        mlbb_resp = sensor._process_dns_query(mlbb_pkt, "192.168.1.90")
        assert mlbb_resp is not None
        self.assertEqual(mlbb_resp[-4:], b"\x00\x00\x00\x00")

    @patch.dict("os.environ", {
        "PULSE_ALLOW_NETWORK_CHANGES": "0",
        "PULSE_ALLOW_SPEED_TESTS": "0",
        "PULSE_ENABLE_DNS_FORWARDING": "0",
        "PULSE_ENABLE_BACKGROUND_SCANS": "0",
    })
    def test_monitoring_only_ignores_saved_schedules_and_network_restrictions(self):
        from host_game_sensor import HostGameSensor

        self.monitor.config["isp"]["speedTestIntervalMinutes"] = 1
        self.monitor.config["gaming"]["preventionMode"] = "auto_wifi_cut"
        self.assertEqual(self.monitor._speedtest_interval_sec(), 0)
        with self.assertRaisesRegex(RuntimeError, "Active speed tests are disabled"):
            self.monitor.run_speedtest()
        self.assertEqual(self.monitor.get_gaming_policy()["preventionMode"], "alert_only")
        with self.assertRaisesRegex(ValueError, "per-device throttle or disconnect"):
            self.monitor.block_game_session({})
        with self.assertRaisesRegex(ValueError, "Router DNS changes are disabled"):
            self.monitor.configure_router_game_dns()

        sensor = HostGameSensor(dns_host="192.168.1.89")
        sensor._apply_policy_and_blocks({
            "blocks": [{"ip": "*", "gameId": "*"}],
            "policy": {"preventionMode": "auto_wifi_cut", "restrictionsEnabled": True},
        })
        self.assertEqual(sensor._active_blocks, [])
        self.assertEqual(sensor._prevention_mode, "alert_only")
        with patch("host_game_sensor.threading.Thread") as thread:
            sensor._ensure_dns_listeners(sensor.dns_host)
            thread.assert_not_called()

        with (
            patch.object(sensor, "_sweep_lan_game_ports") as sweep,
            patch.object(sensor, "_scan_host_netstat_ports"),
            patch.object(sensor._stop, "wait", return_value=True),
        ):
            sensor._auto_detect_loop()
        sweep.assert_not_called()

    @patch.dict("os.environ", {"PULSE_ALLOW_NETWORK_CHANGES": "0"})
    def test_manual_device_disconnect_requires_a_current_detection_and_router_confirmation(self):
        self.monitor._skip_live_probe_in_test = True
        ip = "192.168.1.77"
        mac = "02:aa:bb:cc:dd:ee"
        self.monitor._upsert_inventory({
            "ip": ip, "mac": mac, "vendor": "Apple", "suggestedName": "Staff phone", "arpType": "dynamic",
        })
        signal = {"ip": ip, "domain": "api.mobilelegends.com", "detectionMethod": "Live DNS"}
        session = self.monitor.record_game_detection(signal)["detection"]
        request = {"sessionId": session["id"], "ip": ip, "gameId": "mlbb", "scope": "device_wifi_cut"}
        with self.assertRaisesRegex(ValueError, "current game detection"):
            self.monitor.block_game_session({"ip": ip, "scope": "device_wifi_cut"})
        with self.assertRaisesRegex(ValueError, "different device"):
            self.monitor.block_game_session({**request, "ip": "192.168.1.78"})
        self.assertFalse(self.monitor.block_game_session(request)["success"])
        self.assertEqual(self.monitor.get_game_blocks(), [])

        router = Mock()
        router.read.return_value = {"present": False}
        router.change.return_value = True
        with patch.object(self.monitor, "_manual_game_router", return_value=router):
            result = self.monitor.block_game_session(request)
        self.assertTrue(result["success"])
        router.has_client.assert_called_once_with(ip, "02-AA-BB-CC-DD-EE")
        self.assertEqual(router.change.call_args.args[0]["mode"], "cut")
        rule = self.monitor.get_game_blocks()[0]
        self.assertEqual(rule["cutRouters"], ["192.168.0.1"])
        self.assertEqual(rule["controlStatus"], "active")
        self.assertIsNone(self.monitor._should_sinkhole_query(ip, "mobilelegends.com", None, [rule]))
        self.assertFalse(self.monitor.unblock_game_rule(rule["id"])["success"])
        self.assertEqual(self.monitor.get_game_blocks()[0]["controlStatus"], "restore_pending")
        with patch.object(self.monitor, "_manual_game_router", return_value=router):
            self.assertTrue(self.monitor.unblock_game_rule(rule["id"])["success"])
        self.assertTrue(router.change.call_args.kwargs["restore"])

        new_session = self.monitor.record_game_detection(signal)["detection"]
        router.read.return_value = {"enable": "off", "key": "42", "up_band": "0", "down_band": "0", "up_unit": "KB/s", "down_unit": "KB/s"}
        with patch.object(self.monitor, "_manual_game_router", return_value=router):
            result = self.monitor.block_game_session({
                **request, "sessionId": new_session["id"], "scope": "device_throttle",
                "downloadKbps": 800, "uploadKbps": 400, "durationMinutes": 1,
            })
        self.assertTrue(result["success"])
        self.assertEqual(router.change.call_args.args[0]["after"]["down_band"], "100")
        self.assertEqual(self.monitor.get_game_blocks()[0]["limitsKbps"], {"download": 800, "upload": 400})
        self.assertFalse(self.monitor.get_gaming_policy()["autoPreventEnabled"])
        with self.monitor._connect() as db:
            db.execute("UPDATE game_block_rules SET expires_at=? WHERE id=?", ("2000-01-01T00:00:00Z", result["ruleId"]))
        with (
            patch.object(self.monitor, "_manual_game_router", return_value=router),
            patch.object(self.monitor._stop, "is_set", side_effect=[False, True]),
            patch.object(self.monitor._stop, "wait"),
        ):
            self.monitor._game_control_expiry_loop()
        self.assertTrue(router.change.call_args.kwargs["restore"])
        self.assertEqual(self.monitor.get_game_blocks(), [])

    def test_gateway_access_requires_router_confirmed_client_and_supports_restore(self):
        self.monitor._skip_live_probe_in_test = True
        ip = "192.168.1.77"
        mac = "02:aa:bb:cc:dd:ee"
        payload = {"ip": ip, "mac": mac, "durationMinutes": 5}
        self.monitor.router_state.update(routerClients=[
            {"ip": ip, "mac": mac, "name": "Test client"},
        ], routerClientSource="dhcp")
        router = Mock()
        router.read.return_value = {"present": False}
        router.change.return_value = True
        with (
            patch.object(self.monitor, "_detect_host_lan_ip", return_value="192.168.1.20") as host_ip,
            patch.object(self.monitor, "_manual_game_router", return_value=router),
        ):
            self.assertFalse(self.monitor.block_gateway_device(payload)["success"])
            router.change.assert_not_called()
            self.monitor.router_state["routerClientSource"] = "router"
            with self.assertRaisesRegex(ValueError, "no longer"):
                self.monitor.block_gateway_device({**payload, "mac": "02:aa:bb:cc:dd:ff"})
            router.has_client.return_value = False
            self.assertFalse(self.monitor.block_gateway_device(payload)["success"])
            router.change.assert_not_called()
            host_ip.return_value = ip
            with self.assertRaisesRegex(ValueError, "monitoring PC"):
                self.monitor.block_gateway_device(payload)
            host_ip.return_value = "192.168.1.20"
            router.has_client.return_value = True
            result = self.monitor.block_gateway_device(payload)
            self.assertTrue(result["success"])
            self.assertEqual(self.monitor.get_game_blocks()[0]["deviceName"], "Test client")
            self.assertTrue(self.monitor.restore_gateway_device(result["ruleId"])["success"])
        self.assertEqual(self.monitor.get_game_blocks(), [])

    def test_phone_dns_reports_mobile_legends_and_forwards_reply(self):
        from queue import Queue
        from threading import Event
        from host_game_sensor import HostGameSensor

        sensor = HostGameSensor(dns_host="192.168.1.89")
        query = b"\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api\x0dmobilelegends\x03com\x00\x00\x01\x00\x01"
        response = query[:2] + b"\x81\x80" + query[4:]
        reported = Event()
        subscriber = Queue()
        self.monitor.event_subscribers.add(subscriber)
        self.monitor._skip_live_probe_in_test = True
        attempts = []

        def post_report(payload):
            attempts.append(payload)
            if len(attempts) == 1:
                return False
            result = self.monitor.record_game_detection(payload, include_activity=False)
            reported.set()
            return result["success"]

        with (
            patch("host_game_sensor.socket.socket") as upstream,
            patch.object(sensor, "_post_detection", side_effect=post_report),
        ):
            upstream.return_value.__enter__.return_value.recv.return_value = response
            self.assertEqual(sensor._process_dns_query(query, "192.168.1.50"), response)
            self.assertTrue(reported.wait(timeout=2))
            self.assertEqual(len(attempts), 2)
            event = subscriber.get_nowait()
            self.assertEqual(event["event"], "game_detected")
            detection = event["data"]["detection"]
            self.assertEqual((detection["ip"], detection["gameId"]), ("192.168.1.50", "mlbb"))
            self.assertEqual(self.monitor.get_game_activity()["logs"][0]["id"], detection["id"])
            self.assertEqual(sensor._dns_forwarded_total, 1)
            self.assertEqual(sensor._dns_forward_failures, 0)

    def test_game_session_renewal_and_expiry_publish_live_updates(self):
        from queue import Queue

        self.monitor._skip_live_probe_in_test = True
        payload = {"ip": "192.168.1.50", "domain": "api.mobilelegends.com"}
        opened = self.monitor.record_game_detection(payload, include_activity=False)["detection"]
        subscriber = Queue()
        self.monitor.event_subscribers.add(subscriber)

        self.monitor.record_game_detection(payload, include_activity=False)
        event = subscriber.get_nowait()
        self.assertEqual(event["event"], "game_detected")
        self.assertTrue(event["data"]["updated"])
        self.assertEqual(event["data"]["detection"]["id"], opened["id"])

        with self.monitor._connect() as db:
            db.execute("UPDATE game_activity_logs SET timestamp=? WHERE id=?", ("2000-01-01T00:00:00Z", opened["id"]))
        self.assertFalse(self.monitor.get_game_activity()["logs"][0]["isActive"])
        self.assertEqual(subscriber.get_nowait(), {
            "event": "game_detected", "data": {"endedSessionIds": [opened["id"]]},
        })
