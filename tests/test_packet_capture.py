from pathlib import Path
from unittest.mock import patch
from tests.support import MonitorTestCase


class PacketCaptureTests(MonitorTestCase):
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
        assert tls_hit is not None
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
        assert lan_steam_hit is not None
        self.assertEqual(lan_steam_hit["ip"], "192.168.3.160")
        self.assertEqual(lan_steam_hit["gameId"], "steam")

        # Genuine outbound UDP game traffic (client -> remote Free Fire server :39800) DOES match
        real_ff = build_udp_frame("192.168.2.130", "47.90.10.20", 51234, 39800, b"\x01\x02\x03")
        ff_hit = dissect_raw_packet(real_ff, dlt=1)
        assert ff_hit is not None
        self.assertEqual(ff_hit["ip"], "192.168.2.130")
        self.assertEqual(ff_hit["gameId"], "freefire")

        # Established TCP data flow to public server on game port 7500 DOES match
        tcp_flow = build_tcp_frame("192.168.1.88", "203.0.113.20", 55555, 7500, 0x18, b"\xaa\xbb\xcc\xdd")
        flow_hit = dissect_raw_packet(tcp_flow, dlt=1)
        assert flow_hit is not None
        self.assertEqual(flow_hit["ip"], "192.168.1.88")
        self.assertEqual(flow_hit["gameId"], "codm")

        # 3. DNS Wire query wrapped inside Router TZSP (UDP 37008)
        dns_q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x08gamejoin\x06roblox\x03com\x00\x00\x01\x00\x01"
        inner_dns_frame = build_udp_frame("192.168.2.55", "1.1.1.1", 54321, 53, dns_q)
        dns_answer = dns_q[:2] + b"\x81\x80" + dns_q[4:]
        self.assertIsNone(dissect_raw_packet(build_udp_frame("1.1.1.1", "192.168.2.55", 53, 54321, dns_answer)))
        self.assertIsNone(dissect_raw_packet(inner_dns_frame, infra_ips={"192.168.2.55"}))
        tzsp_payload = b"\x01\x00\x00\x01\x01" + inner_dns_frame
        tzsp_outer = build_udp_frame("192.168.0.1", "192.168.0.224", 40000, 37008, tzsp_payload)
        tzsp_hit = dissect_raw_packet(tzsp_outer, dlt=1)
        assert tzsp_hit is not None
        self.assertEqual(tzsp_hit["ip"], "192.168.2.55")
        self.assertEqual(tzsp_hit["gameId"], "roblox")
        self.assertEqual(tzsp_hit["detectionMethod"], "Wireshark TZSP Stream")

        # 4. .pcap and .pcapng analysis reports historical evidence.
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
        with self.assertRaisesRegex(ValueError, "incomplete .pcap packet"):
            parse_pcap_or_pcapng(pcap_bytes[:-1])
        with self.assertRaisesRegex(ValueError, "incomplete .pcapng block"):
            parse_pcap_or_pcapng(pcapng_bytes[:-1])
        with self.assertRaisesRegex(ValueError, "Mismatched .pcapng block lengths"):
            parse_pcap_or_pcapng(pcapng_bytes[:-4] + b"\0" * 4)

        big_endian_shb = struct.pack(">IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
        self.assertEqual(len(parse_pcap_or_pcapng(pcapng_bytes + big_endian_shb)), 1)

        res = self.monitor.analyze_wireshark_capture({
            "filename": "office_mirror.pcapng",
            "dataBase64": base64.b64encode(pcapng_bytes).decode("ascii"),
            "ingest": True,
        })
        self.assertEqual(res["packetsParsed"], 1)
        self.assertEqual(res["uniqueMatches"], 1)
        self.assertEqual(res["detectionsLogged"], 0)
        self.assertEqual(len(res["gameActivity"]["blocks"]), 0)
        self.assertEqual(res["gameActivity"]["logs"], [])
        self.assertEqual(res["hits"][0]["gameId"], "roblox")

        # 5. Config & heartbeat telemetry round-trip + Display filter sanity
        filt = build_wireshark_display_filter()
        self.assertIn("dns.qry.name", filt)
        self.assertIn("tls.handshake.extensions_server_name", filt)
        self.assertIn("udp.port in", filt)

        cfg_res = self.monitor.set_wireshark_config({"enabled": False})
        self.assertFalse(cfg_res["wiresharkStatus"]["enabled"])
        hb = self.monitor.record_gaming_sensor_heartbeat({
            "pid": 1234,
            "wireshark": {
                "enabled": True, "active": True, "activeInterfaceCount": 2, "engine": "npcap-wpcap",
                "packetsCaptured": 99, "packetsMatched": 2, "pcapBytes": 2048,
            },
        })
        self.assertFalse(hb["wireshark"]["enabled"])
        status = self.monitor.get_game_activity()["wiresharkStatus"]
        self.assertEqual(status["packetsCaptured"], 99)
        self.assertEqual(status["activeInterfaceCount"], 2)
        self.assertTrue(status["sensorCaptureEnabled"])
        self.assertFalse(status["pcapAvailable"])
        (self.monitor._data_dir() / "wireshark_live.pcap").write_bytes(pcap_bytes)
        status = self.monitor.get_wireshark_status()
        self.assertTrue(status["pcapAvailable"])
        self.assertEqual(status["pcapBytes"], len(pcap_bytes))

    def test_wireshark_ignores_ephemeral_client_ports_on_web_flows_and_builds_bpf(self):
        """Regression guard: external :443/:80 traffic with client ephemeral port 27036/27015 must not match games."""
        import socket
        import struct

        from pulse_monitor.game_detector import _NETSTAT_GAME_PORTS
        from pulse_monitor.wireshark_capture import (
            build_wireshark_bpf_filters,
            dissect_raw_packet,
        )

        def build_l4_frame(src_ip: str, dst_ip: str, proto: int, sport: int, dport: int, payload: bytes) -> bytes:
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            if proto == 6:
                l4 = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0) + payload
            else:
                l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(l4),
                1,
                0,
                64,
                proto,
                0,
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip),
            )
            return eth + ip + l4

        # Host/LAN client ephemeral source port 27036 talking to Google HTTPS (:443) or HTTP (:80)
        for p in (
            build_l4_frame("192.168.0.224", "142.250.197.110", 6, 27036, 443, b"\x17\x03\x03\x00\x10data"),
            build_l4_frame("142.250.197.110", "192.168.0.224", 6, 443, 27036, b"\x17\x03\x03\x00\x10resp"),
            build_l4_frame("192.168.1.50", "142.250.197.110", 6, 27036, 443, b"\x17\x03\x03\x00\x10data"),
            build_l4_frame("192.168.1.50", "142.250.197.110", 17, 27015, 443, b"\xc0\x00\x00\x01quic"),
        ):
            self.assertIsNone(
                dissect_raw_packet(
                    p,
                    dlt=1,
                    game_ports=_NETSTAT_GAME_PORTS,
                    self_ips={"192.168.0.224"},
                )
            )

        # Kernel BPF candidate filters stay valid and include DNS/TLS handshake/game ports + SYN filter
        bpfs = build_wireshark_bpf_filters(_NETSTAT_GAME_PORTS)
        self.assertGreaterEqual(len(bpfs), 2)
        self.assertIn("tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16", bpfs[0])
        self.assertIn("ip6[(40 + ((ip6[52:1] & 0xf0) >> 2)):1] = 0x16", bpfs[0])
        self.assertIn("not (ip and tcp and (tcp[13] & 0x12 = 0x02))", bpfs[0])
        self.assertIn("port 27036", bpfs[0])
        self.assertIn("tcp port 443", bpfs[-1])

        # The filter includes supported network signals and omits shared Riot sign-in traffic.
        from pulse_monitor.wireshark_capture import build_wireshark_display_filter
        disp_filter = build_wireshark_display_filter()
        self.assertIn("roblox", disp_filter)
        self.assertIn("steam", disp_filter)
        self.assertIn('dns.qry.name == "wildrift.leagueoflegends.com"', disp_filter)
        self.assertNotIn("auth.riotgames.com", disp_filter)

        # Idempotent alert dismiss returns 200 even if alert already dismissed / absent
        from pulse_monitor.http_handler import RequestHandler
        responses = []
        handler = object.__new__(RequestHandler)
        with patch.object(handler, "_send_json", side_effect=lambda data, code=200: responses.append((code, data))):
            handler._alert_action(self.monitor, "dev-192.0.2.99", "dismiss", {})
        self.assertEqual(responses[0][0], 200)
        self.assertTrue(responses[0][1]["alreadyDismissed"])

        # Verify zero unscheduled WAN-saturating background speed tests by default
        from pulse_monitor.config import DEFAULT_CONFIG
        self.assertEqual(DEFAULT_CONFIG["isp"]["speedTestIntervalMinutes"], 0)
        self.assertEqual(self.monitor._speedtest_interval_sec(), 0.0)

        # Verify frontend browser state binding & top-level action handlers
        repo_root = Path(__file__).resolve().parent.parent
        state_js = (repo_root / "public" / "js" / "state.js").read_text(encoding="utf-8")
        self.assertIn("var appState =", state_js)
        app_js = (repo_root / "public" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("async function promoteLanDeviceAsInfra(", app_js)
        self.assertIn("async function deleteMonitoredDevice(", app_js)
