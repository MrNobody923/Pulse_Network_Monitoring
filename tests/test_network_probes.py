import ipaddress
import subprocess
from unittest.mock import MagicMock, patch
import monitor as monitor_module
from tests.support import MonitorTestCase


class NetworkProbesTests(MonitorTestCase):
    def test_router_refusal_confirms_reachability_without_an_open_management_port(self):
        with (
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(False, True, 2.0)),
            patch.object(self.monitor, "_probe_icmp", return_value=(False, None)),
            patch.object(self.monitor, "_luci_post") as request,
        ):
            result = self.monitor._probe_single_router({"ip": "192.168.0.1", "stok": "sample"}, is_primary=True)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["openPorts"], [])
        self.assertFalse(result["model"])
        request.assert_not_called()

    def test_primary_gateway_exposes_reported_clients_and_negotiated_port_speed(self):
        def reply(host, port, scheme, path, **kwargs):
            responses = {
                "form=router": [{"speed": "2.5 Gbps", "link_status": "up"}],
                "form=client_list": {"list": [
                    {"ipaddr": "192.168.0.20", "macaddr": "02-AA-BB-CC-DD-EE", "hostname": "Office PC"},
                    {"ipaddr": "192.168.0.30", "macaddr": "FF-FF-FF-FF-FF-FF"},
                ]},
                "form=setting": {"enable": True, "mode": "deny"},
            }
            return {"success": True, "data": responses[path.split("?")[-1]]} if path.split("?")[-1] in responses else None

        with (
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 1.0)),
            patch.object(self.monitor, "_probe_icmp", return_value=(True, 1.0)),
            patch.object(self.monitor, "_snmp_get_oids", return_value={}),
            patch.object(self.monitor, "_luci_post", side_effect=reply),
        ):
            router = self.monitor._probe_single_router({"ip": "192.168.0.1", "stok": "fixture"}, is_primary=True)
        self.assertEqual(router["routerClients"], [
            {"ip": "192.168.0.20", "mac": "02:aa:bb:cc:dd:ee", "name": "Office PC"},
        ])
        self.assertTrue(router["authenticated"])
        self.assertTrue(router["denyListEnabled"])
        self.assertEqual(router["ports"][0]["speed"], 2500)
        self.assertEqual(router["ports"][1]["linkStatus"], "unknown")

    def test_device_connection_checks_only_listed_devices_and_reports_tcp_refusal(self):
        ip = "192.168.25.10"
        self.monitor.add_device({"name": "Office AP", "ip": ip, "type": "ap", "port": 443})
        with (
            patch.object(self.monitor, "_probe_icmp", return_value=(False, None)) as ping,
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(False, True, 5.2)) as tcp,
        ):
            summary = self.monitor.get_device_connection(ip)
            self.assertEqual(summary["managementUrl"], f"https://{ip}:443/")
            self.assertNotIn("checkedAt", summary)
            ping.assert_not_called()
            tcp.assert_not_called()
            with self.assertRaises(LookupError):
                self.monitor.get_device_connection("192.168.25.99", check_now=True)
            ping.assert_not_called()
            tcp.assert_not_called()
            result = self.monitor.get_device_connection(ip, check_now=True)
        self.assertEqual(result["icmp"]["status"], "no_reply")
        self.assertEqual(result["tcp"], {"status": "refused", "latencyMs": 5.2})
        self.assertEqual(result["http"]["status"], "tcp_unavailable")
        self.assertIn("checkedAt", result)

    def test_management_http_checks_headers_even_when_head_is_rejected(self):
        ip = "192.168.25.11"
        self.monitor.add_device({"name": "Office switch", "ip": ip, "type": "switch", "port": 80})
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 405
        with (
            patch.object(self.monitor, "_probe_icmp", return_value=(True, 1.0)),
            patch.object(self.monitor, "_probe_tcp_socket", return_value=(True, True, 1.0)),
            patch("pulse_monitor.diagnostics.http.client.HTTPConnection", return_value=connection) as http,
        ):
            result = self.monitor.get_device_connection(ip, check_now=True)
        http.assert_called_once_with(ip, 80, timeout=1.25)
        connection.request.assert_called_once_with("HEAD", "/", headers={"Connection": "close"})
        connection.close.assert_called_once()
        self.assertEqual(result["http"]["status"], "reply")
        self.assertEqual(result["http"]["statusCode"], 405)

    def test_snmp_read_returns_only_requested_device_information(self):
        ip = "192.168.25.11"
        self.monitor.add_device({"name": "Office switch", "ip": ip, "type": "switch"})
        with patch.object(self.monitor, "_snmp_get_oids", return_value={
            "name": "Office switch", "uptime": "24321", "interfaceCount": "16", "other": "discard",
        }) as snmp:
            with self.assertRaises(LookupError):
                self.monitor.read_device_snmp("192.168.25.99", "read-only")
            with self.assertRaises(ValueError):
                self.monitor.read_device_snmp(ip, "")
            snmp.assert_not_called()
            result = self.monitor.read_device_snmp(ip, "read-only")
        self.assertEqual(snmp.call_args.kwargs["community"], "read-only")
        self.assertEqual(result["status"], "reply")
        self.assertEqual(result["values"], {"name": "Office switch", "uptimeSeconds": 243.21, "interfaceCount": 16})

    def test_snmp_v1_falls_back_on_timeout_and_checks_request_id(self):
        oid = ".1.3.6.1.2.1.1.3.0"
        tlv = self.monitor._tlv
        envelope = b"\x02\x01\x00" + tlv(0x04, b"read-only")
        oid_tlv = self.monitor._encode_oid(oid)
        binding = tlv(0x30, tlv(0x30, oid_tlv + tlv(0x43, b"\x30\x39")))
        request_fields = tlv(0x02, b"\x40\x00\x00\x01") + b"\x02\x01\x00\x02\x01\x00"
        response = tlv(0x30, envelope + tlv(0xA2, request_fields + binding))
        self.assertIsNone(self.monitor._decode_snmp_value(
            response, envelope, request_fields.replace(b"\x40", b"\x41"), oid_tlv,
        ))
        with (
            patch("pulse_monitor.probes.secrets.randbits", return_value=1),
            patch("pulse_monitor.probes.socket.socket") as socket,
        ):
            sock = socket.return_value.__enter__.return_value
            sock.recv.side_effect = [TimeoutError, response]
            result = self.monitor._snmp_get_oids("192.168.25.11", {"uptime": oid}, community="read-only")
        self.assertEqual(result, {"uptime": "12345"})
        self.assertEqual(sock.send.call_count, 2)

    def test_switch_samples_preserve_counter_deltas_and_handle_reboots(self):
        device = self.monitor.add_device({"name": "Office switch", "ip": "192.168.50.4", "type": "switch"})
        body = {"community": "fixture-read-only", "indices": [12]}
        measurement = {"uptime": "200", "inErrors": "3"}

        def snmp(ip, oids, community, timeout):
            self.assertEqual(ip, device["ip"])
            if "uptime" in oids:
                return {"uptime": measurement["uptime"]}
            if "name" not in oids:
                return {}
            return {"name": "Port 12", "state": "1", "highSpeed": "2500", "discontinuity": "0", "inErrors": measurement["inErrors"]}

        with patch.object(self.monitor, "_snmp_get_oids", side_effect=snmp):
            first = self.monitor.sample_switch_ports(device["id"], body)
            measurement.update(uptime="250", inErrors="5")
            second = self.monitor.sample_switch_ports(device["id"], body)
            measurement.update(uptime="10", inErrors="8")
            rebooted = self.monitor.sample_switch_ports(device["id"], body)
        self.assertEqual(first["ports"][0]["speedMbps"], 2500)
        self.assertEqual(first["ports"][0]["change"], {})
        self.assertEqual(second["ports"][0]["change"], {"inErrors": 2})
        self.assertEqual(rebooted["ports"][0]["change"], {})
        with patch.object(self.monitor, "_snmp_get_oids", return_value={}):
            unavailable = self.monitor.sample_switch_ports(device["id"], body)
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertEqual(unavailable["sampledAt"], rebooted["sampledAt"])
        self.assertEqual(self.monitor.get_switch_ports(device["id"])["ports"], rebooted["ports"])

    def test_adaptive_probe_schedule_keeps_cached_clients_and_retries_first_failure(self):
        core = self.monitor.add_device({"name": "Core switch", "ip": "192.168.50.5", "type": "switch"})
        client = self.monitor.add_device({"name": "Client", "ip": "192.168.50.6", "type": "device"})
        states = {core["ip"]: "ONLINE_WITH_INTERNET", client["ip"]: "DEVICE_DOWN"}

        def probe(device):
            return {**device, "connectivityState": states[device["ip"]]}

        with (
            patch.object(self.monitor, "get_devices", return_value=[{**core, "archived": False}, {**client, "archived": False}]),
            patch.object(self.monitor, "probe_device", side_effect=probe),
            patch.object(self.monitor, "enrich_fleet_diagnostics"),
            patch("pulse_monitor.engine.time.monotonic") as clock,
        ):
            clock.return_value = 100
            self.assertEqual(len(self.monitor._probe_device_batch()), 2)
            clock.return_value = 104
            self.assertEqual(self.monitor._probe_device_batch(), [])
            clock.return_value = 105
            self.assertEqual([d["id"] for d in self.monitor._probe_device_batch()], [client["id"]])
            clock.return_value = 115
            self.assertEqual([d["id"] for d in self.monitor._probe_device_batch()], [core["id"]])
            self.assertIn(client["ip"], self.monitor.latest_devices)
            self.assertEqual(len(self.monitor.probe_all_devices()), 2)

    def test_monitored_devices_and_connection_checks_require_individual_device_addresses(self):
        device = self.monitor.add_device({"name": "Office AP", "ip": "192.168.10.30"})
        self.assertEqual(self.monitor.get_device_connection(device["ip"])["ip"], device["ip"])
        for ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(ip=ip):
                with self.assertRaisesRegex(ValueError, "individual network device"):
                    self.monitor.add_device({"name": "Invalid device", "ip": ip})
                with self.assertRaisesRegex(ValueError, "individual network device"):
                    self.monitor.update_device(device["id"], {"ip": ip})
                with self.assertRaisesRegex(ValueError, "individual network device"):
                    self.monitor.get_device_connection(ip)
        self.assertEqual(self.monitor.get_device_connection(device["ip"])["ip"], device["ip"])

    def test_traceroute_preserves_submillisecond_results_and_uses_addresses_for_roles(self):
        self.monitor.config["router"]["ip"] = "192.168.55.1"
        loopback = """Tracing route to 127.0.0.1 over a maximum of 1 hops
  1    <1 ms    <1 ms    <1 ms  127.0.0.1
Trace complete.
"""
        partial = """Tracing route to example.test [198.51.100.2]
  1     2 ms     2 ms     2 ms  192.168.55.2
  2    <1 ms     2 ms     3 ms  192.168.55.1
  3     *        *        *     Request timed out.
  4     5 ms     5 ms     5 ms  192.0.2.1
"""
        completed = """traceroute to example.test (198.51.100.2), 20 hops max
 1  192.168.55.1  2.1 ms  2.2 ms  2.3 ms
 2  198.51.100.2  4.1 ms  4.2 ms  4.3 ms
"""
        outputs = [subprocess.CompletedProcess([], 0, stdout, "") for stdout in (loopback, partial, completed)]
        with patch.object(monitor_module.subprocess, "run", side_effect=outputs):
            local = self.monitor.traceroute("127.0.0.1", 1)
            incomplete = self.monitor.traceroute("example.test", 4)
            destination = self.monitor.traceroute("example.test", 20)
        self.assertEqual(local["hops"][0]["role"]["label"], "Local host (loopback)")
        self.assertEqual(local["hops"][0]["latencyDisplay"], "<1 ms")
        self.assertEqual(incomplete["destinationIp"], "198.51.100.2")
        self.assertEqual(
            [hop["role"]["type"] for hop in incomplete["hops"]],
            ["transit", "local", "unknown", "transit"],
        )
        self.assertEqual(incomplete["hops"][1]["latencyDisplay"], "<2 ms")
        self.assertEqual(destination["hops"][-1]["role"]["type"], "destination")
        self.assertEqual(destination["hops"][-1]["latencyMs"], 4.2)

    def test_router_edits_preserve_credentials_for_their_original_address(self):
        original_ip = self.monitor.config["router"]["ip"]
        self.monitor.config["router"].update(stok="original-session", password="original-password")
        self.monitor.config["routers"] = [{"ip": "192.168.1.3", "stok": "other-session"}]

        self.monitor.update_router_config({"ip": original_ip, "port": 443, "useHttps": True})
        self.assertEqual(self.monitor.config["router"]["stok"], "original-session")
        self.assertEqual(self.monitor.config["router"]["password"], "original-password")

        self.monitor.update_router_config({"ip": "192.168.1.2"}, select_primary=True)
        reloaded = monitor_module.Monitor()
        self.assertEqual(reloaded.config["router"]["ip"], "192.168.1.2")
        self.assertEqual(reloaded.config["router"]["stok"], "")
        self.assertEqual(reloaded.config["router"]["password"], "")
        self.assertEqual(reloaded.config["router"]["port"], 80)
        self.assertEqual(reloaded.config["routers"][original_ip]["stok"], "original-session")
        self.assertEqual(reloaded.config["routers"]["192.168.1.3"]["stok"], "other-session")

    def test_failed_router_config_save_preserves_previous_settings(self):
        before = self.monitor._config_file().read_bytes()
        primary_ip = self.monitor.config["router"]["ip"]
        with patch("pulse_monitor.storage.os.replace", side_effect=PermissionError("file is in use")):
            with self.assertRaises(PermissionError):
                self.monitor.update_router_config({"ip": "192.168.1.2"}, select_primary=True)
        self.assertEqual(self.monitor.config["router"]["ip"], primary_ip)
        self.assertEqual(self.monitor._config_file().read_bytes(), before)
        self.assertEqual(list(self.monitor._data_dir().glob(".config.json.*.tmp")), [])

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
