import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree
from pulse_monitor.isp_speed import _counter_delta, _counter_rates, _parse_wifi_signal
from pulse_monitor.probes import _router_link_mbps
from pulse_monitor.router_game_control import RouterGameControl
from pulse_monitor.router_wan import RouterWanSampler


class InterfaceReadingTests(unittest.TestCase):
    def test_wifi_signal_uses_the_connected_routed_adapter(self):
        output = ("Name : Guest\nState : connected\nSignal : 20%\nRssi : -85\n"
                  "Name : Wi-Fi\nState : connected\nSignal : 83%\nRssi : -58\n")
        self.assertEqual(_parse_wifi_signal(output, "wi-fi"), {"signalPercent": 83, "rssiDbm": -58})
        self.assertEqual(_parse_wifi_signal(output.replace("State : connected", "State : disconnected"), "Wi-Fi"), {})
        self.assertEqual(_parse_wifi_signal(output, "Ethernet"), {})

    def test_counter_reset_does_not_create_a_speed_spike(self):
        self.assertIsNone(_counter_delta(20, 900))
        self.assertEqual(_counter_delta(1200, 900), 300)
        self.assertIsNone(_counter_rates((1200, 2000), (9000, 1000), 2))
        self.assertEqual(_counter_rates((2_000_000, 3_000_000), (1_000_000, 1_000_000), 2), (4, 8))
        self.assertEqual(_counter_rates((300, 400), (300, 400), 2), (0, 0))

    def test_router_wan_counters_use_explicit_snmp_wan_interface(self):
        read = Mock(return_value={"rx": "4294967547", "tx": "811", "discontinuity": "16"})
        sampler = RouterWanSampler(read)
        config = {"ip": "192.168.0.1", "wanInterfaceIndex": 7}
        self.assertEqual(sampler.read(config), ("SNMP WAN interface 7", 4294967547, 811, "16"))
        self.assertEqual(read.call_args.args[1]["rx"], "1.3.6.1.2.1.31.1.1.1.6.7")
        read.return_value = {"rx": "99"}
        self.assertIsNone(sampler.read(config))

    def test_router_wan_upnp_reuses_the_discovered_control_endpoint(self):
        with (
            patch("pulse_monitor.router_wan._discover_upnp", return_value="http://192.168.0.1:1901/ctl") as discover,
            patch.object(RouterWanSampler, "_read_upnp_counter", side_effect=[10, 20, TimeoutError(), 20, 40]) as read,
        ):
            sampler = RouterWanSampler(Mock())
            config = {"ip": "192.168.0.1"}
            self.assertEqual(sampler.read(config), ("Router UPnP WAN counters", 10, 20, None))
            self.assertIsNone(sampler.read(config))
            self.assertEqual(sampler.read(config), ("Router UPnP WAN counters", 20, 40, None))
            discover.assert_called_once_with("192.168.0.1")
            self.assertEqual(read.call_args.args, ("192.168.0.1", "http://192.168.0.1:1901/ctl", "Sent"))

    def test_router_link_speed_preserves_gigabit_units(self):
        self.assertEqual(_router_link_mbps("2.5 Gbps"), 2500)
        self.assertEqual(_router_link_mbps("100M"), 100)
        self.assertIsNone(_router_link_mbps("Auto"))

    def test_router_wan_physical_link_is_read_separately_from_counters(self):
        reply = ElementTree.fromstring("<r><NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus></r>")
        with (
            patch("pulse_monitor.router_wan._discover_upnp", return_value="http://192.168.0.1:1901/ctl"),
            patch.object(RouterWanSampler, "_read_upnp_counter", return_value=100),
            patch("pulse_monitor.router_wan._router_http", return_value=reply) as request,
        ):
            sampler = RouterWanSampler(Mock())
            config = {"ip": "192.168.0.1"}
            sampler.read(config)
            link = sampler.physical_link(config)
            assert link is not None
            self.assertEqual(link["status"], "up")
            sampler.physical_link(config)
            request.assert_called_once_with("192.168.0.1", "http://192.168.0.1:1901/ctl", "GetCommonLinkProperties")
            self.assertIsNone(sampler.physical_link({**config, "wanInterfaceIndex": 7}))

    def test_router_bandwidth_requires_readback_and_restores_exact_previous_limits(self):
        from urllib.parse import parse_qs

        mac = "02-AA-BB-CC-DD-EE"
        original = {"enable": "off", "key": "42", "up_band": "25", "down_band": "50", "up_unit": "KB/s", "down_unit": "KB/s"}
        desired = {**original, "enable": "on", "up_band": "32", "down_band": "64"}
        current = dict(original)
        change_effective = False

        def post(host, port, scheme, path, *, timeout, data):
            form = {key: value[0] for key, value in parse_qs(data.decode()).items()}
            if "form=client_list" in path:
                return {"success": True, "data": [{"ip": "192.168.1.77", "mac": mac}]}
            if form["operation"] == "update" and change_effective:
                current.update({key: form[key] for key in original})
            return {"success": True, "data": [{"mac": mac, **current}]}

        router = RouterGameControl({"ip": "192.168.0.1", "stok": "fixture"}, post)
        self.assertTrue(router.has_client("192.168.1.77", mac))
        self.assertFalse(router.has_client("192.168.1.78", mac))
        plan = {"mode": "throttle", "mac": mac, "before": original, "after": desired}
        self.assertFalse(router.change(plan))
        change_effective = True
        self.assertTrue(router.change(plan))
        self.assertEqual(current, desired)
        self.assertTrue(router.change(plan, restore=True))
        self.assertEqual(current, original)

    def test_router_deny_list_requires_enabled_mode_and_restores_its_own_entry(self):
        from urllib.parse import parse_qs

        mac = "02-AA-BB-CC-DD-EE"
        settings = {"enable": "off", "mode": "deny"}
        entries = []

        def post(host, port, scheme, path, *, timeout, data):
            form = {key: value[0] for key, value in parse_qs(data.decode()).items()}
            if "form=setting" in path:
                self.assertEqual(form["operation"], "read")
                return {"success": True, "data": settings}
            if form["operation"] == "insert":
                entries.append({"mac": form["mac"], "name": form["name"], "key": "device-1"})
            if form["operation"] == "remove" and form["key"] == "device-1":
                entries.clear()
            return {"success": True, "data": list(entries)}

        router = RouterGameControl({"ip": "192.168.0.1", "stok": "fixture"}, post)
        plan = {"mode": "cut", "mac": mac, "before": {"present": False}, "name": "Pulse test"}
        self.assertFalse(router.change(plan))
        self.assertEqual(entries, [])
        settings["enable"] = "on"
        self.assertTrue(router.change(plan))
        entries[0]["name"] = "Existing restriction"
        self.assertFalse(router.change(plan, restore=True))
        entries[0]["name"] = "Pulse test"
        self.assertTrue(router.change(plan, restore=True))
        self.assertEqual(entries, [])
