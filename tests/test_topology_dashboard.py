from unittest.mock import patch
from tests.support import MonitorTestCase


class TopologyDashboardTests(MonitorTestCase):
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

            # Map health and connectivity measured by Pulse are separate evidence.
            pdu = self.monitor.ping_topology_pdu(gw["node"]["id"], ap["node"]["id"])
            self.assertFalse(pdu["reachable"])
            self.assertEqual(pdu["probeOrigin"], "monitor")
            self.assertIsNone(pdu["failedAtNodeId"])
            self.assertEqual(pdu["mappedUnhealthyNodeId"], sw["node"]["id"])
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
