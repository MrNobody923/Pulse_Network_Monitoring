import subprocess
from unittest.mock import MagicMock, patch
from tests.support import MonitorTestCase


class PortScannerTests(MonitorTestCase):
    def test_port_scan_detects_open_and_at_risk_ports(self) -> None:
        def fake_connect(address, timeout):
            if address[1] in {23, 80, 443, 445}:
                return MagicMock()
            raise ConnectionRefusedError

        with patch("pulse_monitor.port_scanner.socket.create_connection", side_effect=fake_connect), patch.object(
            self.monitor, "_find_nmap_binary", return_value=""
        ), patch.object(
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
        self.assertEqual(report["counts"]["closed"], 1)
        self.assertEqual(report["scope"]["ports"], [22, 23, 80, 443, 445])

    def test_port_scan_nmap_xml_enrichment_and_service_risk_inference(self) -> None:
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -p 2323,445,8443,9999 -oX - 127.0.0.1" version="7.993">
  <host>
    <status state="up" reason="syn-ack"/>
    <os><osmatch name="Linux 5.15" accuracy="96"/></os>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" method="probed" product="Samba smbd" version="4.17.0"><cpe>cpe:/a:samba:samba:4.17.0</cpe></service>
      </port>
      <port protocol="tcp" portid="2323">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" method="probed" product="BusyBox telnetd"/>
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open" reason="syn-ack"/>
        <service name="http" method="probed" tunnel="ssl" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="open" reason="syn-ack"/>
        <service name="abyss" method="table"/>
      </port>
    </ports>
    <times srtt="1400"/>
  </host>
</nmaprun>"""

        mock_proc = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=sample_xml, stderr="")
        with patch.object(self.monitor, "_find_nmap_binary", return_value="nmap"), patch.object(
            self.monitor, "_grab_service_banner", return_value=""
        ), patch(
            "pulse_monitor.port_scanner.socket.create_connection", return_value=MagicMock()
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
        self.assertEqual(by_port[2323]["serviceSource"], "nmap-probe")
        self.assertEqual(by_port[9999]["serviceSource"], "port-number")
        self.assertNotIn("nmapService", by_port[9999])
        self.assertEqual(report["nmapResultCount"], 4)
        catalog = self.monitor.get_portscan_catalog()
        self.assertTrue(catalog["nmapAvailable"])
        self.assertEqual(len(catalog["history"]), 1)
        self.assertIn(report["reportId"], catalog["reports"])

    def test_port_scan_distinguishes_uncertainty_from_closed_ports(self) -> None:
        def fake_connect(address, timeout):
            if address[1] == 21:
                raise ConnectionRefusedError
            if address[1] == 22:
                raise PermissionError
            raise TimeoutError

        xml = """<nmaprun version="7.993"><host><ports>
          <port protocol="tcp" portid="23"><state state="filtered" reason="admin-prohibited"/></port>
          <port protocol="tcp" portid="24"><state state="open|filtered" reason="no-response"/></port>
          <port protocol="tcp" portid="21"><state state="filtered" reason="no-response"/></port>
        </ports></host></nmaprun>"""
        proc = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=xml, stderr="")
        with patch("pulse_monitor.port_scanner.socket.create_connection", side_effect=fake_connect), patch.object(
            self.monitor, "_find_nmap_binary", return_value="nmap"
        ), patch("pulse_monitor.port_scanner.subprocess.run", return_value=proc):
            report = self.monitor.run_port_scan("127.0.0.1", profile="custom", custom_ports="21-24")

        ports = {p["port"]: (p["state"], p["reason"]) for p in report["allPorts"]}
        self.assertEqual(ports, {
            21: ("closed", "connection-refused"), 22: ("unconfirmed", "connection-error"),
            23: ("filtered", "admin-prohibited"), 24: ("unconfirmed", "timeout"),
        })
        self.assertEqual(report["counts"]["closed"], 1)
        self.assertEqual(report["counts"]["filtered"], 1)
        self.assertEqual(report["counts"]["unconfirmed"], 2)
        self.assertIn("uncertain", report["postureVerdict"])
        self.assertNotIn("host up", report["nmapTranscript"])
        self.assertNotIn("securityGrade", report)

    def test_nmap_grouped_result_only_applies_when_unambiguous(self) -> None:
        xml = '<nmaprun><host><ports><extraports state="closed" count="2"/></ports></host></nmaprun>'
        with patch(
            "pulse_monitor.port_scanner.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=xml, stderr=""),
        ):
            grouped = self.monitor._run_nmap_cli("nmap", "127.0.0.1", [21, 22], 650)
            ambiguous = self.monitor._run_nmap_cli("nmap", "127.0.0.1", [21, 22, 23], 650)
        self.assertEqual({port: result["state"] for port, result in grouped["ports"].items()}, {21: "closed", 22: "closed"})
        self.assertEqual(ambiguous["ports"], {})

    def test_single_port_rechecks_indeterminate_socket_result_with_nmap(self) -> None:
        with patch("pulse_monitor.port_scanner.socket.create_connection", side_effect=TimeoutError), patch.object(
            self.monitor, "_find_nmap_binary", return_value="nmap"
        ), patch.object(self.monitor, "_run_nmap_cli", side_effect=[
            {"ports": {22: {"state": "closed", "reason": "conn-refused"}}},
            {"error": "Nmap timed out"},
        ]) as nmap:
            closed = self.monitor.check_tcp_port("127.0.0.1", 22)
            unconfirmed = self.monitor.check_tcp_port("127.0.0.1", 22)

        nmap.assert_called_with("nmap", "127.0.0.1", [22], 1500, scan_versions=False)
        self.assertEqual((closed["state"], closed["reason"]), ("closed", "conn-refused"))
        self.assertEqual((unconfirmed["state"], unconfirmed["reason"]), ("unconfirmed", "timeout"))

        # Busy lock rejects overlapping scan cleanly
        lock = self.monitor._get_portscan_lock()
        lock.acquire()
        try:
            with self.assertRaises(RuntimeError):
                self.monitor.run_port_scan("127.0.0.1", profile="quick_audit")
        finally:
            lock.release()
