"""Read byte counters from the configured gateway's WAN interface."""

from __future__ import annotations

import http.client
import socket
import time
import urllib.parse
from xml.etree import ElementTree

from .config import utc_now


WAN_SERVICE = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
DISCOVERY_RETRY_SECONDS = 60
ROUTER_SAMPLE_SECONDS = 2


def _router_http(ip: str, url: str, action: str = "") -> ElementTree.Element:
    target = urllib.parse.urlsplit(url)
    if target.scheme != "http" or target.hostname != ip or target.username or target.password:
        raise ValueError("Unexpected router counter endpoint")
    path = urllib.parse.urlunsplit(("", "", target.path or "/", target.query, ""))
    conn = http.client.HTTPConnection(ip, target.port or 80, timeout=1)
    try:
        if action:
            body = (
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:{action} xmlns:u="{WAN_SERVICE}" /></s:Body></s:Envelope>'
            )
            conn.request("POST", path, body=body, headers={
                "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{WAN_SERVICE}#{action}"',
            })
        else:
            conn.request("GET", path)
        response = conn.getresponse()
        content = response.read(65_537)
        if response.status != 200 or len(content) > 65_536 or b"<!DOCTYPE" in content.upper():
            raise ValueError("Router counter endpoint did not return a usable response")
        return ElementTree.fromstring(content)
    finally:
        conn.close()


def _discover_upnp(ip: str) -> str | None:
    group = "239.255.255.250"
    req = (
        f'M-SEARCH * HTTP/1.1\r\nHOST: {group}:1900\r\nMAN: "ssdp:discover"\r\n'
        f"MX: 1\r\nST: {WAN_SERVICE}\r\n\r\n"
    ).encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((ip, 1900))
        local_ip = route.getsockname()[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((local_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        for destination in (ip, group):
            sock.sendto(req, (destination, 1900))
        deadline = time.monotonic() + 1.2
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            reply, peer = sock.recvfrom(4096)
            if peer[0] != ip:
                continue
            for line in reply.decode("iso-8859-1").splitlines():
                field, _, value = line.partition(":")
                if field.lower() != "location":
                    continue
                location = value.strip()
                root = _router_http(ip, location)
                base = root.findtext("{*}URLBase") or location
                for service in root.findall(".//{*}service"):
                    control = service.findtext("{*}controlURL")
                    if control and service.findtext("{*}serviceType") == WAN_SERVICE:
                        return urllib.parse.urljoin(base, control)
    return None


class RouterWanSampler:
    def __init__(self, snmp_get) -> None:
        self._snmp_get = snmp_get
        self._router_ip = ""
        self._upnp_url = None
        self._next_discovery = 0.0
        self._upnp_failures = 0
        self._link_next_check = 0.0
        self._link = None

    def read(self, config: dict) -> tuple[str, int, int, str | None] | None:
        ip = str(config.get("ip") or "")
        if ip != self._router_ip:
            self._router_ip, self._upnp_url, self._next_discovery = ip, None, 0.0
            self._upnp_failures = 0
            self._link_next_check = 0.0
            self._link = None
        if not ip:
            return None
        index = config.get("wanInterfaceIndex")
        if type(index) is int and 0 < index <= 2_147_483_647:
            prefix = "1.3.6.1.2.1.31.1.1.1"
            counters = self._snmp_get(ip, {
                "rx": f"{prefix}.6.{index}", "tx": f"{prefix}.10.{index}",
                "discontinuity": f"{prefix}.19.{index}",
            }, community=config.get("snmpCommunity") or "public", timeout=0.3)
            if "rx" in counters and "tx" in counters:
                rx, tx = counters["rx"], counters["tx"]
                if rx.isdecimal() and tx.isdecimal():
                    return f"SNMP WAN interface {index}", int(rx), int(tx), counters.get("discontinuity")
            return None
        try:
            if not self._upnp_url and time.monotonic() >= self._next_discovery:
                self._next_discovery = time.monotonic() + DISCOVERY_RETRY_SECONDS
                self._upnp_url = _discover_upnp(ip)
            if not self._upnp_url:
                return None
            rx = self._read_upnp_counter(ip, self._upnp_url, "Received")
            tx = self._read_upnp_counter(ip, self._upnp_url, "Sent")
            self._upnp_failures = 0
            return "Router UPnP WAN counters", rx, tx, None
        except (OSError, ValueError, http.client.HTTPException, ElementTree.ParseError):
            if self._upnp_url:
                self._upnp_failures += 1
                if self._upnp_failures >= 3:
                    self._upnp_url = None
                    self._upnp_failures = 0
                    self._next_discovery = time.monotonic()
            return None

    def physical_link(self, config: dict) -> dict | None:
        if not self._upnp_url or config.get("wanInterfaceIndex"):
            self._link = None
            self._link_next_check = 0.0
            return None
        now = time.monotonic()
        if now < self._link_next_check:
            return self._link
        self._link_next_check = now + 10
        self._link = None
        try:
            root = _router_http(self._router_ip, self._upnp_url, "GetCommonLinkProperties")
            status = (root.findtext(".//{*}NewPhysicalLinkStatus") or "").strip().lower()
            if status in {"up", "down", "initializing"}:
                self._link = {"status": status, "timestamp": utc_now()}
        except (OSError, ValueError, http.client.HTTPException, ElementTree.ParseError):
            pass
        return self._link

    @staticmethod
    def _read_upnp_counter(ip: str, url: str, direction: str) -> int:
        root = _router_http(ip, url, f"GetTotalBytes{direction}")
        value = int(root.findtext(f".//{{*}}NewTotalBytes{direction}") or "-1")
        if value < 0:
            raise ValueError("Router returned an invalid counter")
        return value
