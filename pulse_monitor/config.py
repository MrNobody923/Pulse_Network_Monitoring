"""Configuration defaults, constants, and input validation helpers."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import TypeVar


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CONFIG_FILE = DATA_DIR / "config.json"
DATABASE_FILE = DATA_DIR / "network.db"
API_VERSION = "2.1.0"


def manual_speed_tests_enabled() -> bool:
    return os.environ.get("PULSE_ALLOW_SPEED_TESTS", "manual") in {"manual", "1"}


DEFAULT_CONFIG = {
    "router": {
        "ip": "192.168.0.1",
        "port": 80,
        "username": "admin",
        "password": "",
        "stok": "",
        "snmpCommunity": "public",
        "autoLogin": True,
        "pollIntervalSec": 25,
    },
    "routers": {},
    "isp": {
        "targetHosts": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "dnsTestDomain": "google.com",
        "pollIntervalSec": 10,
        "speedTestIntervalMinutes": 0,
    },
    "thresholds": {
        "highLatencyMs": 80,
        "criticalLatencyMs": 200,
        "packetLossWarningPct": 5,
        "packetLossCriticalPct": 25,
    },
    "gaming": {
        "preventionMode": "alert_only",
        "staleSessionSeconds": 75,
    },
    "devicePollIntervalSec": 15,
    "devices": [
        {
            "id": "dev-gateway",
            "name": "Main Gateway Router (TP-Link BE3600)",
            "ip": "192.168.0.1",
            "type": "gateway",
            "checkMethod": "tcp",
            "port": 80,
            "location": "Server Rack 01",
            "critical": True,
        },
        {
            "id": "dev-ap-1",
            "name": "Office AP - Floor 1 (Reception & Lobby)",
            "ip": "192.168.0.10",
            "type": "ap",
            "checkMethod": "tcp",
            "port": 80,
            "location": "Floor 1 Ceiling",
            "critical": True,
        },
        {
            "id": "dev-ap-2",
            "name": "Office AP - Floor 2 (Engineering & Ops)",
            "ip": "192.168.0.11",
            "type": "ap",
            "checkMethod": "tcp",
            "port": 80,
            "location": "Floor 2 Open Space",
            "critical": True,
        },
        {
            "id": "dev-ap-3",
            "name": "Office AP - Executive & Boardroom",
            "ip": "192.168.0.12",
            "type": "ap",
            "checkMethod": "tcp",
            "port": 80,
            "location": "Conference Wing",
            "critical": False,
        },
        {
            "id": "dev-switch-core",
            "name": "Core Distribution Switch (24-Port PoE)",
            "ip": "192.168.0.2",
            "type": "switch",
            "checkMethod": "tcp",
            "port": 80,
            "location": "Server Room Rack",
            "critical": True,
        },
        {
            "id": "dev-srv-local",
            "name": "Local Application / File Server",
            "ip": "192.168.0.50",
            "type": "server",
            "checkMethod": "tcp",
            "port": 80,
            "location": "Server Room",
            "critical": False,
        },
    ],
    "alerts": [],
}

ROUTER_PORTS = [
    ("port-wan", "Internet", "WAN (Internet)", True, "ISP Modem / Fiber ONT Uplink"),
    ("port-lan-1", "LAN 1", "LAN 1 (Core Switch)", False, "PoE Distribution Switch Uplink"),
    ("port-lan-2", "LAN 2", "LAN 2 (AP Floor 1)", False, "Access Point Floor 1"),
    ("port-lan-3", "LAN 3", "LAN 3 (AP Floor 2)", False, "Access Point Floor 2"),
    ("port-lan-4", "LAN 4", "LAN 4 (Local Server / NAS)", False, "Company File Server"),
]

ISP_TARGETS = [
    {"id": "google", "name": "Google (google.com)", "host": "google.com", "ip": "google.com", "port": 443, "color": "#3b82f6", "category": "Search & Global CDN"},
    {"id": "cloudflare", "name": "Cloudflare (1.1.1.1)", "host": "1.1.1.1", "ip": "1.1.1.1", "port": 53, "color": "#f97316", "category": "Tier-1 CDN / DNS"},
    {"id": "googledns", "name": "Google DNS (8.8.8.8)", "host": "8.8.8.8", "ip": "8.8.8.8", "port": 53, "color": "#10b981", "category": "Tier-1 Anycast DNS"},
    {"id": "gateway", "name": "Main Router", "host": "192.168.0.1", "ip": "192.168.0.1", "port": 80, "color": "#06b6d4", "category": "Local Gateway"},
]

KNOWN_OUI_VENDORS: dict[str, tuple[str, str]] = {
    # Verified TP-Link Routers, Deco Mesh & Access Points
    "687ff0": ("TP-Link", "router"),
    "6c5ab0": ("TP-Link", "router"),
    "e4fac4": ("TP-Link", "router"),
    "503dd1": ("TP-Link", "router"),
    "98038e": ("TP-Link Deco Mesh", "router"),
    "c03a55": ("TP-Link", "ap"),
    "1027f5": ("TP-Link", "ap"),
    "f44d30": ("TP-Link", "ap"),
    "50d4f7": ("TP-Link", "ap"),
    "c006c3": ("TP-Link", "ap"),
    "5c628b": ("TP-Link", "ap"),
    "98da24": ("TP-Link", "ap"),
    "e848b8": ("TP-Link", "ap"),
    # Cisco / Enterprise Switches & APs
    "001b0d": ("Cisco", "switch"),
    "002414": ("Cisco", "switch"),
    "f04a02": ("Cisco", "switch"),
    # Ubiquiti UniFi / MikroTik / Ruijie
    "fcecda": ("Ubiquiti", "ap"),
    "788a20": ("Ubiquiti", "ap"),
    "b4fbe4": ("Ubiquiti", "ap"),
    "d4ca6d": ("MikroTik", "router"),
    "cc2de0": ("MikroTik", "router"),
    "488f5a": ("MikroTik", "router"),
    "00749c": ("Ruijie", "ap"),
    "58696c": ("Ruijie", "ap"),
    # Client / Endpoint OUIs
    "b81ea4": ("Apple", "client"),
}

CLIENT_OUI_VENDORS: dict[str, tuple[str, str]] = {
    # Intel & PC / Workstation Hardware
    "1c1bb5": ("Intel Corporate", "client"),
    "40c73c": ("Intel Corporate", "client"),
    "50eb71": ("Intel Corporate", "client"),
    "701ab8": ("Intel Corporate", "client"),
    "9cb150": ("Intel Corporate", "client"),
    "ac675d": ("Intel Corporate", "client"),
    "c403a8": ("Intel Corporate", "client"),
    "d0577e": ("Intel Corporate", "client"),
    "d46d6d": ("Intel Corporate", "client"),
    "dca971": ("Intel Corporate", "client"),
    "e0c264": ("Intel Corporate", "client"),
    "e41fd5": ("Intel Corporate", "client"),
    "f89e94": ("Intel Corporate", "client"),
    "f8e4e3": ("Intel Corporate", "client"),
    "001696": ("QDI / Linux Host", "client"),
    "00155d": ("Microsoft Hyper-V", "client"),
    "18c04d": ("Gigabyte PC", "client"),
    "74563c": ("Gigabyte PC", "client"),
    "7c10c9": ("ASUS PC", "client"),
    "a0ad9f": ("ASUS PC", "client"),
    "9c6b00": ("ASRock PC", "client"),
    "345a60": ("MSI Computer", "client"),
    "f4b520": ("Biostar PC", "client"),
    "7427ea": ("ECS Motherboard", "client"),
    "b4a9fc": ("Quanta Computer", "client"),
    "0894ef": ("Wistron Host", "client"),
    "90cdb6": ("Foxconn / Hon Hai", "client"),
    "3c0af3": ("Cloud Network Tech", "client"),
    "4c2338": ("Cloud Network Tech", "client"),
    "bcf4d4": ("Cloud Network Tech", "client"),
    "1cce51": ("AzureWave Wi-Fi", "client"),
    "90e868": ("AzureWave Wi-Fi", "client"),
    "c0bfbe": ("AzureWave Wi-Fi", "client"),
    "d8c0a6": ("AzureWave Wi-Fi", "client"),
    "30d16b": ("Liteon Technology", "client"),
    "3ca067": ("Liteon Technology", "client"),
    "d03957": ("Liteon Technology", "client"),
    "e00af6": ("Liteon Technology", "client"),
    "105a95": ("TP-Link Device", "client"),
    "3c7895": ("TP-Link Device", "client"),
    "7cc2c6": ("TP-Link Client NIC", "client"),
    "9c5322": ("TP-Link Client NIC", "client"),
    "b4b024": ("TP-Link Client NIC", "client"),
    "200db0": ("Four Seas Wi-Fi NIC", "client"),
    "c0e350": ("China Dragon Wi-Fi", "client"),
    "844709": ("IP3 Century Tech", "client"),
    # Phones & Mobile Devices
    "608373": ("Apple", "client"),
    "7022fe": ("Apple", "client"),
    "70e72c": ("Apple", "client"),
    "80953a": ("Apple", "client"),
    "3cdcbc": ("Samsung Electronics", "client"),
    "006619": ("Huawei Device", "client"),
    "70a703": ("Honor Device", "client"),
    "0c6046": ("vivo Mobile", "client"),
    "18d0c5": ("OPPO Mobile", "client"),
    # Printers, CCTV Cameras & IoT Peripherals
    "381a52": ("Seiko Epson Printer", "client"),
    "5805d9": ("Seiko Epson Printer", "client"),
    "e0ca3c": ("Hikvision Camera", "client"),
    "407aa4": ("Dahua Camera", "client"),
    "c4aac4": ("Dahua Camera", "client"),
    "f8ce07": ("Dahua Camera", "client"),
    "180b1b": ("Amazon Device", "client"),
    "b0f7c4": ("Amazon Device", "client"),
    "381f8d": ("Tuya Smart IoT", "client"),
    "b8060d": ("Tuya Smart IoT", "client"),
    "d8d668": ("Tuya Smart IoT", "client"),
    "f8172d": ("Tuya Smart IoT", "client"),
    "1c8f57": ("Espressif IoT", "client"),
    "d885ac": ("Espressif IoT", "client"),
    "70c912": ("Sichuan AI-Link IoT", "client"),
    "9c1221": ("Sichuan AI-Link IoT", "client"),
    "fc702e": ("Sichuan AI-Link IoT", "client"),
    "6879c4": ("Mxchip IoT", "client"),
    "d42787": ("High-Flying IoT", "client"),
    "e8b723": ("Shenzhen Vatilon", "client"),
    "a82c3e": ("Cultraview Display", "client"),
    "a047d7": ("Best IT World", "client"),
}


@lru_cache(maxsize=1)
def load_nmap_mac_vendors() -> dict[str, str]:
    """Load IEEE OUI vendor prefixes from nmap-mac-prefixes if installed on host or container."""
    candidates = (
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path(r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes"),
        Path(r"C:\Program Files\Nmap\nmap-mac-prefixes"),
    )
    vendors: dict[str, str] = {}
    for path in candidates:
        if not path.is_file():
            continue
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 6:
                    vendors.setdefault(parts[0].lower(), parts[1].strip())
            if vendors:
                break
        except OSError:
            continue
    return vendors

PLACEHOLDER_DEFAULT_IPS = {
    "192.168.0.2",
    "192.168.0.10",
    "192.168.0.11",
    "192.168.0.12",
    "192.168.0.50",
}


_RuntimeAttribute = TypeVar("_RuntimeAttribute")


def runtime_attr(name: str, default: _RuntimeAttribute) -> _RuntimeAttribute:
    """Resolve attributes via the top-level `monitor` module when present (supports unittest.mock.patch)."""
    mod = sys.modules.get("monitor")
    return getattr(mod, name, default) if mod is not None else default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def inferred_inventory_mac(ip: str) -> str:
    """Return the legacy storage key for an IPv4 address found without a MAC."""
    address = ipaddress.IPv4Address(ip)
    return "02:00:" + address.packed.hex(":")


def observed_inventory_mac(mac: str, ip: str) -> str:
    """Hide an address-derived inventory key from hardware telemetry."""
    try:
        return "" if mac == inferred_inventory_mac(ip) else mac
    except ipaddress.AddressValueError:
        return mac


def merge_config(saved: dict) -> dict:
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    for key, value in saved.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def validate_ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError("A valid IP address is required") from exc


def validate_device_ip(value: object) -> str:
    ip = validate_ip(value)
    address = ipaddress.ip_address(ip)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise ValueError("Choose an individual network device")
    return ip


def validate_port(value: object) -> int:
    if not isinstance(value, (str, int, float)):
        raise ValueError("Port must be an integer from 1 to 65535")
    try:
        port = int(value)
    except (ValueError, OverflowError) as exc:
        raise ValueError("Port must be an integer from 1 to 65535") from exc
    if port < 1 or port > 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    return port


def normalize_mac(value: object) -> str:
    mac = str(value).strip().lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("A valid MAC address is required")
    return mac


def validate_host(host: object) -> str:
    value = str(host).strip()
    if not value or len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", value):
        raise ValueError("Enter a valid IP address or hostname")
    return value

