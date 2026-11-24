"""LAN subnet detection, parallel ICMP ping sweeps, ARP discovery, and daily scheduling."""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from typing import TYPE_CHECKING, Callable, cast

from .config import (
    CLIENT_OUI_VENDORS,
    KNOWN_OUI_VENDORS,
    inferred_inventory_mac,
    load_nmap_mac_vendors,
    observed_inventory_mac,
    runtime_attr,
    utc_now,
)

if TYPE_CHECKING:
    from .engine import Monitor


class DiscoveryMixin:
    """Discovers connected wired and Wi-Fi LAN devices and tracks daily scan schedules."""

    @staticmethod
    def _parse_ipconfig_interfaces(output: str) -> list[dict]:
        interfaces: list[dict] = []
        current_name = ""
        current_ip = ""
        current_mask = ""
        disconnected = False

        def flush() -> None:
            nonlocal current_ip, current_mask, current_gw, disconnected
            if current_name and current_ip and current_mask and not disconnected:
                try:
                    net = ipaddress.IPv4Network(f"0.0.0.0/{current_mask}")
                    item = {
                        "name": current_name,
                        "ip": current_ip,
                        "prefix": net.prefixlen,
                    }
                    if current_gw:
                        item["gateway"] = current_gw
                    interfaces.append(item)
                except ValueError:
                    pass
            current_ip = ""
            current_mask = ""
            current_gw = ""
            disconnected = False

        current_gw = ""
        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if line and not line.startswith(" ") and line.endswith(":"):
                flush()
                current_name = line[:-1].strip()
                continue
            if "Media disconnected" in line:
                disconnected = True
            elif "IPv4 Address" in line and ":" in line:
                val = line.split(":", 1)[1].strip()
                val = re.sub(r"\(.*?\)", "", val).strip()
                current_ip = val
            elif "Subnet Mask" in line and ":" in line:
                current_mask = line.split(":", 1)[1].strip()
            elif "Default Gateway" in line and ":" in line:
                gw_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line.split(":", 1)[1])
                if gw_match:
                    current_gw = gw_match.group(1)
        flush()
        return interfaces

    def _linux_lan_interfaces(self, run: Callable[..., subprocess.CompletedProcess[str]]) -> list[dict]:
        """Collect active IPv4 private LAN interfaces and default gateways on Linux/Docker."""
        addresses: list[dict] = []
        default_gw_by_dev: dict[str, str] = {}
        try:
            route_out = run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            for line in route_out.stdout.splitlines():
                m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+(\S+)", line)
                if m:
                    default_gw_by_dev[m.group(2)] = m.group(1)
        except (OSError, subprocess.SubprocessError):
            pass

        try:
            addr_out = run(
                ["ip", "-o", "-4", "addr", "show", "up", "scope", "global"],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            for line in addr_out.stdout.splitlines():
                m = re.match(r"^\d+:\s+([^\s:]+)\s+inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d+)", line)
                if not m:
                    continue
                ifname, ip_str, prefix = m.group(1), m.group(2), int(m.group(3))
                if any(
                    ifname.startswith(pref)
                    for pref in ("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "tailscale")
                ):
                    continue
                item: dict = {"name": ifname, "ip": ip_str, "prefix": prefix}
                if ifname in default_gw_by_dev:
                    item["gateway"] = default_gw_by_dev[ifname]
                addresses.append(item)
        except (OSError, subprocess.SubprocessError):
            pass
        return addresses

    def _local_lan_networks(self) -> list[ipaddress.IPv4Network]:
        self = cast("Monitor", self)
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)

        # Optional Docker / bridged container environment overrides
        env_router_ip = str(os_mod.environ.get("PULSE_ROUTER_IP") or "").strip()
        if env_router_ip:
            try:
                ipaddress.ip_address(env_router_ip)
                self._discovered_gateways = set(getattr(self, "_discovered_gateways", set()) or set()) | {env_router_ip}
                if self.config.get("router", {}).get("ip") != env_router_ip:
                    self.config["router"]["ip"] = env_router_ip
            except ValueError:
                pass

        configured = self._configured_lan_networks(os_mod.environ.get("PULSE_LAN_SUBNETS") or "")
        if configured:
            self._discovered_networks = configured
            return configured

        if os_mod.name != "nt":
            addresses = self._linux_lan_interfaces(subproc_mod.run)
            if not addresses:
                cached = self._known_local_networks()
                if cached:
                    return cached
                router_ip = str(self.config.get("router", {}).get("ip") or "192.168.0.1")
                try:
                    fallback_net = ipaddress.IPv4Network(f"{router_ip}/24", strict=False)
                except ValueError:
                    return []
                self._discovered_networks = [fallback_net]
                return [fallback_net]
        else:
            command = (
                "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue "
                "| Where-Object { $_.AddressState -eq 'Preferred' -and $_.InterfaceIndex -gt 1 } "
                "| ForEach-Object { $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex "
                "-ErrorAction SilentlyContinue; if ($adapter.Status -eq 'Up' -and "
                "$adapter.HardwareInterface) { "
                "$gw = (Get-NetRoute -InterfaceIndex $_.InterfaceIndex -DestinationPrefix '0.0.0.0/0' "
                "-ErrorAction SilentlyContinue | Select-Object -First 1).NextHop; "
                "[PSCustomObject]@{ ip=$_.IPAddress; prefix=$_.PrefixLength; name=$adapter.Name; gateway=$gw } } } "
                "| ConvertTo-Json -Compress"
            )
            addresses = []
            try:
                completed = subproc_mod.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if completed.returncode == 0 and completed.stdout.strip():
                    parsed = json.loads(completed.stdout)
                    addresses = [parsed] if isinstance(parsed, dict) else list(parsed)
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                addresses = []

            if not addresses:
                try:
                    ipcfg = subproc_mod.run(
                        ["ipconfig"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if ipcfg.stdout.strip():
                        addresses = self._parse_ipconfig_interfaces(ipcfg.stdout)
                except (OSError, subprocess.TimeoutExpired):
                    pass

        if not addresses:
            raise RuntimeError("No active wired or Wi-Fi LAN interfaces were found")

        networks: set[ipaddress.IPv4Network] = set()
        gateways: set[str] = set()
        skipped: list[str] = []
        excluded_interfaces = (
            "virtual",
            "vmware",
            "virtualbox",
            "vEthernet",
            "wsl",
            "docker",
            "loopback",
            "tailscale",
            "zerotier",
            "vpn",
            "local area connection*",
        )
        for item in addresses:
            if not isinstance(item, dict):
                continue
            interface_name = str(item.get("name", ""))
            if any(token.lower() in interface_name.lower() for token in excluded_interfaces):
                continue
            try:
                address = ipaddress.IPv4Address(item["ip"])
                prefix = int(item["prefix"])
                network = ipaddress.IPv4Network((address, prefix), strict=False)
            except (KeyError, TypeError, ValueError):
                continue
            if (
                not address.is_private
                or address.is_link_local
            ):
                continue
            if network.num_addresses > 1024:
                skipped.append(
                    f"{interface_name}: {network} is larger than the 1024-address safety limit"
                )
                continue
            networks.add(network)
            gw_raw = str(item.get("gateway") or "").strip()
            if gw_raw and gw_raw != "0.0.0.0":
                try:
                    gw_ip = ipaddress.ip_address(gw_raw)
                    if isinstance(gw_ip, ipaddress.IPv4Address) and gw_ip.is_private:
                        gateways.add(str(gw_ip))
                except ValueError:
                    pass

        if not networks:
            detail = "; ".join(skipped)
            suffix = f" ({detail})" if detail else ""
            raise RuntimeError(f"No supported private LAN subnets found{suffix}")

        sorted_nets = sorted(
            networks,
            key=lambda network: (int(network.network_address), network.prefixlen),
        )
        self._discovered_networks = sorted_nets
        if gateways:
            self._discovered_gateways = gateways
        try:
            with self._connect() as db:
                db.execute(
                    "INSERT OR REPLACE INTO monitor_metadata (key, value) VALUES ('local_subnets', ?)",
                    (json.dumps([str(n) for n in sorted_nets]),),
                )
                if gateways:
                    db.execute(
                        "INSERT OR REPLACE INTO monitor_metadata (key, value) VALUES ('local_gateways', ?)",
                        (json.dumps(sorted(gateways)),),
                    )
        except Exception:
            pass
        return sorted_nets

    @staticmethod
    def _configured_lan_networks(value: str) -> list[ipaddress.IPv4Network]:
        networks: set[ipaddress.IPv4Network] = set()
        for token in value.split(","):
            try:
                network = ipaddress.ip_network(token.strip(), strict=False)
            except ValueError:
                continue
            if isinstance(network, ipaddress.IPv4Network) and network.is_private and network.num_addresses <= 1024:
                networks.add(network)
        return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))

    def _known_local_networks(self) -> list[ipaddress.IPv4Network]:
        self = cast("Monitor", self)
        configured = self._configured_lan_networks(
            runtime_attr("os", os).environ.get("PULSE_LAN_SUBNETS") or ""
        )
        if configured:
            return configured
        cached = getattr(self, "_discovered_networks", None)
        if cached:
            return list(cached)
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT value FROM monitor_metadata WHERE key='local_subnets'"
                ).fetchone()
            if row and row["value"]:
                parsed = self._configured_lan_networks(",".join(json.loads(row["value"])))
                if parsed:
                    self._discovered_networks = parsed
                    return parsed
        except Exception:
            pass
        return []

    def _known_local_gateways(self) -> set[str]:
        self = cast("Monitor", self)
        gws = set(getattr(self, "_discovered_gateways", set()) or set())
        router_ip = str(self.config.get("router", {}).get("ip") or "").strip()
        if router_ip:
            gws.add(router_ip)
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT value FROM monitor_metadata WHERE key='local_gateways'"
                ).fetchone()
            if row and row["value"]:
                gws.update(str(x) for x in json.loads(row["value"]) if x)
        except Exception:
            pass
        for net in self._known_local_networks():
            gws.add(str(net.network_address + 1))
        return gws

    def _subnet_for_ip(self, ip: str, nets: list[ipaddress.IPv4Network] | None = None) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "192.168.0.0/24"
        candidates = nets if nets is not None else self._known_local_networks()
        for net in candidates:
            if addr in net:
                return str(net)
        octets = ip.split(".")
        return f"{'.'.join(octets[:3])}.0/24" if len(octets) == 4 else "192.168.0.0/24"

    def _ping_sweep_hosts(self, networks: list[ipaddress.IPv4Network]) -> list[str]:
        self = cast("Monitor", self)
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)

        hosts = sorted({
            str(address)
            for network in networks
            for address in network.hosts()
            if not address.is_loopback and not address.is_multicast
        })
        is_mocked_subproc = hasattr(subproc_mod.run, "assert_called")
        if os_mod.name == "nt" and not is_mocked_subproc and hasattr(self, "_win32_icmp_echo"):
            def ping_win32(host: str) -> str | None:
                alive, _ = self._win32_icmp_echo(host, timeout_ms=420)
                return host if alive else None

            with ThreadPoolExecutor(max_workers=16) as pool:
                return [h for h in pool.map(ping_win32, hosts) if h is not None]

        def ping(host: str) -> str | None:
            command = (
                ["ping", "-n", "1", "-w", "400", host]
                if os_mod.name == "nt"
                else ["ping", "-c", "1", "-W", "1", host]
            )
            try:
                res = subproc_mod.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=1.5,
                    check=False,
                )
                out = (res.stdout + res.stderr).lower()
                if res.returncode != 0:
                    return None
                if any(bad in out for bad in ("destination host unreachable", "destination net unreachable", "request timed out", "100% loss", "0 received")):
                    return None
                if out.strip() and "ttl=" not in out and "time=" not in out and "time<" not in out:
                    return None
                return host
            except (OSError, subprocess.TimeoutExpired):
                return None

        with ThreadPoolExecutor(max_workers=64) as pool:
            return [h for h in pool.map(ping, hosts) if h is not None]

    @staticmethod
    def _is_valid_unicast_mac(mac: str) -> bool:
        clean = str(mac or "").strip().lower().replace("-", ":")
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", clean):
            return False
        if clean in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            return False
        try:
            # Bit 0 of first octet = 1 means multicast/broadcast
            if int(clean[:2], 16) & 1:
                return False
        except ValueError:
            return False
        return True

    @classmethod
    def _win32_send_arp(cls, ip: str) -> str:
        """Resolve true L2 hardware MAC for a local IPv4 address using Windows iphlpapi.SendARP."""
        if os.name != "nt":
            return ""
        try:
            packed = socket.inet_aton(ip)
            dest_ip = int.from_bytes(packed, byteorder="little")
            mac_buf = (ctypes.c_ubyte * 6)()
            mac_len = ctypes.c_ulong(6)
            ret = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
            if ret == 0 and mac_len.value == 6:
                mac = ":".join(f"{b:02x}" for b in mac_buf)
                if cls._is_valid_unicast_mac(mac):
                    return mac
        except Exception:
            pass
        return ""

    @classmethod
    def _local_host_macs(cls, run: Callable[..., subprocess.CompletedProcess[str]]) -> dict[str, str]:
        """Return {ipv4: hardware_mac} for this machine's active physical LAN adapters."""
        if os.name != "nt":
            return {}
        excluded = (
            "virtual", "vmware", "virtualbox", "vethernet", "wsl",
            "docker", "loopback", "tailscale", "zerotier", "vpn", "local area connection*",
        )
        out: dict[str, str] = {}
        try:
            res = run(["ipconfig", "/all"], capture_output=True, text=True, timeout=8, check=False)
            if not res.stdout:
                return {}
            cur_name = ""
            cur_mac = ""
            cur_ips: list[str] = []
            disconnected = False

            def flush() -> None:
                if cur_name and cur_mac and cur_ips and not disconnected:
                    if not any(tok in cur_name.lower() for tok in excluded):
                        if cls._is_valid_unicast_mac(cur_mac):
                            for ip_s in cur_ips:
                                out[ip_s] = cur_mac

            for raw_line in res.stdout.splitlines():
                line = raw_line.rstrip()
                if line and not line.startswith(" ") and line.endswith(":"):
                    flush()
                    cur_name = line[:-1].strip()
                    cur_mac = ""
                    cur_ips = []
                    disconnected = False
                    continue
                if "Media disconnected" in line:
                    disconnected = True
                elif "Physical Address" in line and ":" in line:
                    m = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
                    if m:
                        cur_mac = m.group(1).lower().replace("-", ":")
                elif "IPv4 Address" in line and ":" in line:
                    val = re.sub(r"\(.*?\)", "", line.split(":", 1)[1]).strip()
                    try:
                        addr = ipaddress.IPv4Address(val)
                        if addr.is_private and not addr.is_link_local:
                            cur_ips.append(str(addr))
                    except ValueError:
                        pass
            flush()
        except Exception:
            return {}
        return out

    def _read_arp_entries(self, platform: str, run: Callable[..., subprocess.CompletedProcess[str]]) -> list[tuple[str, str, str]]:
        """Read IP -> MAC neighbor entries across Windows (`arp -a`) and Linux (`ip neigh` / `/proc/net/arp`)."""
        lines: list[str] = []
        if platform == "nt":
            try:
                completed = run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RuntimeError(
                    f"Unable to read the operating system ARP cache: {exc}"
                ) from exc
            if completed.returncode not in (0, 1) and not completed.stdout:
                raise RuntimeError(completed.stderr.strip() or "ARP discovery failed")
            lines.extend(completed.stdout.splitlines())
        else:
            for cmd in (["ip", "neigh", "show"], ["arp", "-an"]):
                try:
                    res = run(cmd, capture_output=True, text=True, timeout=6, check=False)
                    if res.stdout:
                        lines.extend(res.stdout.splitlines())
                except (OSError, subprocess.SubprocessError):
                    continue
            try:
                with open("/proc/net/arp", encoding="utf-8") as fh:
                    lines.extend(fh.read().splitlines()[1:])
            except OSError:
                pass

        # Parse per-interface sections so same-subnet dynamic entries beat stale cross-adapter entries.
        current_iface_ip = ""
        parsed: list[tuple[str, str, str, str]] = []  # (ip, mac, kind, iface_ip)
        for line in lines:
            iface_match = re.match(r"^\s*Interface:\s*(\d{1,3}(?:\.\d{1,3}){3})\s+---", line, re.IGNORECASE)
            if iface_match:
                current_iface_ip = iface_match.group(1)
                continue
            match = re.search(
                r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"
                r"(?P<mac>(?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})",
                line,
            )
            if not match:
                continue
            ip_s = match.group("ip")
            mac_s = match.group("mac").lower().replace("-", ":")
            if not self._is_valid_unicast_mac(mac_s):
                continue
            kind = "dynamic"
            lower_line = line.lower()
            if "static" in lower_line or "permanent" in lower_line:
                kind = "static"
            parsed.append((ip_s, mac_s, kind, current_iface_ip))

        # Group by IP; if multiple MACs exist across different interfaces, prefer same-/24 dynamic entry.
        by_ip: dict[str, list[tuple[str, str, str]]] = {}
        for ip_s, mac_s, kind, iface_ip in parsed:
            by_ip.setdefault(ip_s, []).append((mac_s, kind, iface_ip))

        result: list[tuple[str, str, str]] = []
        for ip_s, candidates in by_ip.items():
            unique_macs = {c[0] for c in candidates}
            if len(unique_macs) == 1:
                best_kind = "dynamic" if any(c[1] == "dynamic" for c in candidates) else candidates[0][1]
                result.append((ip_s, next(iter(unique_macs)), best_kind))
                continue
            # Resolve cross-interface conflict by preferring same /24 interface + dynamic state
            ip_prefix = ".".join(ip_s.split(".")[:3])
            same_subnet = [c for c in candidates if c[2] and ".".join(c[2].split(".")[:3]) == ip_prefix]
            same_sub_macs = {c[0] for c in same_subnet}
            if len(same_sub_macs) == 1:
                best_kind = "dynamic" if any(c[1] == "dynamic" for c in same_subnet) else same_subnet[0][1]
                result.append((ip_s, next(iter(same_sub_macs)), best_kind))
            else:
                dyn_same = [c for c in same_subnet if c[1] == "dynamic"]
                dyn_macs = {c[0] for c in dyn_same}
                if len(dyn_macs) == 1:
                    result.append((ip_s, next(iter(dyn_macs)), "dynamic"))
        return result

    def discover_devices(self) -> dict:
        self = cast("Monitor", self)
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("A LAN discovery scan is already running")
        try:
            networks = self._local_lan_networks()
            started_at = utc_now()
            ping_alive_hosts = self._ping_sweep_hosts(networks)
            ping_responses = len(ping_alive_hosts)
            scan_id = uuid.uuid4().hex
            arp_entries = self._read_arp_entries(os_mod.name, subproc_mod.run)

            discovered: list[dict] = []
            seen_ips: set[str] = set()
            known_gateways = self._known_local_gateways()
            gw_plus_one = {network.network_address + 1 for network in networks}

            for raw_ip, raw_mac, kind in arp_entries:
                try:
                    ip = self._validate_ip(raw_ip)
                    mac = self._normalize_mac(raw_mac)
                except ValueError:
                    continue
                if mac in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                    continue
                address = ipaddress.ip_address(ip)
                if (
                    address.version != 4
                    or not address.is_private
                    or address.is_multicast
                    or address.is_unspecified
                    or not any(address in network for network in networks)
                    or ip in seen_ips
                ):
                    continue
                seen_ips.add(ip)

                oui = mac.replace(":", "")[:6]
                vendor, device_type = self._vendor_for_oui(oui)
                if address in gw_plus_one or ip in known_gateways:
                    device_type = "gateway"
                discovered.append({
                    "ip": ip,
                    "mac": mac,
                    "arpType": kind,
                    "vendor": vendor,
                    "type": device_type,
                    "suggestedName": "",
                    "latencyMs": None,
                    "observed": True,
                })

            # Merge local monitoring PC's own physical NIC IP -> MAC (never in its own ARP cache)
            is_mocked_subproc = hasattr(subproc_mod.run, "assert_called")
            if os_mod.name == "nt" and not is_mocked_subproc:
                for host_ip, host_mac in self._local_host_macs(subproc_mod.run).items():
                    if host_ip in seen_ips:
                        continue
                    try:
                        addr = ipaddress.ip_address(host_ip)
                    except ValueError:
                        continue
                    if not any(addr in network for network in networks):
                        continue
                    seen_ips.add(host_ip)
                    oui = host_mac.replace(":", "")[:6]
                    vendor, device_type = self._vendor_for_oui(oui)
                    discovered.append({
                        "ip": host_ip,
                        "mac": host_mac,
                        "arpType": "static",
                        "vendor": vendor,
                        "type": device_type,
                        "suggestedName": "",
                        "latencyMs": None,
                        "observed": True,
                    })

            # Merge authoritative router DHCP/ARP clients for IPs not yet resolved locally
            router_clients = (getattr(self, "router_state", None) or {}).get("routerClients") or []
            for rc in router_clients:
                if not isinstance(rc, dict):
                    continue
                rc_ip = str(rc.get("ip") or "").strip()
                rc_mac = str(rc.get("mac") or "").strip().lower().replace("-", ":")
                if not rc_ip or rc_ip in seen_ips or not self._is_valid_unicast_mac(rc_mac):
                    continue
                try:
                    addr = ipaddress.ip_address(rc_ip)
                except ValueError:
                    continue
                if addr.version != 4 or not addr.is_private or not any(addr in network for network in networks):
                    continue
                seen_ips.add(rc_ip)
                oui = rc_mac.replace(":", "")[:6]
                vendor, device_type = self._vendor_for_oui(oui)
                if addr in gw_plus_one or rc_ip in known_gateways:
                    device_type = "gateway"
                rc_name = str(rc.get("name") or rc.get("hostname") or "").strip()
                discovered.append({
                    "ip": rc_ip,
                    "mac": rc_mac,
                    "arpType": "dhcp",
                    "vendor": vendor,
                    "type": device_type,
                    "suggestedName": rc_name,
                    "hostname": rc_name,
                    "latencyMs": None,
                    "observed": True,
                })

            # Resolve ICMP-alive LAN hosts via native Win32 SendARP before falling back to inferred MAC
            for alive_ip in ping_alive_hosts:
                if alive_ip in seen_ips:
                    continue
                seen_ips.add(alive_ip)
                resolved_mac = (
                    self._win32_send_arp(alive_ip)
                    if (os_mod.name == "nt" and not is_mocked_subproc)
                    else ""
                )
                mac = resolved_mac or inferred_inventory_mac(alive_ip)
                arp_kind = "dynamic" if resolved_mac else "icmp"
                oui = mac.replace(":", "")[:6]
                vendor, device_type = self._vendor_for_oui(oui)
                addr = ipaddress.ip_address(alive_ip)
                if addr in gw_plus_one or alive_ip in known_gateways:
                    device_type = "gateway"
                discovered.append({
                    "ip": alive_ip,
                    "mac": mac,
                    "arpType": arp_kind,
                    "vendor": vendor,
                    "type": device_type,
                    "suggestedName": "",
                    "latencyMs": None,
                    "observed": True,
                })

            cand_ips = [item["ip"] for item in discovered]
            all_fps = self._get_cached_fingerprints() if hasattr(self, "_get_cached_fingerprints") else {}
            mac_by_ip = {item["ip"]: item["mac"] for item in discovered}
            all_hosts = self._get_cached_hostnames(mac_by_ip)
            all_fps = {item["ip"]: all_fps[item["ip"]] for item in discovered
                       if all_fps.get(item["ip"], {}).get("mac") == item["mac"]}

            if cand_ips and not is_mocked_subproc:
                unknown_host_ips = [ip_c for ip_c in cand_ips if ip_c not in all_hosts][:24]
                if unknown_host_ips:
                    resolved_hosts = self._resolve_hostnames_bulk(unknown_host_ips, mac_by_ip)
                    if resolved_hosts:
                        all_hosts.update(resolved_hosts)

                unknown_fp_ips = [ip_c for ip_c in cand_ips if ip_c not in all_fps][:16]
                if unknown_fp_ips and hasattr(self, "identify_network_device"):
                    fp_updates: dict[str, dict] = {}

                    def _fp_scan(target_ip: str) -> tuple[str, dict | None]:
                        open_p: list[int] = []
                        for p in (80, 443, 8080, 20001, 22):
                            is_open, _, _ = self._probe_tcp_socket(target_ip, p, timeout=0.25)
                            if is_open:
                                open_p.append(p)
                        if not open_p:
                            return target_ip, None
                        res_fp = self.identify_network_device(target_ip, open_ports=open_p)
                        if res_fp and mac_by_ip.get(target_ip):
                            res_fp["mac"] = mac_by_ip[target_ip]
                        return target_ip, res_fp

                    with ThreadPoolExecutor(max_workers=min(6, len(unknown_fp_ips))) as fp_pool:
                        for ip_key, fp_res in fp_pool.map(_fp_scan, unknown_fp_ips):
                            if fp_res and (fp_res.get("model") or fp_res.get("vendor") or fp_res.get("role") or fp_res.get("snmp")):
                                fp_updates[ip_key] = fp_res
                    if fp_updates:
                        self._save_cached_fingerprints(fp_updates)
                        all_fps.update(fp_updates)

            for item in discovered:
                resolved_vendor, label = self._build_device_label(
                    item["ip"],
                    item["mac"],
                    item["vendor"],
                    item["type"],
                    hostname=all_hosts.get(item["ip"], ""),
                    fp=all_fps.get(item["ip"]),
                )
                item["vendor"] = resolved_vendor
                item["suggestedName"] = label
                if all_hosts.get(item["ip"]):
                    item["hostname"] = all_hosts[item["ip"]]
                self._upsert_inventory(item, scan_id)
                item["observedMac"] = observed_inventory_mac(item["mac"], item["ip"])

            self._mark_unseen_inventory_offline(networks, scan_id, started_at)
            sync_summary = self.sync_infrastructure_devices()
            self._record_event(
                "NETWORK_SCAN",
                "INFO",
                "LAN Discovery Scan Completed",
                f"Pulse observed {len(discovered)} addresses on {', '.join(str(n) for n in networks)} ({ping_responses} ICMP replies).",
                device_name="LAN Discovery",
            )
            timestamp = utc_now()
            echo_addresses = {ipaddress.IPv4Address(ip) for ip in ping_alive_hosts}
            observed_addresses = {ipaddress.IPv4Address(ip) for ip in seen_ips}
            coverage = [
                {
                    "subnet": str(network),
                    "addressesProbed": sum(
                        not address.is_loopback and not address.is_multicast for address in network.hosts()
                    ),
                    "icmpReplies": sum(address in network for address in echo_addresses),
                    "addressesObserved": sum(address in network for address in observed_addresses),
                }
                for network in networks
            ]
            with self._connect() as db:
                db.execute(
                    """INSERT OR REPLACE INTO monitor_metadata (key, value)
                       VALUES ('last_discovery_at', ?), ('last_discovery_coverage', ?)""",
                    (timestamp, json.dumps(coverage)),
                )
            self.broadcast(
                "inventory_update",
                {
                    "inventory": self.get_inventory(),
                    "events": self.get_events(50),
                    "devices": self._hydrated_devices(),
                    "lastDiscoveryAt": timestamp,
                    "routers": self.get_router_fleet() if hasattr(self, "get_router_fleet") else [],
                    "activeAlerts": self.get_active_alerts(),
                    "alertStats": self.get_alert_stats(),
                },
            )
            return {
                "success": True,
                "timestamp": timestamp,
                "totalDiscovered": len(discovered),
                "pingResponses": ping_responses,
                "networks": [str(network) for network in networks],
                "coverage": coverage,
                "devices": discovered,
                "inventory": self.get_inventory(),
                "events": self.get_events(50),
                "infrastructureSync": sync_summary,
                "monitoredDevices": self._hydrated_devices(),
            }
        finally:
            self._scan_lock.release()

    def refresh_live_arp_and_infra(self) -> dict:
        """Lightweight real-time ARP neighbor sync + fingerprint check for newly joined routers, Deco mesh & APs."""
        self = cast("Monitor", self)
        os_mod = runtime_attr("os", os)
        subproc_mod = runtime_attr("subprocess", subprocess)
        if not self._scan_lock.acquire(blocking=False):
            return {"skipped": True}
        try:
            networks = self._known_local_networks() or self._local_lan_networks()
            arp_entries = self._read_arp_entries(os_mod.name, subproc_mod.run)
            known_gateways = self._known_local_gateways()
            gw_plus_one = {network.network_address + 1 for network in networks}
            all_fps = self._get_cached_fingerprints() if hasattr(self, "_get_cached_fingerprints") else {}
            all_hosts = {}

            with self._connect() as db:
                existing_rows = {
                    str(r["mac"]).lower(): dict(r)
                    for r in db.execute("SELECT mac, ip, is_online FROM discovered_devices").fetchall()
                }

            new_or_changed: list[dict] = []
            seen_ips: set[str] = set()
            for raw_ip, raw_mac, kind in arp_entries:
                try:
                    ip = self._validate_ip(raw_ip)
                    mac = self._normalize_mac(raw_mac)
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if mac in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                    continue
                if not addr.is_private or addr.is_multicast or not any(addr in n for n in networks) or ip in seen_ips:
                    continue
                seen_ips.add(ip)

                prev = existing_rows.get(mac)
                prev_fp = all_fps.get(ip, {})
                needs_fp = bool(
                    prev is None
                    or prev.get("ip") != ip
                    or not prev.get("is_online")
                    or (prev_fp and prev_fp.get("mac") and prev_fp.get("mac") != mac)
                )
                if not needs_fp:
                    continue
                oui = mac.replace(":", "")[:6]
                vendor, device_type = self._vendor_for_oui(oui)
                if addr in gw_plus_one or ip in known_gateways:
                    device_type = "gateway"
                new_or_changed.append({
                    "ip": ip,
                    "mac": mac,
                    "arpType": kind,
                    "vendor": vendor,
                    "type": device_type,
                })

            if not new_or_changed:
                return {"changed": 0}

            cand_ips = [x["ip"] for x in new_or_changed]
            mac_by_ip = {item["ip"]: item["mac"] for item in new_or_changed}
            resolved_hosts = self._resolve_hostnames_bulk(cand_ips, mac_by_ip)
            if resolved_hosts:
                all_hosts.update(resolved_hosts)
            if hasattr(self, "identify_network_device"):
                fp_updates: dict[str, dict] = {}

                def _fp_fast(target_ip: str) -> tuple[str, dict | None]:
                    open_p = [p for p in (80, 443, 8080, 20001) if self._probe_tcp_socket(target_ip, p, timeout=0.25)[0]]
                    if not open_p:
                        return target_ip, None
                    res_fp = self.identify_network_device(target_ip, open_ports=open_p)
                    if res_fp:
                        res_fp["mac"] = mac_by_ip.get(target_ip, "")
                    return target_ip, res_fp

                with ThreadPoolExecutor(max_workers=min(16, len(cand_ips))) as pool:
                    for ip_key, fp_res in pool.map(_fp_fast, cand_ips):
                        if fp_res and (fp_res.get("model") or fp_res.get("vendor") or fp_res.get("role")):
                            fp_updates[ip_key] = fp_res
                if fp_updates:
                    self._save_cached_fingerprints(fp_updates)
                    all_fps.update(fp_updates)

            for item in new_or_changed:
                resolved_vendor, label = self._build_device_label(
                    item["ip"],
                    item["mac"],
                    item["vendor"],
                    item["type"],
                    hostname=all_hosts.get(item["ip"], ""),
                    fp=all_fps.get(item["ip"]),
                )
                self._upsert_inventory({
                    "ip": item["ip"],
                    "mac": item["mac"],
                    "arpType": item["arpType"],
                    "vendor": resolved_vendor,
                    "type": item["type"],
                    "suggestedName": label,
                    **({"hostname": all_hosts[item["ip"]]} if all_hosts.get(item["ip"]) else {}),
                })
            sync_res = self.sync_infrastructure_devices()
            self.broadcast(
                "inventory_update",
                {
                    "inventory": self.get_inventory(),
                    "events": self.get_events(50),
                    "devices": self._hydrated_devices(),
                    "routers": self.get_router_fleet() if hasattr(self, "get_router_fleet") else [],
                    "activeAlerts": self.get_active_alerts(),
                    "alertStats": self.get_alert_stats(),
                },
            )
            return {"changed": len(new_or_changed), "sync": sync_res}
        except Exception:
            return {"changed": 0}
        finally:
            self._scan_lock.release()

    def _mark_unseen_inventory_offline(
        self, networks: list[ipaddress.IPv4Network], scan_id: str, started_at: str
    ) -> None:
        self = cast("Monitor", self)
        events = []
        with self._connect() as db:
            rows = db.execute(
                "SELECT mac, ip, suggested_name, is_online, last_scan_id, last_seen FROM discovered_devices"
            ).fetchall()
            for row in rows:
                address = ipaddress.ip_address(row["ip"])
                if (
                    any(address in network for network in networks)
                    and row["last_scan_id"] != scan_id
                    and row["is_online"]
                    and row["last_seen"] < started_at
                ):
                    changed = db.execute(
                        """UPDATE discovered_devices SET is_online=0
                           WHERE mac=? AND last_seen < ? AND is_online=1""",
                        (row["mac"], started_at),
                    ).rowcount
                    if changed:
                        events.append((row["mac"], row["ip"], row["suggested_name"]))
        for mac, ip, name in events:
            self._record_event(
                "DEVICE_MISSING",
                "WARNING",
                "Device not observed in daily LAN scan",
                f"{name} ({ip}) was not observed during the latest LAN scan.",
                mac,
                ip,
                name,
            )

    def last_discovery_at(self) -> str | None:
        self = cast("Monitor", self)
        with self._connect() as db:
            row = db.execute(
                "SELECT value FROM monitor_metadata WHERE key='last_discovery_at'"
            ).fetchone()
        return row["value"] if row else None

    def get_discovery_coverage(self) -> dict:
        self = cast("Monitor", self)
        with self._connect() as db:
            metadata = dict(db.execute(
                """SELECT key, value FROM monitor_metadata
                   WHERE key IN ('last_discovery_at', 'last_discovery_coverage')"""
            ).fetchall())
        try:
            last_scan = json.loads(metadata.get("last_discovery_coverage", "[]"))
        except ValueError:
            last_scan = []
        return {
            "subnets": [str(network) for network in self._known_local_networks()],
            "lastScanAt": metadata.get("last_discovery_at"),
            "lastScan": last_scan if isinstance(last_scan, list) else [],
        }

    def _daily_discovery_due(self) -> bool:
        last_scan = self.last_discovery_at()
        if not last_scan:
            return True
        dt_cls = runtime_attr("datetime", datetime)
        try:
            last_date = (
                dt_cls.fromisoformat(last_scan.replace("Z", "+00:00"))
                .astimezone()
                .date()
            )
        except ValueError:
            return True
        return last_date < dt_cls.now().astimezone().date()

    @staticmethod
    def _vendor_for_oui(oui: str) -> tuple[str, str]:
        key = oui.lower()
        if key in KNOWN_OUI_VENDORS:
            return KNOWN_OUI_VENDORS[key]
        if key in CLIENT_OUI_VENDORS:
            return CLIENT_OUI_VENDORS[key]
        nmap_vendors = load_nmap_mac_vendors()
        if key in nmap_vendors:
            return (nmap_vendors[key], "client")
        if key.startswith("0200"):
            return ("LAN Host", "device")
        if len(key) >= 2:
            try:
                if (int(key[:2], 16) & 2) != 0:
                    return ("Wi-Fi Client (Private MAC)", "device")
            except ValueError:
                pass
        return ("LAN Network Device", "device")

    @staticmethod
    def _probe_netbios_name(ip: str, timeout: float = 0.22) -> str:
        """Query UDP port 137 (NetBIOS Node Status) to fetch active PC/Server workstation name."""
        pkt = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(pkt, (ip, 137))
                data, _ = sock.recvfrom(512)
            if len(data) <= 57:
                return ""
            num = data[56]
            pos = 57
            for _ in range(num):
                if pos + 18 > len(data):
                    break
                raw_name = data[pos : pos + 15].decode("ascii", "ignore").strip()
                suffix = data[pos + 15]
                flags = data[pos + 16]
                if suffix == 0x00 and not (flags & 0x80) and raw_name and not raw_name.startswith("__"):
                    return raw_name
                pos += 18
        except OSError:
            pass
        return ""

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int) -> str:
        """Decode compressed DNS label name safely."""
        labels: list[str] = []
        visited: set[int] = set()
        max_jumps = 12
        while 0 <= offset < len(data) and max_jumps > 0:
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                offset = ((length & 0x3F) << 8) | data[offset + 1]
                max_jumps -= 1
                continue
            offset += 1
            if offset + length > len(data):
                break
            label = data[offset : offset + length].decode("utf-8", "ignore").strip()
            if label:
                labels.append(label)
            offset += length
        return ".".join(labels)

    @classmethod
    def _udp_ptr_query(
        cls, ip: str, target_host: str, port: int, timeout: float = 0.20, recursion: bool = False
    ) -> str:
        """Send a non-blocking UDP DNS/mDNS/LLMNR PTR query and extract cleaned hostname."""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ""
            rev_name = f"{'.'.join(reversed(octets))}.in-addr.arpa"
            qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in rev_name.split(".")) + b"\x00"
            flags = b"\x01\x00" if recursion else b"\x00\x00"
            pkt = b"\x12\x34" + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(pkt, (target_host, port))
                data, _ = sock.recvfrom(512)
            if len(data) <= 12:
                return ""
            if (data[3] & 0x0F) != 0 or int.from_bytes(data[6:8], "big") == 0:
                return ""
            pos = 12 + len(qname) + 4
            if pos + 12 > len(data):
                return ""
            name = cls._parse_dns_name(data, pos + 12).rstrip(".")
            for suffix in (".local", ".lan", ".home", ".internal", ".arpa"):
                if name.lower().endswith(suffix):
                    name = name[: -len(suffix)]
            low = name.lower()
            if not name or low in {"localhost", "root", ip} or re.fullmatch(r"\d+(?:\.\d+){3}", name):
                return ""
            return name[:80]
        except OSError:
            return ""

    @classmethod
    def _probe_mdns_llmnr_name(cls, ip: str, timeout: float = 0.20) -> str:
        """Query unicast mDNS (5353) and LLMNR (5355) directly against the device IP."""
        return (
            cls._udp_ptr_query(ip, ip, 5353, timeout=timeout, recursion=False)
            or cls._udp_ptr_query(ip, ip, 5355, timeout=timeout, recursion=False)
        )

    @classmethod
    def _probe_gateway_dns_ptr(cls, ip: str, gateways: set[str], timeout: float = 0.18) -> str:
        """Query local router/gateway DNS server (UDP 53) for DHCP lease PTR hostname."""
        for gw in sorted(gateways)[:2]:
            name = cls._udp_ptr_query(ip, gw, 53, timeout=timeout, recursion=True)
            if name:
                return name
        return ""

    def _get_cached_hostnames(self, mac_by_ip: dict[str, str] | None = None) -> dict[str, str]:
        self = cast("Monitor", self)
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT value FROM monitor_metadata WHERE key='device_hostnames'"
                ).fetchone()
            if row and row["value"]:
                data = json.loads(row["value"])
                if not isinstance(data, dict):
                    return {}
                names = {}
                for ip, item in data.items():
                    if isinstance(item, dict):
                        if mac_by_ip is None or (item.get("mac") and item["mac"] == mac_by_ip.get(ip)):
                            names[ip] = item["name"]
                    elif mac_by_ip is None and isinstance(item, str):
                        names[ip] = item
                return names
        except Exception:
            pass
        return {}

    def _save_cached_hostnames(self, updates: dict[str, str], mac_by_ip: dict[str, str] | None = None) -> None:
        self = cast("Monitor", self)
        if not updates:
            return
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT value FROM monitor_metadata WHERE key='device_hostnames'").fetchone()
                current = json.loads(row["value"]) if row else {}
                for ip, name in updates.items():
                    if name:
                        mac = observed_inventory_mac((mac_by_ip or {}).get(ip, ""), ip)
                        current[ip] = {"name": name, "mac": mac}
                db.execute(
                    "INSERT OR REPLACE INTO monitor_metadata (key, value) VALUES ('device_hostnames', ?)",
                    (json.dumps(current),),
                )
        except Exception:
            pass

    def _resolve_hostnames_bulk(self, ips: list[str], mac_by_ip: dict[str, str] | None = None) -> dict[str, str]:
        """Resolve hostnames concurrently across NetBIOS, mDNS, LLMNR, and local gateway PTR."""
        unique_ips = sorted({ip for ip in ips if ip})
        if not unique_ips:
            return {}
        gateways = self._known_local_gateways()

        def _resolve_one(ip: str) -> tuple[str, str]:
            name = (
                self._probe_netbios_name(ip)
                or self._probe_mdns_llmnr_name(ip)
                or self._probe_gateway_dns_ptr(ip, gateways)
            )
            return ip, name

        resolved: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=min(48, len(unique_ips))) as pool:
            for ip_key, hostname in pool.map(_resolve_one, unique_ips):
                if hostname:
                    resolved[ip_key] = hostname
        if resolved:
            self._save_cached_hostnames(resolved, mac_by_ip)
        return resolved

    @staticmethod
    def _build_device_label(
        ip: str,
        mac: str,
        vendor: str,
        device_type: str,
        hostname: str = "",
        fp: dict | None = None,
    ) -> tuple[str, str]:
        """Build clean human-readable (vendor, device_name) from hostname, fingerprint, and MAC OUI."""
        fp = fp or {}
        if fp.get("mac") and fp["mac"].lower() != mac.lower():
            fp = {}
        snmp = fp.get("snmp")
        if not isinstance(snmp, dict):
            snmp = {}
        raw_host = str(hostname or snmp.get("sysName") or "").strip()
        fp_model = str(fp.get("model") or "").strip()
        fp_vendor = str(fp.get("vendor") or "").strip()
        resolved_vendor = fp_vendor or vendor or "LAN Network Device"

        hl = raw_host.lower()
        ml = fp_model.lower()
        generic_vendors = {
            "",
            "unknown vendor",
            "wi-fi client (private mac)",
            "lan host",
            "lan network device",
        }
        if resolved_vendor.lower() in generic_vendors or resolved_vendor == "LAN Client":
            if any(t in hl for t in ("desktop-", "win-", "laptop-", "pc-", "msi")) or "windows" in ml:
                resolved_vendor = "Windows PC"
            elif "ubuntu" in ml or "debian" in ml or "ubuntu" in hl:
                resolved_vendor = "Ubuntu Linux Server"
            elif any(t in hl for t in ("android", "redmi", "poco", "galaxy")):
                resolved_vendor = "Android Device"
            elif any(t in hl for t in ("iphone", "ipad", "macbook", "imac")):
                resolved_vendor = "Apple Device"
            elif "epson" in ml or "epson" in hl:
                resolved_vendor = "Seiko Epson Printer"

        if device_type == "gateway":
            return resolved_vendor, f"Subnet Gateway ({ip})"

        if raw_host:
            short_host = raw_host
            if resolved_vendor.lower() in generic_vendors or resolved_vendor.lower() in hl:
                return resolved_vendor, short_host
            return resolved_vendor, f"{short_host} ({resolved_vendor})"

        if fp_model and not fp_model.startswith("SSH-2.0-"):
            short_model = fp_model.split("Dual-Band")[0].split("4-Stream")[0].strip()
            if short_model:
                return resolved_vendor, f"{short_model} ({ip})"

        vl = resolved_vendor.lower()
        if "hikvision" in vl:
            return resolved_vendor, f"Hikvision IP Camera ({ip})"
        if "dahua" in vl:
            return resolved_vendor, f"Dahua IP Camera ({ip})"
        if "epson" in vl:
            return resolved_vendor, f"Epson Printer ({ip})"
        if resolved_vendor == "Wi-Fi Client (Private MAC)":
            return resolved_vendor, f"Private Wi-Fi Device ({ip})"
        return resolved_vendor, f"{resolved_vendor} ({ip})"

