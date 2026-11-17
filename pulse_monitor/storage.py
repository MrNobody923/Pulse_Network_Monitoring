"""SQLite persistence layer for discovered LAN inventory, events, favourites, and config."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .config import (
    CONFIG_FILE,
    DATA_DIR,
    DATABASE_FILE,
    KNOWN_OUI_VENDORS,
    PLACEHOLDER_DEFAULT_IPS,
    normalize_mac,
    runtime_attr,
    utc_now,
    validate_ip,
    validate_port,
)


class StorageMixin:
    """Provides persistent SQLite storage and JSON configuration management."""

    @staticmethod
    def _data_dir() -> Path:
        return runtime_attr("DATA_DIR", DATA_DIR)

    @staticmethod
    def _config_file() -> Path:
        return runtime_attr("CONFIG_FILE", CONFIG_FILE)

    @staticmethod
    def _database_file() -> Path:
        return runtime_attr("DATABASE_FILE", DATABASE_FILE)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self._database_file(), timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _event_store(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS discovered_devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    suggested_name TEXT NOT NULL,
                    arp_type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    authorized INTEGER NOT NULL DEFAULT 0,
                    is_online INTEGER NOT NULL DEFAULT 1,
                    last_scan_id TEXT
                );
                CREATE TABLE IF NOT EXISTS monitor_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_favorites (
                    asset_key TEXT PRIMARY KEY,
                    added_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_archives (
                    asset_key TEXT PRIMARY KEY,
                    archived_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    mac TEXT,
                    ip TEXT,
                    device_name TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_network_events_timestamp
                    ON network_events(timestamp DESC);
                CREATE TABLE IF NOT EXISTS ping_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    ts_epoch REAL NOT NULL,
                    alive INTEGER NOT NULL,
                    latency_ms REAL
                );
                CREATE INDEX IF NOT EXISTS idx_ping_samples_target_ts
                    ON ping_samples(target_id, ts_epoch DESC);
                """
            )
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(discovered_devices)").fetchall()
            }
            if "is_online" not in columns:
                db.execute(
                    "ALTER TABLE discovered_devices ADD COLUMN is_online INTEGER NOT NULL DEFAULT 1"
                )
            if "last_scan_id" not in columns:
                db.execute("ALTER TABLE discovered_devices ADD COLUMN last_scan_id TEXT")

    def save_config(self) -> None:
        data_dir = self._data_dir()
        config_file = self._config_file()
        data_dir.mkdir(parents=True, exist_ok=True)
        temp_file = config_file.with_suffix(".json.tmp")
        temp_file.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        os.replace(temp_file, config_file)

    def get_devices(self) -> list[dict]:
        with self.lock:
            devices = [dict(device) for device in self.config.get("devices", [])]
        favorites = self._favorite_keys()
        archived = self._archived_keys()
        for device in devices:
            favorite_key = (
                f"mac:{device['mac'].lower()}" if device.get("mac") else f"ip:{device['ip']}"
            )
            device["favorite"] = (
                favorite_key in favorites or f"ip:{device['ip']}" in favorites
            )
            device["archived"] = (
                favorite_key in archived or f"ip:{device['ip']}" in archived
            )
        return devices

    def add_device(self, device: dict) -> dict:
        ip = self._validate_ip(device.get("ip"))
        name = str(device.get("name", "")).strip()
        if not name:
            raise ValueError("Device name is required")
        port = self._validate_port(device.get("port", 80))
        raw_mac = self._normalize_mac(device.get("mac")) if device.get("mac") else ""
        if not raw_mac:
            with self._connect() as db:
                row = db.execute(
                    "SELECT mac FROM discovered_devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
                    (ip,),
                ).fetchone()
            if row and row["mac"]:
                raw_mac = str(row["mac"]).lower()
        new_device = {
            "id": str(device.get("id") or f"dev-custom-{uuid.uuid4().hex[:10]}"),
            "name": name[:120],
            "ip": ip,
            "type": str(device.get("type") or "ap")[:24],
            "vendor": str(device.get("vendor") or "")[:80],
            "subnet": self._subnet_for_ip(ip) if hasattr(self, "_subnet_for_ip") else "",
            "checkMethod": "auto",
            "port": port,
            "location": str(device.get("location") or "Office")[:120],
            "critical": bool(device.get("critical", True)),
            "manual": bool(device.get("manual", False)),
            "mac": raw_mac,
        }
        with self.lock:
            if any(d["ip"] == ip for d in self.config["devices"]):
                raise ValueError("A monitored device already uses this IP address")
            self.config["devices"].append(new_device)
            self.save_config()
        if new_device["mac"]:
            self.authorize_device(new_device["mac"])
        self._record_event(
            "DEVICE_ADDED",
            "INFO",
            "Monitored Device Added",
            f"Added {new_device['name']} ({ip}:{port}) [{new_device['type']}] to active monitoring.",
            mac=new_device["mac"],
            ip=ip,
            device_name=new_device["name"],
        )
        return new_device

    def update_device(self, device_id: str, updates: dict) -> dict | None:
        allowed = {"name", "ip", "type", "port", "location", "critical", "checkMethod", "mac"}
        updates = {key: value for key, value in updates.items() if key in allowed}
        if "ip" in updates:
            updates["ip"] = self._validate_ip(updates["ip"])
        if "port" in updates:
            updates["port"] = self._validate_port(updates["port"])
        if "name" in updates:
            updates["name"] = str(updates["name"]).strip()[:120]
            if not updates["name"]:
                raise ValueError("Device name is required")
        if "mac" in updates and updates["mac"]:
            updates["mac"] = self._normalize_mac(updates["mac"])
        with self.lock:
            for device in self.config["devices"]:
                if device["id"] == device_id:
                    device.update(updates)
                    self.save_config()
                    result = dict(device)
                    break
            else:
                return None
        if result.get("mac"):
            self.authorize_device(result["mac"])
        return result

    def delete_device(self, device_id: str) -> bool:
        removed_dev = None
        with self.lock:
            before = len(self.config["devices"])
            kept = []
            for d in self.config["devices"]:
                if d["id"] == device_id and removed_dev is None:
                    removed_dev = dict(d)
                else:
                    kept.append(d)
            self.config["devices"] = kept
            if len(self.config["devices"]) == before:
                return False
            self.save_config()
        if removed_dev:
            rem_ip = removed_dev.get("ip", "")
            if rem_ip:
                self._clear_ip_state_and_alerts(rem_ip)
                self._prune_orphaned_device_alerts(save=True)
            self._record_event(
                "DEVICE_REMOVED",
                "WARNING",
                "Monitored Device Removed",
                f"Removed {removed_dev.get('name', rem_ip)} ({rem_ip}) from active monitoring.",
                mac=removed_dev.get("mac", ""),
                ip=rem_ip,
                device_name=removed_dev.get("name", ""),
            )
        return True

    def sync_infrastructure_devices(self) -> dict:
        """Auto-enroll real discovered Routers, Access Points, Switches, and Gateways from LAN inventory."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM discovered_devices ORDER BY ip ASC"
            ).fetchall()

        if not rows:
            return {"synced": 0, "added": 0, "updated": 0, "removedPlaceholders": 0}

        local_nets = self._known_local_networks()
        known_gateways = self._known_local_gateways()
        router_ip = self.config.get("router", {}).get("ip", "192.168.0.1")
        net_plus_one = {str(n.network_address + 1) for n in local_nets}
        cached_fps = (
            self._get_cached_fingerprints()
            if hasattr(self, "_get_cached_fingerprints")
            else {}
        )

        discovered_ips = {row["ip"] for row in rows}
        db_by_mac = {str(row["mac"] or "").lower(): row for row in rows}
        infra_candidates: list[dict] = []

        for row in rows:
            mac = str(row["mac"] or "").lower()
            ip = str(row["ip"] or "")
            vendor = str(row["vendor"] or "")
            suggested = str(row["suggested_name"] or "")
            oui = mac.replace(":", "")[:6]
            oui_vendor, oui_type = KNOWN_OUI_VENDORS.get(oui, (vendor, "device"))
            fp = cached_fps.get(ip, {})
            fp_role = str(fp.get("role") or "").lower()
            fp_vendor = str(fp.get("vendor") or "")
            fp_model = str(fp.get("model") or "")
            preferred_port = int(fp.get("preferredPort") or 80)

            # Live server/IoT/client fingerprints explicitly override false infrastructure guesses
            fp_mac = str(fp.get("mac") or "").lower()
            if fp_mac and mac and fp_mac != mac:
                fp = {}
                fp_role = fp_vendor = fp_model = ""
            if fp_role in {"server", "client", "iot"}:
                continue

            octets = ip.split(".")
            last_octet = int(octets[3]) if len(octets) == 4 and octets[3].isdigit() else 0
            subnet_cidr = self._subnet_for_ip(ip, local_nets)
            subnet_zone = octets[2] if len(octets) == 4 else "0"

            vendor_lower = (fp_vendor or oui_vendor or vendor).lower()
            is_switch = (
                fp_role == "switch"
                or oui_type == "switch"
                or ("cisco" in vendor_lower and fp_role not in {"ap", "router"})
                or ("switch" in suggested.lower() and fp_role not in {"ap", "router"})
            )
            if local_nets:
                is_gateway = (
                    ip == router_ip
                    or ip in known_gateways
                    or ip in net_plus_one
                )
            else:
                has_router_vendor = vendor_lower not in {"", "unknown vendor"} or oui_type in {"ap", "switch", "gateway", "router"}
                is_gateway = (
                    ip == router_ip
                    or ip in known_gateways
                    or "gateway" in suggested.lower()
                    or (last_octet == 1 and has_router_vendor)
                )
            is_router = (
                not is_gateway
                and not is_switch
                and (fp_role == "router" or (oui_type == "router" and fp_role != "ap"))
            )
            is_ap = (
                not is_gateway
                and not is_switch
                and not is_router
                and "client nic" not in vendor_lower
                and (
                    fp_role == "ap"
                    or oui_type == "ap"
                    or any(
                        token in vendor_lower
                        for token in ("tp-link", "ubiquiti", "mikrotik", "aruba", "ruijie", "omada", "meraki", "netgear")
                    )
                )
            )

            if not (is_gateway or is_switch or is_router or is_ap):
                continue

            clean_vendor = (
                fp_vendor
                if fp_vendor
                else (
                    oui_vendor
                    if oui_vendor and oui_vendor != "Unknown vendor"
                    else ("TP-Link" if ip == router_ip else "Office")
                )
            )
            short_model = (
                fp_model.split("Dual-Band")[0].split("4-Stream")[0].split("Mesh System")[0].strip()
                if fp_model
                else ""
            )
            if "deco" in fp_model.lower():
                clean_vendor = "TP-Link"
                short_model = "Deco Mesh"
            elif "omada eap" in fp_model.lower():
                clean_vendor = "TP-Link"
                short_model = "Omada EAP"
            prefixed_model = (
                short_model
                if short_model and short_model.lower().startswith(clean_vendor.lower())
                else f"{clean_vendor} {short_model}".strip()
            )

            if is_gateway:
                dev_type = "gateway"
                model_tag = prefixed_model if short_model else clean_vendor
                dev_name = (
                    f"Main Gateway Router ({model_tag} · {ip})"
                    if ip == router_ip
                    else f"Subnet Gateway Router ({model_tag} · {ip})"
                )
                location = f"Main Gateway · {subnet_cidr}"
            elif is_router:
                dev_type = "router"
                if "deco mesh" in fp_model.lower() or "deco" in prefixed_model.lower():
                    model_tag = "TP-Link Deco Mesh"
                    location = f"Deco Mesh Zone {subnet_zone} · {subnet_cidr}"
                else:
                    model_tag = prefixed_model if short_model else f"{clean_vendor} Router"
                    if "router" not in model_tag.lower():
                        model_tag = f"{model_tag} Router"
                    location = f"Router Zone {subnet_zone} · {subnet_cidr}"
                dev_name = f"{model_tag} · .{subnet_zone}.{last_octet}"
            elif is_switch:
                dev_type = "switch"
                dev_name = f"{short_model or 'Network Switch'} ({ip})"
                location = f"Network Switch · {subnet_cidr}"
            else:
                dev_type = "ap"
                model_tag = prefixed_model if short_model else f"{clean_vendor} Access Point"
                dev_name = f"{model_tag} · .{subnet_zone}.{last_octet}"
                location = f"Wi-Fi Zone {subnet_zone} · {subnet_cidr}"

            infra_candidates.append({
                "ip": ip,
                "mac": mac,
                "vendor": clean_vendor,
                "type": dev_type,
                "name": dev_name,
                "location": location,
                "subnet": subnet_cidr,
                "hardwareModel": fp_model,
                "critical": True,
                "port": preferred_port,
            })

        cand_by_mac = {c["mac"]: c for c in infra_candidates if c.get("mac")}
        cand_by_ip = {c["ip"]: c for c in infra_candidates if c.get("ip")}

        added_count = 0
        updated_count = 0
        removed_placeholders = 0
        authorized_macs: list[str] = []

        def _is_auto_name(name_val: str) -> bool:
            return any(
                name_val.startswith(prefix)
                for prefix in (
                    "Cisco Managed Switch (",
                    "Network Switch (",
                    "TP-Link ",
                    "Main Gateway Router (",
                    "Subnet Gateway Router (",
                )
            )

        with self.lock:
            kept_devices: list[dict] = []
            removed_ips: set[str] = set()
            for dev in self.config.get("devices", []):
                dev_id = str(dev.get("id") or "")
                dev_ip = dev.get("ip", "")
                dev_mac = str(dev.get("mac") or "").lower()
                if (
                    dev_ip in PLACEHOLDER_DEFAULT_IPS
                    and dev_ip not in discovered_ips
                    and not dev_mac
                ):
                    removed_placeholders += 1
                    removed_ips.add(dev_ip)
                    continue
                # Prune previously auto-enrolled entries whose MAC/IP is no longer verified infrastructure
                is_auto_enrolled = (
                    dev_id.startswith(("dev-gateway-", "dev-router-", "dev-ap-", "dev-switch-"))
                    and not dev.get("manual")
                )
                if is_auto_enrolled and dev_ip != router_ip:
                    is_valid_cand = dev_mac in cand_by_mac or dev_ip in cand_by_ip
                    db_row = db_by_mac.get(dev_mac)
                    if not is_valid_cand and (db_row is not None or dev_mac):
                        removed_placeholders += 1
                        removed_ips.add(dev_ip)
                        continue
                kept_devices.append(dev)

            for rem_ip in removed_ips:
                self._clear_ip_state_and_alerts(rem_ip)

            by_mac = {
                str(d.get("mac") or "").lower(): d
                for d in kept_devices
                if d.get("mac")
            }
            by_ip = {d.get("ip"): d for d in kept_devices if d.get("ip")}

            for cand in infra_candidates:
                existing = by_mac.get(cand["mac"]) or by_ip.get(cand["ip"])
                if existing is not None:
                    if existing.get("manual") or str(existing.get("id") or "").startswith("dev-custom-"):
                        if not existing.get("mac") and cand["mac"]:
                            existing["mac"] = cand["mac"]
                            updated_count += 1
                        continue
                    changed = False
                    if existing.get("ip") != cand["ip"]:
                        old_ip = existing.get("ip")
                        existing["ip"] = cand["ip"]
                        if old_ip:
                            self._clear_ip_state_and_alerts(old_ip)
                        if _is_auto_name(str(existing.get("name") or "")):
                            existing["name"] = cand["name"]
                            existing["location"] = cand["location"]
                        changed = True
                    elif _is_auto_name(str(existing.get("name") or "")) and (
                        existing.get("name") != cand["name"]
                        or existing.get("location") != cand["location"]
                        or existing.get("type") != cand["type"]
                        or existing.get("hardwareModel") != cand.get("hardwareModel", "")
                    ):
                        existing["name"] = cand["name"]
                        existing["location"] = cand["location"]
                        changed = True
                    if not existing.get("mac") and cand["mac"]:
                        existing["mac"] = cand["mac"]
                        changed = True
                    if existing.get("vendor") != cand["vendor"]:
                        existing["vendor"] = cand["vendor"]
                        changed = True
                    if existing.get("subnet") != cand["subnet"]:
                        existing["subnet"] = cand["subnet"]
                        changed = True
                    if existing.get("type") != cand["type"]:
                        existing["type"] = cand["type"]
                        changed = True
                    if cand.get("hardwareModel") and existing.get("hardwareModel") != cand["hardwareModel"]:
                        existing["hardwareModel"] = cand["hardwareModel"]
                        changed = True
                    if cand.get("port") and existing.get("port") != cand["port"] and str(existing.get("id") or "").startswith("dev-"):
                        existing["port"] = cand["port"]
                        changed = True
                    if changed:
                        updated_count += 1
                else:
                    mac_slug = cand["mac"].replace(":", "")[-6:]
                    new_dev = {
                        "id": f"dev-{cand['type']}-{mac_slug}",
                        "name": cand["name"],
                        "ip": cand["ip"],
                        "type": cand["type"],
                        "vendor": cand["vendor"],
                        "subnet": cand["subnet"],
                        "hardwareModel": cand.get("hardwareModel", ""),
                        "checkMethod": "auto",
                        "port": cand.get("port", 80),
                        "location": cand["location"],
                        "critical": True,
                        "mac": cand["mac"],
                    }
                    kept_devices.append(new_dev)
                    by_mac[cand["mac"]] = new_dev
                    by_ip[cand["ip"]] = new_dev
                    added_count += 1
                if cand["mac"]:
                    authorized_macs.append(cand["mac"])

            # Sort devices logically: gateways first, then secondary routers, switches, APs, then by IP
            type_rank = {"gateway": 0, "router": 1, "switch": 2, "ap": 3, "server": 4}
            kept_devices.sort(
                key=lambda d: (
                    type_rank.get(str(d.get("type", "")).lower(), 5),
                    [int(x) if x.isdigit() else 0 for x in str(d.get("ip", "0.0.0.0")).split(".")],
                )
            )
            self.config["devices"] = kept_devices
            self._prune_orphaned_device_alerts(save=False)
            if added_count or updated_count or removed_placeholders:
                self.save_config()

        if authorized_macs:
            with self._connect() as db:
                db.executemany(
                    "UPDATE discovered_devices SET authorized=1 WHERE mac=?",
                    [(m,) for m in authorized_macs],
                )

        return {
            "synced": len(infra_candidates),
            "added": added_count,
            "updated": updated_count,
            "removedPlaceholders": removed_placeholders,
        }

    def _clear_ip_state_and_alerts(self, ip: str) -> None:
        if not ip:
            return
        with self.lock:
            self.active_alerts.pop(f"dev-{ip}", None)
            self.active_alerts.pop(f"perf-{ip}", None)
            self.latest_devices.pop(ip, None)
            self.device_status.pop(ip, None)
            self.history.pop(ip, None)
            self.config["alerts"] = [
                a for a in self.config.get("alerts", [])
                if a.get("ip") != ip
            ]

    def _prune_orphaned_device_alerts(self, save: bool = True) -> int:
        with self.lock:
            devices_by_ip = {
                d["ip"]: d for d in self.config.get("devices", []) if d.get("ip")
            }
            active_ips = set(devices_by_ip.keys())
            removed = 0
            updated = False
            for key in list(self.active_alerts.keys()):
                if key.startswith("dev-") or key.startswith("perf-"):
                    alert = self.active_alerts[key]
                    if alert.get("isDrill"):
                        continue
                    ip = alert.get("ip")
                    if ip not in active_ips:
                        self.active_alerts.pop(key, None)
                        alert["status"] = "RESOLVED"
                        alert["severity"] = "RESOLVED"
                        alert["resolvedAt"] = utc_now()
                        removed += 1
                    else:
                        dev = devices_by_ip[ip]
                        dev_name = dev.get("name") or ip
                        if alert.get("deviceName") != dev_name:
                            alert["deviceName"] = dev_name
                            alert["title"] = (
                                f"{dev_name} ({ip}) is DOWN / Unreachable"
                                if key.startswith("dev-")
                                else f"Latency / packet loss on {dev_name}"
                            )
                            updated = True
            before = len(self.config.get("alerts", []))
            self.config["alerts"] = [
                a for a in self.config.get("alerts", [])
                if not (
                    a.get("status") in {"ACTIVE", "ACKNOWLEDGED", "INVESTIGATING"}
                    and not a.get("isDrill")
                    and (str(a.get("key") or "").startswith("dev-") or str(a.get("key") or "").startswith("perf-"))
                    and a.get("ip") not in active_ips
                )
            ]
            if save and (removed or updated or len(self.config["alerts"]) != before):
                self.save_config()
            return removed

    def _record_ping_sample(self, target_id: str, alive: bool, latency_ms: float | None) -> None:
        now_ts = datetime.now().timestamp()
        with self._connect() as db:
            db.execute(
                "INSERT INTO ping_samples (target_id, ts_epoch, alive, latency_ms) VALUES (?, ?, ?, ?)",
                (target_id, now_ts, 1 if alive else 0, latency_ms),
            )
            # Prune samples older than 30 days occasionally
            if int(now_ts) % 60 < 2:
                cutoff_30d = now_ts - (30 * 86400)
                db.execute("DELETE FROM ping_samples WHERE ts_epoch < ?", (cutoff_30d,))

    def _get_ping_uptime_stats(self, target_id: str) -> dict:
        now_ts = datetime.now().timestamp()
        cutoff_24h = now_ts - 86400
        cutoff_30d = now_ts - (30 * 86400)
        with self._connect() as db:
            row24 = db.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(alive), 0) AS ok FROM ping_samples WHERE target_id=? AND ts_epoch>=?",
                (target_id, cutoff_24h),
            ).fetchone()
            row30 = db.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(alive), 0) AS ok FROM ping_samples WHERE target_id=? AND ts_epoch>=?",
                (target_id, cutoff_30d),
            ).fetchone()
        n24, ok24 = (row24["n"], row24["ok"]) if row24 else (0, 0)
        n30, ok30 = (row30["n"], row30["ok"]) if row30 else (0, 0)
        return {
            "uptime24hPct": round((ok24 / n24) * 100, 2) if n24 else None,
            "uptime30dPct": round((ok30 / n30) * 100, 2) if n30 else None,
            "samples24h": int(n24 or 0),
            "samples30d": int(n30 or 0),
        }

    def _load_recent_ping_samples(self, target_id: str, limit: int = 60) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT ts_epoch, alive, latency_ms FROM ping_samples WHERE target_id=? ORDER BY id DESC LIMIT ?",
                (target_id, limit),
            ).fetchall()
        out = []
        for r in reversed(rows):
            dt = datetime.fromtimestamp(float(r["ts_epoch"])).astimezone()
            alive = bool(r["alive"])
            out.append({
                "time": dt.strftime("%H:%M:%S"),
                "dateTime": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "ms": r["latency_ms"],
                "status": "online" if alive else "offline",
                "message": (
                    f"200 - OK • Response in {r['latency_ms']} ms"
                    if alive
                    else "Connection LOST • Timeout"
                ),
            })
        return out

    @staticmethod
    def _validate_ip(value: object) -> str:
        return validate_ip(value)

    @staticmethod
    def _validate_port(value: object) -> int:
        return validate_port(value)

    @staticmethod
    def _normalize_mac(value: object) -> str:
        return normalize_mac(value)

    def _record_event(
        self,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        mac: str = "",
        ip: str = "",
        device_name: str = "",
    ) -> dict:
        timestamp = utc_now()
        with self._connect() as db:
            cursor = db.execute(
                """INSERT INTO network_events
                   (timestamp, event_type, severity, title, message, mac, ip, device_name)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, event_type, severity, title, message, mac, ip, device_name),
            )
            event_id = cursor.lastrowid
        event = {
            "id": event_id,
            "timestamp": timestamp,
            "eventType": event_type,
            "severity": severity,
            "title": title,
            "message": message,
            "mac": mac,
            "ip": ip,
            "deviceName": device_name,
        }
        self.broadcast("network_event", event)
        return event

    def get_events(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM network_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "eventType": row["event_type"],
                "severity": row["severity"],
                "title": row["title"],
                "message": row["message"],
                "mac": row["mac"],
                "ip": row["ip"],
                "deviceName": row["device_name"],
            }
            for row in rows
        ]

    def clear_events(self) -> dict:
        with self._connect() as db:
            removed = int(db.execute("SELECT COUNT(*) FROM network_events").fetchone()[0] or 0)
            db.execute("DELETE FROM network_events")
        self.broadcast("events_cleared", {"removed": removed})
        return {"success": True, "removed": removed}

    def get_inventory(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM discovered_devices ORDER BY last_seen DESC"
            ).fetchall()
        known_macs = {
            d.get("mac", "").lower() for d in self.get_devices() if d.get("mac")
        }
        favorites = self._favorite_keys()
        archived = self._archived_keys()
        dt_cls = runtime_attr("datetime", datetime)
        today = dt_cls.now().astimezone().date().isoformat()
        return [
            {
                "mac": row["mac"],
                "ip": row["ip"],
                "vendor": row["vendor"],
                "name": row["suggested_name"],
                "suggestedName": row["suggested_name"],
                "arpType": row["arp_type"],
                "firstSeen": row["first_seen"],
                "lastSeen": row["last_seen"],
                "authorized": bool(row["authorized"]) or row["mac"] in known_macs,
                "observed": bool(row["is_online"]),
                "isOnline": bool(row["is_online"]),
                "favorite": (
                    f"mac:{row['mac']}" in favorites
                    or f"ip:{row['ip']}" in favorites
                ),
                "archived": (
                    f"mac:{row['mac']}" in archived
                    or f"ip:{row['ip']}" in archived
                ),
                "isNew": row["first_seen"][:10] == today,
            }
            for row in rows
        ]

    def _favorite_keys(self) -> set[str]:
        with self._connect() as db:
            return {
                row["asset_key"]
                for row in db.execute("SELECT asset_key FROM device_favorites").fetchall()
            }

    def _archived_keys(self) -> set[str]:
        with self._connect() as db:
            return {
                row["asset_key"]
                for row in db.execute("SELECT asset_key FROM device_archives").fetchall()
            }

    def _normalize_asset_key(self, asset_key: str, error_label: str) -> str:
        if asset_key.startswith("mac:"):
            normalized = f"mac:{self._normalize_mac(asset_key[4:])}"
            exists = any(
                device.get("mac", "").lower() == normalized[4:]
                for device in self.get_devices()
            )
            if not exists:
                with self._connect() as db:
                    exists = (
                        db.execute(
                            "SELECT 1 FROM discovered_devices WHERE mac=?",
                            (normalized[4:],),
                        ).fetchone()
                        is not None
                    )
        elif asset_key.startswith("ip:"):
            normalized = f"ip:{self._validate_ip(asset_key[3:])}"
            exists = any(device["ip"] == normalized[3:] for device in self.get_devices())
            if not exists:
                with self._connect() as db:
                    exists = (
                        db.execute(
                            "SELECT 1 FROM discovered_devices WHERE ip=?",
                            (normalized[3:],),
                        ).fetchone()
                        is not None
                    )
        else:
            raise ValueError(f"Invalid {error_label} device key")
        if not exists:
            raise ValueError("Device not found")
        return normalized

    def toggle_favorite(self, asset_key: str) -> bool:
        normalized = self._normalize_asset_key(asset_key, "favourite")
        with self._connect() as db:
            current = db.execute(
                "SELECT 1 FROM device_favorites WHERE asset_key=?", (normalized,)
            ).fetchone()
            if current:
                db.execute("DELETE FROM device_favorites WHERE asset_key=?", (normalized,))
                return False
            db.execute(
                "INSERT INTO device_favorites (asset_key, added_at) VALUES (?, ?)",
                (normalized, utc_now()),
            )
            return True

    def toggle_archive(self, asset_key: str) -> bool:
        normalized = self._normalize_asset_key(asset_key, "archive")
        with self._connect() as db:
            current = db.execute(
                "SELECT 1 FROM device_archives WHERE asset_key=?", (normalized,)
            ).fetchone()
            if current:
                db.execute("DELETE FROM device_archives WHERE asset_key=?", (normalized,))
                return False
            db.execute(
                "INSERT INTO device_archives (asset_key, archived_at) VALUES (?, ?)",
                (normalized, utc_now()),
            )
            return True

    def authorize_device(self, mac: str) -> bool:
        mac = self._normalize_mac(mac)
        with self._connect() as db:
            result = db.execute(
                "UPDATE discovered_devices SET authorized=1 WHERE mac=?", (mac,)
            )
            return result.rowcount > 0

    @staticmethod
    def _is_generic_device_name(name: str, ip: str = "") -> bool:
        low = str(name or "").strip().lower()
        if not low:
            return True
        generic_tokens = (
            "unknown",
            "wi-fi client",
            "private wi-fi",
            "lan host",
            "lan network device",
        )
        if any(tok in low for tok in generic_tokens):
            return True
        if ip and low.endswith(f"({ip.lower()})"):
            return True
        return bool(re.search(r"\(\d{1,3}(?:\.\d{1,3}){3}\)$", low))

    def refresh_inventory_identities(self, resolve_live: bool = False) -> int:
        """Backfill OUI vendors and resolved hostnames across discovered_devices without losing user authorizations."""
        with self._connect() as db:
            db.execute(
                "DELETE FROM discovered_devices WHERE lower(mac) IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')"
            )
            rows = db.execute("SELECT * FROM discovered_devices").fetchall()
        if not rows:
            return 0

        if resolve_live and hasattr(self, "_resolve_hostnames_bulk"):
            online_ips = [str(r["ip"]) for r in rows if r["is_online"] and r["ip"]]
            if online_ips:
                self._resolve_hostnames_bulk(online_ips)

        hostnames = self._get_cached_hostnames() if hasattr(self, "_get_cached_hostnames") else {}
        fps = self._get_cached_fingerprints() if hasattr(self, "_get_cached_fingerprints") else {}
        known_gateways = self._known_local_gateways() if hasattr(self, "_known_local_gateways") else set()
        gw_plus_one = (
            {str(n.network_address + 1) for n in self._known_local_networks()}
            if hasattr(self, "_known_local_networks")
            else set()
        )

        updates: list[tuple[str, str, str]] = []
        for row in rows:
            mac = str(row["mac"] or "").lower()
            ip = str(row["ip"] or "")
            oui = mac.replace(":", "")[:6]
            oui_vendor, oui_type = self._vendor_for_oui(oui) if hasattr(self, "_vendor_for_oui") else ("LAN Network Device", "device")
            if ip in known_gateways or ip in gw_plus_one:
                oui_type = "gateway"
            hostname = str(hostnames.get(ip) or "").strip()
            fp = fps.get(ip) if isinstance(fps, dict) else None

            if hasattr(self, "_build_device_label"):
                resolved_vendor, label = self._build_device_label(
                    ip, mac, oui_vendor, oui_type, hostname=hostname, fp=fp
                )
            else:
                resolved_vendor = oui_vendor
                label = f"{hostname} ({resolved_vendor})" if hostname else f"{resolved_vendor} ({ip})"

            old_vendor = str(row["vendor"] or "")
            old_name = str(row["suggested_name"] or "")
            final_vendor = (
                resolved_vendor
                if not old_vendor or "unknown" in old_vendor.lower() or old_vendor != resolved_vendor
                else old_vendor
            )
            has_better_identity = bool(hostname or (isinstance(fp, dict) and fp.get("model")))
            final_name = (
                label
                if (self._is_generic_device_name(old_name, ip) or has_better_identity)
                else old_name
            )
            if final_vendor != old_vendor or final_name != old_name:
                updates.append((final_vendor, final_name, row["mac"]))

        if updates:
            with self._connect() as db:
                db.executemany(
                    "UPDATE discovered_devices SET vendor=?, suggested_name=? WHERE mac=?",
                    updates,
                )
        return len(updates)

    def _upsert_inventory(self, item: dict, scan_id: str = "") -> None:
        now = utc_now()
        event_args = None
        with self._connect() as db:
            previous = db.execute(
                "SELECT * FROM discovered_devices WHERE mac=?", (item["mac"],)
            ).fetchone()
            if previous is None:
                known = any(
                    d.get("ip") == item["ip"] or d.get("mac", "").lower() == item["mac"]
                    for d in self.get_devices()
                )
                db.execute(
                    """INSERT INTO discovered_devices
                       (mac, ip, vendor, suggested_name, arp_type, first_seen, last_seen,
                        authorized, is_online, last_scan_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                    (
                        item["mac"],
                        item["ip"],
                        item["vendor"],
                        item["suggestedName"],
                        item["arpType"],
                        now,
                        now,
                        int(known),
                        scan_id,
                    ),
                )
                event_args = (
                    "NEW_DEVICE",
                    "WARNING" if not known else "INFO",
                    "New network device detected" if not known else "Known device detected",
                    f"{item['suggestedName']} appeared at {item['ip']} (MAC {item['mac']})."
                    + (" Review and authorize it if expected." if not known else ""),
                    item["mac"],
                    item["ip"],
                    item["suggestedName"],
                )
            else:
                new_name = str(item.get("suggestedName") or "").strip()
                old_name = str(previous["suggested_name"] or "").strip()
                should_rename = bool(
                    new_name
                    and (
                        self._is_generic_device_name(old_name, str(previous["ip"] or ""))
                        or item.get("hostname")
                    )
                )
                final_name = new_name if should_rename else (old_name or new_name)
                if previous["ip"] != item["ip"]:
                    event_args = (
                        "IP_CHANGED",
                        "INFO",
                        "Device IP address changed",
                        f"{item['mac']} moved from {previous['ip']} to {item['ip']}.",
                        item["mac"],
                        item["ip"],
                        final_name,
                    )
                elif not previous["is_online"]:
                    event_args = (
                        "DEVICE_REAPPEARED",
                        "INFO",
                        "Device reconnected",
                        f"{final_name} ({item['ip']}) was seen again.",
                        item["mac"],
                        item["ip"],
                        final_name,
                    )
                db.execute(
                    """UPDATE discovered_devices
                       SET ip=?, vendor=?, suggested_name=?, arp_type=?, last_seen=?, is_online=1,
                           last_scan_id=? WHERE mac=?""",
                    (
                        item["ip"],
                        item["vendor"],
                        final_name,
                        item["arpType"],
                        now,
                        scan_id,
                        item["mac"],
                    ),
                )
        if event_args:
            self._record_event(*event_args)

