"""Incident evidence, maintenance, notifications, and read-only switch telemetry."""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import TYPE_CHECKING, cast

from .config import utc_now

if TYPE_CHECKING:
    from .engine import Monitor


def _timestamp(value: object) -> datetime:
    stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Enter a time with a time zone")
    return stamp.astimezone(timezone.utc)


class OperationsMixin:
    def _operations_store(self) -> None:
        self = cast("Monitor", self)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS maintenance_windows (
                    id TEXT PRIMARY KEY, device_id TEXT NOT NULL, starts_at TEXT NOT NULL,
                    ends_at TEXT NOT NULL, reason TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_notices (
                    incident_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL,
                    title TEXT NOT NULL, message TEXT NOT NULL, ip TEXT NOT NULL,
                    delivery TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (incident_id, kind)
                );
                CREATE TABLE IF NOT EXISTS switch_port_samples (
                    device_id TEXT PRIMARY KEY, ip TEXT NOT NULL, sample TEXT NOT NULL
                );
            """)

    def get_incident(self, key: str) -> dict:
        self = cast("Monitor", self)
        alerts = self.get_active_alerts()
        alert = next((item for item in alerts if item.get("key") == key), None)
        if not alert:
            raise LookupError("This alert is no longer active")
        device = next((item for item in self.get_devices() if item["ip"] == alert.get("ip")), None)
        probe = self.latest_devices.get(device["ip"], {}) if device and not alert.get("isDrill") else {}
        connection = None
        if device and not alert.get("isDrill"):
            try:
                connection = self.get_device_connection(device["ip"])
            except (ValueError, LookupError):
                pass
        history = self.get_device_history(device["id"], "") if connection and device else {}
        upstream = alert.get("upstreamIncident")
        group_key = upstream["key"] if upstream else key
        def in_group(item: dict) -> bool:
            return item.get("key") != key and (
                item.get("key") == group_key or (item.get("upstreamIncident") or {}).get("key") == group_key
            )
        return {
            "alert": alert,
            "affected": [item for item in alerts if in_group(item)],
            "probe": {field: probe.get(field) for field in (
                "lastChecked", "probeMethod", "connectivityState", "icmpAlive",
                "tcpReachable", "tcpPortsChecked", "openPorts", "latencyMs", "packetLossPct",
            )} if probe else None,
            "deviceId": device["id"] if connection and device else None,
            "connection": connection,
            "lastInventoryObservation": history.get("lastSeen"),
            "observationSource": history.get("observationSource"),
        }

    def create_maintenance(self, body: dict) -> dict:
        self = cast("Monitor", self)
        device_id = str(body.get("deviceId") or "")
        if device_id and not any(d["id"] == device_id and not d["archived"] for d in self.get_devices()):
            raise ValueError("Choose an active monitored device")
        starts, ends = _timestamp(body.get("startsAt")), _timestamp(body.get("endsAt"))
        if ends <= starts or ends <= datetime.now(timezone.utc):
            raise ValueError("Maintenance must end after it starts and in the future")
        reason = str(body.get("reason") or "").strip()
        if not reason:
            raise ValueError("Enter a maintenance reason")
        window_id = uuid.uuid4().hex
        with self._connect() as db:
            db.execute(
                "INSERT INTO maintenance_windows VALUES (?, ?, ?, ?, ?)",
                (window_id, device_id, starts.isoformat(), ends.isoformat(), reason[:240]),
            )
        return {"id": window_id}

    def cancel_maintenance(self, window_id: str) -> None:
        self = cast("Monitor", self)
        with self._connect() as db:
            db.execute("DELETE FROM maintenance_windows WHERE id=?", (window_id,))

    def get_operations(self) -> dict:
        self = cast("Monitor", self)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as db:
            windows = [dict(row) for row in db.execute(
                "SELECT * FROM maintenance_windows WHERE ends_at > ? ORDER BY starts_at", (now,)
            )]
            notices = [dict(row) for row in db.execute(
                "SELECT * FROM incident_notices ORDER BY created_at DESC, rowid DESC LIMIT 40"
            )]
        return {"maintenance": windows, "notifications": notices, "emailEnabled": self._alert_email_enabled()}

    @staticmethod
    def _alert_email_enabled() -> bool:
        return all(os.environ.get(key) for key in ("PULSE_SMTP_HOST", "PULSE_ALERT_EMAIL_FROM", "PULSE_ALERT_EMAIL_TO"))

    def _collect_incident_notifications(self) -> None:
        self = cast("Monitor", self)
        alerts = self.get_active_alerts()
        resolved = [
            alert for alert in self.get_alerts()
            if alert.get("status") == "RESOLVED" and alert.get("resolution") != "superseded"
        ]
        devices = {device["ip"]: device["id"] for device in self.get_devices()}
        now = datetime.now(timezone.utc)
        delivery = "pending" if self._alert_email_enabled() else "in_app"
        with self._connect() as db:
            muted = {row[0] for row in db.execute(
                "SELECT device_id FROM maintenance_windows WHERE starts_at <= ? AND ends_at > ?",
                (now.isoformat(), now.isoformat()),
            )}
            for alert in alerts:
                if (
                    alert.get("isDrill") or alert.get("verificationUnavailable")
                    or alert.get("upstreamIncident") or alert.get("category") not in {"device", "router", "isp"}
                    or alert.get("severity") not in {"CRITICAL", "WARNING"}
                    or not alert.get("id") or "" in muted or devices.get(alert.get("ip")) in muted
                ):
                    continue
                try:
                    age = (now - _timestamp(alert.get("firstSeen"))).total_seconds()
                    checked = (now - _timestamp(alert.get("lastChecked"))).total_seconds()
                except ValueError:
                    continue
                if age >= 60 and 0 <= checked <= 120:
                    db.execute(
                        "INSERT OR IGNORE INTO incident_notices VALUES (?, 'outage', ?, ?, ?, ?, ?, 0)",
                        (alert["id"], utc_now(), alert["title"], alert["message"], alert.get("ip") or "", delivery),
                    )
            for alert in resolved:
                if "" in muted or devices.get(alert.get("ip")) in muted:
                    continue
                db.execute(
                    """INSERT OR IGNORE INTO incident_notices
                       SELECT incident_id, 'recovered', ?, ?, ?, ip, ?, 0 FROM incident_notices
                       WHERE incident_id=? AND kind='outage'""",
                    (utc_now(), f"Recovered: {alert['title']}", alert["message"], delivery, alert.get("id")),
                )
            db.execute("DELETE FROM maintenance_windows WHERE ends_at < ?", (now.isoformat(),))

    def _send_incident_email(self, notice: dict) -> None:
        message = EmailMessage()
        message["Subject"] = "Vertex Sentry: " + " ".join(notice["title"].splitlines())
        message["From"] = os.environ["PULSE_ALERT_EMAIL_FROM"]
        message["To"] = os.environ["PULSE_ALERT_EMAIL_TO"]
        message.set_content(f"{notice['message']}\n\nDevice: {notice['ip']}\nRecorded: {notice['created_at']}")
        port = int(os.environ.get("PULSE_SMTP_PORT", "587"))
        with smtplib.SMTP(os.environ["PULSE_SMTP_HOST"], port, timeout=5) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            user = os.environ.get("PULSE_SMTP_USER")
            if user:
                smtp.login(user, os.environ.get("PULSE_SMTP_PASSWORD", ""))
            smtp.send_message(message)

    def _deliver_incident_notifications(self) -> None:
        self = cast("Monitor", self)
        if not self._alert_email_enabled():
            return
        with self._connect() as db:
            pending = [dict(row) for row in db.execute(
                "SELECT * FROM incident_notices WHERE delivery='pending' ORDER BY rowid LIMIT 5"
            )]
        for notice in pending:
            attempts = notice["attempts"] + 1
            try:
                self._send_incident_email(notice)
                status = "sent"
            except (OSError, ValueError, smtplib.SMTPException):
                status = "failed" if attempts >= 3 else "pending"
            with self._connect() as db:
                db.execute(
                    "UPDATE incident_notices SET attempts=?, delivery=? WHERE incident_id=? AND kind=?",
                    (attempts, status, notice["incident_id"], notice["kind"]),
                )

    def _operations_loop(self) -> None:
        self = cast("Monitor", self)
        while not self._stop.is_set():
            try:
                self._collect_incident_notifications()
                self._deliver_incident_notifications()
            except Exception as exc:
                print(f"[monitor] Incident notification check failed: {exc}", flush=True)
            self._stop.wait(15)

    @staticmethod
    def _switch_profiles() -> dict:
        try:
            profiles = json.loads(os.environ.get("PULSE_SWITCH_SNMP", "{}"))
            return profiles if isinstance(profiles, dict) else {}
        except ValueError:
            return {}

    def get_switch_ports(self, device_id: str) -> dict:
        self = cast("Monitor", self)
        device = self._switch_device(device_id)
        with self._connect() as db:
            row = db.execute(
                "SELECT sample FROM switch_port_samples WHERE device_id=? AND ip=?", (device_id, device["ip"])
            ).fetchone()
        return {
            **(json.loads(row["sample"]) if row else {"status": "awaiting_sample", "ports": []}),
            "configured": bool(self._switch_profiles().get(device["ip"])),
        }

    def _switch_device(self, device_id: str) -> dict:
        self = cast("Monitor", self)
        for device in self.get_devices():
            if device["id"] == device_id and device.get("type") == "switch" and not device["archived"]:
                return device
        raise ValueError("Choose an active monitored switch")

    def sample_switch_ports(self, device_id: str, body: dict) -> dict:
        self = cast("Monitor", self)
        if not self._switch_sample_lock.acquire(blocking=False):
            raise ValueError("A switch sample is already running. Try again shortly.")
        try:
            return self._read_switch_ports(device_id, body)
        finally:
            self._switch_sample_lock.release()

    def _read_switch_ports(self, device_id: str, body: dict) -> dict:
        self = cast("Monitor", self)
        device = self._switch_device(device_id)
        ip = device["ip"]
        raw = body if body.get("community") else self._switch_profiles().get(ip)
        if not isinstance(raw, dict):
            raise ValueError("Enter a read-only community and interface indices")
        community, indices = raw.get("community"), raw.get("indices")
        if not isinstance(community, str) or not 1 <= len(community) <= 128 or not community.isprintable():
            raise ValueError("Enter a valid read-only SNMP community")
        if not isinstance(indices, list) or not 1 <= len(indices) <= 32 or any(
            type(value) is not int or not 1 <= value <= 2147483647 for value in indices
        ):
            raise ValueError("Enter 1 to 32 integer IF-MIB interface indices")
        prior = self.get_switch_ports(device_id)
        uptime = self._snmp_get_oids(ip, {"uptime": "1.3.6.1.2.1.1.3.0"}, community, timeout=0.25).get("uptime")
        previous = {port["index"]: port for port in prior.get("ports", [])}

        def number(value: str | None) -> int | None:
            return int(value) if value and value.isascii() and value.isdecimal() and len(value) <= 20 else None

        def read_port(index: int) -> dict | None:
            base = "1.3.6.1.2.1.2.2.1"
            counters = {"inErrors": 14, "outErrors": 20, "inDrops": 13, "outDrops": 19}
            columns = {"name": 2, "state": 8, "speed": 5, **counters}
            oids = {key: f"{base}.{column}.{index}" for key, column in columns.items()}
            oids["highSpeed"] = f"1.3.6.1.2.1.31.1.1.1.15.{index}"
            oids["discontinuity"] = f"1.3.6.1.2.1.31.1.1.1.19.{index}"
            data = self._snmp_get_oids(ip, oids, community, timeout=0.2)
            if not data:
                return None
            old = previous.get(index, {})
            port = {key: number(data.get(key)) for key in counters}
            speed, high_speed = number(data.get("speed")), number(data.get("highSpeed"))
            same_counters = (
                number(uptime) is not None and number(prior.get("uptime")) is not None
                and int(uptime or "0") >= int(prior["uptime"])
                and data.get("discontinuity") is not None and data.get("discontinuity") == old.get("discontinuity")
            )
            return {
                "index": index, "name": data.get("name") or f"ifIndex {index}",
                "state": {"1": "Up", "2": "Down", "3": "Testing", "5": "Dormant", "7": "Lower layer down"}.get(data.get("state") or "", "Unknown"),
                "speedMbps": high_speed or (round(speed / 1_000_000, 2) if speed and speed < 4294967295 else None),
                "discontinuity": data.get("discontinuity"), **port,
                "change": {
                    key: value - old[key] for key, value in port.items()
                    if same_counters and value is not None and isinstance(old.get(key), int) and value >= old[key]
                },
            }

        ports = []
        if uptime is not None:
            with ThreadPoolExecutor(max_workers=4) as pool:
                ports = [port for port in pool.map(read_port, sorted(set(indices))) if port is not None]
        timestamp = utc_now()
        sample = (
            {"status": "reply", "ports": ports, "sampledAt": timestamp, "uptime": uptime,
             "requestedIndices": sorted(set(indices)), "previousSampledAt": prior.get("sampledAt")}
            if ports else {**prior, "status": "unavailable"}
        )
        sample.update(lastAttemptAt=timestamp)
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO switch_port_samples VALUES (?, ?, ?)", (device_id, ip, json.dumps(sample)))
        return {**sample, "configured": bool(self._switch_profiles().get(ip))}

    def _switch_ports_loop(self) -> None:
        self = cast("Monitor", self)
        while not self._stop.wait(5):
            profiles = self._switch_profiles()
            if profiles:
                for device in self.get_devices():
                    if self._stop.is_set():
                        return
                    if device["ip"] in profiles and device.get("type") == "switch" and not device["archived"]:
                        try:
                            self.sample_switch_ports(device["id"], {})
                        except (OSError, ValueError) as exc:
                            print(f"[monitor] Switch port sample failed for {device['ip']}: {exc}", flush=True)
            if self._stop.wait(55):
                return
