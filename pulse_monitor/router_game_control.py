"""Read and verify per-device rules on a compatible authenticated TP-Link router."""

from __future__ import annotations

import urllib.parse

from .config import normalize_mac, validate_ip


def router_clients(data: object) -> list[dict] | None:
    if isinstance(data, dict):
        data = data.get("list")
    if not isinstance(data, list):
        return None
    clients = {}
    for row in data:
        if not isinstance(row, dict):
            continue
        try:
            ip = validate_ip(row.get("ip") or row.get("ipaddr"))
            mac = normalize_mac(row.get("mac") or row.get("macaddr"))
        except ValueError:
            continue
        if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
            continue
        name = str(row.get("hostname") or row.get("name") or ip)[:100]
        clients[(ip, mac)] = {"ip": ip, "mac": mac, "name": name}
    return list(clients.values()) if clients or not data else None


def _enabled(value: object) -> bool | None:
    token = str(value).strip().lower()
    if token in {"true", "1", "on", "enabled"}:
        return True
    if token in {"false", "0", "off", "disabled"}:
        return False
    return None


def _mac(row: dict) -> str:
    return str(row.get("mac") or row.get("macaddr") or "").upper().replace(":", "-")


class RouterGameControl:
    def __init__(self, config: dict, post) -> None:
        self.host = config["ip"]
        self.port = int(config.get("port") or 80)
        self.scheme = "https" if config.get("useHttps") or self.port in (443, 8443) else "http"
        self.prefix = '/cgi-bin/luci/;stok=' + urllib.parse.quote(str(config["stok"]), safe="") + '/admin/'
        self.post = post

    def _request(self, endpoint: str, **fields):
        reply = self.post(
            self.host, self.port, self.scheme, self.prefix + endpoint, timeout=1.2,
            data=urllib.parse.urlencode(fields or {"operation": "read"}).encode(),
        )
        if isinstance(reply, dict) and reply.get("success") is True:
            return reply.get("data")
        return None

    @staticmethod
    def _endpoint(mode: str) -> str:
        return "qos?form=device_list" if mode == "throttle" else "access_control?form=black_devices"

    def clients(self) -> list[dict] | None:
        return router_clients(self._request("client?form=client_list"))

    def has_client(self, ip: str, mac: str) -> bool:
        return any(row["ip"] == ip and _mac(row) == mac for row in self.clients() or [])

    def deny_list_enabled(self) -> bool | None:
        settings = self._request("access_control?form=setting")
        if not isinstance(settings, dict) or "enable" not in settings:
            return None
        enabled = _enabled(settings["enable"])
        if enabled is not True:
            return enabled
        return str(settings.get("mode") or "").lower() in {"black", "blacklist", "deny", "denylist"}

    def read(self, mode: str, mac: str) -> dict | None:
        if mode == "cut":
            if self.deny_list_enabled() is not True:
                return None
        data = self._request(self._endpoint(mode))
        if isinstance(data, dict):
            data = data.get("list")
        if not isinstance(data, list) or any(not isinstance(row, dict) or not _mac(row) for row in data):
            return None
        hits = [row for row in data if _mac(row) == mac]
        if len(hits) > 1:
            return None
        if mode == "cut":
            return {"present": bool(hits), "key": str(hits[0].get("key") or mac),
                    "name": str(hits[0].get("name") or "")} if hits else {"present": False}
        if not hits:
            return None
        row = hits[0]
        enabled = _enabled(row.get("enable"))
        # Only use an exposed hard-limit form. A device-priority flag is insufficient.
        if enabled is None or any(field not in row for field in ("up_band", "down_band", "up_unit", "down_unit")):
            return None
        if any(str(row[field]) not in {"Kbps", "kbps", "KB/s"} for field in ("up_unit", "down_unit")):
            return None
        return {"enable": "on" if enabled else "off", "key": str(row.get("key") or mac),
                **{field: str(row[field]) for field in ("up_band", "down_band", "up_unit", "down_unit")}}

    def change(self, plan: dict, restore: bool = False) -> bool:
        mode, mac, before = plan["mode"], plan["mac"], plan["before"]
        current = self.read(mode, mac)
        if current is None:
            return False
        endpoint = self._endpoint(mode)
        if mode == "throttle":
            desired = plan["after"]
            expected = before if restore else desired
            if current == expected:
                return restore
            if current != (desired if restore else before):
                return False
            self._request(endpoint, operation="update", mac=mac, **expected)
            return self.read(mode, mac) == expected
        if restore:
            if not current["present"]:
                return True
            if current["name"] and current["name"] != plan["name"]:
                return False
            self._request(endpoint, operation="remove", key=current["key"], mac=mac)
        else:
            if current["present"]:
                return False
            self._request(endpoint, operation="insert", mac=mac, name=plan["name"])
        readback = self.read(mode, mac)
        return readback is not None and readback["present"] is not restore and (
            restore or not readback["name"] or readback["name"] == plan["name"]
        )
