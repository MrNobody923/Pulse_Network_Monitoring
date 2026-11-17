"""Accurate device-level mobile & online game detection via DNS forwarding, syslog, and port probes."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import selectors
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

if os.name == "nt":
    import winreg

from .config import utc_now, validate_ip

GAME_SIGNATURES: list[dict] = [
    {
        "id": "mlbb",
        "name": "Mobile Legends: Bang Bang",
        "category": "Mobile MOBA · 5v5",
        "icon": "⚔️",
        "isMobile": True,
        "domains": (
            "ml.youngjoygame.com",
            "youngjoygame.com",
            "api.mobilelegends.com",
            "log.mobilelegends.com",
            "m.mobilelegends.com",
            "mobilelegends.com",
            "mlbb.com",
            "moonton.com",
            "moonton.net",
            "moontongame.com",
            "moontontech.com",
            "yuanzhanapp.com",
            "akmweb.youngjoygame.com",
        ),
        "domainKeywords": ("mobilelegends", "youngjoygame", "moonton", "yuanzhanapp", "mlbb.com"),
        "ports": (5000, 5001, 5002, 5551, 30090, 30091),
        "processes": (),
    },
    {
        "id": "codm",
        "name": "Call of Duty: Mobile",
        "category": "Mobile FPS Shooter",
        "icon": "🎯",
        "isMobile": True,
        "domains": (
            "codm.garena.com",
            "garena.codm.com",
            "codm.garenanow.com",
            "dl.codm.garena.com",
            "tgl.garena.com",
            "auth.garena.com",
            "connect.garena.com",
            "codm.activision.com",
            "activision.com",
            "callofduty.com",
            "demonware.net",
            "proximabeta.com",
            "intlgame.com",
        ),
        "domainKeywords": ("codm.", "activision", "callofduty", "demonware", "proximabeta", "intlgame"),
        "ports": (7500, 7501, 10012),
        "processes": (),
    },
    {
        "id": "pubgm",
        "name": "PUBG Mobile",
        "category": "Mobile Battle Royale",
        "icon": "🪂",
        "isMobile": True,
        "domains": (
            "igamecj.com",
            "gcloudsdk.com",
            "pubgmobile.com",
            "www.pubgmobile.com",
            "pubg.com",
            "krafton.com",
            "lightspeed-studios.com",
            "gameloop.com",
            "tencent-cloud.net",
            "myqcloud.com",
            "gcloud.qq.com",
        ),
        "domainKeywords": ("pubgmobile", "igamecj", "gcloudsdk", "lightspeed-studios", "gameloop"),
        "ports": (17500, 20001),
        "processes": (),
    },
    {
        "id": "hok",
        "name": "Honor of Kings",
        "category": "Mobile MOBA · 5v5",
        "icon": "👑",
        "isMobile": True,
        "domains": (
            "honorofkings.com",
            "smoba.qq.com",
            "anticheatexpert.com",
            "worldofkings.com",
            "sgp.qq.com",
            "levelinfinite.com",
        ),
        "domainKeywords": ("honorofkings", "worldofkings", "smoba.qq", "levelinfinite"),
        "ports": (10010, 10011),
        "processes": (),
    },
    {
        "id": "wildrift",
        "name": "League of Legends: Wild Rift",
        "category": "Mobile MOBA · 5v5",
        "icon": "⚡",
        "isMobile": True,
        "domains": (
            "wildrift.leagueoflegends.com",
            "teamfighttactics.leagueoflegends.com",
            "auth.riotgames.com",
            "riotcdn.net",
            "leagueoflegends.com",
            "rgpub.io",
            "riotgames.net",
        ),
        "domainKeywords": ("wildrift", "riotcdn", "leagueoflegends", "rgpub.io", "riotgames.net"),
        "ports": (5223,),
        "processes": ("League of Legends.exe", "LeagueClientUx.exe"),
    },
    {
        "id": "hoyoverse",
        "name": "Genshin Impact / Honkai: Star Rail",
        "category": "Mobile / PC Action RPG",
        "icon": "✨",
        "isMobile": True,
        "domains": (
            "sg-public-api.hoyoverse.com",
            "sdk-os-static.hoyoverse.com",
            "hoyoverse.com",
            "hoyolab.com",
            "mihoyo.com",
            "yuanshen.com",
            "starrails.com",
            "zenlesszonezero.com",
            "honkaiimpact3.com",
        ),
        "domainKeywords": ("hoyoverse", "hoyolab", "mihoyo", "yuanshen", "starrails", "zenlesszonezero", "honkaiimpact3"),
        "ports": (22101, 22102),
        "processes": ("GenshinImpact.exe", "YuanShen.exe", "StarRail.exe", "ZenlessZoneZero.exe"),
    },
    {
        "id": "freefire",
        "name": "Garena Free Fire",
        "category": "Mobile Battle Royale",
        "icon": "🔥",
        "isMobile": True,
        "domains": (
            "freefiremobile.com",
            "freefireind.com",
            "ff.garena.com",
            "ggblueshark.com",
            "garenanow.com",
            "garena.com",
        ),
        "domainKeywords": ("freefire", "ggblueshark", "ff.garena"),
        "ports": (39698, 39800),
        "processes": ("HD-Player.exe", "Bluestacks.exe", "MuMuPlayer.exe", "dnplayer.exe"),
    },
    {
        "id": "clashofclans",
        "name": "Clash of Clans",
        "category": "Mobile Strategy",
        "icon": "🛡️",
        "isMobile": True,
        "domains": ("game.clashofclans.com", "clashofclans.com", "supercell.com", "supercell.net", "supercellid.com"),
        "domainKeywords": ("clashofclans", "supercellid", "supercell."),
        "ports": (9339,),
        "processes": (),
    },
    {
        "id": "clashroyale",
        "name": "Clash Royale",
        "category": "Mobile Strategy",
        "icon": "🏰",
        "isMobile": True,
        "domains": ("game.clashroyaleapp.com", "clashroyaleapp.com", "clashroyale.com"),
        "domainKeywords": ("clashroyale",),
        "ports": (9339,),
        "processes": (),
    },
    {
        "id": "brawlstars",
        "name": "Brawl Stars",
        "category": "Mobile Arena Brawler",
        "icon": "⭐",
        "isMobile": True,
        "domains": ("game.brawlstarsgame.com", "brawlstarsgame.com", "brawlstars.com", "squadbusters.com"),
        "domainKeywords": ("brawlstars", "squadbusters"),
        "ports": (9339,),
        "processes": (),
    },
    {
        "id": "fcmobile",
        "name": "EA Sports FC Mobile",
        "category": "Mobile Sports",
        "icon": "⚽",
        "isMobile": True,
        "domains": ("fcmobile.ea.com", "easports.com"),
        "domainKeywords": ("fcmobile", "easports"),
        "ports": (3659, 17502),
        "processes": (),
    },
    {
        "id": "casual",
        "name": "8 Ball Pool / Among Us / Monopoly GO",
        "category": "Mobile Casual / Social",
        "icon": "🎱",
        "isMobile": True,
        "domains": ("miniclip.com", "miniclippt.com", "innersloth.com", "among.us", "monopolygo.com", "scopely.com"),
        "domainKeywords": ("miniclip", "innersloth", "monopolygo", "scopely"),
        "ports": (8433, 22023),
        "processes": ("Among Us.exe",),
    },
    {
        "id": "roblox",
        "name": "Roblox",
        "category": "Mobile / PC Sandbox",
        "icon": "🧱",
        "isMobile": True,
        "domains": (
            "presence.roblox.com",
            "apis.roblox.com",
            "clientsettings.roblox.com",
            "gamejoin.roblox.com",
            "auth.roblox.com",
            "realtime.roblox.com",
            "roblox.com",
            "www.roblox.com",
            "rbxcdn.com",
            "rbx.com",
            "robloxlabs.com",
            "rbxinfra.net",
        ),
        "domainKeywords": ("roblox", "rbxcdn", "rbxinfra"),
        "ports": (49152, 53640),
        "processes": ("RobloxPlayerBeta.exe", "RobloxPlayerLauncher.exe", "Windows10Universal.exe"),
    },
    {
        "id": "valorant",
        "name": "Valorant",
        "category": "PC Tactical FPS",
        "icon": "🎯",
        "isMobile": False,
        "domains": ("playvalorant.com", "pvp.net", "riotgames.com"),
        "domainKeywords": ("playvalorant",),
        "ports": (8393, 8394),
        "processes": ("VALORANT.exe", "VALORANT-Win64-Shipping.exe"),
    },
    {
        "id": "minecraft",
        "name": "Minecraft",
        "category": "Mobile / PC Sandbox",
        "icon": "⛏️",
        "isMobile": False,
        "domains": ("sessionserver.mojang.com", "authserver.mojang.com", "minecraft.net", "minecraftservices.com"),
        "domainKeywords": ("minecraft", "mojang.com"),
        "ports": (19132, 25565),
        "processes": ("Minecraft.Windows.exe", "javaw.exe"),
    },
    {
        "id": "steam",
        "name": "Dota 2 / CS2 (Steam)",
        "category": "PC Competitive",
        "icon": "🎮",
        "isMobile": False,
        "domains": (
            "api.steampowered.com",
            "steamcommunity.com",
            "steampowered.com",
            "valvesoftware.com",
            "steamserver.net",
            "steamcontent.com",
            "steamstatic.com",
        ),
        "domainKeywords": ("steampowered", "steamserver", "steamcontent", "valvesoftware"),
        "ports": (27015, 27036),
        "processes": ("dota2.exe", "cs2.exe", "ApexLegends.exe", "FortniteClient-Win64-Shipping.exe", "Overwatch.exe", "GTA5.exe"),
    },
]

_DOH_CANARY_DOMAINS = (
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "doh.dns.apple.com",
    "canary.dns.nextdns.io",
)

_WIFI_CAPTIVE_DOMAINS = (
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "play.googleapis.com",
    "captive.apple.com",
    "gsp1.apple.com",
    "www.msftconnecttest.com",
    "dns.msftncsi.com",
)

_GAME_ID_ALIASES = {
    "riot": "wildrift",
    "supercell": "clashofclans",
}

SCAN_GAME_PORTS = (19132, 25565, 27015, 27036, 9339, 5221, 5223, 7500, 17500, 22101, 30090)
_PASSIVE_DNS_CACHE_EXCLUDE = frozenset({
    "steampowered.com",
    "steamcommunity.com",
    "valvesoftware.com",
    "riotcdn.net",
    "api.steampowered.com",
})
_NETSTAT_GAME_PORTS = frozenset({
    5000, 5001, 5002, 5551, 30090, 30091, 7500, 7501, 10012,
    17500, 20001, 10010, 10011, 5223, 22101, 22102, 39698, 39800,
    9339, 3659, 17502, 8433, 22023, 8393, 8394, 19132, 25565,
    27015, 27036,
})

_MOBILE_HINT_TOKENS = (
    "apple", "iphone", "ipad", "samsung", "huawei", "honor",
    "vivo", "oppo", "android", "private mac", "private wi-fi",
    "redmi", "xiaomi", "poco", "realme",
)
_PC_HINT_TOKENS = (
    "windows", "desktop-", "msi", "asus", "gigabyte", "intel",
    "asrock", "cloud network", "wistron", "quanta", "biostar", "ecs",
)
_NON_GAMING_TOKENS = (
    "epson", "canon", "brother", "printer", "hikvision", "dahua",
    "tuya", "espressif", "mxchip", "ai-link", "high-flying", "hyper-v",
)


class GameDetectorMixin:
    """Detects mobile/PC game launches from exact client DNS/syslog/port signals without guessing."""

    DNS_LISTENER_PORT = 5354
    SYSLOG_LISTENER_PORT = 5140
    HOST_DNS_IP = "192.168.0.224"

    def _game_store(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS game_activity_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL DEFAULT '',
                    device_name TEXT NOT NULL,
                    vendor TEXT NOT NULL DEFAULT '',
                    device_type TEXT NOT NULL DEFAULT '',
                    game_id TEXT NOT NULL,
                    game_name TEXT NOT NULL,
                    game_category TEXT NOT NULL DEFAULT '',
                    game_icon TEXT NOT NULL DEFAULT '🎮',
                    connected_to TEXT NOT NULL DEFAULT '',
                    router_ip TEXT NOT NULL DEFAULT '',
                    zone_label TEXT NOT NULL DEFAULT '',
                    matched_indicator TEXT NOT NULL DEFAULT '',
                    detection_method TEXT NOT NULL DEFAULT 'Live DNS',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_blocked INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_game_activity_ts
                    ON game_activity_logs(timestamp DESC);
                CREATE TABLE IF NOT EXISTS game_block_rules (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '*',
                    mac TEXT NOT NULL DEFAULT '',
                    device_name TEXT NOT NULL DEFAULT '',
                    game_id TEXT NOT NULL DEFAULT '*',
                    game_name TEXT NOT NULL DEFAULT '',
                    scope TEXT NOT NULL DEFAULT 'device_game',
                    cut_wifi INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1
                );
                """
            )
            cols = {
                row["name"]
                for row in db.execute("PRAGMA table_info(game_activity_logs)").fetchall()
            }
            if "is_blocked" not in cols:
                db.execute(
                    "ALTER TABLE game_activity_logs ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0"
                )
            blk_cols = {
                row["name"]
                for row in db.execute("PRAGMA table_info(game_block_rules)").fetchall()
            }
            if "cut_wifi" not in blk_cols:
                db.execute(
                    "ALTER TABLE game_block_rules ADD COLUMN cut_wifi INTEGER NOT NULL DEFAULT 1"
                )
        self._game_listeners_started = False
        self._gaming_sensor_telemetry: dict = {
            "lastSeenEpoch": 0.0,
            "lastSeen": None,
            "pid": None,
            "dnsHost": self.HOST_DNS_IP,
            "dnsPort": 53,
            "hotspotIp": "",
            "syslogPort": 514,
            "dnsQueriesTotal": 0,
            "dnsBlockedTotal": 0,
            "dnsClients": {},
            "lastDnsClientIp": "",
            "lastDnsDomain": "",
            "lastDnsAt": None,
        }

    def get_gaming_policy(self) -> dict:
        with self.lock:
            raw = dict(self.config.get("gaming") or {})
        mode = str(raw.get("preventionMode") or "alert_only").strip().lower()
        if mode not in {"alert_only", "auto_block_game", "auto_wifi_cut"}:
            mode = "alert_only"
        try:
            stale_sec = max(20, min(600, int(raw.get("staleSessionSeconds") or 75)))
        except (TypeError, ValueError):
            stale_sec = 75
        return {
            "preventionMode": mode,
            "autoPreventEnabled": mode in {"auto_block_game", "auto_wifi_cut"},
            "autoCutWifi": mode == "auto_wifi_cut",
            "staleSessionSeconds": stale_sec,
        }

    def set_gaming_policy(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Invalid gaming policy payload")
        mode = str(payload.get("preventionMode") or "").strip().lower()
        if mode not in {"alert_only", "auto_block_game", "auto_wifi_cut"}:
            raise ValueError("preventionMode must be alert_only, auto_block_game, or auto_wifi_cut")
        with self.lock:
            gaming_cfg = self.config.setdefault("gaming", {})
            gaming_cfg["preventionMode"] = mode
            if "staleSessionSeconds" in payload:
                try:
                    gaming_cfg["staleSessionSeconds"] = max(20, min(600, int(payload["staleSessionSeconds"])))
                except (TypeError, ValueError):
                    pass
            self.save_config()

        policy = self.get_gaming_policy()
        mode_labels = {
            "alert_only": "Detect & Alert Only (Manual Block)",
            "auto_block_game": "Real-Time Auto-Block Opened Games",
            "auto_wifi_cut": "Zero-Tolerance Auto-Block Game + Cut User Wi-Fi",
        }
        self._record_event(
            "GAMING_POLICY_UPDATED",
            "WARNING" if policy["autoPreventEnabled"] else "INFO",
            f"🛡️ Game Prevention Mode: {mode_labels[mode]}",
            f"Updated real-time mobile/PC game detection policy to '{mode_labels[mode]}'.",
            device_name="Pulse Game Detector",
        )
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": True, "policy": policy, "gameActivity": activity}

    @staticmethod
    def _detect_host_lan_ip(fallback: str = "192.168.0.224") -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.25)
                s.connect(("192.168.0.1", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                    return ip
        except OSError:
            pass
        return fallback

    @staticmethod
    def _detect_local_dhcp_dns() -> list[str]:
        if os.name != "nt":
            return []
        servers: list[str] = []
        seen: set[str] = set()
        key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root_key:
                sub_count = winreg.QueryInfoKey(root_key)[0]
                for idx in range(sub_count):
                    sub_name = winreg.EnumKey(root_key, idx)
                    with winreg.OpenKey(root_key, sub_name) as if_key:
                        dhcp_ip = ""
                        dns_raw = ""
                        for val_name in ("DhcpIPAddress", "IPAddress"):
                            try:
                                val, _ = winreg.QueryValueEx(if_key, val_name)
                                if isinstance(val, list):
                                    dhcp_ip = str(val[0] or "") if val else ""
                                else:
                                    dhcp_ip = str(val or "")
                                if dhcp_ip and not dhcp_ip.startswith(("0.", "127.", "169.254.")):
                                    break
                            except OSError:
                                continue
                        if not dhcp_ip or dhcp_ip.startswith(("0.", "127.", "169.254.", "172.")):
                            continue
                        for dns_key in ("NameServer", "DhcpNameServer"):
                            try:
                                val, _ = winreg.QueryValueEx(if_key, dns_key)
                                txt = str(val or "").strip()
                                if txt:
                                    dns_raw = txt
                                    break
                            except OSError:
                                continue
                        for tok in re.split(r"[\s,;]+", dns_raw):
                            ip_s = tok.strip()
                            if ip_s and ip_s not in seen:
                                try:
                                    ipaddress.ip_address(ip_s)
                                    seen.add(ip_s)
                                    servers.append(ip_s)
                                except ValueError:
                                    continue
        except OSError:
            pass
        return servers

    def record_gaming_sensor_heartbeat(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            payload = {}
        now_epoch = time.time()
        with self.lock:
            tel = self._gaming_sensor_telemetry
            tel["lastSeenEpoch"] = now_epoch
            tel["lastSeen"] = utc_now()
            if payload.get("pid") is not None:
                tel["pid"] = int(payload["pid"])
            if str(payload.get("dnsHost") or "").strip():
                tel["dnsHost"] = str(payload["dnsHost"]).strip()
            if payload.get("dnsPort") is not None:
                tel["dnsPort"] = int(payload["dnsPort"])
            tel["hotspotIp"] = str(payload.get("hotspotIp") or "").strip()
            if payload.get("dnsQueriesTotal") is not None:
                tel["dnsQueriesTotal"] = int(payload["dnsQueriesTotal"])
            if payload.get("dnsBlockedTotal") is not None:
                tel["dnsBlockedTotal"] = int(payload["dnsBlockedTotal"])
            if isinstance(payload.get("dnsClients"), dict):
                tel["dnsClients"] = {
                    str(k): str(v) for k, v in list(payload["dnsClients"].items())[:120]
                }
            if payload.get("lastDnsClientIp"):
                tel["lastDnsClientIp"] = str(payload["lastDnsClientIp"])[:48]
            if payload.get("lastDnsDomain"):
                tel["lastDnsDomain"] = str(payload["lastDnsDomain"])[:120]
            if payload.get("lastDnsAt"):
                tel["lastDnsAt"] = str(payload["lastDnsAt"])[:64]
        return {
            "success": True,
            "blocks": self.get_game_blocks(),
            "policy": self.get_gaming_policy(),
        }

    def _get_gaming_sensor_status(self) -> dict:
        with self.lock:
            tel = dict(self._gaming_sensor_telemetry)
            dns_clients = dict(tel.get("dnsClients") or {})
            router_cfg = dict(self.config.get("router") or {})

        in_test = getattr(self, "_skip_live_probe_in_test", False)
        host_ip = tel.get("dnsHost") or (
            self.HOST_DNS_IP if in_test else self._detect_host_lan_ip(self.HOST_DNS_IP)
        )
        local_dns = [] if in_test else self._detect_local_dhcp_dns()
        sensor_online = (time.time() - float(tel.get("lastSeenEpoch") or 0.0)) <= 12.0
        non_self_clients = [ip for ip in dns_clients if ip != host_ip]
        dns_intercept_ready = bool(
            non_self_clients
            or (host_ip in local_dns)
            or bool(tel.get("hotspotIp"))
        )
        bypass_dns = [d for d in local_dns if d != host_ip]
        router_state = getattr(self, "router_state", {}) or {}
        return {
            "sensorOnline": sensor_online,
            "lastSeen": tel.get("lastSeen"),
            "dnsHost": host_ip,
            "dnsPort": int(tel.get("dnsPort") or 53),
            "hotspotIp": tel.get("hotspotIp") or "",
            "syslogPort": int(tel.get("syslogPort") or 514),
            "dnsQueriesTotal": int(tel.get("dnsQueriesTotal") or 0),
            "dnsBlockedTotal": int(tel.get("dnsBlockedTotal") or 0),
            "dnsClientsCount": len(non_self_clients),
            "dnsActiveClients": non_self_clients[:25],
            "lastDnsClientIp": tel.get("lastDnsClientIp") or "",
            "lastDnsDomain": tel.get("lastDnsDomain") or "",
            "lastDnsAt": tel.get("lastDnsAt"),
            "localDhcpDnsServers": local_dns,
            "bypassingExternalDns": bypass_dns,
            "dnsInterceptReady": dns_intercept_ready,
            "routerIp": str(router_cfg.get("ip") or "192.168.0.1"),
            "routerAuthenticated": bool(router_state.get("authenticated") or router_cfg.get("stok")),
        }

    def configure_router_game_dns(self) -> dict:
        """Attempt one-click TP-Link LuCI DHCP Primary DNS setup so all Wi-Fi clients route via Pulse DNS."""
        host_ip = self._detect_host_lan_ip(self.HOST_DNS_IP)
        configs = (
            self._resolve_router_configs()
            if hasattr(self, "_resolve_router_configs")
            else [dict(self.config.get("router", {}))]
        )
        primary_ip = str(self.config.get("router", {}).get("ip") or "192.168.0.1")
        cfg = next((c for c in configs if str(c.get("ip") or "") == primary_ip), configs[0] if configs else {})
        stok = str(cfg.get("stok") or "").strip()
        if not stok:
            return {
                "success": False,
                "configured": False,
                "requiresRouterLogin": True,
                "hostIp": host_ip,
                "routerIp": primary_ip,
                "message": (
                    f"Router admin session not connected yet. Open Router Settings to log into {primary_ip}, "
                    f"or log into http://{primary_ip} directly and set DHCP Primary DNS = {host_ip} "
                    f"(Secondary DNS = {primary_ip}). Also you can turn on Windows Mobile Hotspot or set DNS {host_ip} on a test phone for instant tracking."
                ),
            }

        r_port = int(cfg.get("port") or 80)
        scheme = "https" if (bool(cfg.get("useHttps", False)) or r_port in (443, 8443)) else "http"
        enc_stok = urllib.parse.quote(stok, safe="")
        ctx = ssl._create_unverified_context() if scheme == "https" else None

        read_url = f"{scheme}://{primary_ip}:{r_port}/cgi-bin/luci/;stok={enc_stok}/admin/dhcps?form=setting"
        req_read = urllib.request.Request(
            read_url,
            data=b"operation=read",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Pulse/2.1"},
        )
        cur_data: dict = {}
        try:
            with urllib.request.urlopen(req_read, timeout=2.0, context=ctx) as resp:
                parsed = json.loads(resp.read(65536).decode("utf-8", "ignore"))
                if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
                    cur_data = dict(parsed["data"])
        except Exception as exc:
            return {
                "success": False,
                "configured": False,
                "hostIp": host_ip,
                "routerIp": primary_ip,
                "message": f"Could not read DHCP settings from {primary_ip}: {exc}",
            }

        write_fields = {
            **cur_data,
            "operation": "write",
            "pri_dns": host_ip,
            "snd_dns": primary_ip,
        }
        body = urllib.parse.urlencode(write_fields).encode("utf-8")
        req_write = urllib.request.Request(
            read_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Pulse/2.1"},
        )
        try:
            with urllib.request.urlopen(req_write, timeout=3.0, context=ctx) as resp:
                wres = json.loads(resp.read(65536).decode("utf-8", "ignore"))
        except Exception as exc:
            return {
                "success": False,
                "configured": False,
                "hostIp": host_ip,
                "routerIp": primary_ip,
                "message": f"Could not update DHCP DNS on {primary_ip}: {exc}",
            }

        ok = isinstance(wres, dict) and bool(wres.get("success"))
        if ok:
            self._record_event(
                "ROUTER_DHCP_DNS_UPDATED",
                "INFO",
                "📡 Router DHCP DNS Pointed to Pulse Sensor",
                f"Configured TP-Link ({primary_ip}) Primary DNS = {host_ip}, Secondary DNS = {primary_ip} for whole-LAN real-time game monitoring.",
                ip=primary_ip,
                device_name=f"Gateway ({primary_ip})",
            )
            return {
                "success": True,
                "configured": True,
                "hostIp": host_ip,
                "routerIp": primary_ip,
                "message": (
                    f"TP-Link ({primary_ip}) DHCP Primary DNS updated to {host_ip}. "
                    "Phones reconnecting to Wi-Fi (or renewing DHCP lease) will now stream game activity and blocks in real time."
                ),
            }
        return {
            "success": False,
            "configured": False,
            "hostIp": host_ip,
            "routerIp": primary_ip,
            "message": f"Router {primary_ip} rejected automated DHCP write — set Primary DNS = {host_ip} in http://{primary_ip} -> Network -> DHCP Server.",
        }

    @staticmethod
    def _is_doh_canary_domain(domain: object) -> bool:
        dom = str(domain or "").strip().lower().rstrip(".")
        if not dom:
            return False
        return any(dom == sig or dom.endswith(f".{sig}") for sig in _DOH_CANARY_DOMAINS)

    @staticmethod
    def _match_game_signature(
        game_id: object = "", domain: object = "", port: object = None, process: object = ""
    ) -> dict | None:
        gid = str(game_id or "").strip().lower()
        gid = _GAME_ID_ALIASES.get(gid, gid)
        if gid:
            for g in GAME_SIGNATURES:
                if g["id"] == gid or g["name"].lower() == gid:
                    return g
        dom = str(domain or "").strip().lower().rstrip(".")
        if dom:
            for g in GAME_SIGNATURES:
                if any(dom == sig or dom.endswith(f".{sig}") for sig in g["domains"]):
                    return g
            for g in GAME_SIGNATURES:
                if any(kw in dom for kw in g.get("domainKeywords", ())):
                    return g
        proc = str(process or "").strip().lower()
        if proc:
            for g in GAME_SIGNATURES:
                if any(proc == p.lower() for p in g.get("processes", ())):
                    return g
        if port is not None and str(port).strip():
            try:
                pnum = int(port)
                for g in GAME_SIGNATURES:
                    if pnum in g["ports"]:
                        return g
            except (TypeError, ValueError):
                pass
        return None

    def _assemble_client_context(
        self,
        client_ip: str,
        mon_by_ip: dict[str, dict],
        inv_row: dict | None,
        cached_hosts: dict[str, str],
        topo_by_ip: dict[str, dict],
        node_by_id: dict[str, dict],
        topo_links: list[dict],
        infra_devs: list[dict],
        gw_ip: str,
        reporter_ip: str = "",
        allow_live_name_probe: bool = False,
    ) -> dict:
        mon_dev = mon_by_ip.get(client_ip)
        mac = str((mon_dev or {}).get("mac") or (inv_row or {}).get("mac") or "").lower()
        vendor = str((mon_dev or {}).get("vendor") or (inv_row or {}).get("vendor") or "")
        if (not vendor or "unknown" in vendor.lower()) and mac and hasattr(self, "_vendor_for_oui"):
            vendor, _ = self._vendor_for_oui(mac.replace(":", "")[:6])
        if not vendor or "unknown" in vendor.lower():
            vendor = "LAN Client"

        hostname = str(cached_hosts.get(client_ip) or "").strip()
        if (
            allow_live_name_probe
            and not hostname
            and inv_row is None
            and not getattr(self, "_skip_live_probe_in_test", False)
            and hasattr(self, "_probe_netbios_name")
            and hasattr(self, "_probe_mdns_llmnr_name")
        ):
            hostname = (
                self._probe_netbios_name(client_ip, timeout=0.18)
                or self._probe_mdns_llmnr_name(client_ip, timeout=0.16)
            )
            if hostname and hasattr(self, "_save_cached_hostnames"):
                self._save_cached_hostnames({client_ip: hostname})

        if mon_dev and mon_dev.get("name"):
            device_name = str(mon_dev["name"])
        elif inv_row and inv_row.get("suggested_name") and "unknown" not in str(inv_row["suggested_name"]).lower():
            device_name = str(inv_row["suggested_name"])
        elif hostname:
            device_name = (
                f"{hostname} (Host Monitor PC)"
                if client_ip == self.HOST_DNS_IP and vendor == "LAN Client"
                else f"{hostname} ({vendor})"
            )
        elif client_ip == self.HOST_DNS_IP:
            device_name = f"Host Monitor PC ({client_ip})"
        else:
            device_name = f"{vendor} ({client_ip})"

        low_combo = f"{device_name} {vendor}".lower()
        is_laa = False
        if mac:
            try:
                is_laa = (int(mac.split(":")[0], 16) & 2) != 0
            except ValueError:
                pass
        is_mobile = bool(
            not mon_dev and (is_laa or any(tok in low_combo for tok in _MOBILE_HINT_TOKENS))
        )
        if mon_dev:
            device_type = f"Office {str(mon_dev.get('type') or 'Device').upper()}"
        elif is_mobile:
            device_type = "Mobile Phone / Wi-Fi Device"
        elif client_ip == self.HOST_DNS_IP or any(tok in low_combo for tok in _PC_HINT_TOKENS):
            device_type = "PC / Workstation"
        else:
            device_type = "LAN / Wi-Fi Device"

        octets = client_ip.split(".")
        zone_num = octets[2] if len(octets) == 4 else "0"
        zone_prefix = f"{'.'.join(octets[:3])}." if len(octets) == 4 else ""
        subnet_cidr = (
            self._subnet_for_ip(client_ip)
            if hasattr(self, "_subnet_for_ip")
            else f"{zone_prefix}0/24"
        )
        zone_label = f"Zone .{zone_num}.x ({subnet_cidr})"

        connected_to = ""
        router_ip = ""
        rep_ip = str(reporter_ip or "").strip()
        if rep_ip:
            rep_dev = mon_by_ip.get(rep_ip)
            if rep_dev:
                connected_to = f"{rep_dev['name']} ({rep_ip})"
                router_ip = rep_ip

        if not connected_to:
            cnode = topo_by_ip.get(client_ip)
            if cnode:
                for ln in topo_links:
                    peer_id = (
                        ln["target_id"]
                        if ln["source_id"] == cnode["id"]
                        else (ln["source_id"] if ln["target_id"] == cnode["id"] else "")
                    )
                    peer = node_by_id.get(peer_id)
                    if peer and peer.get("node_type") in {"ap", "switch", "gateway", "router", "firewall"}:
                        connected_to = (
                            f"{peer['name']} ({peer['ip']})"
                            if peer.get("ip")
                            else str(peer["name"])
                        )
                        router_ip = str(peer.get("ip") or "")
                        break

        if not connected_to and infra_devs:
            zone_matches = [d for d in infra_devs if d.get("ip") != client_ip and zone_prefix and str(d.get("ip", "")).startswith(zone_prefix)]
            picked = (
                next((d for d in zone_matches if d.get("type") == "ap"), None)
                or next((d for d in zone_matches if d.get("type") == "router"), None)
                or next((d for d in zone_matches if d.get("type") == "gateway"), None)
                or (zone_matches[0] if zone_matches else None)
                or next((d for d in infra_devs if d.get("ip") == gw_ip), None)
                or next((d for d in infra_devs if d.get("type") == "gateway"), None)
            )
            if picked:
                connected_to = f"{picked['name']} ({picked['ip']})"
                router_ip = str(picked["ip"])

        if not connected_to:
            connected_to = f"Main Gateway Router ({gw_ip})"
            router_ip = gw_ip

        return {
            "ip": client_ip,
            "mac": mac,
            "deviceName": device_name,
            "vendor": vendor,
            "deviceType": device_type,
            "isMobile": is_mobile,
            "connectedTo": connected_to,
            "routerIp": router_ip,
            "zoneLabel": zone_label,
        }

    def _resolve_game_client_context(
        self, client_ip: str, reporter_ip: str = ""
    ) -> dict:
        """Identify what device client_ip is and which AP/router/subnet zone it is connected through."""
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM discovered_devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
                (client_ip,),
            ).fetchone()
            topo_nodes = [dict(r) for r in db.execute("SELECT * FROM topology_nodes").fetchall()]
            topo_links = [dict(r) for r in db.execute("SELECT * FROM topology_links").fetchall()]

        inv_row = dict(row) if row is not None else None
        mon_devices = self.get_devices()
        mon_by_ip = {str(d.get("ip") or ""): d for d in mon_devices if d.get("ip")}
        infra_devs = [
            d for d in mon_devices
            if str(d.get("type") or "").lower() in {"ap", "router", "gateway", "switch"}
        ]
        cached_hosts = (
            self._get_cached_hostnames()
            if hasattr(self, "_get_cached_hostnames")
            else {}
        )
        return self._assemble_client_context(
            client_ip=client_ip,
            mon_by_ip=mon_by_ip,
            inv_row=inv_row,
            cached_hosts=cached_hosts,
            topo_by_ip={str(n.get("ip") or ""): n for n in topo_nodes if n.get("ip")},
            node_by_id={n["id"]: n for n in topo_nodes},
            topo_links=topo_links,
            infra_devs=infra_devs,
            gw_ip=str(self.config.get("router", {}).get("ip") or "192.168.0.1"),
            reporter_ip=reporter_ip,
            allow_live_name_probe=True,
        )

    def record_game_detection(self, payload: dict) -> dict:
        """Record a verified device-level mobile/PC game detection, log event, raise alert, and push SSE."""
        if not isinstance(payload, dict):
            raise ValueError("Invalid game detection payload")
        raw_ip = str(
            payload.get("ip") or payload.get("clientIp") or payload.get("deviceIp") or ""
        ).strip()
        client_ip = validate_ip(raw_ip)
        reporter_ip = str(payload.get("reporterIp") or payload.get("routerIp") or "").strip()
        game = self._match_game_signature(
            game_id=payload.get("gameId", ""),
            domain=payload.get("domain", ""),
            port=payload.get("port"),
            process=payload.get("process", ""),
        )
        if game is None:
            raise ValueError("Specify a recognized game, game domain, process, or game port")

        ctx = self._resolve_game_client_context(client_ip, reporter_ip)
        if str(payload.get("deviceName") or "").strip():
            ctx["deviceName"] = str(payload["deviceName"]).strip()[:120]
        if str(payload.get("connectedTo") or "").strip():
            ctx["connectedTo"] = str(payload["connectedTo"]).strip()[:140]

        indicator = (
            str(
                payload.get("matchedIndicator")
                or payload.get("domain")
                or payload.get("process")
                or ""
            ).strip()
            or (f"Port {payload['port']}" if payload.get("port") else "")
            or game["domains"][0]
        )[:120]
        method = str(payload.get("detectionMethod") or "Live DNS").strip()[:60]
        now = utc_now()
        policy = self.get_gaming_policy()

        if self._match_active_block_rule(client_ip, game["id"]) is not None:
            with self._connect() as db:
                db.execute(
                    """UPDATE game_activity_logs
                       SET is_active=0, is_blocked=1, timestamp=?, matched_indicator=?, detection_method=?
                       WHERE ip=? AND game_id=?""",
                    (now, indicator, method, client_ip, game["id"]),
                )
            return {
                "success": True,
                "blocked": True,
                "autoPrevented": bool(payload.get("autoPrevented")),
                "detection": None,
                "gameActivity": self.get_game_activity(60),
            }

        existing_row = None
        with self._connect() as db:
            row = db.execute(
                """SELECT * FROM game_activity_logs
                   WHERE ip=? AND game_id=? AND is_active=1
                   ORDER BY timestamp DESC LIMIT 1""",
                (client_ip, game["id"]),
            ).fetchone()
            if row:
                try:
                    prev_dt = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
                    now_dt = datetime.now(timezone.utc)
                    if (now_dt - prev_dt).total_seconds() < policy["staleSessionSeconds"]:
                        existing_row = dict(row)
                except ValueError:
                    pass

            if existing_row is not None:
                session_id = existing_row["id"]
                db.execute(
                    """UPDATE game_activity_logs
                       SET timestamp=?, device_name=?, connected_to=?, router_ip=?, matched_indicator=?, detection_method=?
                       WHERE id=?""",
                    (
                        now,
                        ctx["deviceName"],
                        ctx["connectedTo"],
                        ctx["routerIp"],
                        indicator,
                        method,
                        session_id,
                    ),
                )
            else:
                session_id = f"game-{uuid.uuid4().hex[:10]}"
                db.execute(
                    """INSERT INTO game_activity_logs
                       (id, timestamp, ip, mac, device_name, vendor, device_type,
                        game_id, game_name, game_category, game_icon,
                        connected_to, router_ip, zone_label, matched_indicator, detection_method, is_active)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        session_id,
                        now,
                        client_ip,
                        ctx["mac"],
                        ctx["deviceName"],
                        ctx["vendor"],
                        ctx["deviceType"],
                        game["id"],
                        game["name"],
                        game["category"],
                        game["icon"],
                        ctx["connectedTo"],
                        ctx["routerIp"],
                        ctx["zoneLabel"],
                        indicator,
                        method,
                    ),
                )

        entry = {
            "id": session_id,
            "timestamp": now,
            "ip": client_ip,
            "mac": ctx["mac"],
            "deviceName": ctx["deviceName"],
            "vendor": ctx["vendor"],
            "deviceType": ctx["deviceType"],
            "gameId": game["id"],
            "gameName": game["name"],
            "gameCategory": game["category"],
            "gameIcon": game["icon"],
            "connectedTo": ctx["connectedTo"],
            "routerIp": ctx["routerIp"],
            "zoneLabel": ctx["zoneLabel"],
            "matchedIndicator": indicator,
            "detectionMethod": method,
            "isActive": True,
            "isBlocked": False,
        }

        if policy["autoPreventEnabled"] and not payload.get("skipAutoPrevent"):
            prevent_scope = "device_wifi_cut" if policy["autoCutWifi"] else "device_game"
            blk_res = self.block_game_session({
                "sessionId": session_id,
                "ip": client_ip,
                "gameId": game["id"],
                "scope": prevent_scope,
                "cutWifi": policy["autoCutWifi"],
                "autoPrevented": True,
            })
            prevented_entry = {
                **entry,
                "isActive": False,
                "isBlocked": True,
                "autoPrevented": True,
            }
            return {
                "success": True,
                "blocked": True,
                "autoPrevented": True,
                "ruleId": blk_res.get("ruleId"),
                "detection": prevented_entry,
                "gameActivity": blk_res.get("gameActivity") or self.get_game_activity(60),
            }

        changed_signal = existing_row is None or (
            existing_row.get("matched_indicator") != indicator
            or existing_row.get("detection_method") != method
        )
        if existing_row is None:
            title = f"{game['icon']} {game['name']} opened on {ctx['deviceName']}"
            msg = (
                f"{ctx['deviceName']} ({client_ip}) opened {game['name']} "
                f"while connected to {ctx['connectedTo']} via {indicator}."
            )
            self._record_event(
                "GAME_DETECTED",
                "INFO",
                title,
                msg,
                mac=ctx["mac"],
                ip=client_ip,
                device_name=ctx["deviceName"],
            )
            alert_key = f"game-{client_ip}-{game['id']}"
            alert = self._make_alert(alert_key, "INFO", title, msg, client_ip, 443)
            alert.update({
                "type": "GAME_DETECTED",
                "category": "gaming",
                "errorCode": f"GAME_{game['id'].upper()}",
                "target": f"{ctx['deviceName']} → {ctx['connectedTo']}",
                "deviceName": ctx["deviceName"],
                "gameName": game["name"],
                "connectedTo": ctx["connectedTo"],
                "likelyFault": f"Active {game['name']} session ({method})",
                "rootCause": f"Device {ctx['deviceName']} ({ctx['deviceType']}) accessed {indicator}.",
                "remediation": [
                    f"Connected access point / router: {ctx['connectedTo']}",
                    f"Zone: {ctx['zoneLabel']}",
                    "No outage — informational notification triggered on game launch.",
                ],
            })
            with self.lock:
                self.active_alerts[alert_key] = alert
            self.save_alert(alert)
            self.broadcast("new_alert", alert)

        activity = self.get_game_activity(60)
        if changed_signal:
            self.broadcast("game_detected", {"detection": entry, "gameActivity": activity})
        return {"success": True, "detection": entry, "gameActivity": activity}

    def expire_stale_game_sessions(self, max_idle_seconds: int | None = None) -> int:
        """Automatically end active game sessions when no traffic/process heartbeat was seen recently."""
        idle_limit = (
            int(max_idle_seconds)
            if max_idle_seconds is not None
            else self.get_gaming_policy()["staleSessionSeconds"]
        )
        now_dt = datetime.now(timezone.utc)
        expired_ids: list[str] = []
        expired_keys: set[str] = set()
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, ip, game_id, timestamp FROM game_activity_logs WHERE is_active=1"
            ).fetchall()
            for r in rows:
                try:
                    prev_dt = datetime.fromisoformat(str(r["timestamp"]).replace("Z", "+00:00"))
                    if (now_dt - prev_dt).total_seconds() >= idle_limit:
                        expired_ids.append(r["id"])
                        expired_keys.add(f"game-{r['ip']}-{r['game_id']}")
                except ValueError:
                    continue
            if expired_ids:
                placeholders = ",".join("?" for _ in expired_ids)
                db.execute(
                    f"UPDATE game_activity_logs SET is_active=0 WHERE id IN ({placeholders})",
                    tuple(expired_ids),
                )
        if expired_keys:
            changed_cfg = False
            with self.lock:
                for key in expired_keys:
                    if self.active_alerts.pop(key, None) is not None:
                        changed_cfg = True
                prev_len = len(self.config.get("alerts", []))
                self.config["alerts"] = [
                    a for a in self.config.get("alerts", [])
                    if a.get("key") not in expired_keys
                ]
                if len(self.config["alerts"]) != prev_len:
                    changed_cfg = True
                if changed_cfg:
                    self.save_config()
        return len(expired_ids)

    def mark_game_session_ended_by_ip_game(self, client_ip: str, game_id: str) -> dict:
        """Immediately mark active sessions ended when the host sensor detects a game process closed."""
        ip = validate_ip(client_ip)
        raw_gid = str(game_id or "").strip().lower()
        gid = _GAME_ID_ALIASES.get(raw_gid, raw_gid)
        if not gid:
            raise ValueError("Game id is required")
        with self._connect() as db:
            db.execute(
                "UPDATE game_activity_logs SET is_active=0 WHERE ip=? AND game_id=? AND is_active=1",
                (ip, gid),
            )
        alert_key = f"game-{ip}-{gid}"
        with self.lock:
            self.active_alerts.pop(alert_key, None)
            self.config["alerts"] = [
                a for a in self.config.get("alerts", []) if a.get("key") != alert_key
            ]
            self.save_config()
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": True, "gameActivity": activity}

    def _build_online_game_devices(self, active_logs: list[dict], blocks: list[dict]) -> list[dict]:
        """Build automatic list of currently online client devices (phones, tablets, PCs) with live game state."""
        infra_types = {"router", "gateway", "ap", "switch", "firewall"}
        mon_devices = self.get_devices()
        mon_by_ip = {str(d.get("ip") or ""): d for d in mon_devices if d.get("ip")}
        infra_ips = {
            ip for ip, d in mon_by_ip.items()
            if str(d.get("type") or "").lower() in infra_types
        }
        gw_ip = str(self.config.get("router", {}).get("ip") or "192.168.0.1")
        if gw_ip:
            infra_ips.add(gw_ip)

        with self._connect() as db:
            inv_rows = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM discovered_devices WHERE is_online=1 ORDER BY ip LIMIT 200"
                ).fetchall()
            ]
            topo_nodes = [dict(r) for r in db.execute("SELECT * FROM topology_nodes").fetchall()]
            topo_links = [dict(r) for r in db.execute("SELECT * FROM topology_links").fetchall()]

        inv_by_ip = {str(r.get("ip") or ""): r for r in inv_rows if r.get("ip")}
        cached_hosts = (
            self._get_cached_hostnames()
            if hasattr(self, "_get_cached_hostnames")
            else {}
        )
        node_by_id = {n["id"]: n for n in topo_nodes}
        topo_by_ip = {str(n.get("ip") or ""): n for n in topo_nodes if n.get("ip")}
        infra_devs = [
            d for d in mon_devices
            if str(d.get("type") or "").lower() in {"ap", "router", "gateway", "switch"}
        ]

        candidate_ips: list[str] = []
        seen_ips: set[str] = set()

        def _add_candidate(ip_val: str) -> None:
            ip_s = str(ip_val or "").strip()
            if (
                not ip_s
                or ip_s in seen_ips
                or ip_s in infra_ips
                or ip_s.startswith("172.27.")
                or ip_s.startswith("127.")
            ):
                return
            seen_ips.add(ip_s)
            candidate_ips.append(ip_s)

        for row in inv_rows:
            if row.get("archived"):
                continue
            low = f"{row.get('suggested_name') or ''} {row.get('vendor') or ''}".lower()
            if any(tok in low for tok in _NON_GAMING_TOKENS):
                continue
            _add_candidate(row.get("ip", ""))

        for dev in mon_devices:
            if dev.get("archived"):
                continue
            dtype = str(dev.get("type") or "").lower()
            if dtype in infra_types:
                continue
            low = f"{dev.get('name') or ''} {dev.get('vendor') or ''}".lower()
            if any(tok in low for tok in _NON_GAMING_TOKENS):
                continue
            _add_candidate(dev.get("ip", ""))

        for log in active_logs:
            _add_candidate(log.get("ip", ""))
        for blk in blocks:
            if blk.get("ip") and blk.get("ip") != "*":
                _add_candidate(blk["ip"])
        _add_candidate(self.HOST_DNS_IP)

        online_devices: list[dict] = []
        for ip in candidate_ips[:120]:
            ctx = self._assemble_client_context(
                client_ip=ip,
                mon_by_ip=mon_by_ip,
                inv_row=inv_by_ip.get(ip),
                cached_hosts=cached_hosts,
                topo_by_ip=topo_by_ip,
                node_by_id=node_by_id,
                topo_links=topo_links,
                infra_devs=infra_devs,
                gw_ip=gw_ip,
                allow_live_name_probe=False,
            )
            dev_active = [
                {
                    "id": x["id"],
                    "gameId": x["gameId"],
                    "gameName": x["gameName"],
                    "gameIcon": x["gameIcon"],
                    "matchedIndicator": x["matchedIndicator"],
                    "detectionMethod": x["detectionMethod"],
                    "timestamp": x["timestamp"],
                }
                for x in active_logs
                if x["ip"] == ip
            ]
            exact_blk = next((b for b in blocks if b["ip"] == ip), None)
            any_blk = exact_blk or next((b for b in blocks if b["ip"] == "*"), None)
            block_rule = (
                {
                    "id": any_blk["id"],
                    "gameId": any_blk["gameId"],
                    "gameName": any_blk["gameName"],
                    "scope": any_blk["scope"],
                }
                if any_blk
                else None
            )

            online_devices.append({
                "ip": ip,
                "mac": ctx["mac"],
                "deviceName": ctx["deviceName"],
                "vendor": ctx["vendor"],
                "deviceType": ctx["deviceType"],
                "isMobile": ctx["isMobile"],
                "connectedTo": ctx["connectedTo"],
                "zoneLabel": ctx["zoneLabel"],
                "activeGames": dev_active,
                "blockRule": block_rule,
            })

        online_devices.sort(
            key=lambda d: (
                0 if d["activeGames"] else 1,
                0 if d["blockRule"] else 1,
                0 if d["isMobile"] else 1,
                str(d["deviceName"]).lower(),
            )
        )
        return online_devices

    def get_game_activity(self, limit: int = 100) -> dict:
        self.expire_stale_game_sessions()
        policy = self.get_gaming_policy()
        sensor_status = self._get_gaming_sensor_status()
        limit = max(1, min(int(limit), 300))
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM game_activity_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()

        logs = [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "ip": r["ip"],
                "mac": r["mac"],
                "deviceName": r["device_name"],
                "vendor": r["vendor"],
                "deviceType": r["device_type"],
                "gameId": r["game_id"],
                "gameName": r["game_name"],
                "gameCategory": r["game_category"],
                "gameIcon": r["game_icon"],
                "connectedTo": r["connected_to"],
                "routerIp": r["router_ip"],
                "zoneLabel": r["zone_label"],
                "matchedIndicator": r["matched_indicator"],
                "detectionMethod": r["detection_method"],
                "isActive": bool(r["is_active"]),
                "isBlocked": bool(r["is_blocked"]) if "is_blocked" in r.keys() else False,
            }
            for r in rows
        ]
        blocks = self.get_game_blocks()
        active_logs = [x for x in logs if x["isActive"]]
        online_devices = self._build_online_game_devices(active_logs, blocks)
        game_counts: dict[str, int] = {}
        zone_counts: dict[str, int] = {}
        for item in logs:
            game_counts[item["gameName"]] = game_counts.get(item["gameName"], 0) + 1
            if item["connectedTo"]:
                zone_counts[item["connectedTo"]] = zone_counts.get(item["connectedTo"], 0) + 1

        top_game = max(game_counts, key=game_counts.get) if game_counts else "None yet"
        top_zone = max(zone_counts, key=zone_counts.get) if zone_counts else "No traffic yet"
        catalog = [
            {
                "id": g["id"],
                "name": g["name"],
                "category": g["category"],
                "icon": g["icon"],
                "isMobile": bool(g.get("isMobile")),
                "domains": list(g["domains"]),
                "ports": list(g["ports"]),
            }
            for g in GAME_SIGNATURES
        ]
        return {
            "logs": logs,
            "blocks": blocks,
            "onlineDevices": online_devices,
            "autoScanActive": True,
            "policy": policy,
            "sensorStatus": sensor_status,
            "summary": {
                "activeCount": len(active_logs),
                "blockedCount": len(blocks),
                "totalCount": len(logs),
                "onlineDevicesCount": len(online_devices),
                "topGame": top_game,
                "topZone": top_zone,
                "hostDnsServerIp": sensor_status["dnsHost"],
                "hostDnsPort": 53,
                "hostSyslogPort": 514,
                "dnsListenerPort": self.DNS_LISTENER_PORT,
                "syslogListenerPort": self.SYSLOG_LISTENER_PORT,
            },
            "catalog": catalog,
        }

    def get_game_blocks(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM game_block_rules WHERE active=1 ORDER BY created_at DESC"
            ).fetchall()
        return [
            {
                "id": r["id"],
                "createdAt": r["created_at"],
                "ip": r["ip"],
                "mac": r["mac"],
                "deviceName": r["device_name"],
                "gameId": r["game_id"],
                "gameName": r["game_name"],
                "scope": r["scope"],
                "cutWifi": bool(r["cut_wifi"]) if "cut_wifi" in r.keys() else True,
                "active": bool(r["active"]),
            }
            for r in rows
        ]

    @staticmethod
    def _is_wifi_captive_domain(domain: object) -> bool:
        dom = str(domain or "").strip().lower().rstrip(".")
        if not dom:
            return False
        return any(dom == sig or dom.endswith(f".{sig}") for sig in _WIFI_CAPTIVE_DOMAINS)

    @staticmethod
    def _should_sinkhole_query(
        client_ip: str, qname: str, matched_sig: dict | None, active_blocks: list[dict]
    ) -> dict | None:
        """Decide whether a DNS query from client_ip must be sinkholed to 0.0.0.0."""
        gid = matched_sig["id"] if matched_sig else ""
        is_captive = GameDetectorMixin._is_wifi_captive_domain(qname)
        for rule in active_blocks:
            r_ip = str(rule.get("ip") or "")
            r_gid = str(rule.get("gameId") or "")
            r_scope = str(rule.get("scope") or "")
            if r_ip == client_ip:
                if r_gid == "*" or r_scope in {"device_all_games", "device_wifi_cut"}:
                    return rule
                if matched_sig is not None and r_gid == gid:
                    return rule
                if bool(rule.get("cutWifi")) and is_captive:
                    return rule
            elif r_ip == "*" and matched_sig is not None and r_gid in (gid, "*"):
                return rule
        return None

    def _match_active_block_rule(self, client_ip: str, game_id: str) -> dict | None:
        for rule in self.get_game_blocks():
            if rule["ip"] in (client_ip, "*") and (
                rule["gameId"] in (game_id, "*")
                or rule.get("scope") in {"device_all_games", "device_wifi_cut"}
            ):
                return rule
        return None

    def _enforce_router_client_block(
        self, ip: str, mac: str, device_name: str, router_ip: str, block: bool
    ) -> list[str]:
        """Best-effort TP-Link LuCI MAC access-control block/unblock on company routers with valid stok."""
        clean_mac = str(mac or "").strip().upper().replace("-", ":")
        if ip == "*" or not clean_mac or getattr(self, "_skip_live_probe_in_test", False):
            return []

        configs = (
            self._resolve_router_configs()
            if hasattr(self, "_resolve_router_configs")
            else [dict(self.config.get("router", {}))]
        )
        primary_ip = str(self.config.get("router", {}).get("ip") or "192.168.0.1")
        targets = [
            cfg for cfg in configs
            if str(cfg.get("stok") or "").strip()
            and str(cfg.get("ip") or "") in {router_ip, primary_ip}
        ]
        if not targets:
            targets = [cfg for cfg in configs if str(cfg.get("stok") or "").strip()]
        if not targets:
            return []

        enforced: list[str] = []
        ctx = ssl._create_unverified_context()
        for cfg in targets:
            r_host = str(cfg.get("ip") or "").strip()
            r_port = int(cfg.get("port") or 80)
            use_https = bool(cfg.get("useHttps", False)) or r_port in (443, 8443)
            scheme = "https" if use_https else "http"
            encoded_stok = urllib.parse.quote(str(cfg.get("stok") or ""), safe="")
            mac_dash = clean_mac.replace(":", "-")
            endpoints = (
                (
                    f"/cgi-bin/luci/;stok={encoded_stok}/admin/access_control?form=black_devices",
                    urllib.parse.urlencode({
                        "operation": "insert" if block else "remove",
                        "key": clean_mac,
                        "name": str(device_name or ip)[:32],
                        "mac": mac_dash,
                    }).encode("utf-8"),
                ),
                (
                    f"/cgi-bin/luci/;stok={encoded_stok}/admin/client?form=client_list",
                    urllib.parse.urlencode({
                        "operation": "block" if block else "unblock",
                        "mac": mac_dash,
                    }).encode("utf-8"),
                ),
            )
            for ep_path, body in endpoints:
                req = urllib.request.Request(
                    f"{scheme}://{r_host}:{r_port}{ep_path}",
                    data=body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Pulse/2.1",
                    },
                )
                try:
                    with urllib.request.urlopen(
                        req, timeout=1.2, context=ctx if scheme == "https" else None
                    ) as resp:
                        raw = resp.read(8192).decode("utf-8", "ignore")
                    if '"success":true' in raw.replace(" ", "").lower():
                        enforced.append(f"{r_host}")
                        break
                except Exception:
                    continue
        return enforced

    def block_game_session(self, payload: dict) -> dict:
        """Block/shut off a user's game (and optionally their Wi-Fi access) via DNS sinkhole, socket RST & router MAC block."""
        if not isinstance(payload, dict):
            raise ValueError("Invalid block request payload")
        session_id = str(payload.get("sessionId") or "").strip()
        scope = str(payload.get("scope") or "device_game").strip().lower()
        if scope not in {"device_game", "device_all_games", "device_wifi_cut", "network_game"}:
            scope = "device_game"
        cut_wifi = bool(payload.get("cutWifi", True))

        raw_ip = str(payload.get("ip") or payload.get("clientIp") or "").strip()
        raw_game_id = str(payload.get("gameId") or "").strip().lower()

        if session_id:
            with self._connect() as db:
                srow = db.execute(
                    "SELECT ip, game_id FROM game_activity_logs WHERE id=?", (session_id,)
                ).fetchone()
            if srow:
                if not raw_ip:
                    raw_ip = str(srow["ip"] or "")
                if not raw_game_id:
                    raw_game_id = str(srow["game_id"] or "")

        if scope == "network_game":
            ip = "*"
            mac = ""
            router_ip = ""
            device_name = "All Network Devices (Whole LAN)"
            cut_wifi = False
        else:
            ip = validate_ip(raw_ip)
            ctx = self._resolve_game_client_context(ip)
            mac = ctx["mac"]
            router_ip = ctx.get("routerIp", "")
            device_name = ctx["deviceName"]

        if scope in {"device_all_games", "device_wifi_cut"} or raw_game_id == "*":
            sig = self._match_game_signature(game_id=raw_game_id) if raw_game_id and raw_game_id != "*" else None
            game_id = "*"
            if scope == "device_wifi_cut":
                game_name = (
                    f"{sig['name']} + User Wi-Fi Cut Off"
                    if sig is not None
                    else "All Games + User Wi-Fi Cut Off"
                )
            else:
                game_name = "All Games + User Wi-Fi" if cut_wifi else "All Mobile & Online Games"
            game_ports: tuple[int, ...] = SCAN_GAME_PORTS
        else:
            sig = self._match_game_signature(game_id=raw_game_id)
            if sig is None:
                raise ValueError("Select a valid game or block scope")
            game_id = sig["id"]
            game_name = sig["name"]
            game_ports = tuple(sig.get("ports") or ())

        now = utc_now()
        with self._connect() as db:
            existing = db.execute(
                "SELECT id FROM game_block_rules WHERE ip=? AND game_id=? AND active=1",
                (ip, game_id),
            ).fetchone()
            if existing:
                rule_id = existing["id"]
                db.execute(
                    "UPDATE game_block_rules SET created_at=?, mac=?, device_name=?, game_name=?, scope=?, cut_wifi=? WHERE id=?",
                    (now, mac, device_name, game_name, scope, 1 if cut_wifi else 0, rule_id),
                )
            else:
                rule_id = f"gblk-{uuid.uuid4().hex[:10]}"
                db.execute(
                    """INSERT INTO game_block_rules
                       (id, created_at, ip, mac, device_name, game_id, game_name, scope, cut_wifi, active)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (rule_id, now, ip, mac, device_name, game_id, game_name, scope, 1 if cut_wifi else 0),
                )

            if ip == "*":
                db.execute(
                    "UPDATE game_activity_logs SET is_active=0, is_blocked=1 WHERE game_id=?",
                    (game_id,),
                )
            elif game_id == "*":
                db.execute(
                    "UPDATE game_activity_logs SET is_active=0, is_blocked=1 WHERE ip=?",
                    (ip,),
                )
            else:
                db.execute(
                    "UPDATE game_activity_logs SET is_active=0, is_blocked=1 WHERE ip=? AND game_id=?",
                    (ip, game_id),
                )

        # Clear matching active game alerts
        with self.lock:
            for k in list(self.active_alerts.keys()):
                if not k.startswith("game-"):
                    continue
                al = self.active_alerts[k]
                a_ip = str(al.get("ip") or "")
                a_gid = str(al.get("errorCode") or "").replace("GAME_", "").lower()
                if (ip in (a_ip, "*")) and (game_id in (a_gid, "*")):
                    self.active_alerts.pop(k, None)
            self.config["alerts"] = [
                a for a in self.config.get("alerts", [])
                if not (
                    str(a.get("key") or "").startswith("game-")
                    and ip in (str(a.get("ip") or ""), "*")
                    and game_id in (str(a.get("errorCode") or "").replace("GAME_", "").lower(), "*")
                )
            ]
            self.save_config()

        # Best-effort TCP RST burst across game + scan ports to drop active local sockets
        if ip != "*" and not getattr(self, "_skip_live_probe_in_test", False):
            linger = struct.pack("ii", 1, 0)
            burst_ports = list(dict.fromkeys([*game_ports, *SCAN_GAME_PORTS]))
            for p in burst_ports[:10]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rsock:
                        rsock.settimeout(0.06)
                        rsock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                        rsock.connect((ip, int(p)))
                except OSError:
                    pass

        router_applied = (
            self._enforce_router_client_block(ip, mac, device_name, router_ip, block=True)
            if (cut_wifi or scope in {"device_all_games", "device_wifi_cut"})
            else []
        )
        router_note = (
            f" Router MAC kick applied on {', '.join(router_applied)}."
            if router_applied
            else " Enforced via per-device DNS 0.0.0.0 sinkhole & active socket reset."
        )
        auto_prevented = bool(payload.get("autoPrevented"))
        action_prefix = "🛡️ Auto-Prevented" if auto_prevented else "🛑 Blocked"
        self._record_event(
            "GAME_AUTO_PREVENTED" if auto_prevented else "GAME_BLOCKED",
            "WARNING",
            f"{action_prefix}: {game_name}",
            f"Shut off {game_name} on {device_name} ({ip}).{router_note}",
            mac=mac,
            ip="" if ip == "*" else ip,
            device_name=device_name,
        )
        activity = self.get_game_activity(100)
        bcast_payload: dict = {"gameActivity": activity}
        if auto_prevented:
            bcast_payload["detection"] = {
                "id": session_id or rule_id,
                "timestamp": now,
                "ip": ip,
                "mac": mac,
                "deviceName": device_name,
                "gameId": game_id,
                "gameName": game_name,
                "gameIcon": "🛡️",
                "connectedTo": f"Router ({router_ip})" if router_ip else "Company Wi-Fi",
                "matchedIndicator": str(payload.get("matchedIndicator") or game_name),
                "detectionMethod": str(payload.get("detectionMethod") or "Real-Time Auto-Prevention"),
                "autoPrevented": True,
                "isBlocked": True,
            }
        self.broadcast("game_detected", bcast_payload)
        return {
            "success": True,
            "ruleId": rule_id,
            "autoPrevented": auto_prevented,
            "routerEnforced": router_applied,
            "gameActivity": activity,
        }

    def unblock_game_rule(self, rule_id: str) -> dict:
        rid = str(rule_id or "").strip()
        if not rid:
            raise ValueError("Block rule id is required")
        with self._connect() as db:
            row = db.execute("SELECT * FROM game_block_rules WHERE id=?", (rid,)).fetchone()
            if row is None:
                raise ValueError("Game block rule not found")
            rule = dict(row)
            db.execute("DELETE FROM game_block_rules WHERE id=?", (rid,))
            if rule["ip"] == "*":
                db.execute(
                    "UPDATE game_activity_logs SET is_blocked=0 WHERE game_id=?",
                    (rule["game_id"],),
                )
            elif rule["game_id"] == "*":
                db.execute(
                    "UPDATE game_activity_logs SET is_blocked=0 WHERE ip=?",
                    (rule["ip"],),
                )
            else:
                db.execute(
                    "UPDATE game_activity_logs SET is_blocked=0 WHERE ip=? AND game_id=?",
                    (rule["ip"], rule["game_id"]),
                )

        self._enforce_router_client_block(
            rule["ip"], rule.get("mac") or "", rule["device_name"], "", block=False
        )
        self._record_event(
            "GAME_UNBLOCKED",
            "INFO",
            f"🟢 Unblocked: {rule['game_name']}",
            f"Restored access for {rule['device_name']} ({rule['ip']}).",
            mac=rule.get("mac") or "",
            ip="" if rule["ip"] == "*" else rule["ip"],
            device_name=rule["device_name"],
        )
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": True, "gameActivity": activity}

    @staticmethod
    def _parse_dns_question(raw_query: bytes) -> tuple[bytes, int, int, bytes] | None:
        if len(raw_query) < 12:
            return None
        txid = raw_query[0:2]
        idx = 12
        while idx < len(raw_query):
            length = raw_query[idx]
            if length == 0:
                idx += 1
                break
            if (length & 0xC0) != 0:
                idx += 2
                break
            idx += 1 + length
        if idx + 4 > len(raw_query):
            return None
        qtype = int.from_bytes(raw_query[idx : idx + 2], "big")
        qclass = int.from_bytes(raw_query[idx + 2 : idx + 4], "big")
        question = raw_query[12 : idx + 4]
        return txid, qtype, qclass, question

    @staticmethod
    def _build_dns_nxdomain_reply(raw_query: bytes) -> bytes:
        """Build a valid NXDOMAIN (RCODE=3) reply for DoH/Private Relay canary domains."""
        parsed = GameDetectorMixin._parse_dns_question(raw_query)
        if not parsed:
            return b""
        txid, _qtype, _qclass, question = parsed
        return txid + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question

    @staticmethod
    def _build_dns_sinkhole_reply(raw_query: bytes) -> bytes:
        """Build a valid DNS NOERROR response returning 0.0.0.0 (A) / :: (AAAA) with TTL=1s."""
        parsed = GameDetectorMixin._parse_dns_question(raw_query)
        if not parsed:
            return b""
        txid, qtype, qclass, question = parsed

        if qtype == 1 and qclass == 1:
            # Answer ptr 0xc00c, Type A (1), Class IN (1), TTL 1s, RDLEN 4, 0.0.0.0
            header = txid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x00\x00\x00\x00"
            return header + question + answer
        if qtype == 28 and qclass == 1:
            # Type AAAA (28), Class IN (1), TTL 1s, RDLEN 16, ::
            header = txid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x01\x00\x10" + (b"\x00" * 16)
            return header + question + answer
        # NODATA for HTTPS/SVCB/etc. so OS resolver doesn't fail over to secondary DNS
        return txid + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + question

    @staticmethod
    def _batch_scan_ports_nonblocking(
        client_ips: list[str], ports: tuple[int, ...], timeout_sec: float = 0.16
    ) -> dict[str, int]:
        """Connect-scan (ip x ports) rapidly using non-blocking selectors batches (<=256 fds/batch for Windows)."""
        open_by_ip: dict[str, int] = {}
        targets = [(ip, int(p)) for ip in client_ips for p in ports]
        batch_size = 220
        for offset in range(0, len(targets), batch_size):
            batch = targets[offset : offset + batch_size]
            sel = selectors.DefaultSelector()
            pending: dict[socket.socket, tuple[str, int]] = {}
            try:
                for ip, port in batch:
                    if ip in open_by_ip:
                        continue
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setblocking(False)
                        err = sock.connect_ex((ip, port))
                        if err == 0:
                            open_by_ip.setdefault(ip, port)
                            sock.close()
                        elif err in (10035, 115, 36):  # WSAEWOULDBLOCK / EINPROGRESS
                            sel.register(sock, selectors.EVENT_WRITE, data=(ip, port))
                            pending[sock] = (ip, port)
                        else:
                            sock.close()
                    except OSError:
                        continue
                deadline = time.monotonic() + timeout_sec
                while pending and time.monotonic() < deadline:
                    wait_t = max(0.01, deadline - time.monotonic())
                    for key, _events in sel.select(timeout=wait_t):
                        sock = key.fileobj
                        ip, port = key.data
                        sel.unregister(sock)
                        pending.pop(sock, None)
                        try:
                            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                            if err == 0:
                                open_by_ip.setdefault(ip, port)
                        except OSError:
                            pass
                        finally:
                            sock.close()
            finally:
                for sock in list(pending):
                    try:
                        sel.unregister(sock)
                    except Exception:
                        pass
                    try:
                        sock.close()
                    except OSError:
                        pass
                sel.close()
        return open_by_ip

    def _sync_topology_arp_and_clients(self) -> int:
        """Harvest fresh live ARP neighbors and authenticated router DHCP/client lists across topology."""
        if getattr(self, "_skip_live_probe_in_test", False):
            return 0
        synced = 0
        # 1. Fast ARP table refresh across all connected subnets
        if hasattr(self, "_read_arp_entries"):
            try:
                arp_entries = self._read_arp_entries(os, subprocess)
                local_nets = self._known_local_networks() if hasattr(self, "_known_local_networks") else []
                with self._connect() as db:
                    known_macs = {
                        r["ip"]: r["mac"]
                        for r in db.execute("SELECT ip, mac FROM discovered_devices").fetchall()
                    }
                for raw_ip, raw_mac, kind in arp_entries:
                    try:
                        ip = validate_ip(raw_ip)
                        mac = str(raw_mac or "").strip().lower().replace("-", ":")
                        addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if mac in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"} or not addr.is_private:
                        continue
                    if local_nets and not any(addr in n for n in local_nets):
                        continue
                    if ip not in known_macs and hasattr(self, "_vendor_for_oui"):
                        vendor, _ = self._vendor_for_oui(mac.replace(":", "")[:6])
                        self._upsert_inventory({
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor,
                            "suggestedName": f"{vendor} ({ip})" if vendor and vendor != "Unknown" else f"LAN Device ({ip})",
                            "arpType": kind,
                        })
                        synced += 1
            except Exception:
                pass

        # 2. Query authenticated routers/APs in topology for active wireless/DHCP client lists
        routers_polled = 0
        if hasattr(self, "_resolve_router_configs"):
            ctx = ssl._create_unverified_context()
            for cfg in self._resolve_router_configs():
                stok = str(cfg.get("stok") or "").strip()
                if not stok:
                    continue
                host = str(cfg.get("ip") or "").strip()
                port = int(cfg.get("port") or 80)
                scheme = "https" if (bool(cfg.get("useHttps", False)) or port in (443, 8443)) else "http"
                enc_stok = urllib.parse.quote(stok, safe="")
                routers_polled += 1
                for ep in ("/admin/dhcps?form=client", "/admin/client?form=client_list"):
                    req = urllib.request.Request(
                        f"{scheme}://{host}:{port}/cgi-bin/luci/;stok={enc_stok}{ep}",
                        data=b"operation=read",
                        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Pulse/2.1"},
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=1.3, context=ctx if scheme == "https" else None) as resp:
                            payload = json.loads(resp.read(128 * 1024).decode("utf-8", "ignore"))
                    except Exception:
                        continue
                    rows = payload.get("data") if isinstance(payload, dict) else None
                    if not isinstance(rows, list):
                        continue
                    hosts_map: dict[str, str] = {}
                    for cl in rows:
                        if not isinstance(cl, dict):
                            continue
                        cip = str(cl.get("ipaddr") or cl.get("ip") or "").strip()
                        cmac = str(cl.get("macaddr") or cl.get("mac") or "").strip().lower().replace("-", ":")
                        cname = str(cl.get("hostname") or cl.get("name") or "").strip()
                        try:
                            cip = validate_ip(cip)
                        except ValueError:
                            continue
                        if cname and cname.lower() not in {"*", "unknown", "—", "--"}:
                            hosts_map[cip] = cname[:80]
                        if cmac and len(cmac) == 17 and hasattr(self, "_vendor_for_oui"):
                            vendor, _ = self._vendor_for_oui(cmac.replace(":", "")[:6])
                            self._upsert_inventory({
                                "ip": cip,
                                "mac": cmac,
                                "vendor": vendor,
                                "suggestedName": cname or f"{vendor} ({cip})",
                                "arpType": "dhcp",
                            })
                            synced += 1
                    if hosts_map and hasattr(self, "_save_cached_hostnames"):
                        self._save_cached_hostnames(hosts_map)
        return routers_polled

    def _collect_local_os_game_signals(self) -> list[dict]:
        """Inspect host OS processes, netstat sockets, and non-passive DNS cache on Windows."""
        if sys.platform != "win32" or getattr(self, "_skip_live_probe_in_test", False):
            return []
        flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        host_ip = self._detect_host_lan_ip(self.HOST_DNS_IP)
        found: list[dict] = []
        seen_games: set[str] = set()

        # 1. Running Windows game / Android emulator processes
        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=2.5, creationflags=flags,
            )
            if res.returncode == 0:
                for row in csv.reader(res.stdout.splitlines()):
                    pname = str(row[0] or "").strip() if row else ""
                    if not pname:
                        continue
                    sig = self._match_game_signature(process=pname)
                    if sig and sig["id"] not in seen_games:
                        seen_games.add(sig["id"])
                        found.append({
                            "ip": host_ip,
                            "gameId": sig["id"],
                            "process": pname,
                            "matchedIndicator": f"Process {pname}",
                            "detectionMethod": "Topology Host Process Scan",
                        })
        except Exception:
            pass

        # 2. Active outbound / inbound TCP sockets against dedicated game server ports
        try:
            res = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=2.5, creationflags=flags,
            )
            if res.returncode == 0:
                own_pid = str(os.getpid())
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "ESTABLISHED":
                        continue
                    if parts[-1] == own_pid or ":" not in parts[1] or ":" not in parts[2]:
                        continue
                    local_ip = parts[1].rsplit(":", 1)[0].strip("[]")
                    remote_ip = parts[2].rsplit(":", 1)[0].strip("[]")
                    try:
                        rport = int(parts[2].rsplit(":", 1)[1])
                        lport = int(parts[1].rsplit(":", 1)[1])
                        r_addr = ipaddress.ip_address(remote_ip)
                    except ValueError:
                        continue
                    is_public_remote = not (r_addr.is_private or r_addr.is_loopback or r_addr.is_link_local or r_addr.is_multicast)
                    if rport in _NETSTAT_GAME_PORTS and is_public_remote:
                        sig = self._match_game_signature(port=rport)
                        target_ip = host_ip if local_ip in (host_ip, "127.0.0.1") else local_ip
                        if sig and (sig["id"] not in seen_games):
                            seen_games.add(sig["id"])
                            found.append({
                                "ip": target_ip,
                                "gameId": sig["id"],
                                "port": rport,
                                "matchedIndicator": f"TCP -> {parts[2]}",
                                "detectionMethod": "Topology Host Netstat Scan",
                            })
                    elif lport in _NETSTAT_GAME_PORTS and self._is_real_lan_client_ip(remote_ip):
                        sig = self._match_game_signature(port=lport)
                        if sig:
                            found.append({
                                "ip": remote_ip,
                                "gameId": sig["id"],
                                "port": lport,
                                "matchedIndicator": f"Client {remote_ip} -> :{lport}",
                                "detectionMethod": "Topology Socket Client Scan",
                            })
        except Exception:
            pass

        # 3. Live non-expired Windows DNS client cache entries (excludes passive Steam/Riot CDN)
        try:
            res = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=2.5, creationflags=flags,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if ":" not in line:
                        continue
                    cand = line.split(":", 1)[1].strip().lower().rstrip(".")
                    if not cand or "." not in cand or cand in _PASSIVE_DNS_CACHE_EXCLUDE:
                        continue
                    sig = self._match_game_signature(domain=cand)
                    if sig and sig["id"] not in seen_games:
                        seen_games.add(sig["id"])
                        found.append({
                            "ip": host_ip,
                            "gameId": sig["id"],
                            "domain": cand,
                            "detectionMethod": "Topology Host DNS Cache Scan",
                        })
        except Exception:
            pass

        return found

    def scan_lan_for_games(self, include_topology_refresh: bool = False) -> dict:
        """Scan the whole network topology (routers, APs, topology nodes, host OS & all LAN clients) for open games."""
        infra_types = {"router", "gateway", "ap", "switch", "firewall", "cloud"}
        mon_devices = self.get_devices()
        infra_ips = {
            str(d.get("ip") or "").strip()
            for d in mon_devices
            if str(d.get("type") or "").lower() in infra_types
        }
        gw_ip = str(self.config.get("router", {}).get("ip") or "192.168.0.1").strip()
        if gw_ip:
            infra_ips.add(gw_ip)

        routers_polled = 0
        detections: list[dict] = []

        confirmed_hits = 0
        if include_topology_refresh:
            routers_polled = self._sync_topology_arp_and_clients()
            self.poll_router_logs_for_games()
            for sig_payload in self._collect_local_os_game_signals():
                confirmed_hits += 1
                try:
                    res = self.record_game_detection(sig_payload)
                    if res.get("detection"):
                        detections.append(res["detection"])
                except Exception:
                    pass

        with self._connect() as db:
            inv_rows = db.execute(
                "SELECT DISTINCT ip, vendor, suggested_name FROM discovered_devices WHERE is_online=1 ORDER BY ip LIMIT 1024"
            ).fetchall()
            topo_nodes = [dict(r) for r in db.execute("SELECT * FROM topology_nodes").fetchall()]

        for n in topo_nodes:
            if str(n.get("node_type") or "").lower() in infra_types and str(n.get("ip") or "").strip():
                infra_ips.add(str(n["ip"]).strip())
        topology_hubs = max(
            len(infra_ips),
            sum(1 for n in topo_nodes if str(n.get("node_type") or "").lower() in infra_types),
            len(self.config.get("routers") or {}) + 1,
        )

        client_ips: list[str] = []
        seen_client_ips: set[str] = set()

        def _push_target(raw_ip: str, label_hint: str = "") -> None:
            ip = str(raw_ip or "").strip()
            if (
                not ip
                or ip in seen_client_ips
                or ip in infra_ips
                or ip.startswith(("172.27.", "127."))
            ):
                return
            low = label_hint.lower()
            if low and any(tok in low for tok in _NON_GAMING_TOKENS):
                return
            seen_client_ips.add(ip)
            client_ips.append(ip)

        for n in topo_nodes:
            if str(n.get("node_type") or "").lower() not in infra_types:
                _push_target(n.get("ip", ""), f"{n.get('name') or ''} {n.get('vendor') or ''}")
        for d in mon_devices:
            if not d.get("archived") and str(d.get("type") or "").lower() not in infra_types:
                _push_target(d.get("ip", ""), f"{d.get('name') or ''} {d.get('vendor') or ''}")
        for r in inv_rows:
            _push_target(r["ip"], f"{r['suggested_name'] or ''} {r['vendor'] or ''}")
        with self.lock:
            dns_clients = list((self._gaming_sensor_telemetry.get("dnsClients") or {}).keys())
        for dc_ip in dns_clients:
            _push_target(dc_ip)
        host_ip = self.HOST_DNS_IP if getattr(self, "_skip_live_probe_in_test", False) else self._detect_host_lan_ip(self.HOST_DNS_IP)
        _push_target(host_ip)

        if client_ips:
            if getattr(self, "_skip_live_probe_in_test", False):
                def _check_host_ports(target_ip: str) -> tuple[str, int | None]:
                    for port in SCAN_GAME_PORTS:
                        is_open, _, _ = self._probe_tcp_socket(target_ip, port, timeout=0.06)
                        if is_open:
                            return target_ip, port
                    return target_ip, None

                with ThreadPoolExecutor(max_workers=min(48, len(client_ips))) as pool:
                    hits = {ip_k: p for ip_k, p in pool.map(_check_host_ports, client_ips) if p is not None}
            else:
                hits = self._batch_scan_ports_nonblocking(client_ips, SCAN_GAME_PORTS, timeout_sec=0.14)

            for ip_key, open_port in hits.items():
                confirmed_hits += 1
                res = self.record_game_detection({
                    "ip": ip_key,
                    "port": open_port,
                    "detectionMethod": "Whole-Topology Port Scan" if include_topology_refresh else "Active Game Port Scan",
                })
                if res.get("detection"):
                    detections.append(res["detection"])

        activity = self.get_game_activity(100)
        if include_topology_refresh:
            self._record_event(
                "GAME_TOPOLOGY_SCAN",
                "INFO",
                "🔍 Whole-Topology Game Scan Completed",
                (
                    f"Scanned {topology_hubs} topology router/AP hub(s) ({len(topo_nodes)} map node(s)) and "
                    f"{len(client_ips)} connected device(s) across all subnets — {confirmed_hits} open game hit(s), {len(detections)} newly logged."
                ),
                device_name="Pulse Topology Game Scanner",
            )
            self.broadcast("game_detected", {"gameActivity": activity})

        return {
            "success": True,
            "topologyNodesScanned": len(topo_nodes),
            "topologyHubsScanned": topology_hubs,
            "routersPolled": routers_polled,
            "scannedDevices": len(client_ips),
            "confirmedHits": confirmed_hits,
            "detectedCount": len(detections),
            "activeCount": int((activity.get("summary") or {}).get("activeCount") or 0),
            "blockedCount": len(activity.get("blocks") or []),
            "detections": detections,
            "gameActivity": activity,
        }

    def dismiss_game_session(self, session_id: str) -> dict:
        sid = str(session_id or "").strip()
        if not sid:
            raise ValueError("Game session id is required")
        with self._connect() as db:
            row = db.execute(
                "SELECT ip, game_id FROM game_activity_logs WHERE id=?", (sid,)
            ).fetchone()
            if row is None:
                raise ValueError("Game activity session not found")
            db.execute("UPDATE game_activity_logs SET is_active=0 WHERE id=?", (sid,))
        alert_key = f"game-{row['ip']}-{row['game_id']}"
        with self.lock:
            self.active_alerts.pop(alert_key, None)
            self.config["alerts"] = [
                a for a in self.config.get("alerts", []) if a.get("key") != alert_key
            ]
            self.save_config()
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": True, "gameActivity": activity}

    def clear_game_activity(self) -> dict:
        with self._connect() as db:
            removed = int(db.execute("SELECT COUNT(*) FROM game_activity_logs").fetchone()[0] or 0)
            db.execute("DELETE FROM game_activity_logs")
        with self.lock:
            for k in [key for key in list(self.active_alerts.keys()) if key.startswith("game-")]:
                self.active_alerts.pop(k, None)
            self.config["alerts"] = [
                a for a in self.config.get("alerts", []) if not str(a.get("key") or "").startswith("game-")
            ]
            self.save_config()
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": True, "removed": removed, "gameActivity": activity}

    @staticmethod
    def _extract_dns_qname(packet: bytes) -> str:
        """Parse Question 1 QNAME from a raw UDP DNS query packet."""
        if len(packet) <= 12:
            return ""
        idx = 12
        labels: list[str] = []
        while idx < len(packet):
            length = packet[idx]
            if length == 0:
                break
            if (length & 0xC0) != 0:
                break
            idx += 1
            if idx + length > len(packet):
                return ""
            labels.append(packet[idx : idx + length].decode("utf-8", "ignore"))
            idx += length
        return ".".join(labels).lower()

    def _is_real_lan_client_ip(self, candidate_ip: str) -> bool:
        """Accept only non-loopback, non-Docker-NAT private LAN IPs matching our monitored LAN ranges."""
        try:
            ip_obj = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False
        if not isinstance(ip_obj, ipaddress.IPv4Address) or not ip_obj.is_private or ip_obj.is_loopback:
            return False
        local_nets = self._known_local_networks() if hasattr(self, "_known_local_networks") else []
        if local_nets:
            return any(ip_obj in net for net in local_nets)
        return not str(ip_obj).startswith("172.")

    def start_game_listeners(self) -> None:
        """Start container UDP DNS listener (5354) and Router Syslog listener (5140)."""
        if getattr(self, "_game_listeners_started", False):
            return
        self._game_listeners_started = True
        threading.Thread(
            target=self._dns_game_listener_loop, daemon=True, name="game-dns-listener"
        ).start()
        threading.Thread(
            target=self._syslog_game_listener_loop, daemon=True, name="game-syslog-listener"
        ).start()

    def _dns_game_listener_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.DNS_LISTENER_PORT))
            sock.settimeout(1.0)
        except OSError:
            sock.close()
            return

        def _handle_dns_packet(raw: bytes, client_addr: tuple[str, int]) -> None:
            qname = self._extract_dns_qname(raw)
            if qname and self._is_doh_canary_domain(qname):
                nxd = self._build_dns_nxdomain_reply(raw)
                if nxd:
                    try:
                        sock.sendto(nxd, client_addr)
                    except OSError:
                        pass
                return
            sig = self._match_game_signature(domain=qname) if qname else None
            policy = self.get_gaming_policy()
            sinkhole_rule = (
                self._should_sinkhole_query(client_addr[0], qname, sig, self.get_game_blocks())
                if qname
                else None
            )
            if sinkhole_rule is not None or (sig and policy["autoPreventEnabled"]):
                sink = self._build_dns_sinkhole_reply(raw)
                if sink:
                    try:
                        sock.sendto(sink, client_addr)
                    except OSError:
                        pass
                if sinkhole_rule is None and sig and self._is_real_lan_client_ip(client_addr[0]):
                    try:
                        self.record_game_detection({
                            "ip": client_addr[0],
                            "domain": qname,
                            "detectionMethod": f"DNS Query (UDP {self.DNS_LISTENER_PORT})",
                        })
                    except Exception:
                        pass
                return
            if sig and self._is_real_lan_client_ip(client_addr[0]):
                try:
                    self.record_game_detection({
                        "ip": client_addr[0],
                        "domain": qname,
                        "detectionMethod": f"DNS Query (UDP {self.DNS_LISTENER_PORT})",
                    })
                except Exception:
                    pass
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fwd:
                    fwd.settimeout(1.5)
                    fwd.sendto(raw, ("1.1.1.1", 53))
                    resp, _ = fwd.recvfrom(4096)
                sock.sendto(resp, client_addr)
            except OSError:
                pass

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    threading.Thread(
                        target=_handle_dns_packet, args=(data, addr), daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            sock.close()

    def _parse_syslog_game_text(self, text: str, sender_ip: str = "") -> tuple[str, str, int | None] | None:
        matched_domain = ""
        for dm in re.findall(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){1,5}\b", text):
            if self._match_game_signature(domain=dm):
                matched_domain = dm.lower()
                break
        matched_port = None
        if not matched_domain:
            pm = re.search(r"(?:DPT|dst_port|port)[=: ]+(\d{2,5})", text, re.I)
            if pm and self._match_game_signature(port=pm.group(1)):
                matched_port = int(pm.group(1))
        if not matched_domain and matched_port is None:
            return None

        client_ip = ""
        for cand_ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            if cand_ip != sender_ip and self._is_real_lan_client_ip(cand_ip):
                client_ip = cand_ip
                break
        if not client_ip and sender_ip and self._is_real_lan_client_ip(sender_ip):
            client_ip = sender_ip
        if not client_ip:
            return None
        return client_ip, matched_domain, matched_port

    def poll_router_logs_for_games(self) -> int:
        """Poll authenticated TP-Link LuCI system logs for game domain/port traces."""
        if getattr(self, "_skip_live_probe_in_test", False):
            return 0
        configs = (
            self._resolve_router_configs()
            if hasattr(self, "_resolve_router_configs")
            else [dict(self.config.get("router", {}))]
        )
        authed = [c for c in configs if str(c.get("stok") or "").strip()]
        if not authed:
            return 0
        seen = getattr(self, "_seen_router_log_lines", None)
        if seen is None:
            seen = set()
            self._seen_router_log_lines = seen
        found = 0
        ctx = ssl._create_unverified_context()
        for cfg in authed:
            host = str(cfg.get("ip") or "").strip()
            port = int(cfg.get("port") or 80)
            scheme = "https" if (bool(cfg.get("useHttps", False)) or port in (443, 8443)) else "http"
            enc_stok = urllib.parse.quote(str(cfg.get("stok") or ""), safe="")
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/cgi-bin/luci/;stok={enc_stok}/admin/syslog?form=log",
                data=b"operation=read",
                headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Pulse/2.1"},
            )
            try:
                with urllib.request.urlopen(req, timeout=1.5, context=ctx if scheme == "https" else None) as resp:
                    payload = json.loads(resp.read(128 * 1024).decode("utf-8", "ignore"))
            except Exception:
                continue
            rows = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                continue
            for item in rows[-80:]:
                line = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                if line in seen:
                    continue
                seen.add(line)
                if len(seen) > 1500:
                    seen.clear()
                parsed = self._parse_syslog_game_text(line, sender_ip=host)
                if not parsed:
                    continue
                client_ip, matched_domain, matched_port = parsed
                try:
                    self.record_game_detection({
                        "ip": client_ip,
                        "reporterIp": host,
                        "domain": matched_domain,
                        "port": matched_port,
                        "detectionMethod": f"Router Log Poll ({host})",
                    })
                    found += 1
                except Exception:
                    pass
        return found

    def _syslog_game_listener_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.SYSLOG_LISTENER_PORT))
            sock.settimeout(1.0)
        except OSError:
            sock.close()
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                text = data.decode("utf-8", "ignore")
                sender_ip = addr[0]
                parsed = self._parse_syslog_game_text(text, sender_ip=sender_ip)
                if not parsed:
                    continue
                client_ip, matched_domain, matched_port = parsed
                try:
                    self.record_game_detection({
                        "ip": client_ip,
                        "reporterIp": sender_ip if self._is_real_lan_client_ip(sender_ip) else "",
                        "domain": matched_domain,
                        "port": matched_port,
                        "detectionMethod": f"Router Syslog (UDP {self.SYSLOG_LISTENER_PORT})",
                    })
                except Exception:
                    pass
        finally:
            sock.close()
