"""Accurate device-level mobile & online game detection via DNS forwarding, syslog, and port probes."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import selectors
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

if os.name == "nt":
    import ctypes
    import winreg
    from ctypes import wintypes

    class _ProcessEntry(ctypes.Structure):
        # PROCESSENTRY32W from tlhelp32.h.
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for _process_iterator in (_kernel32.Process32FirstW, _kernel32.Process32NextW):
        _process_iterator.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ProcessEntry))
        _process_iterator.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.ProcessIdToSessionId.argtypes = (wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    _kernel32.ProcessIdToSessionId.restype = wintypes.BOOL

from typing import TYPE_CHECKING, cast

from .config import normalize_mac, observed_inventory_mac, utc_now, validate_ip
from .router_game_control import RouterGameControl

if TYPE_CHECKING:
    from .engine import Monitor

STEAM_CLIENT_ID = "steam_client"
RIOT_CLIENT_ID = "riot_client"
LAUNCHER_IDS = frozenset({STEAM_CLIENT_ID, RIOT_CLIENT_ID})
RIOT_WEBSITE_ID = "riot_website"
MLBB_WEBSITE_ID = "mlbb_website"
_WEBSITE_SIGNATURES = [
    {
        "id": website_id,
        "name": f"{name} website",
        "category": "Website",
        "icon": "🌐",
        "isMobile": is_mobile,
        "domains": domains,
        "exactDomainsOnly": True,
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    }
    for website_id, name, is_mobile, domains in (
        (RIOT_WEBSITE_ID, "Riot Games", False, ("riotgames.com", "www.riotgames.com")),
        (MLBB_WEBSITE_ID, "Mobile Legends", True, ("mobilelegends.com", "www.mobilelegends.com", "m.mobilelegends.com", "play.mobilelegends.com")),
        ("wildrift_website", "Wild Rift", True, ("wildrift.leagueoflegends.com",)),
        ("supercell_website", "Supercell", False, ("supercell.com", "www.supercell.com")),
        ("clashofclans_website", "Clash of Clans", True, ("clashofclans.com", "www.clashofclans.com")),
        ("clashroyale_website", "Clash Royale", True, ("clashroyale.com", "www.clashroyale.com")),
        ("brawlstars_website", "Brawl Stars", True, ("brawlstars.com", "www.brawlstars.com")),
        ("hayday_website", "Hay Day", True, ("hayday.com", "www.hayday.com")),
        ("boombeach_website", "Boom Beach", True, ("boombeach.com", "www.boombeach.com", "boombeach.supercell.com")),
        ("moco_website", "mo.co", True, ("mo.co", "www.mo.co")),
        ("squadbusters_website", "Squad Busters", True, ("squadbusters.com", "www.squadbusters.com", "squadbusters.supercell.com")),
    )
]
WEBSITE_IDS = frozenset(signature["id"] for signature in _WEBSITE_SIGNATURES)
MONITOR_ONLY_IDS = LAUNCHER_IDS | WEBSITE_IDS
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
            "mlbb.io",
            "moonton.com",
            "moonton.net",
            "moontongame.com",
            "moontontech.com",
            "yuanzhanapp.com",
            "yuanzhan.com",
            "akmweb.youngjoygame.com",
            "viztagame.com",
            "bytegsdk.com",
            "orientalgame.com",
            "joygame.com",
        ),
        "domainKeywords": (
            "youngjoygame",
            "moonton",
            "yuanzhanapp",
            "mlbb.com",
            "mlbb.io",
            "viztagame",
            "orientalgame",
        ),
        "ports": (5508, 5551, 30090, 30091),
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
            "gcloudcs.com",
            "pubgmobile.com",
            "www.pubgmobile.com",
            "pubg.com",
            "krafton.com",
            "lightspeed-studios.com",
            "gameloop.com",
            "gcloud.qq.com",
        ),
        "domainKeywords": ("pubgmobile", "igamecj", "gcloudsdk", "gcloudcs", "lightspeed-studios", "gameloop"),
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
            "hok.qq.com",
            "pvp.qq.com",
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
        "domains": ("wildrift.leagueoflegends.com",),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "lol",
        "name": "League of Legends",
        "category": "PC MOBA · 5v5",
        "icon": "⚔️",
        "isMobile": False,
        "domains": (),
        "domainKeywords": (),
        "ports": (),
        "processes": ("League of Legends.exe",),
    },
    {
        "id": "runeterra",
        "name": "Legends of Runeterra",
        "category": "PC / Mobile Card Game",
        "icon": "🃏",
        "isMobile": True,
        "domains": ("playruneterra.com",),
        "domainKeywords": (),
        "ports": (),
        "processes": ("LoR.exe",),
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
            "dl.ff.garena.com",
            "ff.garenanow.com",
            "ggblueshark.com",
            "freefire.com",
        ),
        "domainKeywords": ("freefire", "ggblueshark", "ff.garena"),
        "ports": (39698, 39800),
        "processes": (),
    },
    {
        "id": "clashofclans",
        "name": "Clash of Clans",
        "category": "Mobile Strategy",
        "icon": "🛡️",
        "isMobile": True,
        "domains": ("clashofclans.com",),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "clashroyale",
        "name": "Clash Royale",
        "category": "Mobile Strategy",
        "icon": "🏰",
        "isMobile": True,
        "domains": ("game.clashroyaleapp.com", "clashroyaleapp.com", "clashroyale.com"),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "brawlstars",
        "name": "Brawl Stars",
        "category": "Mobile Arena Brawler",
        "icon": "⭐",
        "isMobile": True,
        "domains": ("brawlstarsgame.com", "brawlstars.com"),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "hayday",
        "name": "Hay Day",
        "category": "Mobile Farming",
        "icon": "🌾",
        "isMobile": True,
        "domains": ("hayday.com", "haydaygame.com"),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "boombeach",
        "name": "Boom Beach",
        "category": "Mobile / PC Strategy",
        "icon": "🏝️",
        "isMobile": True,
        "domains": ("boombeach.com",),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "moco",
        "name": "mo.co",
        "category": "Mobile Action",
        "icon": "👾",
        "isMobile": True,
        "domains": ("mo.co",),
        "domainKeywords": (),
        "ports": (),
        "processes": (),
    },
    {
        "id": "squadbusters",
        "name": "Squad Busters",
        "category": "Mobile Party Action",
        "icon": "💎",
        "isMobile": True,
        "domains": ("squadbusters.com",),
        "domainKeywords": (),
        "ports": (),
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
        "ports": (53640,),
        "processes": ("RobloxPlayerBeta.exe",),
    },
    {
        "id": "valorant",
        "name": "Valorant",
        "category": "PC Tactical FPS",
        "icon": "🎯",
        "isMobile": False,
        "domains": ("playvalorant.com", "valorant.com"),
        "domainKeywords": (),
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
        "processes": (
            "Minecraft.Windows.exe",
            "Minecraft.exe",
            "Lunar Client.exe",
            "Badlion Client.exe",
        ),
    },
    {
        "id": "fortnite",
        "name": "Fortnite (Epic Games)",
        "category": "PC / Mobile Battle Royale",
        "icon": "🪂",
        "isMobile": True,
        "domains": ("fortnite.com", "ol.epicgames.com", "epicgames.dev"),
        "domainKeywords": ("fortnite",),
        "ports": (5795, 5800),
        "processes": ("FortniteClient-Win64-Shipping.exe",),
    },
    {
        "id": "steam",
        "name": "Steam-related activity",
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
        "processes": ("dota2.exe", "cs2.exe", "ApexLegends.exe", "Overwatch.exe", "GTA5.exe"),
    },
    {
        "id": STEAM_CLIENT_ID,
        "name": "Steam Client",
        "category": "PC Launcher",
        "icon": "🎮",
        "isMobile": False,
        "domains": (),
        "domainKeywords": (),
        "ports": (),
        "processes": ("steam.exe",),
    },
    {
        "id": RIOT_CLIENT_ID,
        "name": "Riot Client",
        "category": "PC Launcher",
        "icon": "🎮",
        "isMobile": False,
        "domains": (),
        "domainKeywords": (),
        "ports": (),
        "processes": ("RiotClientServices.exe",),
    },
    *_WEBSITE_SIGNATURES,
]

ANDROID_GAME_PACKAGES = {
    "com.mobile.legends": "mlbb",
    "com.riotgames.league.wildrift": "wildrift",
    "com.roblox.client": "roblox",
    "com.supercell.clashofclans": "clashofclans",
    "com.supercell.clashroyale": "clashroyale",
    "com.supercell.brawlstars": "brawlstars",
    "com.supercell.hayday": "hayday",
    "com.supercell.boombeach": "boombeach",
    "com.supercell.moco": "moco",
    "com.supercell.squad": "squadbusters",
}

_DOH_CANARY_DOMAINS = (
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "doh.dns.apple.com",
    "canary.dns.nextdns.io",
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
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

SCAN_GAME_PORTS = (19132, 25565, 27015, 27036, 7500, 17500, 22101, 30090)
PORT_HINT_METHODS = frozenset({"Whole-Topology Port Scan", "Active Game Port Scan", "Auto LAN Game Port Sensor"})
DNS_CACHE_HINT_METHODS = frozenset({"Auto DNS Cache Sensor", "Topology Host DNS Cache Scan"})
_NETSTAT_GAME_PORTS = frozenset({
    5508, 5551, 30090, 30091, 7500, 7501, 10012,
    17500, 20001, 10010, 10011, 22101, 22102, 39698, 39800,
    3659, 17502, 8433, 22023, 8393, 8394, 5795, 5800,
    19132, 25565, 27015, 27036,
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

HOST_PROCESS_DETECTION = "Windows game process"
MANAGED_PROCESS_DETECTION = "Managed Windows game process"
ANDROID_APP_DETECTION = "Android foreground app"


def _game_hint_type(method: str) -> str | None:
    if method in {"Real-Time LAN Broadcast Listener", "Wireshark LAN Broadcast"}:
        return "lan_discovery"
    if method in PORT_HINT_METHODS:
        return "port"
    if method in DNS_CACHE_HINT_METHODS:
        return "dns_cache"
    if method.startswith(("Wireshark File (", "Wireshark Capture (")):
        return "capture_file"
    return None


def list_windows_processes(*, current_session_only: bool = False) -> list[str] | None:
    """Return a successful process snapshot, or None if Windows could not enumerate it."""
    if sys.platform != "win32":
        return None
    session_id = wintypes.DWORD()
    process_session = wintypes.DWORD()
    if current_session_only and not _kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
        return None
    snapshot = _kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        return None
    entry = _ProcessEntry()
    entry.dwSize = ctypes.sizeof(entry)
    names = []
    try:
        found = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if not current_session_only or (
                _kernel32.ProcessIdToSessionId(entry.th32ProcessID, ctypes.byref(process_session))
                and process_session.value == session_id.value
            ):
                names.append(entry.szExeFile)
            found = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return names if ctypes.get_last_error() == 18 else None  # ERROR_NO_MORE_FILES
    finally:
        _kernel32.CloseHandle(snapshot)


def host_game_processes(ip: str, processes: list[str]) -> dict[tuple[str, str], dict]:
    open_games = {}
    for name in processes:
        game = GameDetectorMixin._match_game_signature(process=name)
        if game is not None:
            open_games.setdefault((ip, game["id"]), {
                "ip": ip,
                "gameId": game["id"],
                "process": name,
                "matchedIndicator": f"Process {name}",
                "detectionMethod": HOST_PROCESS_DETECTION,
            })
    return open_games


class GameDetectorMixin:
    """Detects mobile/PC game launches from exact client DNS/syslog/port signals without guessing."""

    DNS_LISTENER_PORT = 5354
    SYSLOG_LISTENER_PORT = 5140
    HOST_DNS_IP = "192.168.0.224"
    _cached_dhcp_dns_val: list[str] = []
    _cached_dhcp_dns_ts = float("-inf")

    def _game_store(self) -> None:
        self = cast("Monitor", self)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS game_activity_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    player TEXT NOT NULL DEFAULT '',
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
                    is_dismissed INTEGER NOT NULL DEFAULT 0,
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
                    throttle_routers TEXT,
                    cut_routers TEXT,
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
            if "is_dismissed" not in cols:
                db.execute(
                    "ALTER TABLE game_activity_logs ADD COLUMN is_dismissed INTEGER NOT NULL DEFAULT 0"
                )
            if "player" not in cols:
                db.execute("ALTER TABLE game_activity_logs ADD COLUMN player TEXT NOT NULL DEFAULT ''")
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_game_activity_active ON game_activity_logs(ip, game_id, player) WHERE is_active=1"
            )
            blk_cols = {
                row["name"]
                for row in db.execute("PRAGMA table_info(game_block_rules)").fetchall()
            }
            if "cut_wifi" not in blk_cols:
                db.execute(
                    "ALTER TABLE game_block_rules ADD COLUMN cut_wifi INTEGER NOT NULL DEFAULT 1"
                )
            if "throttle_routers" not in blk_cols:
                db.execute("ALTER TABLE game_block_rules ADD COLUMN throttle_routers TEXT")
            if "cut_routers" not in blk_cols:
                db.execute("ALTER TABLE game_block_rules ADD COLUMN cut_routers TEXT")
            for column in ("control_plan", "control_status", "expires_at"):
                if column not in blk_cols:
                    db.execute(f"ALTER TABLE game_block_rules ADD COLUMN {column} TEXT")
        self._game_restriction_lock = threading.Lock()
        self._game_listeners_started = False
        self._game_endpoint_seen: dict[str, float] = {}
        self._gaming_sensor_telemetry: dict = {
            "lastSeenEpoch": 0.0,
            "lastSeen": None,
            "pid": None,
            "dnsHost": "",
            "dnsPort": 53,
            "hotspotIp": "",
            "syslogPort": 514,
            "dnsQueriesTotal": 0,
            "dnsBlockedTotal": 0,
            "dnsForwardedTotal": 0,
            "dnsForwardFailures": 0,
            "dnsClients": {},
            "lastDnsClientIp": "",
            "lastDnsDomain": "",
            "lastDnsAt": None,
            "wireshark": None,
            "wiresharkLastAnalyze": None,
        }

    def get_gaming_policy(self) -> dict:
        self = cast("Monitor", self)
        with self.lock:
            raw = dict(self.config.get("gaming") or {})
        mode = str(raw.get("preventionMode") or "alert_only").strip().lower()
        restrictions_enabled = os.environ.get("PULSE_ALLOW_NETWORK_CHANGES") == "1"
        if not restrictions_enabled or mode not in {"alert_only", "auto_block_game", "auto_wifi_cut"}:
            mode = "alert_only"
        try:
            stale_sec = max(20, min(600, int(raw.get("staleSessionSeconds") or 75)))
        except (TypeError, ValueError):
            stale_sec = 75
        return {
            "preventionMode": mode,
            "restrictionsEnabled": restrictions_enabled,
            "deviceControlsEnabled": True,
            "autoPreventEnabled": mode in {"auto_block_game", "auto_wifi_cut"},
            "autoCutWifi": mode == "auto_wifi_cut",
            "staleSessionSeconds": stale_sec,
        }

    def set_gaming_policy(self, payload: dict) -> dict:
        self = cast("Monitor", self)
        if not isinstance(payload, dict):
            raise ValueError("Invalid gaming policy payload")
        mode = str(payload.get("preventionMode") or "").strip().lower()
        if mode not in {"alert_only", "auto_block_game", "auto_wifi_cut"}:
            raise ValueError("preventionMode must be alert_only, auto_block_game, or auto_wifi_cut")
        if mode != "alert_only" and os.environ.get("PULSE_ALLOW_NETWORK_CHANGES") != "1":
            raise ValueError("Game restrictions are disabled in monitoring-only mode")
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
    def _detect_host_lan_ip(fallback: str = "192.168.0.224", gateway_ip: str = "192.168.0.1") -> str:
        now = time.monotonic()
        cached = getattr(GameDetectorMixin, "_cached_host_ip_val", None)
        cached_ts = getattr(GameDetectorMixin, "_cached_host_ip_ts", 0.0)
        if cached and (now - cached_ts) < 25.0:
            return cached
        for probe_ip in (gateway_ip or "192.168.0.1", "1.1.1.1"):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.25)
                    s.connect((probe_ip, 80))
                    ip = s.getsockname()[0]
                    if ip and not ip.startswith(("127.", "169.254.")):
                        GameDetectorMixin._cached_host_ip_val = ip
                        GameDetectorMixin._cached_host_ip_ts = now
                        return ip
            except OSError:
                continue
        return fallback

    @staticmethod
    def _detect_local_dhcp_dns() -> list[str]:
        if os.name != "nt":
            return []
        now = time.monotonic()
        cached = getattr(GameDetectorMixin, "_cached_dhcp_dns_val", None)
        cached_ts = getattr(GameDetectorMixin, "_cached_dhcp_dns_ts", 0.0)
        if cached is not None and (now - cached_ts) < 30.0:
            return list(cached)
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
        GameDetectorMixin._cached_dhcp_dns_val = list(servers)
        GameDetectorMixin._cached_dhcp_dns_ts = now
        return servers

    def record_gaming_sensor_heartbeat(self, payload: dict) -> dict:
        self = cast("Monitor", self)
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
            tel["dnsForwardingEnabled"] = payload.get("dnsForwardingEnabled") is True
            tel["hotspotIp"] = str(payload.get("hotspotIp") or "").strip()
            if payload.get("dnsQueriesTotal") is not None:
                tel["dnsQueriesTotal"] = int(payload["dnsQueriesTotal"])
            if payload.get("dnsBlockedTotal") is not None:
                tel["dnsBlockedTotal"] = int(payload["dnsBlockedTotal"])
            for key in ("dnsForwardedTotal", "dnsForwardFailures"):
                if payload.get(key) is not None:
                    tel[key] = int(payload[key])
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
            if isinstance(payload.get("wireshark"), dict):
                tel["wireshark"] = dict(payload["wireshark"])
        return {
            "success": True,
            "blocks": self.get_game_blocks(),
            "policy": self.get_gaming_policy(),
            "wireshark": self.get_wireshark_config(),
        }

    def get_wireshark_config(self) -> dict:
        self = cast("Monitor", self)
        with self.lock:
            gaming = dict(self.config.get("gaming") or {})
        raw = dict(gaming.get("wireshark") or {})
        selected = raw.get("selectedInterfaces")
        return {
            "enabled": True if raw.get("enabled") is None else bool(raw.get("enabled")),
            "selectedInterfaces": [str(x) for x in selected] if isinstance(selected, list) else None,
        }

    def set_wireshark_config(self, payload: dict) -> dict:
        self = cast("Monitor", self)
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        with self.lock:
            gaming = self.config.setdefault("gaming", {})
            ws = dict(gaming.get("wireshark") or {})
            if "enabled" in payload:
                ws["enabled"] = bool(payload["enabled"])
            if "selectedInterfaces" in payload:
                sel = payload["selectedInterfaces"]
                ws["selectedInterfaces"] = [str(x).strip() for x in sel if str(x).strip()] if isinstance(sel, list) else None
            gaming["wireshark"] = ws
            self.save_config()
        return {"success": True, "wiresharkStatus": self.get_wireshark_status()}

    def get_wireshark_status(self) -> dict:
        self = cast("Monitor", self)
        from .wireshark_capture import (
            PcapRingRecorder,
            build_wireshark_display_filter,
            find_wireshark_binaries,
            list_npcap_interfaces,
        )

        cfg = self.get_wireshark_config()
        with self.lock:
            tel = dict(self._gaming_sensor_telemetry)
        sensor_online = (time.time() - float(tel.get("lastSeenEpoch") or 0.0)) <= 12.0
        live_ws = dict(tel.get("wireshark") or {}) if isinstance(tel.get("wireshark"), dict) else {}
        last_analyze = tel.get("wiresharkLastAnalyze")

        if live_ws:
            bins = {
                "tsharkInstalled": bool(live_ws.get("tsharkInstalled")),
                "tsharkPath": live_ws.get("tsharkPath") or "",
                "dumpcapInstalled": bool(live_ws.get("dumpcapInstalled")),
                "wiresharkGuiInstalled": bool(live_ws.get("wiresharkGuiInstalled")),
                "npcapAvailable": bool(live_ws.get("npcapAvailable")),
            }
            ifaces = list(live_ws.get("interfaces") or [])
        else:
            in_test = getattr(self, "_skip_live_probe_in_test", False)
            bins = find_wireshark_binaries(os.environ.get("PULSE_TSHARK_PATH", ""))
            ifaces = [] if in_test else list_npcap_interfaces(
                bins.get("wpcapPath", ""), bins.get("tsharkPath", "")
            )

        pcap_path = self._data_dir() / "wireshark_live.pcap"
        try:
            pcap_bytes = int(pcap_path.stat().st_size) if pcap_path.exists() else len(PcapRingRecorder.GLOBAL_HEADER)
        except OSError:
            pcap_bytes = len(PcapRingRecorder.GLOBAL_HEADER)

        selected = (
            cfg.get("selectedInterfaces")
            if cfg.get("selectedInterfaces") is not None
            else list(live_ws.get("selectedInterfaces") or [x["name"] for x in ifaces if x.get("preferred")][:4])
        )
        engine_name = (
            live_ws.get("engine")
            or ("tshark" if bins.get("tsharkInstalled") else ("npcap-wpcap" if bins.get("npcapAvailable") else "offline-pcap"))
        )
        return {
            "enabled": bool(cfg.get("enabled", True)),
            "sensorCaptureEnabled": live_ws.get("enabled") if sensor_online else None,
            "active": bool(sensor_online and live_ws.get("active")),
            "activeInterfaceCount": live_ws.get("activeInterfaceCount") if sensor_online else 0,
            "sensorOnline": sensor_online,
            "engine": engine_name,
            "tsharkInstalled": bool(bins.get("tsharkInstalled")),
            "tsharkPath": str(bins.get("tsharkPath") or ""),
            "dumpcapInstalled": bool(bins.get("dumpcapInstalled")),
            "wiresharkGuiInstalled": bool(bins.get("wiresharkGuiInstalled")),
            "npcapAvailable": bool(bins.get("npcapAvailable")),
            "tzspActive": bool(sensor_online and live_ws.get("tzspActive")),
            "tzspPort": int(live_ws.get("tzspPort") or 37008),
            "interfaces": ifaces,
            "selectedInterfaces": selected,
            "packetsCaptured": int(live_ws.get("packetsCaptured") or 0),
            "packetsMatched": int(live_ws.get("packetsMatched") or 0),
            "dnsMatches": int(live_ws.get("dnsMatches") or 0),
            "tlsSniMatches": int(live_ws.get("tlsSniMatches") or 0),
            "httpMatches": int(live_ws.get("httpMatches") or 0),
            "portMatches": int(live_ws.get("portMatches") or 0),
            "pcapBytes": pcap_bytes,
            "pcapAvailable": pcap_bytes > len(PcapRingRecorder.GLOBAL_HEADER),
            "pcapUrl": "/api/gaming/wireshark/capture.pcap",
            "lastHitAt": live_ws.get("lastHitAt"),
            "recentHits": list(live_ws.get("recentHits") or []),
            "displayFilter": live_ws.get("displayFilter") or build_wireshark_display_filter(GAME_SIGNATURES),
            "lastAnalyze": last_analyze,
        }

    def get_wireshark_capture_bytes(self) -> bytes:
        self = cast("Monitor", self)
        from .wireshark_capture import PcapRingRecorder

        pcap_path = self._data_dir() / "wireshark_live.pcap"
        if pcap_path.is_file():
            try:
                data = pcap_path.read_bytes()
                if len(data) >= 24:
                    return data
            except OSError:
                pass
        return PcapRingRecorder.GLOBAL_HEADER

    def analyze_wireshark_capture(self, payload: dict) -> dict:
        self = cast("Monitor", self)
        import base64
        from .wireshark_capture import dissect_raw_packet, parse_pcap_or_pcapng

        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        b64_raw = str(payload.get("dataBase64") or "").strip()
        filename = str(payload.get("filename") or "capture.pcapng").strip()[:160]
        if not b64_raw:
            raise ValueError("Capture file payload (dataBase64) is required")
        if "," in b64_raw and b64_raw[:64].lower().startswith("data:"):
            b64_raw = b64_raw.split(",", 1)[1]
        try:
            raw_bytes = base64.b64decode(b64_raw, validate=False)
        except Exception as exc:
            raise ValueError("Invalid base64 capture payload") from exc

        frames = parse_pcap_or_pcapng(raw_bytes)
        seen_hits: set[tuple[str, str, str]] = set()
        hits: list[dict] = []
        matched_packets = 0

        for ts_epoch, dlt, frame in frames:
            res = dissect_raw_packet(
                frame,
                dlt=dlt,
                ts_epoch=ts_epoch,
                matcher=self._match_game_signature,
                game_ports=_NETSTAT_GAME_PORTS,
            )
            if not res:
                continue
            matched_packets += 1
            hit_key = (res["ip"], res["gameId"], res.get("matchedIndicator", ""))
            if hit_key not in seen_hits:
                seen_hits.add(hit_key)
                hits.append({
                    "timestamp": datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "ip": res["ip"],
                    "remoteIp": res.get("remoteIp", ""),
                    "gameId": res["gameId"],
                    "gameName": res["gameName"],
                    "protocol": res.get("protocol", ""),
                    "matchedIndicator": res.get("matchedIndicator", ""),
                    "detectionMethod": f"Wireshark File ({filename})",
                    "port": res.get("port"),
                    "domain": res.get("domain", ""),
                })

        summary = {
            "filename": filename,
            "analyzedAt": utc_now(),
            "packetsParsed": len(frames),
            "matchedPackets": matched_packets,
            "uniqueMatches": len(hits),
            "detectionsLogged": 0,
            "hits": hits[:80],
        }
        with self.lock:
            self._gaming_sensor_telemetry["wiresharkLastAnalyze"] = summary
        activity = self.get_game_activity(100)
        return {
            "success": True,
            **summary,
            "detections": [],
            "gameActivity": activity,
        }

    def _get_gaming_sensor_status(self) -> dict:
        self = cast("Monitor", self)
        with self.lock:
            tel = dict(self._gaming_sensor_telemetry)
            dns_clients = dict(tel.get("dnsClients") or {})
            router_cfg = dict(self.config.get("router") or {})

        in_test = getattr(self, "_skip_live_probe_in_test", False)
        host_ip = tel.get("dnsHost") or (
            self.HOST_DNS_IP if in_test else self._detect_host_lan_ip("127.0.0.1", router_cfg.get("ip") or "")
        )
        local_dns = [] if in_test else self._detect_local_dhcp_dns()
        sensor_online = (time.time() - float(tel.get("lastSeenEpoch") or 0.0)) <= 12.0
        non_self_clients = [
            ip for ip in dns_clients
            if ip not in {host_ip, tel.get("hotspotIp"), "127.0.0.1", "::1"}
        ]
        dns_intercept_ready = sensor_online and bool(non_self_clients)
        bypass_dns = [d for d in local_dns if d != host_ip]
        router_state = getattr(self, "router_state", {}) or {}
        return {
            "sensorOnline": sensor_online,
            "lastSeen": tel.get("lastSeen"),
            "dnsForwardingEnabled": bool(tel.get("dnsForwardingEnabled")),
            "dnsHost": host_ip,
            "dnsPort": int(tel.get("dnsPort") or 53),
            "hotspotIp": tel.get("hotspotIp") or "",
            "syslogPort": int(tel.get("syslogPort") or 514),
            "dnsQueriesTotal": int(tel.get("dnsQueriesTotal") or 0),
            "dnsBlockedTotal": int(tel.get("dnsBlockedTotal") or 0),
            "dnsForwardedTotal": int(tel.get("dnsForwardedTotal") or 0),
            "dnsForwardFailures": int(tel.get("dnsForwardFailures") or 0),
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
        self = cast("Monitor", self)
        if os.environ.get("PULSE_ALLOW_NETWORK_CHANGES") != "1":
            raise ValueError("Router DNS changes are disabled in monitoring-only mode")
        with self.lock:
            telemetry = self._gaming_sensor_telemetry
            sensor_dns_ready = telemetry.get("dnsForwardingEnabled") and time.time() - telemetry["lastSeenEpoch"] <= 12
        if not sensor_dns_ready:
            raise ValueError("The host sensor is not configured to forward DNS")
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
    def _domain_keyword_matches(keyword: str, domain: str) -> bool:
        """Match game keywords strictly on DNS label boundaries (never substring inside unrelated words)."""
        kw = str(keyword or "").strip().lower()
        if not kw or not domain:
            return False
        if kw.endswith("."):
            core = re.escape(kw.rstrip("."))
            return re.search(rf"(?:^|[.-]){core}\.", domain) is not None
        return re.search(rf"(?:^|[.-]){re.escape(kw)}(?:[.-]|$)", domain) is not None

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
                if g.get("exactDomainsOnly") and dom in g["domains"]:
                    return g
            for g in GAME_SIGNATURES:
                if not g.get("exactDomainsOnly") and any(dom == sig or dom.endswith(f".{sig}") for sig in g["domains"]):
                    return g
            for g in GAME_SIGNATURES:
                if any(GameDetectorMixin._domain_keyword_matches(kw, dom) for kw in g.get("domainKeywords", ())):
                    return g
        proc = str(process or "").strip().lower()
        if proc:
            for g in GAME_SIGNATURES:
                if any(proc == p.lower() for p in g.get("processes", ())):
                    return g
        if isinstance(port, (str, int, float)) and str(port).strip():
            try:
                pnum = int(port)
                for g in GAME_SIGNATURES:
                    if pnum in g["ports"]:
                        return g
            except (OverflowError, ValueError):
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
        reporter_ip: str = "",
        allow_live_name_probe: bool = False,
    ) -> dict:
        self = cast("Monitor", self)
        host_ip = self._reporting_host_ip()
        mon_dev = mon_by_ip.get(client_ip)
        if inv_row and mon_dev and mon_dev.get("mac") and mon_dev["mac"].lower() != inv_row["mac"].lower():
            mon_dev = None
        mac = observed_inventory_mac(
            str((mon_dev or {}).get("mac") or (inv_row or {}).get("mac") or "").lower(), client_ip,
        )
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
                if client_ip == host_ip and vendor == "LAN Client"
                else f"{hostname} ({vendor})"
            )
        elif client_ip == host_ip:
            device_name = f"Host Monitor PC ({client_ip})"
        else:
            device_name = f"{vendor} ({client_ip})"

        low_combo = f"{device_name} {vendor}".lower()
        is_mobile = bool(not mon_dev and any(tok in low_combo for tok in _MOBILE_HINT_TOKENS))
        if mon_dev:
            device_type = f"Office {str(mon_dev.get('type') or 'Device').upper()}"
        elif is_mobile:
            device_type = "Mobile Phone / Wi-Fi Device"
        elif client_ip == host_ip or any(tok in low_combo for tok in _PC_HINT_TOKENS):
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
        self = cast("Monitor", self)
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM discovered_devices WHERE ip=? AND is_online=1 ORDER BY last_seen DESC LIMIT 1",
                (client_ip,),
            ).fetchone()
            topo_nodes = [dict(r) for r in db.execute("SELECT * FROM topology_nodes").fetchall()]
            topo_links = [dict(r) for r in db.execute("SELECT * FROM topology_links").fetchall()]

        inv_row = dict(row) if row is not None else None
        mon_devices = self.get_devices()
        mon_by_ip = {str(d.get("ip") or ""): d for d in mon_devices if d.get("ip")}
        cached_hosts = (
            self._get_cached_hostnames({client_ip: inv_row["mac"]} if inv_row else {})
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
            reporter_ip=reporter_ip,
            allow_live_name_probe=True,
        )

    def record_game_detection(self, payload: dict, *, player: str = "", include_activity: bool = True) -> dict:
        """Record a verified device-level mobile/PC game detection, log event, raise alert, and push SSE."""
        self = cast("Monitor", self)
        if not isinstance(payload, dict):
            raise ValueError("Invalid game detection payload")
        raw_ip = str(
            payload.get("ip") or payload.get("clientIp") or payload.get("deviceIp") or ""
        ).strip()
        client_ip = validate_ip(raw_ip)
        method = str(payload.get("detectionMethod") or "Live DNS").strip()[:60]
        hint_type = _game_hint_type(method)
        if hint_type:
            return {"success": True, "detection": None, "portHint": hint_type == "port", "hintType": hint_type,
                    **({"gameActivity": self.get_game_activity(60)} if include_activity else {})}
        reporter_ip = str(payload.get("reporterIp") or payload.get("routerIp") or "").strip()
        game = self._match_game_signature(
            game_id=payload.get("gameId", ""),
            domain=payload.get("domain", ""),
            port=payload.get("port"),
            process=payload.get("process", ""),
        )
        if game is None:
            raise ValueError("Specify a recognized game, game domain, process, or game port")
        launcher = game["id"] in LAUNCHER_IDS
        website = game["id"] in WEBSITE_IDS
        monitor_only = game["id"] in MONITOR_ONLY_IDS
        domain = str(payload.get("domain") or "").strip().lower().rstrip(".")
        if website and domain not in game["domains"]:
            raise ValueError(f"{game['name']} activity requires a matching website hostname")
        process_name = str(payload.get("process") or "").strip()
        if launcher:
            expected_process = game["processes"][0]
            if (
                method not in {HOST_PROCESS_DETECTION, MANAGED_PROCESS_DETECTION}
                or process_name.lower() != expected_process.lower()
            ):
                raise ValueError(f"{game['name']} requires a Windows {expected_process} process report")
            method = "Managed Windows client process" if method == MANAGED_PROCESS_DETECTION else "Windows client process"

        ctx = self._resolve_game_client_context(client_ip, reporter_ip)
        if str(payload.get("deviceName") or "").strip():
            ctx["deviceName"] = str(payload["deviceName"]).strip()[:120]
        if str(payload.get("connectedTo") or "").strip():
            ctx["connectedTo"] = str(payload["connectedTo"]).strip()[:140]

        indicator = f"Process {expected_process}" if launcher else (
            str(
                payload.get("matchedIndicator")
                or payload.get("domain")
                or payload.get("process")
                or ""
            ).strip()
            or (f"Port {payload['port']}" if payload.get("port") else "")
            or next(iter(game["domains"]), game["name"])
        )[:120]
        self.expire_stale_game_sessions()
        now = utc_now()
        policy = self.get_gaming_policy()

        if not monitor_only and self._match_active_block_rule(client_ip, game["id"]) is not None:
            with self._connect() as db:
                latest_blk = db.execute(
                    "SELECT id FROM game_activity_logs WHERE ip=? AND game_id=? ORDER BY timestamp DESC LIMIT 1",
                    (client_ip, game["id"]),
                ).fetchone()
                if latest_blk is not None:
                    db.execute(
                        """UPDATE game_activity_logs
                           SET is_active=0, is_blocked=1, timestamp=?, matched_indicator=?, detection_method=?
                           WHERE id=?""",
                        (now, indicator, method, latest_blk["id"]),
                    )
            return {
                "success": True,
                "blocked": True,
                "autoPrevented": bool(payload.get("autoPrevented")),
                "detection": None,
                **({"gameActivity": self.get_game_activity(60)} if include_activity else {}),
            }

        existing_row = None
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT * FROM game_activity_logs
                   WHERE ip=? AND game_id=? AND is_active=1
                     AND (player=? OR player='' OR ?='')
                   ORDER BY (player=?) DESC, timestamp DESC LIMIT 1""",
                (client_ip, game["id"], player, player, player),
            ).fetchone()
            if row and not _game_hint_type(row["detection_method"]):
                try:
                    prev_dt = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
                    now_dt = datetime.now(timezone.utc)
                    if (now_dt - prev_dt).total_seconds() < policy["staleSessionSeconds"]:
                        existing_row = dict(row)
                except ValueError:
                    pass

            if existing_row and method == ANDROID_APP_DETECTION and existing_row["detection_method"] != method:
                # Start a new confirmed detection so a preceding network signal cannot consume its alert.
                db.execute("UPDATE game_activity_logs SET is_active=0 WHERE id=?", (existing_row["id"],))
                existing_row = None

            if existing_row is not None:
                session_id = existing_row["id"]
                if (existing_row["player"] and not player) or (
                    existing_row["detection_method"] == ANDROID_APP_DETECTION and method != ANDROID_APP_DETECTION
                ):
                    # Network traffic cannot keep a directly observed app open.
                    db.commit()
                    return {
                        "success": True, "detection": None,
                        **({"gameActivity": self.get_game_activity(60)} if include_activity else {}),
                    }
                if existing_row["detection_method"] == HOST_PROCESS_DETECTION and method != HOST_PROCESS_DETECTION:
                    method = existing_row["detection_method"]
                    indicator = existing_row["matched_indicator"]
                db.execute(
                    """UPDATE game_activity_logs
                       SET timestamp=?, player=?, mac=?, device_name=?, vendor=?, device_type=?,
                           connected_to=?, router_ip=?, zone_label=?, matched_indicator=?, detection_method=?
                       WHERE id=?""",
                    (
                        now,
                        player,
                        ctx["mac"],
                        ctx["deviceName"],
                        ctx["vendor"],
                        ctx["deviceType"],
                        ctx["connectedTo"],
                        ctx["routerIp"],
                        ctx["zoneLabel"],
                        indicator,
                        method,
                        session_id,
                    ),
                )
            else:
                session_id = f"game-{uuid.uuid4().hex[:10]}"
                db.execute(
                    """INSERT INTO game_activity_logs
                       (id, timestamp, ip, player, mac, device_name, vendor, device_type,
                        game_id, game_name, game_category, game_icon,
                        connected_to, router_ip, zone_label, matched_indicator, detection_method, is_active)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        session_id,
                        now,
                        client_ip,
                        player,
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

        dismissed = bool(existing_row and existing_row["is_dismissed"])
        if existing_row and player and not existing_row["player"] and not dismissed:
            previous_key = self._game_alert_key(client_ip, game["id"], "")
            player_key = self._game_alert_key(client_ip, game["id"], player)
            with self.lock:
                existing_alert = self.active_alerts.pop(previous_key, None)
                if existing_alert is not None:
                    self.active_alerts[player_key] = {**existing_alert, "key": player_key}
                for alert in self.config.get("alerts", []):
                    if alert.get("key") == previous_key:
                        alert["key"] = player_key
                if existing_alert is not None:
                    self.save_config()
        entry = {
            "id": session_id,
            "timestamp": now,
            "ip": client_ip,
            "player": player,
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
            "isActive": not dismissed,
            "isDismissed": dismissed,
            "isBlocked": False,
        }

        if not monitor_only and policy["autoPreventEnabled"] and not payload.get("skipAutoPrevent"):
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

        if existing_row is None:
            self.broadcast("game_detected", {"detection": entry})
            evidence = "running" if launcher else "observed" if website else (
                "opened" if process_name or method == ANDROID_APP_DETECTION else "traffic detected"
            )
            title = f"{game['icon']} {game['name']} {evidence} on {ctx['deviceName']}"
            msg = (
                f"{game['name']} {evidence} on {ctx['deviceName']} ({client_ip}). "
                f"Observed via {indicator}."
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
            alert_key = self._game_alert_key(client_ip, game["id"], player)
            alert = self._make_alert(alert_key, "INFO", title, msg, client_ip, 443)
            alert.update({
                "type": "GAME_DETECTED",
                "category": "gaming",
                "errorCode": f"GAME_{game['id'].upper()}",
                "target": f"{ctx['deviceName']} → {ctx['connectedTo']}",
                "deviceName": ctx["deviceName"],
                "gameName": game["name"],
                "connectedTo": ctx["connectedTo"],
                "likelyFault": f"{game['name']} {evidence} ({method})",
                "rootCause": f"Observed {indicator} on {ctx['deviceName']} ({ctx['deviceType']}).",
                "remediation": [
                    f"Connected access point / router: {ctx['connectedTo']}",
                    f"Zone: {ctx['zoneLabel']}",
                    "Informational notification for the observed activity.",
                ],
            })
            with self.lock:
                self.active_alerts[alert_key] = alert
            self.save_alert(alert)
            self.broadcast("new_alert", alert)

        elif not dismissed:
            self.broadcast("game_detected", {"detection": entry, "updated": True})
        return {
            "success": True,
            "detection": None if dismissed else entry,
            **({"gameActivity": self.get_game_activity(60)} if include_activity else {}),
        }

    @staticmethod
    def _game_alert_key(ip: str, game_id: str, player: str) -> str:
        return f"game-{ip}-{game_id}" + (f"-{player}" if player else "")

    def expire_stale_game_sessions(self, max_idle_seconds: int | None = None) -> int:
        """Automatically end active game sessions when no traffic/process heartbeat was seen recently."""
        self = cast("Monitor", self)
        idle_limit = (
            int(max_idle_seconds)
            if max_idle_seconds is not None
            else self.get_gaming_policy()["staleSessionSeconds"]
        )
        now_dt = datetime.now(timezone.utc)
        expired_ids: list[str] = []
        expired_keys: set[str] = set()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT id, ip, game_id, player, timestamp FROM game_activity_logs WHERE is_active=1"
            ).fetchall()
            for r in rows:
                try:
                    prev_dt = datetime.fromisoformat(str(r["timestamp"]).replace("Z", "+00:00"))
                    if (now_dt - prev_dt).total_seconds() >= idle_limit:
                        expired_ids.append(r["id"])
                        expired_keys.add(self._game_alert_key(r["ip"], r["game_id"], r["player"]))
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
        if expired_ids:
            self.broadcast("game_detected", {"endedSessionIds": expired_ids})
        return len(expired_ids)

    def mark_game_session_ended_by_ip_game(
        self, client_ip: str, game_id: str, *, player: str = "", include_activity: bool = True, detection_method: str = ""
    ) -> dict:
        """Immediately mark active sessions ended when the host sensor detects a game process closed."""
        self = cast("Monitor", self)
        ip = validate_ip(client_ip)
        raw_gid = str(game_id or "").strip().lower()
        gid = _GAME_ID_ALIASES.get(raw_gid, raw_gid)
        if not gid:
            raise ValueError("Game id is required")
        with self._connect() as db:
            cur = db.execute(
                """UPDATE game_activity_logs SET is_active=0 WHERE ip=? AND game_id=? AND player=? AND is_active=1
                   AND (?='' OR detection_method=?)""",
                (ip, gid, player, detection_method, detection_method),
            )
            changed = int(cur.rowcount or 0) > 0
        if not changed:
            return {"success": True, "changed": False, **({"gameActivity": self.get_game_activity(100)} if include_activity else {})}
        alert_key = self._game_alert_key(ip, gid, player)
        with self.lock:
            self.active_alerts.pop(alert_key, None)
            self.config["alerts"] = [
                a for a in self.config.get("alerts", []) if a.get("key") != alert_key
            ]
            self.save_config()
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": True, **({"gameActivity": activity} if include_activity else {})}

    def report_android_game_activity(self, payload: dict) -> dict:
        ip = validate_ip(payload.get("ip"))
        if not self._is_real_lan_client_ip(ip):
            raise ValueError("The Android phone must be on a monitored LAN subnet")
        package = str(payload.get("package") or "")
        game_id = ANDROID_GAME_PACKAGES.get(package)
        if game_id is None:
            raise ValueError("Unrecognized Android game package")
        if payload.get("ended") is True:
            return self.mark_game_session_ended_by_ip_game(
                ip, game_id, include_activity=False, detection_method=ANDROID_APP_DETECTION,
            )
        return self.record_game_detection({
            "ip": ip,
            "gameId": game_id,
            "matchedIndicator": f"Android app {package}",
            "detectionMethod": ANDROID_APP_DETECTION,
            "skipAutoPrevent": True,
        }, include_activity=False)

    def _reporting_host_ip(self) -> str:
        tel = self._gaming_sensor_telemetry
        if time.time() - float(tel.get("lastSeenEpoch") or 0) <= 12:
            return str(tel.get("dnsHost") or "")
        return self.HOST_DNS_IP if getattr(self, "_skip_live_probe_in_test", False) else ""

    def _build_online_game_devices(self, active_logs: list[dict], blocks: list[dict]) -> list[dict]:
        """Build automatic list of currently online client devices (phones, tablets, PCs) with live game state."""
        self = cast("Monitor", self)
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
                    "SELECT * FROM discovered_devices WHERE is_online=1 ORDER BY ip"
                ).fetchall()
            ]
            topo_nodes = [dict(r) for r in db.execute("SELECT * FROM topology_nodes").fetchall()]
            topo_links = [dict(r) for r in db.execute("SELECT * FROM topology_links").fetchall()]

        inv_by_ip = {str(r.get("ip") or ""): r for r in inv_rows if r.get("ip")}
        cached_hosts = (
            self._get_cached_hostnames({ip: row["mac"] for ip, row in inv_by_ip.items()})
            if hasattr(self, "_get_cached_hostnames")
            else {}
        )
        node_by_id = {n["id"]: n for n in topo_nodes}
        topo_by_ip = {str(n.get("ip") or ""): n for n in topo_nodes if n.get("ip")}

        candidate_ips: list[str] = []
        seen_ips: set[str] = set()

        def _add_candidate(ip_val: str) -> None:
            ip_s = str(ip_val or "").strip()
            if (
                not ip_s
                or ip_s in seen_ips
                or ip_s in infra_ips
                or ip_s.startswith("127.")
            ):
                return
            seen_ips.add(ip_s)
            candidate_ips.append(ip_s)

        games_by_ip: dict[str, list[dict]] = {}
        for log in active_logs:
            _add_candidate(log.get("ip", ""))
            games_by_ip.setdefault(log["ip"], []).append(log)
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
            probe = self.latest_devices.get(dev["ip"], {})
            if probe.get("directlyReachable"):
                _add_candidate(dev["ip"])
        _add_candidate(self._reporting_host_ip())

        online_devices: list[dict] = []
        for ip in candidate_ips:
            ctx = self._assemble_client_context(
                client_ip=ip,
                mon_by_ip=mon_by_ip,
                inv_row=inv_by_ip.get(ip),
                cached_hosts=cached_hosts,
                topo_by_ip=topo_by_ip,
                node_by_id=node_by_id,
                topo_links=topo_links,
                allow_live_name_probe=False,
            )
            dev_active = [
                {
                    "id": x["id"],
                    "gameId": x["gameId"],
                    "gameName": x["gameName"],
                    "player": x["player"],
                    "gameIcon": x["gameIcon"],
                    "matchedIndicator": x["matchedIndicator"],
                    "detectionMethod": x["detectionMethod"],
                    "timestamp": x["timestamp"],
                }
                for x in games_by_ip.get(ip, [])
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

    def note_game_endpoint(self, ip: str) -> None:
        self = cast("Monitor", self)
        with self.lock:
            self._game_endpoint_seen[validate_ip(ip)] = time.monotonic()

    def _get_game_coverage(self, sensor_status: dict) -> dict:
        self = cast("Monitor", self)
        with self.lock:
            cutoff = time.monotonic() - 90
            for ip in [ip for ip, seen in self._game_endpoint_seen.items() if seen < cutoff]:
                del self._game_endpoint_seen[ip]
            endpoints = sorted(self._game_endpoint_seen)
            dns_clients = dict(self._gaming_sensor_telemetry.get("dnsClients") or {})
        recent_dns = []
        now = datetime.now(timezone.utc)
        dns_cutoff = now - timedelta(seconds=90)
        local_ips = {sensor_status["dnsHost"], sensor_status["hotspotIp"], "127.0.0.1", "::1"}
        if sensor_status["sensorOnline"]:
            for ip, observed_at in dns_clients.items():
                if ip in local_ips:
                    continue
                try:
                    stamp = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                    if stamp.tzinfo is not None and dns_cutoff <= stamp <= now:
                        recent_dns.append(validate_ip(ip))
                except ValueError:
                    continue
        return {
            **self.get_discovery_coverage(),
            "endpointIps": endpoints,
            "recentDnsIps": sorted(set(recent_dns)),
            "endpointEnrollmentEnabled": bool(os.environ.get("PULSE_GAME_ENDPOINT_TOKEN")),
        }

    def get_game_activity(self, limit: int = 100) -> dict:
        self = cast("Monitor", self)
        self.expire_stale_game_sessions()
        policy = self.get_gaming_policy()
        sensor_status = self._get_gaming_sensor_status()
        limit = max(1, min(int(limit), 300))
        with self._connect() as db:
            rows = db.execute(
                """SELECT * FROM game_activity_logs WHERE is_active=1 AND is_dismissed=0
                   UNION ALL SELECT * FROM (
                       SELECT * FROM game_activity_logs ORDER BY timestamp DESC LIMIT ?
                   ) WHERE is_active=0 OR is_dismissed=1 ORDER BY timestamp DESC""",
                (limit,),
            ).fetchall()

        logs = []
        for r in rows:
            hint_type = _game_hint_type(r["detection_method"])
            logs.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "ip": r["ip"],
                "player": r["player"],
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
                "isActive": bool(r["is_active"] and not r["is_dismissed"] and not hint_type),
                "portHint": hint_type == "port",
                "hintType": hint_type,
                "isDismissed": bool(r["is_dismissed"]),
                "isBlocked": bool(r["is_blocked"]) if "is_blocked" in r.keys() else False,
            })
            if hint_type == "lan_discovery":
                logs[-1].update(mac="", deviceName="Unverified device", vendor="", deviceType="",
                                connectedTo="", routerIp="")
        blocks = self.get_game_blocks()
        active_logs = [x for x in logs if x["isActive"]]
        online_devices = self._build_online_game_devices(
            active_logs, [rule for rule in blocks if not rule["controlStatus"] or rule["controlStatus"] == "active"]
        )
        game_counts: dict[str, int] = {}
        zone_counts: dict[str, int] = {}
        for item in logs:
            if item["hintType"]:
                continue
            game_counts[item["gameName"]] = game_counts.get(item["gameName"], 0) + 1
            if item["connectedTo"]:
                zone_counts[item["connectedTo"]] = zone_counts.get(item["connectedTo"], 0) + 1

        top_game = max(game_counts, key=game_counts.__getitem__) if game_counts else "None yet"
        top_zone = max(zone_counts, key=zone_counts.__getitem__) if zone_counts else "No traffic yet"
        catalog = [
            {
                "id": g["id"],
                "name": g["name"],
                "category": g["category"],
                "icon": g["icon"],
                "isMobile": bool(g.get("isMobile")),
                "hasWindowsProcess": bool(g["processes"]),
                "hasAndroidPackage": g["id"] in ANDROID_GAME_PACKAGES.values(),
                "domains": list(g["domains"]),
                "ports": list(g["ports"]),
            }
            for g in GAME_SIGNATURES
        ]
        return {
            "logs": logs,
            "blocks": blocks,
            "onlineDevices": online_devices,
            "autoScanActive": os.environ.get("PULSE_ENABLE_BACKGROUND_SCANS") == "1",
            "policy": policy,
            "sensorStatus": sensor_status,
            "coverage": self._get_game_coverage(sensor_status),
            "wiresharkStatus": self.get_wireshark_status(),
            "summary": {
                "activeCount": len(active_logs),
                "blockedCount": len(blocks),
                "totalCount": sum(not item["hintType"] for item in logs),
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
        self = cast("Monitor", self)
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
                "throttleRouters": json.loads(r["throttle_routers"]) if r["throttle_routers"] else [],
                "cutRouters": json.loads(r["cut_routers"]) if r["cut_routers"] else [],
                "controlStatus": r["control_status"],
                "expiresAt": r["expires_at"],
                "limitsKbps": json.loads(r["control_plan"]).get("limitsKbps") if r["control_plan"] else None,
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
        """Decide whether a DNS query from client_ip must be sinkholed immediately to 0.0.0.0."""
        if matched_sig and matched_sig["id"] in MONITOR_ONLY_IDS:
            matched_sig = None
        gid = matched_sig["id"] if matched_sig else ""
        is_captive = GameDetectorMixin._is_wifi_captive_domain(qname)
        for rule in active_blocks:
            if rule.get("controlStatus"):
                continue
            r_ip = str(rule.get("ip") or "")
            r_gid = str(rule.get("gameId") or "")
            r_scope = str(rule.get("scope") or "")
            if r_ip == client_ip:
                if r_scope == "device_throttle" or rule.get("cutRouters"):
                    continue
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
        rules_enabled = os.environ.get("PULSE_ALLOW_NETWORK_CHANGES") == "1"
        for rule in self.get_game_blocks():
            if rule.get("controlStatus"):
                continue
            if not rules_enabled and not (rule.get("throttleRouters") or rule.get("cutRouters")):
                continue
            if rule["ip"] in (client_ip, "*") and (
                rule["gameId"] in (game_id, "*")
                or rule.get("scope") in {"device_all_games", "device_wifi_cut", "device_throttle"}
            ):
                return rule
        return None

    def _enforce_router_client_block(
        self,
        ip: str,
        mac: str,
        device_name: str,
        router_ip: str,
        block: bool,
        mode: str = "cut",
        router_targets: list[str] | None = None,
    ) -> list[str]:
        """Best-effort TP-Link LuCI QoS bandwidth throttle (1 KB/s) or MAC access-control block/unblock."""
        self = cast("Monitor", self)
        clean_mac = str(mac or "").strip().upper().replace("-", ":")
        if ip == "*" or not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", clean_mac) or getattr(self, "_skip_live_probe_in_test", False):
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
        if router_targets is not None:
            targets = [
                cfg for cfg in configs
                if cfg.get("ip") in router_targets and str(cfg.get("stok") or "").strip()
            ]
        elif mode == "throttle" and block:
            targets.sort(key=lambda cfg: cfg.get("ip") != router_ip)
        elif not targets:
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
            if mode == "throttle":
                endpoints = (
                    (
                        f"/cgi-bin/luci/;stok={encoded_stok}/admin/qos?form=device_list",
                        urllib.parse.urlencode({
                            "operation": "update" if block else "remove",
                            "key": mac_dash,
                            "mac": mac_dash,
                            "ip": ip,
                            "name": str(device_name or ip)[:32],
                            "enable": "on" if block else "off",
                            "up_band": "1" if block else "0",
                            "down_band": "1" if block else "0",
                            "up_unit": "KB/s",
                            "down_unit": "KB/s",
                        }).encode("utf-8"),
                    ),
                    (
                        f"/cgi-bin/luci/;stok={encoded_stok}/admin/qos?form=device_list",
                        urllib.parse.urlencode({
                            "operation": "insert" if block else "remove",
                            "mac": mac_dash,
                            "ip": ip,
                            "name": str(device_name or ip)[:32],
                            "enable": "on" if block else "off",
                            "up_band": "1" if block else "0",
                            "down_band": "1" if block else "0",
                            "up_unit": "KB/s",
                            "down_unit": "KB/s",
                        }).encode("utf-8"),
                    ),
                )
            else:
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
                    reply = json.loads(raw)
                    if isinstance(reply, dict) and reply.get("success") is True:
                        enforced.append(r_host)
                        break
                except Exception:
                    continue
            if mode == "throttle" and block and enforced:
                break
        return enforced

    def block_game_session(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Invalid block request payload")
        router_only = payload.get("routerOnly") is True or os.environ.get("PULSE_ALLOW_NETWORK_CHANGES") != "1"
        if router_only and (payload.get("scope") not in ("device_throttle", "device_wifi_cut") or payload.get("autoPrevented")):
            raise ValueError("Select a per-device throttle or disconnect from a current game detection")
        with self._game_restriction_lock:
            return self._block_game_session(payload, router_only=router_only)

    def _validate_device_control_target(self, ip: str, mac: str, observed_mac: str) -> None:
        self = cast("Monitor", self)
        if not mac or mac != observed_mac:
            raise ValueError("The selected detection needs a confirmed device MAC. Refresh LAN inventory and wait for a new detection.")
        infrastructure = set(self._known_local_gateways())
        infrastructure.update(
            d["ip"] for d in self.get_devices()
            if str(d.get("type") or "").lower() in {"ap", "gateway", "router", "switch", "firewall"}
        )
        infrastructure.update(str(cfg.get("ip") or "") for cfg in self._resolve_router_configs())
        sensor = self._get_gaming_sensor_status()
        infrastructure.update(ip for ip in (sensor.get("dnsHost"), sensor.get("hotspotIp")) if isinstance(ip, str))
        if ip in infrastructure or not self._is_real_lan_client_ip(ip):
            raise ValueError("Device controls require an individual client on a monitored LAN.")

    def _manual_game_router(self, ip: str) -> RouterGameControl | None:
        self = cast("Monitor", self)
        if getattr(self, "_skip_live_probe_in_test", False):
            return None
        for cfg in self._resolve_router_configs():
            if cfg.get("ip") == ip and str(cfg.get("stok") or "").strip():
                return RouterGameControl(cfg, self._luci_post)
        return None

    @staticmethod
    def _game_control_number(value: object, label: str, low: int, high: int) -> int:
        text = str(value)
        if not re.fullmatch(r"[0-9]{1,7}", text) or not low <= int(text) <= high:
            raise ValueError(f"{label} must be between {low} and {high}.")
        return int(text)

    def block_gateway_device(self, payload: dict) -> dict:
        self = cast("Monitor", self)
        ip = validate_ip(payload.get("ip"))
        mac = normalize_mac(payload.get("mac"))
        with self._game_restriction_lock:
            self._validate_device_control_target(ip, mac, mac)
            local_ip = self._detect_host_lan_ip("", gateway_ip=ip)
            if not local_ip or local_ip == ip:
                raise ValueError("Device access controls require a client other than the monitoring PC.")
            gateway = str(self.config["router"]["ip"])
            if self.router_state.get("ip") != gateway or self.router_state.get("routerClientSource") != "router":
                return {"success": False, "error": "Connect the main router admin session and refresh its client list."}
            client = next((row for row in self.router_state.get("routerClients", [])
                           if row["ip"] == ip and row["mac"] == mac), None)
            if client is None:
                raise ValueError("The client is no longer in the main router's client list.")
            return self._apply_manual_game_control(payload, ip, mac, client["name"], "device_wifi_cut", gateway)

    def restore_gateway_device(self, rule_id: object) -> dict:
        self = cast("Monitor", self)
        with self._game_restriction_lock:
            with self._connect() as db:
                rule = db.execute(
                    """SELECT * FROM game_block_rules WHERE id=? AND active=1
                       AND scope='device_wifi_cut' AND control_plan IS NOT NULL""",
                    (str(rule_id or ""),),
                ).fetchone()
            if rule is None:
                raise ValueError("Device access rule not found")
            return self._restore_manual_game_control(dict(rule))

    def _apply_manual_game_control(
        self, payload: dict, ip: str, mac: str, name: str, scope: str, gateway: str | None = None,
    ) -> dict:
        self = cast("Monitor", self)
        mode = "throttle" if scope == "device_throttle" else "cut"
        duration = self._game_control_number(payload.get("durationMinutes", 15), "Duration in minutes", 1, 240)
        limits = None
        if mode == "throttle":
            limits = {
                "download": self._game_control_number(payload.get("downloadKbps", 512), "Download Kbps", 8, 1_000_000),
                "upload": self._game_control_number(payload.get("uploadKbps", 256), "Upload Kbps", 8, 1_000_000),
            }
        with self._connect() as db:
            existing = db.execute(
                "SELECT id FROM game_block_rules WHERE active=1 AND (ip=? OR mac=?) AND scope IN ('device_throttle', 'device_wifi_cut')",
                (ip, mac),
            ).fetchone()
        if existing:
            raise ValueError("Restore the existing device restriction before applying a new one.")
        gateway = gateway or str(self.config.get("router", {}).get("ip") or "192.168.0.1")
        router = self._manual_game_router(gateway)
        wire_mac = mac.upper().replace(":", "-")
        before = router.read(mode, wire_mac) if router and router.has_client(ip, wire_mac) else None
        if router is None or before is None:
            hint = "Sign in under Router Settings. The main router must confirm this client and expose its bandwidth limit or an enabled deny list."
            return {"success": False, "scope": scope, "routerEnforced": [],
                    "enforcementDetails": {"requiresSetup": True, "setupHint": hint, "layers": []}}
        if before.get("present") or before.get("enable") == "on":
            raise ValueError("The router already has a restriction on this device. Review it in the router before continuing.")

        rule_id = f"gblk-{uuid.uuid4().hex[:10]}"
        plan = {"gateway": gateway, "mode": mode, "mac": wire_mac, "before": before,
                "name": f"Pulse {rule_id[5:]}", "limitsKbps": limits}
        label = "Block device access"
        if limits:
            after = {**before, "enable": "on"}
            for direction, field in (("upload", "up"), ("download", "down")):
                value = limits[direction]
                if before[f"{field}_unit"] == "KB/s":
                    if value % 8:
                        raise ValueError("This router uses KB/s. Enter limits divisible by 8 Kbps.")
                    value //= 8
                after[f"{field}_band"] = str(value)
            plan["after"] = after
            label = f"{limits['download']} Kbps down / {limits['upload']} Kbps up"
        expires = (datetime.now(timezone.utc) + timedelta(minutes=duration)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        # Journal the original state before changing the router so restart can recover an interrupted write.
        with self._connect() as db:
            db.execute(
                """INSERT INTO game_block_rules
                   (id, created_at, ip, mac, device_name, game_name, scope, cut_wifi, control_plan, control_status, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'applying', ?)""",
                (rule_id, utc_now(), ip, mac, name, label, scope, mode == "cut", json.dumps(plan), expires),
            )
        confirmed = router.change(plan)
        throttle = json.dumps([gateway]) if confirmed and limits else None
        cut = json.dumps([gateway]) if confirmed and not limits else None
        with self._connect() as db:
            db.execute(
                "UPDATE game_block_rules SET control_status=?, throttle_routers=?, cut_routers=? WHERE id=?",
                ("active" if confirmed else "restore_pending", throttle, cut, rule_id),
            )
        self._record_event(
            "GAME_BLOCKED" if confirmed else "GAME_CONTROL_UNVERIFIED", "WARNING",
            label if confirmed else "Device restriction could not be verified",
            f"Router {gateway}: {label} for {name} ({ip}). " +
            (f"Restoration due {expires}." if confirmed else "Pulse will verify restoration."),
            mac=mac, ip=ip, device_name=name,
        )
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": confirmed, "scope": scope, "ruleId": rule_id, "gameActivity": activity,
                "routerEnforced": [gateway] if confirmed else [], "expiresAt": expires,
                "enforcementDetails": {"requiresSetup": not confirmed, "layers": [label] if confirmed else [],
                                       "setupHint": "The router did not confirm the change. Pulse will retry restoration." if not confirmed else ""}}

    def _restore_manual_game_control(self, rule: dict) -> dict:
        self = cast("Monitor", self)
        plan = json.loads(rule["control_plan"])
        router = self._manual_game_router(plan["gateway"])
        restored = router is not None and router.change(plan, restore=True)
        with self._connect() as db:
            if restored:
                db.execute("DELETE FROM game_block_rules WHERE id=?", (rule["id"],))
            else:
                db.execute("UPDATE game_block_rules SET control_status='restore_pending' WHERE id=?", (rule["id"],))
        if restored:
            self._record_event("GAME_UNBLOCKED", "INFO", "Device access restored",
                               f"Router {plan['gateway']} confirmed restoration for {rule['device_name']}.",
                               mac=rule["mac"], ip=rule["ip"], device_name=rule["device_name"])
        elif rule["control_status"] == "restore_pending":
            return {"success": False, "error": "Router restoration is still unverified. Pulse will retry."}
        activity = self.get_game_activity(100)
        self.broadcast("game_detected", {"gameActivity": activity})
        return {"success": restored, "gameActivity": activity,
                **({} if restored else {"error": "The router did not confirm restoration. Pulse will retry."})}

    def _game_control_expiry_loop(self) -> None:
        self = cast("Monitor", self)
        while not self._stop.is_set():
            try:
                with self._game_restriction_lock:
                    with self._connect() as db:
                        rows = db.execute(
                            """SELECT * FROM game_block_rules WHERE active=1 AND control_plan IS NOT NULL
                               AND (control_status IN ('applying', 'restore_pending') OR expires_at<=?)""",
                            (utc_now(),),
                        ).fetchall()
                    for row in rows:
                        self._restore_manual_game_control(dict(row))
            except Exception as exc:
                print(f"[monitor] Device restoration retry: {exc}", flush=True)
            self._stop.wait(15)

    def _block_game_session(self, payload: dict, *, router_only: bool) -> dict:
        """Apply a device restriction through router QoS, router access control, or game DNS rules."""
        self = cast("Monitor", self)
        if not isinstance(payload, dict):
            raise ValueError("Invalid block request payload")
        session_id = str(payload.get("sessionId") or "").strip()
        srow = None
        scope = str(payload.get("scope") or "device_throttle").strip().lower()
        if scope not in {"device_throttle", "device_game", "device_all_games", "device_wifi_cut", "network_game"}:
            scope = "device_throttle"
        cut_wifi = bool(payload.get("cutWifi", False))

        raw_ip = str(payload.get("ip") or payload.get("clientIp") or "").strip()
        raw_game_id = str(payload.get("gameId") or "").strip().lower()

        if router_only and not session_id:
            raise ValueError("Select a current game detection before applying a device control")
        if session_id:
            with self._connect() as db:
                srow = db.execute(
                    "SELECT ip, mac, game_id, timestamp, is_active, is_dismissed, detection_method FROM game_activity_logs WHERE id=?", (session_id,)
                ).fetchone()
            if srow is None:
                raise ValueError("Game activity session not found")
            hint_type = _game_hint_type(srow["detection_method"])
            if hint_type:
                evidence = {"port": "An open port", "dns_cache": "Cached DNS", "capture_file": "An imported capture"}
                raise ValueError(f"{evidence[hint_type]} does not qualify for game-session controls.")
            if (raw_ip and raw_ip != srow["ip"]) or (raw_game_id and raw_game_id != srow["game_id"]):
                raise ValueError("The selected game session belongs to a different device or game")
            if router_only:
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.get_gaming_policy()["staleSessionSeconds"])
                if not srow["is_active"] or srow["is_dismissed"] or srow["timestamp"] <= cutoff.isoformat().replace("+00:00", "Z"):
                    raise ValueError("The game detection has expired. Select a current detection.")
            raw_ip = srow["ip"]
            raw_game_id = srow["game_id"]

        if raw_game_id in MONITOR_ONLY_IDS:
            signal = self._match_game_signature(game_id=raw_game_id)
            name = signal["name"] if signal else "This activity"
            raise ValueError(f"{name} detections are for monitoring only")

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
            if srow and srow["mac"] and mac and srow["mac"] != mac:
                raise ValueError("The device address changed. Select a current game session.")
            if router_only:
                if srow is None:
                    raise ValueError("Select a current game detection before applying a device control")
                self._validate_device_control_target(ip, mac, srow["mac"])
                return self._apply_manual_game_control(payload, ip, mac, device_name, scope)

        if scope in {"device_all_games", "device_wifi_cut", "device_throttle"} or raw_game_id == "*":
            game_id = "*"
            if scope == "device_throttle":
                cut_wifi = False
                game_name = "Device bandwidth limit (1 KB/s)"
            elif scope == "device_wifi_cut":
                cut_wifi = True
                sig = self._match_game_signature(game_id=raw_game_id)
                game_name = (
                    f"{sig['name']} + User Wi-Fi Cut Off"
                    if sig is not None
                    else "All Games + User Wi-Fi Cut Off"
                )
            else:
                game_name = "All Games + User Wi-Fi" if cut_wifi else "All Mobile & Online Games"
        else:
            sig = self._match_game_signature(game_id=raw_game_id)
            if sig is None:
                raise ValueError("Select a valid game or block scope")
            game_id = sig["id"]
            game_name = sig["name"]

        router_applied: list[str] = []
        now = utc_now()
        with self._connect() as db:
            existing = db.execute(
                """SELECT id, mac, throttle_routers FROM game_block_rules
                   WHERE ip=? AND game_id=? AND active=1 AND control_plan IS NULL AND (scope='device_throttle')=?""",
                (ip, game_id, scope == "device_throttle"),
            ).fetchone()
            if scope == "device_throttle":
                if existing and existing["throttle_routers"]:
                    if existing["mac"] != mac:
                        raise ValueError("Restore the previous device limit before applying a new one to this IP.")
                    router_applied = json.loads(existing["throttle_routers"])
                else:
                    router_applied = self._enforce_router_client_block(
                        ip, mac, device_name, router_ip, block=True, mode="throttle"
                    )
                if not router_applied:
                    hint = (
                        "The device needs a known MAC address. Refresh the LAN inventory and try again."
                        if not mac else
                        "The router did not confirm the bandwidth limit. Sign in under Router Settings and check that the router supports per-device bandwidth limits."
                    )
                    return {
                        "success": False,
                        "scope": scope,
                        "routerEnforced": [],
                        "enforcementDetails": {"requiresSetup": True, "setupHint": hint, "layers": []},
                    }
            throttle_routers = json.dumps(router_applied) if scope == "device_throttle" else None
            if existing:
                rule_id = existing["id"]
                db.execute(
                    "UPDATE game_block_rules SET created_at=?, mac=?, device_name=?, game_name=?, scope=?, cut_wifi=?, throttle_routers=? WHERE id=?",
                    (now, mac, device_name, game_name, scope, 1 if cut_wifi else 0, throttle_routers, rule_id),
                )
            else:
                rule_id = f"gblk-{uuid.uuid4().hex[:10]}"
                db.execute(
                    """INSERT INTO game_block_rules
                       (id, created_at, ip, mac, device_name, game_id, game_name, scope, cut_wifi, throttle_routers, active)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (rule_id, now, ip, mac, device_name, game_id, game_name, scope, 1 if cut_wifi else 0, throttle_routers),
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

        if not router_only and (cut_wifi or scope in {"device_all_games", "device_wifi_cut"}):
            router_applied = self._enforce_router_client_block(
                ip, mac, device_name, router_ip, block=True, mode="cut"
            )

        sensor_status = self._get_gaming_sensor_status()
        is_host_ip = ip in (str(sensor_status.get("dnsHost") or ""), "127.0.0.1")
        dns_ready = bool(sensor_status.get("dnsInterceptReady"))
        client_in_dns = ip in set(sensor_status.get("dnsActiveClients") or [])
        local_dhcp_has_host = str(sensor_status.get("dnsHost") or "") in (
            sensor_status.get("localDhcpDnsServers") or []
        )
        dns_active_for_target = not router_only and bool(client_in_dns or local_dhcp_has_host or dns_ready)
        enforced_layers: list[str] = []
        if router_applied:
            enforced_layers.append(
                f"Router QoS 1 KB/s ({', '.join(router_applied)})"
                if scope == "device_throttle"
                else f"Router MAC Kick ({', '.join(router_applied)})"
            )
        if not router_only and scope != "device_throttle" and (client_in_dns or local_dhcp_has_host):
            enforced_layers.append("DNS 0.0.0.0 Sinkhole")

        requires_setup = bool(
            ip != "*"
            and not is_host_ip
            and not router_applied
            and not client_in_dns
            and not local_dhcp_has_host
        )
        setup_hint = ""
        if requires_setup:
            r_ip = sensor_status.get("routerIp") or "192.168.0.1"
            h_ip = sensor_status.get("dnsHost") or self.HOST_DNS_IP
            setup_hint = (
                f"Block rule saved for {ip}, but router QoS admin login is not connected and {ip} is currently "
                f"using external DHCP DNS ({', '.join(sensor_status.get('localDhcpDnsServers') or ['1.1.1.1'])}). "
                f"Sign into Router Settings ({r_ip}) for router access control, or set router DHCP DNS to {h_ip} for DNS filtering."
            )

        enforcement_details = {
            "scope": scope,
            "routerEnforced": router_applied,
            "routerAuthenticated": bool(sensor_status.get("routerAuthenticated")),
            "dnsInterceptReady": dns_active_for_target,
            "clientObservedOnDns": client_in_dns,
            "isLocalHost": is_host_ip,
            "layers": enforced_layers,
            "requiresSetup": requires_setup,
            "setupHint": setup_hint,
        }

        if router_applied:
            router_note = (
                f" Router QoS 1 KB/s limit applied on {', '.join(router_applied)}."
                if scope == "device_throttle"
                else f" Router MAC kick applied on {', '.join(router_applied)}."
            )
        else:
            router_note = " DNS filtering applies when the device uses the monitor for DNS."

        auto_prevented = bool(payload.get("autoPrevented"))
        action_prefix = "🛡️ Auto-Prevented" if auto_prevented else ("🐌 Throttled" if scope == "device_throttle" else "🛑 Blocked")
        self._record_event(
            "GAME_AUTO_PREVENTED" if auto_prevented else "GAME_BLOCKED",
            "WARNING",
            f"{action_prefix}: {game_name}",
            f"Applied control on {device_name} ({ip}): {game_name}.{router_note}",
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
            "scope": scope,
            "autoPrevented": auto_prevented,
            "routerEnforced": router_applied,
            "enforcementDetails": enforcement_details,
            "gameActivity": activity,
        }

    def unblock_game_rule(self, rule_id: str) -> dict:
        with self._game_restriction_lock:
            return self._unblock_game_rule(rule_id)

    def _unblock_game_rule(self, rule_id: str) -> dict:
        self = cast("Monitor", self)
        rid = str(rule_id or "").strip()
        if not rid:
            raise ValueError("Block rule id is required")
        with self._connect() as db:
            manual = db.execute("SELECT * FROM game_block_rules WHERE id=? AND control_plan IS NOT NULL", (rid,)).fetchone()
        if manual is not None:
            return self._restore_manual_game_control(dict(manual))
        with self._connect() as db:
            row = db.execute("SELECT * FROM game_block_rules WHERE id=?", (rid,)).fetchone()
            if row is None:
                raise ValueError("Game block rule not found")
            rule = dict(row)
            throttle = rule["scope"] == "device_throttle"
            if throttle or rule["cut_routers"]:
                router_records = rule["throttle_routers"] if throttle else rule["cut_routers"]
                targets = json.loads(router_records) if router_records else None
                restored = self._enforce_router_client_block(
                    rule["ip"], rule["mac"], rule["device_name"], "",
                    block=False, mode="throttle" if throttle else "cut", router_targets=targets,
                )
                if targets and not set(targets).issubset(restored):
                    return {
                        "success": False,
                        "error": "The router did not confirm removal of the device restriction. Check Router Settings and retry.",
                    }
            db.execute("DELETE FROM game_block_rules WHERE id=?", (rid,))
            db.execute(
                """UPDATE game_activity_logs AS log SET is_blocked=EXISTS (
                       SELECT 1 FROM game_block_rules AS rule WHERE rule.active=1 AND rule.control_plan IS NULL
                       AND rule.ip IN (log.ip, '*') AND rule.game_id IN (log.game_id, '*')
                   ) WHERE ? IN (log.ip, '*') AND ? IN (log.game_id, '*')""",
                (rule["ip"], rule["game_id"]),
            )

        if not rule["cut_routers"] and (rule["cut_wifi"] or rule["scope"] in {"device_all_games", "device_wifi_cut"}):
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
        batch_size = 24
        for offset in range(0, len(targets), batch_size):
            if offset > 0:
                time.sleep(0.012)
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
                        sock = cast(socket.socket, key.fileobj)
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
        self = cast("Monitor", self)
        if getattr(self, "_skip_live_probe_in_test", False):
            return 0
        synced = 0
        # 1. Fast ARP table refresh across all connected subnets
        if hasattr(self, "_read_arp_entries"):
            try:
                arp_entries = self._read_arp_entries(os.name, subprocess.run)
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
        """Inspect running host processes and established network connections on Windows."""
        if sys.platform != "win32" or getattr(self, "_skip_live_probe_in_test", False):
            return []
        flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        host_ip = self._detect_host_lan_ip(self.HOST_DNS_IP)
        found = list(host_game_processes(host_ip, list_windows_processes() or []).values())
        seen_games = {hit["gameId"] for hit in found}

        # 2. Active outbound / inbound TCP sockets against dedicated game server ports
        try:
            res = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
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

        return found

    def scan_lan_for_games(self, include_topology_refresh: bool = False) -> dict:
        """Scan the whole network topology (routers, APs, topology nodes, host OS & all LAN clients) for open games."""
        self = cast("Monitor", self)
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
        open_port_hits = 0
        if include_topology_refresh:
            if not getattr(self, "_skip_live_probe_in_test", False):
                try:
                    self.discover_devices()
                except RuntimeError:
                    # Discovery already running. Use topology and DHCP records for this pass.
                    pass
            routers_polled = self._sync_topology_arp_and_clients()
            self.poll_router_logs_for_games()
            for sig_payload in self._collect_local_os_game_signals():
                confirmed_hits += 1
                try:
                    sig_payload["skipAutoPrevent"] = True
                    res = self.record_game_detection(sig_payload)
                    if res.get("detection"):
                        detections.append(res["detection"])
                except Exception:
                    pass

        with self._connect() as db:
            inv_rows = db.execute(
                "SELECT DISTINCT ip, vendor, suggested_name FROM discovered_devices WHERE is_online=1 ORDER BY ip"
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
            try:
                ip = validate_ip(str(raw_ip or "").strip())
                address = ipaddress.ip_address(ip)
            except ValueError:
                return
            if ip in seen_client_ips or ip in infra_ips or address.version != 4 or address.is_loopback:
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

            open_port_hits = len(hits)

        activity = self.get_game_activity(100)
        if include_topology_refresh:
            self._record_event(
                "GAME_TOPOLOGY_SCAN",
                "INFO",
                "Game scan completed",
                (
                    f"Checked game-related ports on {len(client_ips)} candidate device(s). "
                    f"Attempted client-list reads on {routers_polled} router(s). "
                    f"Local game signals: {confirmed_hits}. Open-port hints: {open_port_hits}."
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
            "openPortHits": open_port_hits,
            "detectedCount": len(detections),
            "activeCount": int((activity.get("summary") or {}).get("activeCount") or 0),
            "blockedCount": len(activity.get("blocks") or []),
            "detections": detections,
            "gameActivity": activity,
        }

    def dismiss_game_session(self, session_id: str) -> dict:
        self = cast("Monitor", self)
        sid = str(session_id or "").strip()
        if not sid:
            raise ValueError("Game session id is required")
        with self._connect() as db:
            row = db.execute(
                "SELECT ip, game_id, player FROM game_activity_logs WHERE id=?", (sid,)
            ).fetchone()
            if row is None:
                raise ValueError("Game activity session not found")
            changed = db.execute(
                "UPDATE game_activity_logs SET is_dismissed=1 WHERE id=? AND is_active=1 AND is_dismissed=0",
                (sid,),
            ).rowcount
        if not changed:
            return {"success": True, "gameActivity": self.get_game_activity(100)}
        alert_key = self._game_alert_key(row["ip"], row["game_id"], row["player"])
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
        self = cast("Monitor", self)
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
        self = cast("Monitor", self)
        try:
            ip_obj = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False
        if not isinstance(ip_obj, ipaddress.IPv4Address) or not ip_obj.is_private or ip_obj.is_loopback:
            return False
        local_nets = self._known_local_networks() if hasattr(self, "_known_local_networks") else []
        if local_nets:
            return any(ip_obj in net for net in local_nets)
        return not (ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_reserved)

    @staticmethod
    def _syslog_game_client_ip(text: str, sender_ip: str) -> str:
        # DNS and firewall logs carry the client separately from the reporting router.
        match = re.search(
            r'\b(?:src|src_ip|source_ip|client|client_ip|clientip|from)["\s:=]+((?:\d{1,3}\.){3}\d{1,3})\b',
            text, re.I,
        )
        if not match or match.group(1) == sender_ip:
            return ""
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            return ""
        if address.is_private and not (address.is_loopback or address.is_unspecified or address.is_link_local):
            return str(address)
        return ""

    def start_game_listeners(self) -> None:
        """Start container UDP DNS listener (5354) and Router Syslog listener (5140)."""
        if getattr(self, "_game_listeners_started", False):
            return
        self._game_listeners_started = True
        if os.environ.get("PULSE_ENABLE_DNS_FORWARDING") == "1":
            threading.Thread(
                target=self._dns_game_listener_loop, daemon=True, name="game-dns-listener"
            ).start()
        threading.Thread(
            target=self._syslog_game_listener_loop, daemon=True, name="game-syslog-listener"
        ).start()

    def _dns_game_listener_loop(self) -> None:
        self = cast("Monitor", self)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        worker_slots = threading.BoundedSemaphore(32)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.DNS_LISTENER_PORT))
            sock.settimeout(1.0)
        except OSError:
            sock.close()
            return

        def _handle_dns_packet(raw: bytes, client_addr: tuple[str, int]) -> None:
            if len(raw) < 12 or raw[2] & 0x80:
                return
            qname = self._extract_dns_qname(raw)
            policy = self.get_gaming_policy()
            if policy["restrictionsEnabled"] and qname and self._is_doh_canary_domain(qname):
                nxd = self._build_dns_nxdomain_reply(raw)
                if nxd:
                    try:
                        sock.sendto(nxd, client_addr)
                    except OSError:
                        pass
                return
            sig = self._match_game_signature(domain=qname) if qname else None
            sinkhole_rule = (
                self._should_sinkhole_query(client_addr[0], qname, sig, self.get_game_blocks())
                if qname and policy["restrictionsEnabled"]
                else None
            )
            auto_prevent = sig and sig["id"] not in MONITOR_ONLY_IDS and policy["autoPreventEnabled"]
            if sinkhole_rule is not None or auto_prevent:
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
                    fwd.connect(("1.1.1.1", 53))
                    fwd.send(raw)
                    resp = fwd.recv(4096)
                if len(resp) >= 12 and resp[:2] == raw[:2] and resp[2] & 0x80:
                    sock.sendto(resp, client_addr)
            except OSError:
                pass

        def _run_dns_worker(raw: bytes, client_addr: tuple[str, int]) -> None:
            try:
                _handle_dns_packet(raw, client_addr)
            finally:
                worker_slots.release()

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    if worker_slots.acquire(blocking=False):
                        try:
                            threading.Thread(target=_run_dns_worker, args=(data, addr), daemon=True).start()
                        except RuntimeError:
                            worker_slots.release()
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

        client_ip = self._syslog_game_client_ip(text, sender_ip)
        if not client_ip or not self._is_real_lan_client_ip(client_ip):
            return None
        return client_ip, matched_domain, matched_port

    def poll_router_logs_for_games(self) -> int:
        """Poll authenticated TP-Link LuCI system logs for game domain/port traces."""
        self = cast("Monitor", self)
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
        seen_by_router = getattr(self, "_seen_router_log_lines", None)
        if seen_by_router is None:
            seen_by_router = {}
            self._seen_router_log_lines = seen_by_router
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
            lines = [json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item) for item in rows[-80:]]
            router_key = (host, port)
            seen = seen_by_router.get(router_key)
            if seen is None:
                seen_by_router[router_key] = set(lines)
                continue
            seen_by_router[router_key] = set(lines)
            for line in lines:
                if line in seen:
                    continue
                seen.add(line)
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
                    }, include_activity=False)
                    found += 1
                except Exception:
                    pass
        return found

    def _syslog_game_listener_loop(self) -> None:
        self = cast("Monitor", self)
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
