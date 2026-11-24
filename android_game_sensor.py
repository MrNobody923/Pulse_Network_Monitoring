"""Report supported foreground games from one authorized Android phone."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from pulse_monitor.game_detector import ANDROID_GAME_PACKAGES


def _adb_output(adb: str, *args: str) -> str:
    result = subprocess.run(
        [adb, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Android Debug Bridge command failed")
    return result.stdout


def foreground_game_package(output: str) -> str | None:
    if "ACTIVITY MANAGER TOP-RESUMED" not in output:
        raise RuntimeError("The phone did not return a top-resumed Android activity")
    match = re.search(r"(?m)^\s*packageName=([\w.]+)(?:\s|$)", output)
    state = re.search(r"(?m)^\s*state=(\w+)", output)
    if match and match[1] in ANDROID_GAME_PACKAGES and (state is None or state[1] == "RESUMED"):
        return match[1]
    return None


def _phone_wifi_ip(adb: str, selector: list[str]) -> str:
    addresses = _adb_output(adb, *selector, "shell", "ip", "-o", "-4", "addr", "show", "dev", "wlan0")
    match = re.search(r"\binet\s+(\d+(?:\.\d+){3})/\d+\s", addresses)
    if match is None:
        raise RuntimeError("No IPv4 address on Android wlan0. Connect the phone to office Wi-Fi or use --phone-ip.")
    return match[1]


def _report(port: int, ip: str, package: str, *, ended: bool = False) -> None:
    body = json.dumps({"ip": ip, "package": package, "ended": ended})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        connection.request("POST", "/api/gaming/android", body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        result = json.load(response)
        if response.status != 200 or not result.get("success"):
            raise RuntimeError(result.get("error") or f"Monitor returned HTTP {response.status}")
    finally:
        connection.close()


def watch_phone(adb: str, selector: list[str], port: int, phone_ip: str | None) -> None:
    device_state = _adb_output(adb, *selector, "get-state").strip()
    if device_state != "device":
        raise RuntimeError("Connect one Android phone by USB, unlock it, and approve USB debugging.")
    ip = phone_ip or _phone_wifi_ip(adb, selector)
    print(f"Watching supported Android games on {ip}. Press Ctrl+C to stop.", flush=True)
    active: tuple[str, str] | None = None
    next_report = 0.0
    next_ip_check = time.monotonic() + 5
    try:
        while True:
            snapshot = _adb_output(
                adb, *selector, "shell",
                "dumpsys activity top-resumed | grep -E 'ACTIVITY MANAGER TOP-RESUMED|^[[:space:]]*packageName=|^[[:space:]]*state='",
            )
            package = foreground_game_package(snapshot)
            now = time.monotonic()
            if phone_ip is None and now >= next_ip_check:
                ip = _phone_wifi_ip(adb, selector)
                next_ip_check = now + 5
            current = (ip, package) if package else None
            if active is not None and active != current:
                _report(port, *active, ended=True)
                print(f"Left foreground: {active[1]}", flush=True)
                active = None
            if current is not None and (active != current or now >= next_report):
                _report(port, *current)
                if active != current:
                    print(f"Game in foreground: {current[1]}", flush=True)
                active = current
                next_report = now + 5
            time.sleep(1)
    finally:
        if active is not None:
            try:
                _report(port, *active, ended=True)
            except (OSError, RuntimeError, ValueError, http.client.HTTPException):
                print("Could not send the end report. Vertex Sentry will expire the detection.", flush=True)


def main() -> int:
    bundled_adb = Path(__file__).resolve().parent / "data" / "android-tools" / "platform-tools" / "adb.exe"
    default_adb = str(bundled_adb) if bundled_adb.is_file() else shutil.which("adb")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=default_adb, help="Path to Google Android Platform-Tools adb")
    parser.add_argument("--serial", help="ADB serial when more than one authorized device is attached")
    parser.add_argument("--port", type=int, default=os.environ.get("PORT", "3000"), help="Local Vertex Sentry port")
    parser.add_argument("--phone-ip", type=ipaddress.IPv4Address, help="Phone's office Wi-Fi IPv4 address when auto-detection is unavailable")
    args = parser.parse_args()
    if not args.adb:
        parser.error("Install Google Android Platform-Tools and set --adb to its adb executable")
    selector = ["-s", args.serial] if args.serial else ["-d"]
    try:
        watch_phone(args.adb, selector, args.port, str(args.phone_ip) if args.phone_ip else None)
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, http.client.HTTPException) as exc:
        parser.exit(1, f"Android game sensor: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
