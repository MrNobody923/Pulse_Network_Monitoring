"""Real ISP bandwidth measurement, ISP identity lookup, and live WAN throughput sampling.

Every number produced here is measured — nothing is estimated or synthesised:

* ``run_speedtest`` performs a multi-stream HTTPS download/upload test against
  Cloudflare's public speed-test edge (``speed.cloudflare.com``), the same
  backend used by https://speed.cloudflare.com.
* ``fetch_isp_identity`` asks the same edge which ISP / ASN / public IP the
  office connection egresses through.
* ``WanThroughputSampler`` reads the host's network-interface byte counters
  once per second to show live Rx/Tx bandwidth in real time.
"""

from __future__ import annotations

import ctypes
import http.client
import json
import os
import re
import socket
import ssl
import statistics
import subprocess
import threading
import time
import urllib.request

if os.name == "nt":
    import ctypes.wintypes

from typing import TYPE_CHECKING, cast

from .config import manual_speed_tests_enabled, utc_now
from .router_wan import ROUTER_SAMPLE_SECONDS, RouterWanSampler

if TYPE_CHECKING:
    from .engine import Monitor

SPEED_HOST = "speed.cloudflare.com"
DOWNLOAD_STREAMS = 6
UPLOAD_STREAMS = 4
DOWNLOAD_SECONDS = 10.0
UPLOAD_SECONDS = 8.0
DOWNLOAD_CHUNK_BYTES = 25_000_000
UPLOAD_BODY_BYTES = 256 * 1024
MAX_TEST_BYTES = 600_000_000  # hard data cap per phase
RAMP_UP_FRACTION = 0.25  # ignore TCP slow-start at the beginning of each phase
LIVE_HISTORY_POINTS = 120
IDENTITY_REFRESH_SEC = 600
USER_AGENT = "PulseNetworkMonitor/1.0 (+speedtest)"


def _https_connection(timeout: float) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(
        SPEED_HOST, 443, timeout=timeout, context=ssl.create_default_context()
    )


def _speedtest_failure(phase: str, error: Exception) -> str:
    if isinstance(error, PermissionError) or getattr(error, "winerror", None) == 10013:
        return (
            f"{phase} test blocked: this Vertex Sentry process could not open an HTTPS connection to {SPEED_HOST}. "
            "Allow outbound HTTPS for the monitoring process."
        )
    return f"{phase} test failed: {error}"


def _server_duration_ms(response: http.client.HTTPResponse) -> float:
    """Cloudflare reports its own processing time; subtract it from the RTT."""
    header = response.getheader("Server-Timing") or ""
    match = re.search(r"\bdur=(\d+(?:\.\d+)?)", header)
    return float(match.group(1)) if match else 0.0


def _parse_asn_org(org_value: object) -> tuple[str | None, str | None]:
    text = str(org_value or "").strip()
    if not text:
        return None, None
    match = re.match(r"^(AS\d+)\s+(.+)$", text, re.I)
    if match:
        return match.group(1).upper(), match.group(2).strip()
    return None, text


def fetch_isp_identity(timeout: float = 6.0) -> dict:
    """Return the ISP, ASN, public IP and edge location serving this connection."""
    # Primary: ipinfo.io (reliable over HTTPS without bot-blocking /meta 403)
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"Accept": "application/json", "User-Agent": "curl/8.5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                meta = json.loads(resp.read().decode("utf-8"))
                asn, provider = _parse_asn_org(meta.get("org"))
                if provider or meta.get("ip"):
                    city = meta.get("city") or ""
                    region = meta.get("region") or ""
                    country = meta.get("country") or ""
                    loc = ", ".join(p for p in (city, region, country) if p) or None
                    return {
                        "provider": provider or "Unknown ISP",
                        "asn": asn,
                        "publicIp": meta.get("ip"),
                        "edgeColo": None,
                        "location": loc,
                        "checkedAt": utc_now(),
                    }
    except Exception:
        pass

    # Fallback: Cloudflare speed edge /meta with browser-like headers
    conn = _https_connection(timeout)
    try:
        conn.request(
            "GET",
            "/meta",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json",
            },
        )
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"ISP lookup returned HTTP {response.status}")
        meta = json.loads(body.decode("utf-8"))
    finally:
        conn.close()
    city = meta.get("city") or ""
    country = meta.get("country") or ""
    return {
        "provider": meta.get("asOrganization") or "Unknown ISP",
        "asn": f"AS{meta['asn']}" if meta.get("asn") else None,
        "publicIp": meta.get("clientIp"),
        "edgeColo": meta.get("colo"),
        "location": ", ".join(part for part in (city, country) if part) or None,
        "checkedAt": utc_now(),
    }


def _rating(download_mbps: float) -> str:
    if download_mbps >= 500:
        return "Gigabit-Class Fiber"
    if download_mbps >= 100:
        return "High-Speed Broadband"
    if download_mbps >= 30:
        return "Standard Office Speed"
    return "Slow / Bottlenecked"


if os.name == "nt":
    class _MIB_IF_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.wintypes.ULONG),
            ("InterfaceGuid", ctypes.c_byte * 16),
            ("Alias", ctypes.c_wchar * 257),
            ("Description", ctypes.c_wchar * 257),
            ("PhysicalAddressLength", ctypes.wintypes.ULONG),
            ("PhysicalAddress", ctypes.c_ubyte * 32),
            ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
            ("Mtu", ctypes.wintypes.ULONG),
            ("Type", ctypes.wintypes.ULONG),
            ("TunnelType", ctypes.c_int),
            ("MediaType", ctypes.c_int),
            ("PhysicalMediumType", ctypes.c_int),
            ("AccessType", ctypes.c_int),
            ("DirectionType", ctypes.c_int),
            ("InterfaceAndOperStatusFlags", ctypes.c_byte),
            ("OperStatus", ctypes.c_int),
            ("AdminStatus", ctypes.c_int),
            ("MediaConnectState", ctypes.c_int),
            ("NetworkGuid", ctypes.c_byte * 16),
            ("ConnectionType", ctypes.c_int),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
            ("InOctets", ctypes.c_uint64),
            ("InUcastPkts", ctypes.c_uint64),
            ("InNUcastPkts", ctypes.c_uint64),
            ("InDiscards", ctypes.c_uint64),
            ("InErrors", ctypes.c_uint64),
            ("InUnknownProtos", ctypes.c_uint64),
            ("InUcastOctets", ctypes.c_uint64),
            ("InMulticastOctets", ctypes.c_uint64),
            ("InBroadcastOctets", ctypes.c_uint64),
            ("OutOctets", ctypes.c_uint64),
            ("OutUcastPkts", ctypes.c_uint64),
            ("OutNUcastPkts", ctypes.c_uint64),
            ("OutDiscards", ctypes.c_uint64),
            ("OutErrors", ctypes.c_uint64),
            ("OutUcastOctets", ctypes.c_uint64),
            ("OutMulticastOctets", ctypes.c_uint64),
            ("OutBroadcastOctets", ctypes.c_uint64),
            ("OutQLen", ctypes.c_uint64),
        ]
else:
    class _MIB_IF_ROW2:
        pass


class WanThroughputSampler:
    """Reads cumulative Rx/Tx byte counters of the primary internet-facing network adapter."""

    def __init__(self) -> None:
        self.source = "NIC Counter" if os.name == "nt" else "/proc/net/dev"
        self.link_speed_mbps: float | None = None
        self.interface_id = None
        self.wifi_alias = ""
        self._signal_alias = ""
        self._signal_checked = float("-inf")
        self._signal = {}

    def wifi_signal(self) -> dict:
        alias = self.wifi_alias
        if alias != self._signal_alias or time.monotonic() - self._signal_checked >= 15:
            self._signal_alias = alias
            self._signal_checked = time.monotonic()
            self._signal = {}
            if alias:
                try:
                    result = subprocess.run(
                        ["netsh", "wlan", "show", "interfaces"], capture_output=True,
                        text=True, errors="replace", timeout=3, creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    if result.returncode == 0:
                        self._signal = _parse_wifi_signal(result.stdout, alias)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        return self._signal

    def _read_win32_primary_nic(self) -> tuple[int, int] | None:
        try:
            iphlp = ctypes.windll.iphlpapi
            dest_nbo = int.from_bytes(socket.inet_aton("1.1.1.1"), "little")
            idx = ctypes.wintypes.DWORD()
            if iphlp.GetBestInterface(dest_nbo, ctypes.byref(idx)) != 0 or not idx.value:
                return None
            row = _MIB_IF_ROW2()
            row.InterfaceIndex = idx.value
            if iphlp.GetIfEntry2(ctypes.byref(row)) != 0:
                return None
            alias = row.Alias.strip() or row.Description.strip() or f"NIC #{idx.value}"
            self.interface_id = bytes(row.InterfaceGuid)
            self.wifi_alias = alias if row.Type == 71 else ""
            self.source = f"{alias} (Live NIC)"
            self.link_speed_mbps = round(row.ReceiveLinkSpeed / 1_000_000, 1) if row.ReceiveLinkSpeed else None
            return int(row.InOctets), int(row.OutOctets)
        except (AttributeError, OSError, ValueError):
            return None

    def read_counters(self) -> tuple[int, int] | None:
        try:
            if os.name == "nt":
                win_pair = self._read_win32_primary_nic()
                if win_pair is not None:
                    return win_pair
                self.source = "All host interfaces (netstat)"
                self.interface_id = "netstat"
                self.wifi_alias = ""
                self.link_speed_mbps = None
                output = subprocess.run(
                    ["netstat", "-e"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                ).stdout
                for line in output.splitlines():
                    match = re.match(r"^\s*\S.*?\s(\d+)\s+(\d+)\s*$", line)
                    if match:
                        return int(match.group(1)), int(match.group(2))
                return None
            with open("/proc/net/route", encoding="utf-8") as handle:
                routes = [line.split() for line in handle.readlines()[1:]]
            defaults = [row for row in routes if len(row) >= 8 and row[1] == "00000000"
                        and row[7] == "00000000" and int(row[3], 16) & 1]
            if not defaults:
                return None
            interface = min(defaults, key=lambda row: int(row[6]))[0]
            self.interface_id = interface
            self.source = interface
            with open("/proc/net/dev", encoding="utf-8") as handle:
                for line in handle.readlines()[2:]:
                    name, data = line.split(":", 1)
                    if name.strip() != interface:
                        continue
                    fields = data.split()
                    return int(fields[0]), int(fields[8])
            return None
        except (OSError, ValueError, subprocess.SubprocessError):
            return None


def _parse_wifi_signal(output: str, alias: str) -> dict:
    for block in re.split(r"(?im)^\s*Name\s*:\s*", output)[1:]:
        fields = block.splitlines()
        if not fields or fields[0].strip().casefold() != alias.casefold():
            continue
        if not re.search(r"(?im)^\s*State\s*:\s*connected\s*$", block):
            continue
        quality = re.search(r"(?im)^\s*Signal\s*:\s*(\d+)%", block)
        rssi = re.search(r"(?im)^\s*Rssi\s*:\s*(-\d+)\s*$", block)
        return {
            "signalPercent": int(quality[1]) if quality and int(quality[1]) <= 100 else None,
            "rssiDbm": int(rssi[1]) if rssi and -127 <= int(rssi[1]) < 0 else None,
        }
    return {}


def _counter_delta(current: int, previous: int) -> int | None:
    delta = current - previous
    if delta >= 0:
        return delta
    return None


def _counter_rates(current: tuple[int, int], previous: tuple[int, int], seconds: float) -> tuple[float, float] | None:
    rx = _counter_delta(current[0], previous[0])
    tx = _counter_delta(current[1], previous[1])
    if rx is None or tx is None or seconds <= 0:
        return None
    return round(rx * 8 / seconds / 1_000_000, 2), round(tx * 8 / seconds / 1_000_000, 2)


class IspSpeedMixin:
    """Real-time ISP speed test, ISP identity, and live throughput for the Monitor."""

    # ------------------------------------------------------------------ helpers
    def _isp_set(self, **values) -> None:
        self = cast("Monitor", self)
        with self.lock:
            self.isp_state.update(values)

    def get_live_isp_telemetry(self) -> dict:
        self = cast("Monitor", self)
        with self.lock:
            return {key: self.isp_state.get(key) for key in ("liveThroughput", "routerWanThroughput")}

    def refresh_isp_identity(self) -> dict | None:
        try:
            identity = fetch_isp_identity()
        except Exception as exc:  # network down, DNS failure, HTTP error
            self._isp_set(providerError=str(exc))
            return None
        self._isp_set(provider=identity, providerError=None)
        return identity

    # --------------------------------------------------------------- speed test
    def _measure_latency(self, samples: int = 10) -> tuple[float, float]:
        conn = _https_connection(5)
        rtts: list[float] = []
        warmed_up = False
        last_error = None
        try:
            for _ in range(samples + 2):
                started = time.perf_counter()
                try:
                    conn.request(
                        "GET", "/__down?bytes=0",
                        headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"},
                    )
                    response = conn.getresponse()
                    response.read()
                except PermissionError:
                    raise
                except (OSError, http.client.HTTPException) as error:
                    conn.close()
                    if last_error is not None and not rtts:
                        raise
                    last_error = error
                    continue
                if response.status != 200:
                    raise RuntimeError(f"{SPEED_HOST} returned HTTP {response.status}")
                elapsed = (time.perf_counter() - started) * 1000
                if not warmed_up:
                    warmed_up = True
                    continue  # first request includes TCP + TLS handshakes
                rtts.append(max(0.1, elapsed - _server_duration_ms(response)))
                if len(rtts) >= samples:
                    break
        finally:
            conn.close()
        if len(rtts) < min(3, samples):
            raise RuntimeError("Too few successful latency samples") from last_error
        ordered = list(rtts)  # jitter from consecutive samples in measurement order
        ping = round(statistics.median(rtts), 1)
        jitter = round(
            sum(abs(ordered[i] - ordered[i - 1]) for i in range(1, len(ordered)))
            / max(1, len(ordered) - 1),
            1,
        )
        return ping, jitter

    def _run_transfer_phase(
        self,
        phase: str,
        streams: int,
        duration: float,
        progress_base: int,
        progress_span: int,
        extra: dict,
    ) -> float:
        self = cast("Monitor", self)
        counters = [0] * streams
        last_transfer = [0.0] * streams
        errors: list[Exception] = []
        stop = threading.Event()
        budget = MAX_TEST_BYTES // streams

        def download_worker(index: int) -> None:
            conn = _https_connection(3)
            try:
                while not stop.is_set() and counters[index] < budget:
                    try:
                        remaining = min(DOWNLOAD_CHUNK_BYTES, budget - counters[index])
                        conn.request(
                            "GET", f"/__down?bytes={remaining}&_={time.monotonic_ns()}",
                            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity", "Cache-Control": "no-cache"},
                        )
                        with conn.getresponse() as response:
                            if response.status != 200:
                                raise RuntimeError(f"HTTP {response.status} from {SPEED_HOST}")
                            while not stop.is_set() and remaining:
                                chunk = response.read1(min(64 * 1024, remaining))
                                if not chunk:
                                    raise RuntimeError("Download response ended before the requested byte count")
                                remaining -= len(chunk)
                                counters[index] += len(chunk)
                                last_transfer[index] = time.perf_counter()
                    except (OSError, http.client.HTTPException, RuntimeError) as exc:
                        errors.append(exc)
                        conn.close()
                        if isinstance(exc, PermissionError):
                            stop.set()
                        stop.wait(0.5)
            finally:
                conn.close()

        payload = b"\0" * (64 * 1024)

        def upload_worker(index: int) -> None:
            conn = _https_connection(3)
            body_size = UPLOAD_BODY_BYTES
            remaining = budget
            while not stop.is_set() and remaining:
                try:
                    body_size = min(body_size, remaining)
                    started_request = time.perf_counter()
                    conn.putrequest("POST", "/__up")
                    conn.putheader("User-Agent", USER_AGENT)
                    conn.putheader("Content-Type", "application/octet-stream")
                    conn.putheader("Content-Length", str(body_size))
                    conn.endheaders()
                    sent = 0
                    while sent < body_size and not stop.is_set():
                        piece = payload[: min(len(payload), body_size - sent)]
                        remaining -= len(piece)
                        conn.send(piece)
                        sent += len(piece)
                    if sent == body_size:
                        transfer_at = time.perf_counter()
                        response = conn.getresponse()
                        response.read()
                        if 200 <= response.status < 300:
                            counters[index] += sent
                            last_transfer[index] = transfer_at
                            elapsed = max(time.perf_counter() - started_request, 0.001)
                            body_size = max(len(payload), min(8_000_000, int(0.5 * sent / elapsed)))
                        else:
                            errors.append(RuntimeError(f"HTTP {response.status} from {SPEED_HOST}"))
                            stop.wait(0.5)
                except (OSError, http.client.HTTPException) as exc:
                    errors.append(exc)
                    conn.close()
                    if isinstance(exc, PermissionError):
                        stop.set()
                    stop.wait(0.5)
            conn.close()

        worker = download_worker if phase == "download" else upload_worker
        threads = [
            threading.Thread(target=worker, args=(i,), daemon=True, name=f"st-{phase}-{i}")
            for i in range(streams)
        ]
        started = time.perf_counter()
        for thread in threads:
            thread.start()

        samples: list[tuple[float, int]] = [(0.0, 0)]
        try:
            while True:
                time.sleep(0.25)
                elapsed = time.perf_counter() - started
                total = sum(counters)
                samples.append((elapsed, total))
                # Instantaneous rate over the last ~1 s window
                window = [s for s in samples if s[0] >= elapsed - 1.0]
                t0, b0 = window[0]
                live_mbps = (
                    round((total - b0) * 8 / max(elapsed - t0, 0.001) / 1_000_000, 1)
                    if elapsed > t0
                    else 0.0
                )
                pct = progress_base + int(min(1.0, elapsed / duration) * progress_span)
                self.broadcast(
                    "speedtest_progress",
                    {
                        **extra,
                        "phase": phase,
                        "phaseLabel": f"Measuring {phase.title()} Speed...",
                        "message": f"Live {phase} throughput: {live_mbps} Mbps",
                        "currentMbps": live_mbps,
                        f"{phase}Mbps": live_mbps,
                        "bytesTransferred": total,
                        "progressPct": pct,
                    },
                )
                if elapsed >= duration or stop.is_set() or not any(thread.is_alive() for thread in threads) or self._stop.is_set():
                    break
        finally:
            stop.set()
            deadline = time.monotonic() + 4
            for thread in threads:
                thread.join(timeout=max(0, deadline - time.monotonic()))

        end_time = samples[-1][0]
        end_bytes = sum(counters)
        if self._stop.is_set() or any(thread.is_alive() for thread in threads):
            raise RuntimeError(f"The {phase} test was interrupted")
        if end_bytes < 256 * 1024:
            if errors:
                raise errors[-1]
            raise RuntimeError(f"Too little data was transferred to measure speed from {SPEED_HOST}")
        if end_bytes >= budget * streams:
            end_time = max(last_transfer) - started
            samples = [sample for sample in samples if sample[0] < end_time]
        else:
            samples.pop()
        samples.append((end_time, end_bytes))
        ramp_cut = end_time * RAMP_UP_FRACTION
        ramp_time, ramp_bytes = next(s for s in samples if s[0] >= ramp_cut)
        steady_seconds = max(end_time - ramp_time, 0.001)
        if ramp_time == end_time or end_bytes == ramp_bytes:
            return round(end_bytes * 8 / end_time / 1_000_000, 1)
        return round((end_bytes - ramp_bytes) * 8 / steady_seconds / 1_000_000, 1)

    def run_speedtest(self) -> dict:
        self = cast("Monitor", self)
        if not manual_speed_tests_enabled():
            raise RuntimeError("Active speed tests are disabled. Live interface throughput is still available.")
        if not self._speedtest_lock.acquire(blocking=False):
            raise RuntimeError("A speed test is already running — results will stream in shortly.")
        self._last_speedtest = time.time()
        self._isp_set(speedTestRunning=True, speedTestError=None)
        phase = "Latency"
        try:
            self.broadcast(
                "speedtest_progress",
                {
                    "phase": "ping",
                    "phaseLabel": "Measuring latency...",
                    "message": f"Connecting to {SPEED_HOST} from the monitoring PC...",
                    "currentMbps": 0.0,
                    "progressPct": 3,
                },
            )
            with self.lock:
                identity = self.isp_state.get("provider") or {}
            ping_ms, jitter_ms = self._measure_latency()
            base = {"pingMs": ping_ms, "jitterMs": jitter_ms}
            self.broadcast(
                "speedtest_progress",
                {
                    **base,
                    "phase": "ping",
                    "phaseLabel": f"Ping {ping_ms} ms · Jitter {jitter_ms} ms",
                    "message": f"Ping {ping_ms} ms (jitter {jitter_ms} ms) · starting download...",
                    "currentMbps": 0.0,
                    "progressPct": 10,
                },
            )
            phase = "Download"
            download = self._run_transfer_phase(
                "download", DOWNLOAD_STREAMS, DOWNLOAD_SECONDS, 10, 50, base
            )
            phase = "Upload"
            upload = self._run_transfer_phase(
                "upload", UPLOAD_STREAMS, UPLOAD_SECONDS, 60, 38,
                {**base, "downloadMbps": download},
            )
            result = {
                "timestamp": utc_now(),
                "downloadMbps": download,
                "uploadMbps": upload,
                "pingMs": ping_ms,
                "jitterMs": jitter_ms,
                "rating": _rating(download),
                "server": " ".join(filter(None, ["Cloudflare", (identity or {}).get("edgeColo")])),
                "provider": (identity or {}).get("provider"),
                "publicIp": (identity or {}).get("publicIp"),
                "method": f"{DOWNLOAD_STREAMS}x HTTPS download / {UPLOAD_STREAMS}x HTTPS upload streams",
            }
            with self.lock:
                self.isp_state["lastSpeedTest"] = result
                history = self.isp_state.setdefault("speedHistory", [])
                history.append(result)
                del history[:-24]
            try:
                if hasattr(self, "_connect"):
                    with self._connect() as db:
                        db.execute(
                            "INSERT OR REPLACE INTO monitor_metadata (key, value) VALUES ('last_speed_test', ?)",
                            (json.dumps(result),),
                        )
            except Exception:
                pass
            self.broadcast(
                "speedtest_progress",
                {
                    **result,
                    "phase": "complete",
                    "phaseLabel": "Speed Test Complete",
                    "message": f"Measured {download} Mbps down / {upload} Mbps up",
                    "currentMbps": download,
                    "progressPct": 100,
                },
            )
            self._record_event(
                "SPEED_TEST",
                "INFO",
                "Internet Speed Test Complete",
                f"Measured {round(download / 8, 2)} MB/s ({download} Mbps) down / {round(upload / 8, 2)} MB/s ({upload} Mbps) up · Ping {ping_ms} ms ({result['server']}).",
                ip=(identity or {}).get("publicIp") or "",
                device_name="ISP Internet Uplink",
            )
            self.broadcast("speedtest_result", result)
            return result
        except Exception as exc:
            message = _speedtest_failure(phase, exc)
            self._isp_set(speedTestError=message)
            self._record_event(
                "SPEED_TEST",
                "WARNING",
                "Internet Speed Test Failed",
                message,
                device_name="ISP Internet Uplink",
            )
            self.broadcast(
                "speedtest_progress",
                {"phase": "error", "message": message, "progressPct": 0},
            )
            raise RuntimeError(message) from exc
        finally:
            self._isp_set(speedTestRunning=False)
            self._speedtest_lock.release()

    # -------------------------------------------------- live throughput loop
    def _speedtest_interval_sec(self) -> float:
        self = cast("Monitor", self)
        if os.environ.get("PULSE_ALLOW_SPEED_TESTS") != "1":
            return 0.0
        try:
            minutes = float(self.config.get("isp", {}).get("speedTestIntervalMinutes", 0))
        except (TypeError, ValueError):
            minutes = 0.0
        return minutes * 60 if minutes > 0 else 0.0

    def _router_wan_loop(self) -> None:
        self = cast("Monitor", self)
        sampler = RouterWanSampler(self._snmp_get_oids)
        previous = None
        last_unavailable = None
        while not self._stop.is_set():
            started = time.monotonic()
            with self.lock:
                config = dict(self.config.get("router", {}))
            ip = config.get("ip")
            reading = sampler.read(config)
            sampled_at = time.monotonic()
            rates = None
            if reading is None:
                if previous and previous[0][0] == ip and sampled_at - previous[2] <= 6:
                    self._stop.wait(max(0, ROUTER_SAMPLE_SECONDS - (time.monotonic() - started)))
                    continue
                previous = None
                state = "unavailable"
                source = None
            else:
                source, rx, tx, generation = reading
                identity = (ip, source, generation)
                if previous and identity == previous[0] and sampled_at - previous[2] <= 6:
                    rates = _counter_rates((rx, tx), previous[1], sampled_at - previous[2])
                previous = (identity, (rx, tx), sampled_at)
                state = "live" if rates is not None else "sampling"
            link = sampler.physical_link(config)
            marker = (ip, source, state, link) if rates is None else None
            if marker is None or marker != last_unavailable:
                live = {
                    "timestamp": utc_now(), "routerIp": ip, "status": state, "source": source,
                    "rxMbps": rates[0] if rates is not None else None,
                    "txMbps": rates[1] if rates is not None else None,
                    "physicalLink": link,
                }
                self._isp_set(routerWanThroughput=live)
                self.broadcast("router_wan_throughput", live)
            last_unavailable = marker
            self._stop.wait(max(0, ROUTER_SAMPLE_SECONDS - (time.monotonic() - started)))

    def _wan_throughput_loop(self) -> None:
        self = cast("Monitor", self)
        sampler = WanThroughputSampler()
        previous = sampler.read_counters()
        previous_id = sampler.interface_id
        previous_at = time.monotonic()
        last_identity = 0.0
        loop_started = time.monotonic()
        has_speedtest = bool(self.isp_state.get("lastSpeedTest"))
        first_auto_test_at = time.time() + (300 if has_speedtest else 8)
        history: list[dict] = []
        peak_rx = peak_tx = 0.0
        while not self._stop.wait(1.0):
            now = time.monotonic()

            if now - last_identity >= IDENTITY_REFRESH_SEC or (
                last_identity == 0.0 and now - loop_started >= 2
            ):
                last_identity = now
                threading.Thread(
                    target=self.refresh_isp_identity, daemon=True, name="isp-identity"
                ).start()

            interval = self._speedtest_interval_sec()
            if interval > 0:
                next_at = (
                    self._last_speedtest + interval
                    if self._last_speedtest
                    else first_auto_test_at
                )
                self._isp_set(nextAutoTestAt=next_at)
                if time.time() >= next_at and not self._speedtest_lock.locked():
                    self._last_speedtest = time.time()
                    threading.Thread(
                        target=self._auto_speedtest, daemon=True, name="auto-speedtest"
                    ).start()
            else:
                self._isp_set(nextAutoTestAt=None)

            current = sampler.read_counters()
            now = time.monotonic()
            rates = (
                _counter_rates(current, previous, now - previous_at)
                if current is not None and previous is not None and previous_id == sampler.interface_id
                else None
            )
            previous, previous_at, previous_id = current, now, sampler.interface_id
            if rates is None:
                history.clear()
                peak_rx = peak_tx = 0.0
                unavailable = {"timestamp": utc_now(), "source": sampler.source,
                               "rxMbps": None, "txMbps": None, "wifiSignal": {}, "history": []}
                self._isp_set(liveThroughput=unavailable)
                self.broadcast("wan_throughput", unavailable)
                continue
            rx_mbps, tx_mbps = rates
            peak_rx = max(peak_rx, rx_mbps)
            peak_tx = max(peak_tx, tx_mbps)
            point = {"t": utc_now(), "rx": rx_mbps, "tx": tx_mbps}
            history.append(point)
            del history[:-LIVE_HISTORY_POINTS]
            st = self.isp_state.get("lastSpeedTest") or {}
            live = {
                "timestamp": point["t"],
                "rxMbps": rx_mbps,
                "txMbps": tx_mbps,
                "peakRxMbps": peak_rx,
                "peakTxMbps": peak_tx,
                "source": sampler.source,
                "linkSpeedMbps": sampler.link_speed_mbps,
                "wifiSignal": sampler.wifi_signal(),
                "lastDownloadMbps": st.get("downloadMbps"),
                "lastUploadMbps": st.get("uploadMbps"),
                "history": list(history),
            }
            self._isp_set(liveThroughput=live)
            self.broadcast("wan_throughput", {k: v for k, v in live.items() if k != "history"})

    def _auto_speedtest(self) -> None:
        try:
            self.run_speedtest()
        except RuntimeError as exc:
            print(f"[monitor] Scheduled speed test failed: {exc}", flush=True)
