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
import subprocess
import threading
import time
import urllib.request

if os.name == "nt":
    import ctypes.wintypes

from .config import utc_now

SPEED_HOST = "speed.cloudflare.com"
DOWNLOAD_STREAMS = 6
UPLOAD_STREAMS = 4
DOWNLOAD_SECONDS = 10.0
UPLOAD_SECONDS = 8.0
DOWNLOAD_CHUNK_BYTES = 25_000_000
UPLOAD_BODY_BYTES = 8_000_000
MAX_TEST_BYTES = 600_000_000  # hard data cap per phase
RAMP_UP_FRACTION = 0.25  # ignore TCP slow-start at the beginning of each phase
LIVE_HISTORY_POINTS = 120
IDENTITY_REFRESH_SEC = 600
USER_AGENT = "PulseNetworkMonitor/1.0 (+speedtest)"


def _https_connection(timeout: float) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(
        SPEED_HOST, 443, timeout=timeout, context=ssl.create_default_context()
    )


def _server_duration_ms(response: http.client.HTTPResponse) -> float:
    """Cloudflare reports its own processing time; subtract it from the RTT."""
    header = response.getheader("Server-Timing") or ""
    match = re.search(r"dur=([\d.]+)", header)
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
                        "edgeColo": meta.get("timezone") or country or None,
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
            self.source = f"{alias} (Live NIC)"
            if row.ReceiveLinkSpeed:
                self.link_speed_mbps = round(row.ReceiveLinkSpeed / 1_000_000, 1)
            return int(row.InOctets), int(row.OutOctets)
        except (AttributeError, OSError, ValueError):
            return None

    def read_counters(self) -> tuple[int, int] | None:
        try:
            if os.name == "nt":
                win_pair = self._read_win32_primary_nic()
                if win_pair is not None:
                    return win_pair
                self.source = "netstat -e"
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
            rx = tx = 0
            with open("/proc/net/dev", encoding="utf-8") as handle:
                for line in handle.readlines()[2:]:
                    name, data = line.split(":", 1)
                    if name.strip() == "lo":
                        continue
                    fields = data.split()
                    rx += int(fields[0])
                    tx += int(fields[8])
            return rx, tx
        except (OSError, ValueError, subprocess.SubprocessError):
            return None


def _counter_delta(current: int, previous: int) -> int | None:
    delta = current - previous
    if delta >= 0:
        return delta
    if previous < 2**32:  # 32-bit counter wrapped
        return current + 2**32 - previous
    return None


class IspSpeedMixin:
    """Real-time ISP speed test, ISP identity, and live throughput for the Monitor."""

    # ------------------------------------------------------------------ helpers
    def _isp_set(self, **values) -> None:
        with self.lock:
            self.isp_state.update(values)

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
        try:
            for attempt in range(samples + 1):
                started = time.perf_counter()
                conn.request(
                    "GET", "/__down?bytes=0", headers={"User-Agent": USER_AGENT}
                )
                response = conn.getresponse()
                response.read()
                elapsed = (time.perf_counter() - started) * 1000
                if attempt == 0:
                    continue  # first request includes TCP + TLS handshakes
                rtts.append(max(0.1, elapsed - _server_duration_ms(response)))
        finally:
            conn.close()
        if not rtts:
            raise RuntimeError("Latency measurement failed")
        ordered = list(rtts)  # jitter from consecutive samples in measurement order
        rtts.sort()
        ping = round(rtts[len(rtts) // 2], 1)  # median
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
        counters = [0] * streams
        errors: list[str] = []
        stop = threading.Event()

        def download_worker(index: int) -> None:
            while not stop.is_set():
                conn = _https_connection(10)
                try:
                    conn.request(
                        "GET",
                        f"/__down?bytes={DOWNLOAD_CHUNK_BYTES}",
                        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
                    )
                    response = conn.getresponse()
                    if response.status != 200:
                        errors.append(f"HTTP {response.status}")
                        stop.wait(0.5)
                        continue
                    while not stop.is_set():
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        counters[index] += len(chunk)
                except (OSError, http.client.HTTPException) as exc:
                    errors.append(str(exc))
                    stop.wait(0.5)
                finally:
                    conn.close()

        payload = b"\0" * (64 * 1024)

        def upload_worker(index: int) -> None:
            while not stop.is_set():
                conn = _https_connection(10)
                try:
                    conn.putrequest("POST", "/__up")
                    conn.putheader("User-Agent", USER_AGENT)
                    conn.putheader("Content-Type", "application/octet-stream")
                    conn.putheader("Content-Length", str(UPLOAD_BODY_BYTES))
                    conn.endheaders()
                    sent = 0
                    while sent < UPLOAD_BODY_BYTES and not stop.is_set():
                        piece = payload[: min(len(payload), UPLOAD_BODY_BYTES - sent)]
                        conn.send(piece)
                        sent += len(piece)
                        counters[index] += len(piece)
                    if sent >= UPLOAD_BODY_BYTES:
                        conn.getresponse().read()
                except (OSError, http.client.HTTPException) as exc:
                    errors.append(str(exc))
                    stop.wait(0.5)
                finally:
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
                if elapsed >= duration or total >= MAX_TEST_BYTES:
                    break
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=3)

        end_time, end_bytes = samples[-1]
        if end_bytes < 256 * 1024:
            detail = f" ({errors[-1]})" if errors else ""
            raise RuntimeError(
                f"Could not reach {SPEED_HOST} to measure {phase} speed{detail}. "
                "Check that the internet connection is up and the server is allowed outbound HTTPS."
            )
        ramp_cut = end_time * RAMP_UP_FRACTION
        ramp_time, ramp_bytes = next(s for s in samples if s[0] >= ramp_cut)
        steady_seconds = max(end_time - ramp_time, 0.001)
        return round((end_bytes - ramp_bytes) * 8 / steady_seconds / 1_000_000, 1)

    def run_speedtest(self) -> dict:
        if not self._speedtest_lock.acquire(blocking=False):
            raise RuntimeError("A speed test is already running — results will stream in shortly.")
        self._last_speedtest = time.time()
        self._isp_set(speedTestRunning=True, speedTestError=None)
        try:
            self.broadcast(
                "speedtest_progress",
                {
                    "phase": "ping",
                    "phaseLabel": "Identifying ISP & measuring latency...",
                    "message": f"Connecting to {SPEED_HOST} and identifying your ISP...",
                    "currentMbps": 0.0,
                    "progressPct": 3,
                },
            )
            identity = self.refresh_isp_identity()
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
            download = self._run_transfer_phase(
                "download", DOWNLOAD_STREAMS, DOWNLOAD_SECONDS, 10, 50, base
            )
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
                "server": f"Cloudflare {identity.get('edgeColo') if identity else ''}".strip(),
                "provider": (identity or {}).get("provider"),
                "publicIp": (identity or {}).get("publicIp"),
                "method": f"{DOWNLOAD_STREAMS}x HTTPS download / {UPLOAD_STREAMS}x HTTPS upload streams",
            }
            with self.lock:
                self.isp_state["lastSpeedTest"] = result
                history = self.isp_state.setdefault("speedHistory", [])
                history.append(result)
                del history[:-24]
                self.isp_state["diagnosis"] = self._build_isp_diagnosis(
                    overall=self.isp_state.get("overallHealth", "GOOD"),
                    score=int(self.isp_state.get("healthScore") or 80),
                    gw_alive=True,
                    gw_latency=self.isp_state.get("wanGatewayLatencyMs"),
                    wan_latency=self.isp_state.get("tier1LatencyMs") or ping_ms,
                    jitter_ms=jitter_ms,
                    loss_pct=int(self.isp_state.get("packetLossPct") or 0),
                    dns_ms=self.isp_state.get("dnsResolutionMs"),
                    last_speed=result,
                )
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
                ip=identity.get("publicIp") or "",
                device_name="ISP Internet Uplink",
            )
            self.broadcast("speedtest_result", result)
            return result
        except Exception as exc:
            self._isp_set(speedTestError=str(exc))
            self._record_event(
                "SPEED_TEST",
                "WARNING",
                "Internet Speed Test Failed",
                str(exc),
                device_name="ISP Internet Uplink",
            )
            self.broadcast(
                "speedtest_progress",
                {"phase": "error", "message": str(exc), "progressPct": 0},
            )
            raise RuntimeError(str(exc)) from exc
        finally:
            self._isp_set(speedTestRunning=False)
            self._speedtest_lock.release()

    # -------------------------------------------------- live throughput loop
    def _speedtest_interval_sec(self) -> float:
        try:
            minutes = float(self.config.get("isp", {}).get("speedTestIntervalMinutes", 0))
        except (TypeError, ValueError):
            minutes = 0.0
        return minutes * 60 if minutes > 0 else 0.0

    def _wan_throughput_loop(self) -> None:
        sampler = WanThroughputSampler()
        previous = sampler.read_counters()
        previous_at = time.monotonic()
        last_identity = 0.0
        loop_started = time.monotonic()
        has_speedtest = bool(self.isp_state.get("lastSpeedTest"))
        first_auto_test_at = time.time() + (300 if has_speedtest else 8)
        history: list[dict] = []
        peak_rx = peak_tx = 0.0
        while not self._stop.is_set():
            self._stop.wait(1.0)
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
            if current is None or previous is None:
                previous, previous_at = current, now
                continue
            seconds = max(now - previous_at, 0.001)
            rx_delta = _counter_delta(current[0], previous[0])
            tx_delta = _counter_delta(current[1], previous[1])
            previous, previous_at = current, now
            if rx_delta is None or tx_delta is None:
                continue
            rx_mbps = round(rx_delta * 8 / seconds / 1_000_000, 2)
            tx_mbps = round(tx_delta * 8 / seconds / 1_000_000, 2)
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
