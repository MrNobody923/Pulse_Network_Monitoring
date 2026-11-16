# Pulse Network Monitor

**Pulse Network Monitor** is a real-time local network operations dashboard, fault-isolation monitor, and LAN game/device activity controller built with a zero-dependency Python backend, SQLite persistence, Server-Sent Events (SSE) live streaming, and a modern modular HTML/CSS/JavaScript web interface.

Designed for office and internal company networks, it translates raw network telemetry into clear, plain-English health summaries, root-cause diagnostics, interactive topology mapping, security port auditing, and real-time mobile/PC game detection with per-device shut-off enforcement.

---

## Key Features

- **Real-Time Overview & Ping/Uptime Monitor**
  - Continuous TCP/ICMP latency, jitter, packet-loss, and WAN throughput monitoring against Cloudflare (`1.1.1.1`), Google DNS (`8.8.8.8`), `google.com`, and the local gateway router.
  - Interactive 45-bar heartbeat strip, multi-series latency canvas graph, 24-hour/30-day SQLite uptime history, and live speed gauge (MB/s).
- **Wi-Fi, Switch & Router Problem Finder (Triage)**
  - Monitors office gateways, secondary routers, managed switches, and Wi-Fi access points every 30 seconds.
  - Distinguishes **device power/cable failures** (`DEVICE_DOWN`) from **upstream internet outages** (`ONLINE_NO_INTERNET`) and unstable links (`DEGRADED_LINK`), with actionable fix steps.
- **Interactive Network Map (Packet Tracer-Style Topology)**
  - Drag-and-drop visual hardware map supporting Gateways, Switches, Wi-Fi APs, Firewalls, Servers, Endpoints, and ISP Cloud nodes.
  - Click-to-wire or drag-to-connect cable types (CAT6 Ethernet, Fiber Optic, Wi-Fi Wireless, WAN), live animated PDU ping trace, automatic problem isolation highlighting, and port-level inspection.
- **Automatic LAN Discovery & Device Inventory**
  - Discovers devices across local wired and Wi-Fi subnets (`192.168.0.0/22` etc.) with MAC OUI vendor lookup, NetBIOS/mDNS/LLMNR hostname resolution, DHCP client sync, favourites, archival, CSV export, and new-device review tracking.
- **Internet & Multi-Router Fleet Telemetry**
  - Supports TP-Link LuCI and SNMPv1/v2c polling for hardware models, port link speeds/duplex status, CPU/RAM meters, and WAN status across primary and secondary routers.
- **Port Security Check (Nmap Scanner)**
  - Integrates `nmap` + fallback TCP scanning across target hosts or discovered devices with A–F security posture grading, plain-English risk explanations, remediation guidance, and raw scanner transcript output.
- **Connection Test Toolkit & Live Terminal Logs**
  - Built-in traceroute, DNS benchmark, TCP port checker, and a fixed-height scrollable PowerShell-style live event console (`tail -f`) streamed over SSE (`/api/events`).
- **Mobile & Online Game Detector + Per-User Shut-Off**
  - Automatically detects connected company phones, tablets, and PCs opening mobile or online games (Mobile Legends, Call of Duty: Mobile, PUBG Mobile, Honor of Kings, Wild Rift, Free Fire, Genshin Impact/Honkai, Clash titles, Roblox, Valorant, Minecraft, Steam titles) via the companion host sensor (`host_game_sensor.py`: UDP 53 DNS forwarder, UDP 514 Router Syslog listener, Windows process/DNS-cache/netstat checks, and LAN port sweeps).
  - Clean UI shows open games when active and provides one-click **Block Game & Cut User Wi-Fi** (per-device `0.0.0.0` DNS sinkhole with `TTL=1s`, socket RST reset, and optional TP-Link LuCI MAC blacklisting), **Block Game Only**, and **Unblock User** controls strictly scoped to the targeted device.
- **Dark, Light & Color-Blind Safe (CVD) Themes**
  - Full Dark Mode, Daylight Mode, and Okabe-Ito Color-Vision-Deficiency safe palette toggleable from the top header.

---

## Project Layout

```text
server.py                  HTTP server, REST API & SSE entrypoint (port 3000)
monitor.py                 Public Python facade exporting Monitor & config symbols
host_game_sensor.py        Host DNS (UDP 53), Syslog (UDP 514), process & port sensor
start-monitor.bat          Windows one-click launcher (Docker or native Python + Sensor)
Dockerfile                 Python 3.12-slim container image with ping, iproute2, nmap
docker-compose.yml         Container definition exposing ports 3000, 5354/udp, 5140/udp
pulse_monitor/             Modular backend package (engine, probes, discovery, topology,
                           game_detector, port_scanner, isp_speed, alerts, storage, etc.)
public/                    Frontend SPA (index.html, css/*, js/*, manifest.json)
tests/                     Python unittest regression suite
```

---

## Getting Started

### Option 1: Windows One-Click Launch
1. Install **Python 3.9+** (no external `pip` packages required for the core app) and optionally **Docker Desktop**.
2. Double-click `start-monitor.bat` (or run `python server.py` and `python host_game_sensor.py`).
3. Open **`http://localhost:3000`** in your browser.

### Option 2: Docker Compose
```bash
docker compose up -d --build
```
- Web dashboard runs at **`http://localhost:3000`**.
- Adjust `PULSE_LAN_SUBNETS`, `PULSE_ROUTER_IP`, and `TZ` in `docker-compose.yml` to match your local network.
- On Windows hosts using Docker Desktop bridge networking, run `python host_game_sensor.py` directly on the host PC so LAN client DNS (`UDP 53`) and Syslog (`UDP 514`) packets retain real client device IPs.

---

## Whole-Network Game Detection Setup
To automatically detect and enforce blocks on Wi-Fi mobile phones and tablets across your internal network:
1. Keep `host_game_sensor.py` running on the monitoring host PC.
2. Point your main router's **DHCP Primary DNS** (or individual test devices) to the monitoring host's LAN IP on **UDP port `53`**, or configure Router Syslog forwarding to **UDP port `514`**.
3. Normal internet DNS queries forward immediately to your upstream router DNS, while blocked user devices/games receive instant `0.0.0.0` sinkhole responses.
4. *(Optional)* Enter your TP-Link router credentials in **Router Settings** inside the web app to enable hardware-level MAC access-control blacklisting alongside DNS & socket enforcement.

---

## Key API Endpoints

| Method & Endpoint | Description |
|---|---|
| `GET /api/health` | Service health check |
| `GET /api/status` | Full monitor snapshot (router, ISP, devices, topology, alerts, gaming) |
| `GET /api/events` | Real-time Server-Sent Events (SSE) stream |
| `GET /api/mobile/summary` | Compact summary payload for mobile/polling clients |
| `POST /api/devices` / `PUT /api/devices/<id>` | Add or update monitored equipment |
| `POST /api/network/discover` | Trigger immediate LAN wired/Wi-Fi ARP/subnet discovery |
| `GET /api/topology` / `POST /api/topology/node` | Read or manage Packet Tracer-style topology nodes and links |
| `POST /api/tools/port-scan` | Run Nmap/TCP security port audit against a target host |
| `GET /api/gaming/activity` / `GET /api/gaming/blocks` | Live detected game sessions, online devices, and active blocks |
| `POST /api/gaming/block` / `POST /api/gaming/unblock` | Enforce or remove per-device game and Wi-Fi shut-off rules |

---

## Running Tests

```bash
python -m unittest discover -s tests -v
```

> **Security Notice:** Keep Pulse Network Monitor on a trusted internal company LAN and do not expose it directly to the public internet without an authenticating reverse proxy.
