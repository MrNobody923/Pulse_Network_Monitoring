# Pulse Network Monitor

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-0%20pip%20packages-brightgreen.svg)](https://docs.python.org/3/library/)
[![Docker Ready](https://img.shields.io/badge/docker-compose%20ready-2496ed.svg)](docker-compose.yml)
[![Live SSE Telemetry](https://img.shields.io/badge/streaming-Server--Sent%20Events-orange.svg)](#key-features)

**Pulse Network Monitor** is a real-time local network operations center (NOC) dashboard, fault-isolation monitor, and internal LAN device activity manager. Built with a **zero-dependency Python standard library backend**, persistent **SQLite (WAL mode)**, **Server-Sent Events (SSE)** live telemetry streaming, and a responsive **modular HTML5/CSS3/ES6 web interface**.

Designed for company offices and internal networks, Pulse translates complex raw network packets, SNMP/HTTP counters, and telemetry into clear, plain-English health summaries, root-cause diagnostics, interactive topology maps, port security audits, and real-time mobile/PC game detection with per-user shut-off enforcement.

---

## Architecture Overview

```text
       ┌────────────────────────────────────────────────────────┐
       │              Internal Office / Company LAN             │
       │  (PCs, Workstations, Mobile Phones, Tablets, IoT, APs) │
       └───────────────────────────┬────────────────────────────┘
                                   │
                     DHCP DNS (UDP 53) / Syslog (514)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │      host_game_sensor.py (Companion Detection Daemon)  │
       │   * Transparent DNS Forwarder & Sinkhole (UDP 53)      │
       │   * Router Syslog Event Collector (UDP 514)            │
       │   * Windows Process & Socket Inspector                 │
       │   * Targeted TCP RST Drop & Process Terminate          │
       └───────────────────────────┬────────────────────────────┘
                                   │ HTTP POST Telemetry
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │           server.py / pulse_monitor (Core Engine)       │
       │   * Multi-target TCP/ICMP Probes (Gateway/DNS/WAN)     │
       │   * Multi-Router Fleet Telemetry (TP-Link LuCI / SNMP) │
       │   * Cloudflare Edge Speed & WAN Throughput Sampler     │
       │   * Automatic ARP / Subnet Discovery Engine            │
       │   * Intelligent Outage & Triage Rule Evaluator         │
       │   * SQLite Persistence (WAL Mode) in data/network.db   │
       └───────────────────────────┬────────────────────────────┘
                                   │ SSE /api/events & REST APIs
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │          Web Management Dashboard (Vanilla JS SPA)     │
       │   * Real-Time Ping Heartbeats & Line Speedometer       │
       │   * Interactive Packet Tracer-Style Topology Canvas    │
       │   * Multi-Router Cable Port Speeds & Fleet Meters      │
       │   * Nmap Port Security Audits & Risk Posture (A-F)     │
       │   * Live Gaming Activity Console & One-Click Block/Cut │
       │   * Dark, Light & Color-Blind Safe (CVD) Themes        │
       └────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. Real-Time Ping, SLA Heartbeats & Bandwidth Speedometer
- **Multi-Target Internet Gateway Probing:** Continuous TCP/ICMP latency, jitter, and packet loss checks against Cloudflare (`1.1.1.1`), Google DNS (`8.8.8.8`), `google.com`, and the local office router (`192.168.0.1`).
- **Verified Line Speed vs Live NIC Throughput:**
  - Accurately measures true internet line bandwidth via multi-stream HTTPS download/upload tests against Cloudflare's speed edge.
  - Live throughput sampler reads hardware NIC octet counters once per second without overwriting verified line speeds with idle background traffic.
  - Persists bandwidth benchmarks across restarts in SQLite metadata.
- **Interactive SLA Heartbeats:** 45-pill historical strip and high-resolution timeseries graph with per-target hover tooltips and 24-hour/30-day uptime statistics.

### 2. Wi-Fi, Switch & Router Problem Finder (Intelligent Triage)
- Probes gateways, secondary routers, managed switches, and Wi-Fi access points every 30 seconds.
- Automatically isolates root causes to distinguish:
  - **`DEVICE_DOWN`**: Hardware power cuts or disconnected Ethernet cables.
  - **`ONLINE_NO_INTERNET`**: Upstream ISP or DNS outages where LAN equipment is healthy.
  - **`DEGRADED_LINK`**: Packet loss, cable link duplex mismatches, or jitter spikes.
- Generates plain-English diagnostic explanations and step-by-step resolution guides.

### 3. Interactive Packet Tracer-Style Network Topology Map
- **Visual Hardware Layout:** Drag-and-drop canvas supporting Gateways, Switches, Access Points, Firewalls, Servers, Workstations, and ISP Cloud nodes.
- **Dynamic Cabling:** Click-to-wire or drag-to-connect with CAT6 Ethernet, Fiber Optic, Wi-Fi Wireless, and WAN links.
- **Live Diagnostics & Ping Simulation:** Real-time animated PDU packet flow, problem isolation highlighting, port inspection, and JSON topology export/import.

### 4. Multi-Router Fleet & Port Link Speed Monitoring
- Polling for TP-Link LuCI routers and SNMPv1/v2c network equipment.
- Tracks physical Ethernet cable link speeds (1000 Mbps Full Duplex vs degraded 100 Mbps Half Duplex).
- Monitors hardware health: CPU utilization, RAM usage, Wi-Fi client counts, and public WAN IP status.

### 5. Automatic LAN Discovery & Device Inventory
- Scans wired and Wi-Fi subnets (e.g. `192.168.0.0/22`) using non-intrusive ARP sweeps and ICMP echo.
- Automatic IEEE OUI MAC vendor identification, NetBIOS, mDNS, and LLMNR hostname resolution.
- Device tagging: Favorites, Archival, New Device Reviews, and CSV inventory export.

### 6. Port Security Check (Nmap Scanner)
- Comprehensive TCP port auditing with fallback socket scanning for environments without binary Nmap.
- Plain-English security posture ratings (**Grade A through F**) with risk explanations for exposed management interfaces (SSH, Telnet, SMB, RDP, HTTP/HTTPS).
- Raw terminal transcript viewer and targeted device remediation steps.

### 7. Mobile & Online Game Detector + Per-User Shut-Off
- **Automatic Multi-Vector Game Detection:** Detects popular mobile and online games (*Mobile Legends, Call of Duty: Mobile, PUBG Mobile, Honor of Kings, Wild Rift, Free Fire, Genshin Impact, Clash of Clans, Roblox, Valorant, Minecraft, Steam*) in real time.
- **Zero Dropdown Automation:** Displays active games automatically as they are opened across internal devices.
- **Scrollable Live Terminal Console:** Displays timestamped detection and enforcement events with terminal styling and auto-scroll controls.
- **Per-User Shut-Off Enforcement:**
  - **`Block Game & Cut User Wi-Fi`**: Issues an instant `0.0.0.0` DNS sinkhole (`TTL=1s`), drops active TCP sockets via TCP RST, terminates host game processes, and optionally pushes MAC address blacklisting rules to TP-Link routers via LuCI.
  - **Strict Per-User Scoping:** Other internal employees and devices remain completely unaffected.

---

## Project Structure

```text
├── server.py                  # Main HTTP server & REST/SSE application entry point (port 3000)
├── monitor.py                 # Public Python facade exporting Monitor engine & config symbols
├── host_game_sensor.py        # Companion sensor for DNS (UDP 53), Syslog (514), and sockets
├── start-monitor.bat          # Windows one-click launcher (Python + Sensor daemon)
├── Dockerfile                 # Multi-stage lightweight Python container image
├── docker-compose.yml         # Container configuration with volume mounts & port forwards
├── pulse_monitor/             # Modular monitoring engine package
│   ├── engine.py              # Central Monitor coordinator & orchestration
│   ├── alerts.py              # Outage alerting & threshold tracking
│   ├── config.py              # Configuration defaults & network validation utilities
│   ├── diagnostics.py         # Network triage & root-cause correlation
│   ├── discovery.py           # LAN ARP/ICMP subnet discovery & NetBIOS resolver
│   ├── game_detector.py       # Game telemetry, DNS sinkholing & Wi-Fi cutoff logic
│   ├── http_handler.py        # REST API endpoints, routing & SSE broadcaster
│   ├── isp_speed.py           # Cloudflare bandwidth testing & live throughput sampler
│   ├── port_scanner.py        # Nmap XML parser & socket scanner
│   ├── probes.py              # Multi-target ping engine & router telemetry
│   ├── storage.py             # SQLite database layer (WAL mode)
│   └── topology.py            # Topology node/link persistence & PDU simulator
├── public/                    # Frontend Single-Page Application (SPA)
│   ├── index.html             # Main dashboard layout
│   ├── css/                   # Modular stylesheet architecture
│   │   ├── base.css           # Design tokens, variables & typography
│   │   ├── components.css     # Buttons, cards, modals & status pills
│   │   ├── isp-speedtest.css  # Speedometer, ISP diagnostics & SLA heartbeat styles
│   │   ├── nmap-scanner.css   # Security auditor & terminal styling
│   │   ├── topology.css       # Topology canvas & interactive wiring controls
│   │   └── modals.css         # Config modals & dialog windows
│   └── js/                    # Modular JavaScript application
│       ├── app.js             # Application bootstrapper & SSE event handlers
│       ├── state.js           # Central reactive state store & API fetch client
│       ├── audio.js           # Audio alert notifications
│       ├── overview-lan.js    # LAN device inventory & discovery views
│       ├── alerts-router.js   # Alerts panel & multi-router fleet metrics
│       ├── charts-timeline.js # Timeseries latency graphs & Uptime Kuma cards
│       ├── isp-speedtest.js   # Live animated speedometer & ISP diagnostics
│       ├── nmap-scanner.js    # Security port scanner controls & risk grades
│       ├── topology.js        # Topology graph interactions, drag-and-drop & cabling
│       ├── game-detector.js   # Gaming terminal console & block enforcement controls
│       └── modals-tools.js    # Diagnostics wizard, traceroute & dialog helpers
├── tests/                     # Unit & integration regression test suite
│   └── test_monitor.py        # 25 comprehensive automated test cases
└── data/                      # Persistent storage directory
    └── network.db             # SQLite database file (auto-created)
```

---

## Quick Start Guide

### Option 1: Native Windows Quick Launch
1. Ensure **Python 3.9+** is installed on your machine.
2. Double-click `start-monitor.bat` (or run in PowerShell/CMD):
   ```powershell
   python server.py
   ```
3. In a second administrative terminal (to enable UDP port 53 DNS forwarder):
   ```powershell
   python host_game_sensor.py
   ```
4. Access the web dashboard at **`http://localhost:3000`**.

### Option 2: Docker Compose
```bash
docker compose up -d --build
```
- Web dashboard: **`http://localhost:3000`**
- Adjust `PULSE_LAN_SUBNETS` and `PULSE_ROUTER_IP` in `docker-compose.yml` to match your local subnet.

---

## Setting Up Whole-Network Game Detection

To detect and enforce game restrictions on mobile phones and tablets across your company Wi-Fi:
1. Keep `host_game_sensor.py` running on the monitoring host PC.
2. Set your main office router's **DHCP Primary DNS** to the IP of the monitoring host PC (port `53`).
3. *(Optional)* Configure your router's Syslog forwarding to send connection logs to the host PC on **UDP port `514`**.
4. *(Optional)* Open **Router Settings** in the dashboard and enter your TP-Link router credentials to allow automated MAC blacklisting alongside DNS sinkholing.

---

## Key REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service uptime and heartbeat health check |
| `GET` | `/api/status` | Complete system snapshot (ISP, routers, inventory, alerts) |
| `GET` | `/api/events` | Server-Sent Events (SSE) live telemetry stream |
| `GET` | `/api/mobile/summary` | Compact JSON payload optimized for mobile/polling clients |
| `POST` | `/api/devices` | Enroll new hardware into active 30s monitoring |
| `PUT` | `/api/devices/<id>` | Update monitored hardware details or threshold settings |
| `POST` | `/api/network/discover` | Trigger immediate LAN ARP/ICMP subnet discovery |
| `POST` | `/api/speedtest/run` | Execute on-demand Cloudflare internet bandwidth test |
| `GET` | `/api/topology` | Retrieve topology nodes, cables, and layout configuration |
| `POST` | `/api/topology/node` | Add or update a topology node on the canvas |
| `POST` | `/api/topology/link` | Connect equipment with Ethernet, Fiber, or Wi-Fi links |
| `POST` | `/api/tools/port-scan` | Run an Nmap/TCP security port audit against target IP |
| `GET` | `/api/gaming/activity` | Retrieve live detected game sessions and online devices |
| `GET` | `/api/gaming/blocks` | List active per-user game and Wi-Fi blocks |
| `POST` | `/api/gaming/block` | Enforce instant game block or user Wi-Fi shut-off |
| `POST` | `/api/gaming/unblock` | Restore network access for a previously restricted device |

---

## Automated Test Suite

Run the full automated unit test suite to verify storage, discovery, alerts, game detection, and topology:

```bash
python -m unittest discover -s tests -v
```

All 25 test cases execute against an in-memory or isolated test database and complete in ~15 seconds.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
