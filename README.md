# Vertex Sentry

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Django 5.2](https://img.shields.io/badge/Django-5.2-0C4B33.svg)](https://docs.djangoproject.com/en/5.2/)
[![Docker Ready](https://img.shields.io/badge/docker-compose%20ready-2496ed.svg)](docker-compose.yml)
[![Live SSE Telemetry](https://img.shields.io/badge/streaming-Server--Sent%20Events-orange.svg)](#key-features)

**Vertex Sentry** is a real-time local network operations center (NOC) dashboard, fault-isolation monitor, and internal LAN device activity manager. Built with a **Django web backend**, persistent **SQLite (WAL mode)**, **Server-Sent Events (SSE)** live telemetry streaming, and a responsive **modular HTML5/CSS3/ES6 web interface**.

Designed for company offices and internal networks, Vertex Sentry translates complex raw network packets, SNMP/HTTP counters, and telemetry into clear, plain-English health summaries, root-cause diagnostics, interactive topology maps, port security audits, and real-time mobile/PC game detection with per-user shut-off enforcement.

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
       │   * Host game process detection and DNS filtering    │
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
       │   * Nmap Port Checks & Exposure Review            │
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
- Probes gateways, secondary routers, managed switches, and Wi-Fi access points at the configured monitor interval.
- Distinguishes probe results:
  - **`DEVICE_DOWN`**: TCP and ICMP received no reply.
  - **`ONLINE_NO_INTERNET`**: The local device replied and the monitor's external checks failed.
  - **`DEGRADED_LINK`**: The device's response time or probe loss exceeds a configured threshold.
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
- Checks selected TCP/IPv4 ports from the monitor with optional Nmap service detection.
- Reports open, closed, filtered, and unconfirmed counts and identifies the evidence behind service names and review flags.
- Copy the scan transcript, retest individual ports, or rerun a saved scan with its original profile and timeout.

### 7. Mobile & Online Game Detector + Per-User Shut-Off
- **Live Windows detection:** Recognized local Windows game processes appear automatically and their sessions end when the processes close.
- **Steam client:** The Game Detector tracks when `steam.exe` starts and exits on the monitoring PC or an enrolled Windows endpoint. Steam network traffic is shown separately.
- **Network detection:** DNS, router logs, and packet capture can identify recent game traffic on phones and other devices when the monitor can see it.
- **Port hints:** Listening ports are counted separately during scans and do not create game sessions.
- **Desktop alerts:** Open Game Detector on localhost or HTTPS and choose **Enable desktop alerts**. Keep the dashboard tab open to receive new game detections. Desktop alerts identify a recognized Windows game process as an opening and recognized network signals as game activity.
- **Scrollable Live Terminal Console:** Displays timestamped detection and enforcement events with terminal styling and auto-scroll controls.
- **Dismiss** hides the current session from the live list until the game closes or its network activity expires.
- **Limit Bandwidth** sets separate upload and download limits for a confirmed client for a selected duration.
- **Block Device Access** requests a temporary device-wide deny-list entry on a compatible main router.

---

## Project Structure

```text
server.py                  Dashboard entry point
start-monitor.bat          Windows launcher
monitor.py                 Public Python interface to the monitor
host_game_sensor.py        Windows host sensor and managed endpoint CLI
android_game_sensor.py     Android foreground game sensor CLI
pulse_monitor/
    runtime.py             Django listener and worker startup/shutdown
    django_settings.py     Django host and middleware settings
    urls.py, http_handler.py   Dashboard, sensor APIs, and event stream
    engine.py, storage.py  Monitor coordinator and SQLite persistence
    discovery.py, probes.py, diagnostics.py, operations.py
    alerts.py, topology.py, port_scanner.py
    isp_speed.py, router_wan.py, router_game_control.py
    game_detector.py, wireshark_capture.py
public/                    Dashboard HTML, JavaScript, styles, and icons
tests/                     Regression tests organized by feature
docs/                      Dated verification reports
data/                      Local database, captures, and device configuration
```

Run the regression suite and Django configuration check from the repository root:

```shell
python -m unittest discover -s tests
python -m django check --settings=pulse_monitor.django_settings
```

The [November 19 verification report](docs/verification-2026-11-19.md) records the results from that installation.

---

## Quick Start Guide

### Option 1: Native Windows Quick Launch
1. Ensure **Python 3.10+** is installed on your machine.
2. Double-click `start-monitor.bat` (or run in PowerShell/CMD):
   ```powershell
   python -m pip install -r requirements.txt
   python server.py
   ```
3. Open **`http://localhost:3000`**. Both Windows launch methods start the host game sensor automatically. Packet capture uses Npcap or TShark when available. Set `PULSE_HOST_GAME_SENSOR=0` before launch if you run a separate sensor on the same host.

### Option 2: Docker Compose
```bash
docker compose up -d --build
```
- Web dashboard: **`http://localhost:3000`**

The native dashboard listens on loopback by default. Docker Compose publishes port 3000 on host loopback. For managed endpoints or operators on other hosts, use a TLS reverse proxy on the monitor host. Restrict dashboard routes to authenticated operators and expose the endpoint enrollment route only to managed clients. Set `PULSE_BIND_HOST` for a different trusted bind address. Set `PULSE_ALLOWED_HOSTS` to the comma-separated hostnames or IP addresses used by remote clients. Start with `server.py` so the Django listener and monitor workers share one process. Set `PULSE_TSHARK_PATH` on the machine running the relevant process to use a custom TShark executable.
- Adjust `PULSE_LAN_SUBNETS` and `PULSE_ROUTER_IP` in `docker-compose.yml` to match your local subnet.
- Run `python host_game_sensor.py` on the Windows host to report its local game processes to the container.

## Checking a device connection

Open **Devices**, select a monitored or discovered device by name, and choose **Check now**. Vertex Sentry sends one ICMP echo check, tests the configured TCP port, and checks a known management web service with an HTTP HEAD request. The panel shows the HTTP status and timing when there is a reply, including status codes such as 401 and 405. **Open management page** appears when a web management endpoint is known.

From the local dashboard, expand **Read device information via SNMP** and enter the device's read-only SNMP v1/v2c community. Vertex Sentry can read the reported name, description, agent uptime, and interface count. The entry is cleared after submission and is used for that request only. SNMP v1/v2c sends the community in cleartext on the management network.

To find and save devices, open **Devices → Discover LAN devices**. Search the saved inventory by name, IP, MAC, or vendor, or choose **Scan LAN** to refresh it. Select a star to save that device and **View Favourites** to show the saved devices.

## Device history and upstream outages

Open **Devices → History** on a device row to see its inventory observations and recent events. The timeline matches observed MAC addresses and monitored device IDs. Clearing the event log also clears the timeline events. **Needs review** keeps discovered records in the inbox until you approve or ignore them. **Ignored** lets you return a device to review. These actions change the inventory status only.

For a monitored device, use **History → Confirmed upstream device** to select the monitored router, switch, or access point it relies on. Alerts group concurrent probe failures along these saved dependencies. Each downstream alert retains its own probe results and actions. Grouping follows current checks, so the group clears when the upstream recovers.

Open **Alerts → Incident details** in the toolbar to choose an active or recently resolved incident. Active incidents show current probe evidence, the last inventory observation, and related alerts. Use **Copy summary** to hand the incident to another operator. Under **Maintenance & notifications**, schedule a window for one device or all monitored equipment. Checks continue during maintenance. Unconfirmed results, simulations, and downstream members of a correlated incident are excluded from notifications. A sustained incident becomes eligible after 60 seconds. A recovery notice follows only if an outage notice was recorded.

Notifications appear in the app. To also send email, set `PULSE_SMTP_HOST`, `PULSE_ALERT_EMAIL_FROM`, and `PULSE_ALERT_EMAIL_TO` on the server. Set `PULSE_SMTP_PORT` for a STARTTLS port other than 587 and `PULSE_SMTP_USER` and `PULSE_SMTP_PASSWORD` if the relay requires login. The app shows delivery status in the notifications list.

For a monitored switch, open **Devices → Switch ports**. Enter a read-only SNMP v1/v2c community and the switch's IF-MIB interface indices. The table shows reported link state, speed, error totals, and drop totals. Changes are shown when the switch provides enough evidence to compare counters across samples. For background polling, set `PULSE_SWITCH_SNMP` on the server to a JSON object keyed by switch IP, with `community` and `indices` for each switch. For example, `{"192.168.0.10":{"community":"YOUR-READ-ONLY-COMMUNITY","indices":[1,2,3,4]}}`. Use a management network for v1/v2c because it transmits the community in cleartext.

The default probe interval is 15 seconds for gateways, routers, switches, and firewalls, 30 seconds for APs and servers, and 60 seconds for clients. A first failed check schedules a follow-up in about five seconds. Devices shows the age and normal cadence of the latest check.

## Monitoring-only defaults

Vertex Sentry reads the monitoring PC's interface counters about once per second and sends small reachability checks to the main router and external targets. The **Main router WAN traffic** card samples the router separately. It uses the configured router's UPnP WAN counters when available, or 64-bit SNMP counters when **SNMP WAN Interface Index** is set to the router's WAN `ifIndex`. If the router provides neither source, the card shows **WAN counters unavailable**. Select **Test Internet Speed Now** to measure the monitoring PC's path to Cloudflare and save the result and timestamp. Scheduled speed tests, automatic LAN sweeps, DNS forwarding, and automatic game restrictions are off by default. Passive packet capture, router logs, and managed endpoint reports still feed live game alerts.

Open **Internet → Gateway & routers** for WAN probe quality, WAN physical link status, the monitoring PC's LAN link and Wi-Fi signal, and router Ethernet ports. Router clients and port details depend on the admin session. Use the main router's **Settings** to connect it, then select **Refresh main gateway**. Timed **Block access** from the connected-device list requires a confirmed router client and enabled deny-list mode. **Restore access** verifies removal of the app's rule. Vertex Sentry must stay running to restore automatically at expiry.

In the local **Game Detector** dashboard, **Limit Bandwidth** and **Block Device Access** require a current detection, a confirmed client identity, and an authenticated main router that exposes compatible controls. Vertex Sentry reads back each change before showing it as applied. Use **Restore Access** to remove it early. Vertex Sentry attempts restoration at expiry and retries when router verification is unavailable. If Vertex Sentry is stopped or the router session expires, restore the device in the router interface or reconnect Vertex Sentry so it can retry. Test both applying and restoring access with a spare client before using production devices.

If clients currently use Vertex Sentry as their DNS server, restore their normal DNS settings before upgrading to these defaults. Use **Unblock** to remove any rules previously applied to a router.

Speed tests default to on demand. Set `PULSE_ALLOW_SPEED_TESTS=0` to disable them entirely, or set `PULSE_ALLOW_SPEED_TESTS=1` to also honor a configured schedule. Other optional settings are `PULSE_ENABLE_BACKGROUND_SCANS=1`, `PULSE_ENABLE_DNS_FORWARDING=1`, and `PULSE_ALLOW_NETWORK_CHANGES=1`. Set a flag on the process that performs the action. For container DNS forwarding, an opt-in Compose override must also publish UDP port 5354.

---

## Setting Up Whole-Network Game Detection

Open **Game Detector → Detection coverage** to see the configured subnets, per-subnet counts from the last LAN scan, and detection evidence by IP. Discovery can observe devices even when no detection signal is available. Updated process-only Windows sensors send a heartbeat every 30 seconds while they can read the signed-in session, including when no game is open. Recent endpoint and DNS evidence expire after 90 seconds.

The same subnet configuration controls general LAN discovery. Give the Vertex Sentry host a route to every managed subnet and allow the ICMP and management ports used by your devices from the Vertex Sentry host. Use **LAN Discovery** to see each subnet's ICMP replies and addresses observed through the local ARP cache. A missing reply means Vertex Sentry did not observe that address through its scan. The topology's **Test Ping** checks reachability from Vertex Sentry, and the saved map path represents the links entered in the dashboard.

1. Set `PULSE_LAN_SUBNETS` on the central monitor to a comma-separated list of the managed IPv4 subnets, for example `192.168.0.0/24,10.20.40.0/24,10.20.50.0/24`. Enter larger ranges as multiple /22 or smaller subnets. The central monitor needs a network route to each subnet it probes.
2. Open **Game Detector** and run the topology scan to refresh discovery, router DHCP clients, and reachable game ports. A game port identifies a listening service on a device. Use endpoint reports for Windows game launches.
3. Keep `host_game_sensor.py` running on the monitoring host PC. Send router logs or mirrored traffic with the original client IP to detect supported mobile game traffic. Devices can keep using their usual DNS resolver. A regular Wi-Fi connection to the same network does not give the monitor visibility into every client's traffic.
4. For Windows account attribution, use your endpoint management or logon tooling to start the process-only sensor on each managed Windows PC **as the signed-in user**. It opens no listening ports and only reports recognized processes in that Windows session. Set the same `PULSE_GAME_ENDPOINT_TOKEN` secret on the central monitor and the enrolled PCs. Set the central monitor's token before startup. Behind a TLS reverse proxy, have the proxy connect to Vertex Sentry over loopback and restrict dashboard access to operators.

   ```powershell
   python host_game_sensor.py --process-only --api-url https://pulse.example.org/api/gaming/endpoint
   ```

   Run the command against your own Vertex Sentry URL. Direct connections use the reporting PC's source IP, so route between subnets without NAT if the detector needs to identify individual clients. The Game Detector can filter by Windows account, device, game, or IP.

### Verify an Android game launch

On the monitoring PC, use [Google Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools) and connect one authorized Android phone by USB. Keep the phone on a monitored Wi-Fi subnet. Enable USB debugging in Developer options and approve the connection on the unlocked phone.

```powershell
python android_game_sensor.py
```

Use `--adb C:\path\to\adb.exe` if ADB is outside PATH, or `--phone-ip` with the phone's current Wi-Fi IPv4 address if automatic detection fails. Open a supported game and look for **App open** with **Android foreground app** in **Game Detector → Live activity**. Switch to the Home screen to end the detection. The sensor sends only recognized game package IDs and the phone's Wi-Fi address to the local monitor. Press Ctrl+C to stop the sensor.

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
