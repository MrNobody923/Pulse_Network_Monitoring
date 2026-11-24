# Vertex Sentry verification report

November 19, 2026 · Native Windows installation at `http://localhost:3000`

The dashboard, live WAN and LAN monitoring, alerts, inventory, and connection tools responded during the audit. Router-admin telemetry and device restrictions still need verification on the installed Archer BE3600 firmware. The app is running with the fixes below.

All **67 automated tests** passed. Pyright reported zero errors, and all dashboard scripts passed JavaScript syntax checks.

## Feature results

| Area | Result | Evidence |
| --- | --- | --- |
| Dashboard, navigation, and updates | Verified live | All 11 workspaces loaded in Chrome without JavaScript exceptions. Checked mobile navigation, live events, and polling with the event stream disabled. |
| HTTP API and exports | Verified live | 23 HTTP reads returned successfully, including health, status, mobile summary, inventory CSV, alerts, topology, capture status, branding, and fallback pages. The event stream returned its initial snapshot. |
| ISP, WAN traffic, and LAN connection | Verified live | The router reported its WAN link up over UPnP. Router WAN counters and monitoring-PC interface counters updated. The gateway replied and external probes reported good health at the final check. |
| On-demand internet speed test | Verified live | The test from the monitoring PC completed at 30.9 Mbps down, 26.3 Mbps up, and 94.3 ms latency. Its result was still available after the server restart. |
| Monitored devices, inventory, and Favourites | Live reads and automated tests passed | The live dashboard showed 18 configured devices, 14 router records, and 466 inventory entries. Favourites and discovery inventory loaded in Chrome, with search verified in the earlier discovery check. Automated tests covered discovery, adding and removing devices, review, archive, and Favourites persistence. |
| Network alerts and full diagnostics | Verified live | Alerts showed the latest probe measurements and unconfirmed reachability separately. Full Diagnostics reported two slow devices, two ARP-only observations, and one device that received no reply. Archived equipment was excluded from the report totals. |
| Gateway management connection | Verified live | The Archer BE3600 at `192.168.0.1` returned an ICMP reply, accepted TCP port 80, and returned HTTP 200. |
| Router client list, physical Ethernet ports, and hardware readings | Live verification pending | The BE3600 had no authenticated session. All five Ethernet port readings were unavailable. The app displayed labelled LAN inventory, and simulated router replies verified the client parser and Ethernet speed handling. |
| Device access control and game bandwidth controls | Tested with simulated router replies | Timed block, restore, readback, and expiry paths passed automated tests. Live deny-list access and hard bandwidth limits on this firmware remain unverified. |
| Game Detector and capture | Live sensor and capture verified, detection tested with fixtures | The Windows sensor was online and Npcap captured packets. No active game session was present during the final check. Tests exercised process, DNS, packet decoding, session expiry, and game rule handling. |
| Ping and uptime history | Live data and automated tests passed | The API returned ping history, the chart loaded, and tests verified history persistence and unknown periods outside collected samples. |
| Connection tools | Verified live | Four DNS resolvers answered for `example.com`. Traceroute reached loopback in one hop and the local TCP check found the dashboard listening on port 3000. |
| Topology and event log | Live reads and automated tests passed | The configured map and event log loaded. Tests exercised node and link changes, health correlation, and topology ping in isolated data. |
| Port checks | Binary, UI, and automated tests verified | Nmap 7.993 is installed, the scanner catalog and page loaded, and tests covered Nmap result parsing and the socket fallback. |
| Switch management and SNMP | Tested with fixtures | The SNMP query and response handling passed tests. The TL-SG1016DE management IP remains unconfirmed and a live SNMP response is pending. |
| Docker Compose | Configuration valid, runtime pending | `docker compose config --quiet` passed. The Docker Desktop engine was unavailable. |

## Fixes applied

- Full Diagnostics now includes high latency and probe loss, excludes archived devices, and identifies missing Ethernet telemetry. Simulated port values are excluded from its verified port count.
- The fallback Devices page now uses the key that was actually saved for a favourite, including devices initially saved by IP. The dashboard and fallback page distinguish direct replies from ARP-only observations. Unknown devices are excluded from the Offline count.
- Game Detector now counts open ports as scan hints. They no longer create or extend game sessions or qualify for game-session restrictions. The two older open-port records in the live history appeared as hints after restart.

## Live items to confirm

- **Archer BE3600** — Connect the router admin session from **Internet → Gateway & routers → Settings** and refresh. Check the router-reported clients and Ethernet details, then verify block and restore on a spare client. Test fixed bandwidth limits only if the firmware exposes them.
- **Device identity** — The saved label for `192.168.1.77` references `.1.64`. Verify the IP and MAC against the physical equipment before changing that record.
- **Switch** — Confirm the TL-SG1016DE management IP and check its web response from **Devices**. A live SNMP test needs a device with a configured read-only community.
- **Mobile games and Docker** — Confirm game start and expiry with a spare client on a network visible to the sensor. Check container startup when the Docker Desktop engine is available.

This report combines measurements taken during the audit with automated tests. Live measurements and inventory counts can change between samples.

## Follow-up on the replaced router

A later check received an ICMP reply from `192.168.3.4` in 13 ms. Vincent confirmed it is the deployed mini PC **PC21**. The monitored record now shows **PC21** as a workstation/client device at the same IP and MAC address. A fresh probe confirmed it was online, and it remains in Favourites.

Vertex Sentry reported five reachable records with a Deco model fingerprint. Their addresses were `192.168.0.43`, `192.168.0.52`, `192.168.0.105`, `192.168.2.121`, and `192.168.2.206`. All five were already in Favourites. The offline TP-Link router at `192.168.0.212` was already archived. The follow-up could not establish which Deco replaced it.
