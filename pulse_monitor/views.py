"""Server-rendered HTML fallback views for `/devices` and `/events`."""

from __future__ import annotations

import html
from datetime import datetime


REFRESH_SECONDS = 15

PAGE_STYLE = """
:root{color-scheme:dark;--bg:#0b1120;--panel:#111a2b;--panel2:#0e1728;--line:#223149;--text:#e7edf7;--muted:#91a0b7;--cyan:#32c5dc;--green:#32c48d;--red:#f16b75;--amber:#f2b84b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",Arial,sans-serif}
.layout{min-height:100vh}.side{position:fixed;inset:0 auto 0 0;width:230px;padding:26px 16px;background:#0e1727;border-right:1px solid var(--line);display:flex;flex-direction:column}
.brand{padding:0 10px 28px;color:var(--text);font-size:20px;font-weight:750}.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:2px}
.label{padding:0 12px 10px;color:#66758d;font-size:10px;font-weight:700;letter-spacing:1.6px}
.nav a{display:block;padding:11px 13px;margin:4px 0;border-radius:9px;color:var(--muted);text-decoration:none;font-weight:600}.nav a:hover,.nav a.active{background:#122b3b;color:var(--cyan)}
.side-foot{margin-top:auto;border-top:1px solid var(--line);padding:14px 12px;color:var(--muted);font-size:12px}
.workspace{margin-left:230px}.top{min-height:68px;padding:12px clamp(20px,4vw,48px);display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:#0b1120}
.top-title{font-size:14px;font-weight:700}.live{color:var(--green);font-size:12px;font-weight:700}
main{max-width:1450px;margin:auto;padding:32px clamp(18px,4vw,48px) 60px}.heading{margin-bottom:22px}.heading h1{margin:0;font-size:30px;letter-spacing:-.7px}.heading p{margin:6px 0 0;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:20px}.cards-lan{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:16px}.metric,.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px}
.metric{padding:15px 16px;height:100%}.metric span{display:block;color:var(--muted);font-size:12px;font-weight:600}.metric strong{display:block;margin-top:8px;font-size:26px;line-height:1.1}.metric small{display:block;margin-top:7px;color:#71819b;font-size:11px}
.metric-link{display:block;color:inherit;text-decoration:none;border-radius:13px}.metric-link:hover .metric,.metric-link.active .metric{border-color:var(--cyan);background:#132238}.metric-link:hover .metric{transform:translateY(-1px)}
.filter-pills{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}.filter-pill{display:inline-block;padding:6px 12px;border-radius:20px;border:1px solid var(--line);background:var(--panel2);color:var(--muted);font-size:12px;font-weight:600;text-decoration:none}.filter-pill:hover,.filter-pill.active{border-color:var(--cyan);color:var(--cyan);background:#122b3b}
.list-row-num{color:#66758d;font-size:12px;font-weight:600;width:36px}
.red{color:var(--red)!important}.green{color:var(--green)!important}.amber{color:var(--amber)!important}.cyan{color:var(--cyan)!important}
.panel{margin:0 0 18px;padding:21px 22px}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:15px;flex-wrap:wrap}
.panel h2{margin:0;font-size:17px}.muted{color:var(--muted)}.actions{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
button,.button{border:1px solid #2a405d;border-radius:8px;background:#15243a;color:var(--text);font:inherit;font-size:12px;font-weight:600;padding:9px 13px;cursor:pointer;text-decoration:none}
button:hover,.button:hover{border-color:var(--cyan);color:var(--cyan)}.primary{background:#087d9b;border-color:#087d9b;color:white}
.table-wrap{width:100%;overflow-x:hidden;border:1px solid var(--line);border-radius:9px}table{width:100%;border-collapse:collapse;table-layout:fixed;min-width:0}th,td{text-align:left;padding:10px 9px;border-bottom:1px solid var(--line);font-size:12.5px;vertical-align:middle;overflow-wrap:anywhere;word-break:break-word}th{background:var(--panel2);color:#8292aa;font-size:10px;text-transform:uppercase;letter-spacing:1px}tr:last-child td{border-bottom:0}tbody tr:hover{background:#142036}
.device-name{font-weight:650}.sub{display:block;color:var(--muted);font-size:11px;margin-top:2px}.pill{display:inline-block;padding:3px 8px;border-radius:30px;background:#1a293d;color:#bdc9da;font-size:10px;font-weight:700;max-width:100%;white-space:normal}
.pill.online{color:var(--green);background:#123128}.pill.offline{color:var(--red);background:#3a202a}.pill.warning{color:var(--amber);background:#392e19}.pill.new{color:var(--cyan);background:#12313c}
.inline-form{display:inline}.star{font-size:16px;padding:4px 8px}.star.on{color:#f2b84b;border-color:#68532a;background:#342b19}.actions-cell{white-space:normal}
.empty{padding:24px;text-align:center;color:var(--muted)}.notice{margin:0 0 18px;padding:12px 15px;border:1px solid #286273;border-radius:9px;background:#112936;color:#c7f3fa}
.form-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;align-items:end}.field label{display:block;margin-bottom:5px;color:var(--muted);font-size:11px}.field input,.field select{width:100%;padding:10px;border:1px solid #2a405d;border-radius:7px;background:#0b1423;color:var(--text);font:inherit}
.footnote{color:#74839a;font-size:11px;margin-top:10px}.split{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:1100px){.cards{grid-template-columns:repeat(3,minmax(130px,1fr))}}
@media(max-width:760px){.side{position:sticky;inset:auto;width:auto;padding:10px 13px;border-right:0;border-bottom:1px solid var(--line)}.brand{padding:0 4px 10px}.brand small,.label,.side-foot{display:none}.nav{display:flex;gap:4px;overflow-x:auto}.nav a{flex:none;padding:8px 10px;font-size:12px}.workspace{margin:0}.top{min-height:48px;padding:10px 16px}main{padding:22px 14px 40px}.heading h1{font-size:25px}.panel{padding:16px}.split{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr 1fr}}
@media(max-width:430px){.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.metric{padding:13px}.metric strong{font-size:23px}.form-grid{grid-template-columns:1fr}}
"""


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _timestamp(value: object) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone()
        return parsed.strftime("%b %d, %Y %H:%M")
    except ValueError:
        return str(value)


def dashboard_rows(snapshot: dict) -> list[dict]:
    inventory_by_ip: dict[str, dict] = {}
    for item in snapshot["networkInventory"]:
        if item.get("ip") and item["ip"] not in inventory_by_ip:
            inventory_by_ip[item["ip"]] = item
    rows = []
    monitored_ips = set()
    for device in snapshot["devices"]:
        ip = device["ip"]
        monitored_ips.add(ip)
        asset = inventory_by_ip.get(ip, {})
        rows.append({
            "name": device["name"],
            "ip": ip,
            "mac": device.get("mac") or asset.get("mac", ""),
            "vendor": asset.get("vendor", device.get("type", "Monitored device")),
            "status": device.get("status", "unknown"),
            "monitored": True,
            "online": device.get("alive") is True
            or device.get("status") in {"online", "warning"},
            "favorite": bool(device.get("favorite") or asset.get("favorite")),
            "archived": bool(device.get("archived") or asset.get("archived")),
            "favorite_key": (
                f"mac:{device.get('mac') or asset.get('mac')}"
                if device.get("mac") or asset.get("mac")
                else f"ip:{ip}"
            ),
            "authorized": True,
            "is_new": False,
            "first_seen": asset.get("firstSeen", ""),
            "last_seen": asset.get("lastSeen") or device.get("lastChecked", ""),
        })
    for asset in snapshot["networkInventory"]:
        if asset["ip"] in monitored_ips:
            continue
        rows.append({
            "name": asset.get("name") or asset["ip"],
            "ip": asset["ip"],
            "mac": asset.get("mac", ""),
            "vendor": asset.get("vendor") or "LAN Client",
            "status": "online" if asset.get("isOnline") else "offline",
            "online": bool(asset.get("isOnline")),
            "monitored": False,
            "favorite": bool(asset.get("favorite")),
            "favorite_key": (
                f"mac:{asset['mac']}" if asset.get("mac") else f"ip:{asset['ip']}"
            ),
            "authorized": bool(asset.get("authorized")),
            "archived": bool(asset.get("archived")),
            "is_new": bool(asset.get("isNew") and not asset.get("authorized")),
            "first_seen": asset.get("firstSeen", ""),
            "last_seen": asset.get("lastSeen", ""),
        })
    return sorted(
        rows,
        key=lambda row: (
            0 if row["status"] == "offline" else 1,
            0 if row["favorite"] else 1,
            row["name"].casefold(),
        ),
    )


def render_table(
    rows: list[dict], filter_by: str = "all", return_to: str = "/devices"
) -> str:
    if filter_by == "all":
        rows = [row for row in rows if not row["archived"]]
    elif filter_by == "connected":
        rows = [row for row in rows if row["online"] and not row["archived"]]
    elif filter_by == "favorites":
        rows = [row for row in rows if row["favorite"] and not row["archived"]]
    elif filter_by == "new":
        rows = [row for row in rows if row["is_new"] and not row["archived"]]
    elif filter_by == "down":
        rows = [
            row
            for row in rows
            if row["monitored"] and row["status"] == "offline" and not row["archived"]
        ]
    elif filter_by == "offline":
        rows = [row for row in rows if not row["online"] and not row["archived"]]
    elif filter_by == "disconnected":
        rows = [
            row
            for row in rows
            if not row["monitored"] and not row["online"] and not row["archived"]
        ]
    elif filter_by == "archived":
        rows = [row for row in rows if row["archived"]]

    if not rows:
        text = {
            "connected": "No devices are connected right now.",
            "favorites": "No devices have been marked as favourites.",
            "new": "No new devices are awaiting review.",
            "down": "No monitored devices are down.",
            "offline": "No devices are currently offline.",
            "disconnected": "No disconnected LAN assets were found.",
            "archived": "No devices have been archived.",
        }.get(filter_by, "No devices have been discovered yet.")
        return f'<div class="empty">{_e(text)}</div>'

    output = [
        '<div class="table-wrap"><table><thead><tr>'
        '<th style="width:4%">#</th>'
        '<th style="width:18%">Device (List View)</th>'
        '<th style="width:11%">IP address</th>'
        '<th style="width:13%">MAC address</th>'
        '<th style="width:12%">Type / vendor</th>'
        '<th style="width:12%">Status</th>'
        '<th style="width:11%">Last seen</th>'
        '<th style="width:7%">Favourite</th>'
        '<th style="width:12%">Actions</th>'
        "</tr></thead><tbody>"
    ]
    for index, row in enumerate(rows, start=1):
        status = row["status"]
        status_class = (
            "offline"
            if status == "offline"
            else ("online" if status in {"online", "warning"} else "warning")
        )
        status_label = {
            "offline": "DOWN" if row["monitored"] else "OFFLINE / DISCONNECTED",
            "online": "CONNECTED",
            "warning": "DEGRADED",
            "unknown": "WAITING",
        }.get(status, str(status).upper())
        badges = f'<span class="pill {status_class}">{_e(status_label)}</span>'
        if row["is_new"]:
            badges += ' <span class="pill new">NEW</span>'
        if row["archived"]:
            badges += ' <span class="pill warning">ARCHIVED</span>'
        favorite_class = "star on" if row["favorite"] else "star"
        output.append(
            "<tr>"
            f'<td class="list-row-num">{index}</td>'
            f'<td><span class="device-name">{_e(row["name"])}</span>'
            f'<span class="sub">{"Monitored equipment" if row["monitored"] else "Discovered LAN / Wi-Fi asset"}</span></td>'
            f'<td>{_e(row["ip"])}</td><td>{_e(row["mac"] or "—")}</td>'
            f'<td>{_e(row["vendor"])}</td><td>{badges}</td>'
            f'<td>{_e(_timestamp(row["last_seen"] or row.get("last_checked")))}</td>'
            '<td><form class="inline-form" method="post" action="/actions/favorite">'
            f'<input type="hidden" name="asset_key" value="{_e(row["favorite_key"])}">'
            f'<input type="hidden" name="return_to" value="{_e(return_to)}">'
            f'<button class="{favorite_class}" title="Toggle favourite" aria-label="Toggle favourite">'
            f'{"★" if row["favorite"] else "☆"}</button></form></td>'
        )
        output.append('<td class="actions-cell">')
        if not row["authorized"] and row["mac"]:
            output.append(
                '<form class="inline-form" method="post" action="/actions/authorize">'
                f'<input type="hidden" name="mac" value="{_e(row["mac"])}">'
                f'<input type="hidden" name="return_to" value="{_e(return_to)}">'
                "<button type=\"submit\">Review</button></form> "
            )
        else:
            output.append('<span class="muted">—</span> ')
        output.append(
            '<form class="inline-form" method="post" action="/actions/archive">'
            f'<input type="hidden" name="asset_key" value="{_e(row["favorite_key"])}">'
            f'<input type="hidden" name="return_to" value="{_e(return_to)}">'
            f'<button type="submit">{"Restore" if row["archived"] else "Archive"}</button></form>'
        )
        output.append("</td></tr>")
    output.append("</tbody></table></div>")
    return "".join(output)


def render_page(
    monitor_instance: object,
    path: str,
    message: str = "",
    filter_by: str = "all",
) -> str:
    snapshot = monitor_instance.snapshot()
    rows = dashboard_rows(snapshot)
    active_rows = [row for row in rows if not row["archived"]]
    archived_rows = [row for row in rows if row["archived"]]
    favorite_count = sum(1 for row in active_rows if row["favorite"])
    connected_count = sum(1 for row in active_rows if row["online"])
    disconnected_assets = [
        row for row in active_rows if not row["monitored"] and not row["online"]
    ]
    down_count = sum(
        1 for row in active_rows if row["monitored"] and row["status"] == "offline"
    )
    offline_count = sum(1 for row in active_rows if not row["online"])
    new_count = sum(1 for row in active_rows if row["is_new"])

    title, subtitle = {
        "/devices": (
            "Devices & LAN assets",
            "Row-by-row vertical list of monitored equipment and discovered network clients.",
        ),
        "/events": (
            "Network event history",
            "Recent discovery, outage, recovery, and device-change records.",
        ),
    }.get(
        path,
        (
            "Network overview",
            "Live device health, daily LAN scan status, and row-by-row asset list.",
        ),
    )
    nav = [
        ("/", "Overview"),
        ("/devices", "Devices & LAN Assets"),
        ("/events", "Event history"),
    ]
    nav_html = "".join(
        f'<a class="{"active" if path == href or (href == "/" and path not in {"/devices", "/events"}) else ""}" href="{href}">{label}</a>'
        for href, label in nav
    )
    notice = f'<div class="notice">{_e(message)}</div>' if message else ""
    last_scan = _timestamp(monitor_instance.last_discovery_at())
    target_path = "/devices" if path == "/devices" else "/"
    return_to = f"{target_path}?filter={filter_by}"

    overview_stats = [
        (
            "All devices",
            len(active_rows),
            "All active devices connected/known on the network",
            "",
            "all",
        ),
        (
            "Connected currently",
            connected_count,
            "Devices online and responding right now",
            "green",
            "connected",
        ),
        (
            "Favourites",
            favorite_count,
            "Starred priority devices",
            "amber",
            "favorites",
        ),
        (
            "New devices",
            new_count,
            "Newly discovered devices today",
            "cyan" if new_count else "",
            "new",
        ),
        (
            "Down",
            down_count,
            "Monitored equipment failing checks",
            "red" if down_count else "green",
            "down",
        ),
        (
            "Disconnected",
            len(disconnected_assets),
            "LAN assets not seen on latest scan",
            "amber" if disconnected_assets else "",
            "disconnected",
        ),
        (
            "Archived devices",
            len(archived_rows),
            "Devices stored in the archive list",
            "",
            "archived",
        ),
    ]
    overview_cards = "".join(
        f'<a class="metric-link{" active" if filter_by == key else ""}" href="{target_path}?filter={key}">'
        f'<div class="metric"><span>{_e(label)}</span><strong class="{color}">{_e(value)}</strong>'
        f"<small>{_e(note)}</small></div></a>"
        for label, value, note, color, key in overview_stats
    )

    lan_asset_stats = [
        (
            "Overall users & devices",
            len(active_rows),
            f"{connected_count} connected now · {len(active_rows)} total active",
            "",
            "all",
        ),
        (
            "Down devices",
            down_count,
            "Monitored devices failing probes",
            "red" if down_count else "green",
            "down",
        ),
        (
            "Offline",
            offline_count,
            f"{down_count} down · {len(disconnected_assets)} disconnected",
            "amber" if offline_count else "green",
            "offline",
        ),
        (
            "New devices",
            new_count,
            "New devices detected in daily scan",
            "cyan" if new_count else "",
            "new",
        ),
        (
            "Favourites",
            favorite_count,
            "Starred favourite devices",
            "amber",
            "favorites",
        ),
    ]
    lan_asset_cards = "".join(
        f'<a class="metric-link{" active" if filter_by == key else ""}" href="{target_path}?filter={key}#lan-assets">'
        f'<div class="metric"><span>{_e(label)}</span><strong class="{color}">{_e(value)}</strong>'
        f"<small>{_e(note)}</small></div></a>"
        for label, value, note, color, key in lan_asset_stats
    )

    filter_tabs = [
        ("all", f"All devices ({len(active_rows)})"),
        ("connected", f"Connected currently ({connected_count})"),
        ("favorites", f"Favourites ({favorite_count})"),
        ("new", f"New devices ({new_count})"),
        ("down", f"Down ({down_count})"),
        ("offline", f"Offline ({offline_count})"),
        ("disconnected", f"Disconnected ({len(disconnected_assets)})"),
        ("archived", f"Archived ({len(archived_rows)})"),
    ]
    pills_html = "".join(
        f'<a class="filter-pill{" active" if filter_by == key else ""}" href="{target_path}?filter={key}#lan-assets">{_e(label)}</a>'
        for key, label in filter_tabs
    )

    content = [
        notice,
        f'<div class="heading"><h1>{_e(title)}</h1><p>{_e(subtitle)}</p></div>',
    ]
    if path == "/devices":
        content.append(
            f'<section class="cards">{overview_cards}</section>'
            '<section class="panel" id="lan-assets"><div class="panel-head"><div>'
            "<h2>LAN asset inventory (List View)</h2>"
            f'<div class="footnote">Automatic daily scan: Active (runs every 24h) · Last completed scan: {_e(last_scan)}</div>'
            '</div><div class="actions"><form method="post" action="/actions/discover">'
            f'<input type="hidden" name="return_to" value="{_e(return_to)}">'
            '<button class="primary" type="submit">Scan local LAN now</button></form>'
            '<a class="button" href="/api/network/inventory/export">Export CSV</a></div></div>'
            f'<div class="cards-lan">{lan_asset_cards}</div>'
            f'<div class="filter-pills">{pills_html}</div>'
            f"{render_table(rows, filter_by, return_to)}</section>"
            '<section class="panel"><div class="panel-head"><div><h2>Add a monitored device</h2>'
            '<div class="footnote">Reachability checks run every 30 seconds; devices that fail TCP and ICMP checks appear as DOWN.</div></div></div>'
            '<form method="post" action="/actions/add-device" class="form-grid">'
            '<div class="field"><label for="name">Name</label><input id="name" name="name" required maxlength="120"></div>'
            '<div class="field"><label for="ip">IP address</label><input id="ip" name="ip" required inputmode="decimal"></div>'
            '<div class="field"><label for="port">TCP port</label><input id="port" name="port" type="number" min="1" max="65535" value="80" required></div>'
            '<div class="field"><label for="type">Device type</label><select id="type" name="type"><option>device</option><option>ap</option><option>switch</option><option>gateway</option><option>server</option></select></div>'
            '<button class="primary" type="submit">Add device</button></form></section>'
        )
    elif path == "/events":
        events = snapshot["networkEvents"]
        if events:
            event_rows = [
                {
                    "name": event.get("title", "Network event"),
                    "ip": event.get("ip") or "—",
                    "mac": event.get("mac") or "—",
                    "vendor": event.get("eventType", ""),
                    "status": (
                        "warning" if event.get("severity") == "WARNING" else "online"
                    ),
                    "monitored": False,
                    "online": True,
                    "favorite": False,
                    "favorite_key": "",
                    "authorized": True,
                    "is_new": False,
                    "first_seen": "",
                    "last_seen": event.get("timestamp"),
                    "message": event.get("message", ""),
                }
                for event in events
            ]
            event_markup = (
                '<div class="table-wrap"><table><thead><tr>'
                "<th>Event</th><th>IP address</th><th>MAC address</th><th>Type</th><th>Time</th>"
                "</tr></thead><tbody>"
                + "".join(
                    f'<tr><td><span class="device-name">{_e(row["name"])}</span>'
                    f'<span class="sub">{_e(row["message"])}</span></td>'
                    f'<td>{_e(row["ip"])}</td><td>{_e(row["mac"])}</td>'
                    f'<td>{_e(row["vendor"])}</td><td>{_e(_timestamp(row["last_seen"]))}</td></tr>'
                    for row in event_rows
                )
                + "</tbody></table></div>"
            )
        else:
            event_markup = '<div class="empty">No network events have been recorded.</div>'
        content.append(
            f'<section class="panel"><div class="panel-head"><h2>Latest events</h2></div>{event_markup}</section>'
        )
    else:
        content.append(f'<section class="cards">{overview_cards}</section>')
        content.append(
            '<section class="panel"><div class="panel-head"><div><h2>Down monitored devices</h2>'
            '<div class="footnote">Device availability checks run every 30 seconds.</div></div>'
            '<a class="button" href="/devices?filter=down">View down devices</a></div>'
            f'{render_table(rows, "down", return_to)}</section>'
        )
        content.append(
            '<section class="panel" id="lan-assets"><div class="panel-head"><div><h2>LAN asset discovery (List View)</h2>'
            f'<div class="footnote">Automatic daily wired &amp; Wi-Fi LAN scan enabled (every 24h) · Last completed: {_e(last_scan)}</div></div>'
            '<div class="actions"><form method="post" action="/actions/discover">'
            f'<input type="hidden" name="return_to" value="{_e(return_to)}">'
            '<button class="primary" type="submit">Scan local LAN now</button></form>'
            '<a class="button" href="/devices">Open full device page</a></div></div>'
            f'<div class="cards-lan">{lan_asset_cards}</div>'
            f'<div class="filter-pills">{pills_html}</div>'
            f"{render_table(rows, filter_by, return_to)}"
            '<div class="footnote">Daily discovery automatically scans connected private wired/Wi-Fi subnets and highlights newly connected devices.</div>'
            "</section>"
        )
        recent_events = snapshot["networkEvents"][:8]
        if recent_events:
            event_markup = "".join(
                f'<tr><td>{_e(_timestamp(event.get("timestamp")))}</td>'
                f'<td>{_e(event.get("title"))}</td><td>{_e(event.get("deviceName") or event.get("ip") or "—")}</td>'
                f'<td>{_e(event.get("severity"))}</td></tr>'
                for event in recent_events
            )
            content.append(
                '<section class="panel"><div class="panel-head"><h2>Recent activity</h2>'
                '<a class="button" href="/events">All events</a></div>'
                '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Device</th><th>Severity</th></tr></thead>'
                f"<tbody>{event_markup}</tbody></table></div></section>"
            )

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="refresh" content="{REFRESH_SECONDS}">'
        f"<title>{_e(title)} · Pulse Network Monitor</title>"
        f'<style>{PAGE_STYLE}</style></head><body><div class="layout">'
        '<aside class="side"><div class="brand">Pulse<small>NETWORK MONITOR</small></div>'
        '<div class="label">WORKSPACE</div><nav class="nav" aria-label="Main navigation">'
        f"{nav_html}</nav><div class=\"side-foot\">Python monitoring · refreshing every {REFRESH_SECONDS}s</div></aside>"
        '<div class="workspace"><header class="top"><div class="top-title">Network operations</div>'
        '<span class="live">● MONITORING</span></header><main>'
        f'{"".join(content)}</main></div></div></body></html>'
    )

