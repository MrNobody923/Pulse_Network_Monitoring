"""Interactive company network map management, cable path checks, and live problem tracking."""

from __future__ import annotations

import uuid
from collections import deque

from .config import utc_now, validate_ip, validate_port

VALID_NODE_TYPES = {
    "cloud",
    "gateway",
    "router",
    "switch",
    "ap",
    "firewall",
    "server",
    "device",
}
VALID_CABLE_TYPES = {"copper", "fiber", "wireless", "wan"}


class TopologyMixin:
    """Persists custom network topology nodes/links and correlates live down/problem states."""

    def _topology_store(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS topology_nodes (
                    id TEXT PRIMARY KEY,
                    device_id TEXT,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '',
                    node_type TEXT NOT NULL DEFAULT 'device',
                    port INTEGER NOT NULL DEFAULT 80,
                    location TEXT NOT NULL DEFAULT '',
                    vendor TEXT NOT NULL DEFAULT '',
                    x REAL NOT NULL DEFAULT 360,
                    y REAL NOT NULL DEFAULT 180,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS topology_links (
                    id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    cable_type TEXT NOT NULL DEFAULT 'copper',
                    source_port TEXT NOT NULL DEFAULT '',
                    target_port TEXT NOT NULL DEFAULT '',
                    label TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _clean_node_type(value: object) -> str:
        t = str(value or "device").strip().lower()
        if t == "isp":
            return "cloud"
        if t in VALID_NODE_TYPES:
            return t
        return "device"

    @staticmethod
    def _clean_cable_type(value: object) -> str:
        c = str(value or "copper").strip().lower()
        return c if c in VALID_CABLE_TYPES else "copper"

    @staticmethod
    def _default_cable_and_ports(
        src_node: dict,
        dst_node: dict,
        requested_cable: object,
        existing_links: list[dict],
    ) -> tuple[str, str, str]:
        req = str(requested_cable or "").strip().lower()
        st = str(src_node.get("node_type") or "device").lower()
        dt = str(dst_node.get("node_type") or "device").lower()
        if req in VALID_CABLE_TYPES:
            cable_type = req
        elif st == "cloud" or dt == "cloud":
            cable_type = "wan"
        elif st in {"ap", "device"} or dt in {"ap", "device"}:
            cable_type = "wireless"
        else:
            cable_type = "copper"

        def next_port(nid: str, ntype: str, peer_type: str) -> str:
            used = sum(
                1
                for ln in existing_links
                if ln.get("source_id") == nid or ln.get("target_id") == nid
            )
            idx = used + 1
            if ntype == "cloud":
                return "ISP"
            if peer_type == "cloud" and ntype in {"gateway", "router", "firewall"}:
                return "WAN"
            if cable_type == "wireless" and ntype in {"ap", "device"}:
                return "Wi-Fi" if ntype == "device" else f"WLAN{idx}"
            if ntype in {"gateway", "router", "firewall"}:
                return f"Gi0/{idx}"
            if ntype == "switch":
                return f"Port {idx}"
            return f"Eth{idx - 1}" if idx > 1 else "Eth0"

        return (
            cable_type,
            next_port(src_node["id"], st, dt),
            next_port(dst_node["id"], dt, st),
        )

    def _raw_topology_nodes(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM topology_nodes ORDER BY created_at ASC, name ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def _raw_topology_links(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM topology_links ORDER BY created_at ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def _classify_node_health(
        self,
        raw_node: dict,
        devices_by_id: dict[str, dict],
        devices_by_ip: dict[str, dict],
        inventory_by_ip: dict[str, dict],
    ) -> dict:
        node_type = raw_node["node_type"]
        ip = raw_node.get("ip") or ""
        device_id = raw_node.get("device_id") or ""
        mon_dev = devices_by_id.get(device_id) or (devices_by_ip.get(ip) if ip else None)
        inv_dev = inventory_by_ip.get(ip) if ip else None

        health_state = "unknown"
        status_label = "PROBING"
        alive = None
        has_internet = None
        latency_ms = None
        packet_loss = None
        open_ports: list[int] = []
        mac = ""
        vendor = raw_node.get("vendor") or ""
        diag_title = ""
        likely_fault = ""
        diag_summary = ""
        fix_steps: list[str] = []
        last_checked = ""

        if node_type == "cloud" and not mon_dev:
            isp = self.get_isp_state()
            isp_health = str(isp.get("overallHealth") or "UNKNOWN").upper()
            latency_ms = isp.get("tier1LatencyMs")
            packet_loss = isp.get("packetLossPct")
            isp_diag = isp.get("diagnosis") or {}
            if isp_health == "OUTAGE":
                health_state = "down"
                status_label = "WAN DOWN"
                alive = False
                has_internet = False
                likely_fault = isp_diag.get("bottleneckLayer") or "ISP Fiber / Modem Outage"
                diag_summary = isp_diag.get("summary") or "External ISP backbone probes timed out."
                fix_steps = list(isp_diag.get("solutions") or [])
            elif isp_health == "DEGRADED":
                health_state = "degraded"
                status_label = "DEGRADED"
                alive = True
                has_internet = True
                likely_fault = isp_diag.get("bottleneckLayer") or "ISP High Latency / Loss"
                diag_summary = isp_diag.get("summary") or "Elevated WAN packet loss or RTT."
                fix_steps = list(isp_diag.get("solutions") or [])
            elif isp_health in {"EXCELLENT", "GOOD"}:
                health_state = "online"
                status_label = "ISP ONLINE"
                alive = True
                has_internet = True
                diag_summary = isp_diag.get("summary") or "ISP uplink responding normally."
            else:
                health_state = "unknown"
                status_label = "PROBING"
        elif mon_dev is not None:
            alive = mon_dev.get("alive")
            has_internet = mon_dev.get("hasInternet")
            latency_ms = mon_dev.get("latencyMs")
            packet_loss = mon_dev.get("packetLossPct")
            open_ports = list(mon_dev.get("openPorts") or [])
            mac = mon_dev.get("mac") or (inv_dev.get("mac", "") if inv_dev else "")
            vendor = vendor or mon_dev.get("vendor") or (inv_dev.get("vendor", "") if inv_dev else "")
            diag_title = mon_dev.get("diagnosisTitle") or ""
            likely_fault = mon_dev.get("likelyFault") or ""
            diag_summary = mon_dev.get("diagnosisSummary") or ""
            fix_steps = list(mon_dev.get("fixSteps") or [])
            last_checked = mon_dev.get("lastChecked") or ""
            conn_state = mon_dev.get("connectivityState") or ""
            dev_status = mon_dev.get("status") or "unknown"

            if dev_status == "offline" or conn_state == "DEVICE_DOWN":
                health_state = "down"
                status_label = "DEVICE DOWN"
            elif conn_state == "ONLINE_NO_INTERNET":
                health_state = "no_internet"
                status_label = "NO INTERNET"
            elif dev_status == "warning" or conn_state == "DEGRADED_LINK":
                health_state = "degraded"
                status_label = "DEGRADED"
            elif dev_status == "online" or alive is True:
                health_state = "online"
                status_label = "ONLINE"
            else:
                health_state = "unknown"
                status_label = "PROBING"
        elif inv_dev is not None:
            mac = inv_dev.get("mac") or ""
            vendor = vendor or inv_dev.get("vendor") or ""
            last_checked = inv_dev.get("lastSeen") or ""
            if inv_dev.get("isOnline"):
                wan_up = self._is_wan_internet_up()
                alive = True
                has_internet = wan_up
                if wan_up:
                    health_state = "online"
                    status_label = "ONLINE (ARP)"
                    diag_summary = "Host seen active on LAN ARP scan."
                else:
                    health_state = "no_internet"
                    status_label = "NO INTERNET"
                    likely_fault = "Upstream WAN / ISP Outage"
                    diag_summary = "Host is active on local LAN, but upstream ISP WAN is down."
            else:
                alive = False
                has_internet = False
                health_state = "disconnected"
                status_label = "DISCONNECTED"
                likely_fault = "Host Unplugged / Off Wi-Fi / Powered Off"
                diag_summary = "Not seen in recent ARP/ICMP LAN scan."
                fix_steps = [
                    f"Verify {raw_node['name']} ({ip}) is powered on and connected to Ethernet/Wi-Fi.",
                    "Check switch link LEDs or enroll for 30s active probing.",
                ]

        is_problem = health_state in {"down", "disconnected", "no_internet", "degraded"}
        return {
            **raw_node,
            "deviceId": mon_dev.get("id") if mon_dev else device_id,
            "monitored": mon_dev is not None,
            "mac": mac,
            "vendor": vendor,
            "alive": alive,
            "hasInternet": has_internet,
            "healthState": health_state,
            "statusLabel": status_label,
            "isProblem": is_problem,
            "latencyMs": latency_ms,
            "packetLossPct": packet_loss,
            "openPorts": open_ports,
            "diagnosisTitle": diag_title,
            "likelyFault": likely_fault,
            "diagnosisSummary": diag_summary,
            "fixSteps": fix_steps,
            "lastChecked": last_checked,
        }

    def get_topology(self) -> dict:
        raw_nodes = self._raw_topology_nodes()
        raw_links = self._raw_topology_links()
        hydrated_devices = self._hydrated_devices()
        devices_by_id = {d["id"]: d for d in hydrated_devices if d.get("id")}
        devices_by_ip = {d["ip"]: d for d in hydrated_devices if d.get("ip")}
        inventory_by_ip: dict[str, dict] = {}
        for item in self.get_inventory():
            if item.get("ip") and item["ip"] not in inventory_by_ip:
                inventory_by_ip[item["ip"]] = item

        nodes = [
            self._classify_node_health(n, devices_by_id, devices_by_ip, inventory_by_ip)
            for n in raw_nodes
        ]
        node_map = {n["id"]: n for n in nodes}

        links: list[dict] = []
        severity_rank = {
            "down": 5,
            "disconnected": 4,
            "no_internet": 3,
            "degraded": 2,
            "unknown": 1,
            "online": 0,
        }
        for ln in raw_links:
            src = node_map.get(ln["source_id"])
            dst = node_map.get(ln["target_id"])
            if not src or not dst:
                continue
            s_state = src["healthState"]
            d_state = dst["healthState"]
            worst = s_state if severity_rank.get(s_state, 0) >= severity_rank.get(d_state, 0) else d_state
            links.append({
                "id": ln["id"],
                "sourceId": ln["source_id"],
                "targetId": ln["target_id"],
                "sourceName": src["name"],
                "targetName": dst["name"],
                "cableType": ln["cable_type"],
                "sourcePort": ln.get("source_port") or "",
                "targetPort": ln.get("target_port") or "",
                "label": ln.get("label") or "",
                "sourceState": s_state,
                "targetState": d_state,
                "linkHealth": worst,
            })

        topo_ips = {n["ip"] for n in nodes if n.get("ip")}
        all_events = self.get_events(120)
        topo_logs = [
            ev
            for ev in all_events
            if (ev.get("ip") and ev["ip"] in topo_ips)
            or str(ev.get("eventType") or "").startswith(("TOPOLOGY_", "WAN_", "ROUTER_"))
        ][:60]

        summary = {
            "totalNodes": len(nodes),
            "totalLinks": len(links),
            "online": sum(1 for n in nodes if n["healthState"] == "online"),
            "down": sum(1 for n in nodes if n["healthState"] == "down"),
            "disconnected": sum(1 for n in nodes if n["healthState"] == "disconnected"),
            "noInternet": sum(1 for n in nodes if n["healthState"] == "no_internet"),
            "degraded": sum(1 for n in nodes if n["healthState"] == "degraded"),
            "unknown": sum(1 for n in nodes if n["healthState"] == "unknown"),
        }
        summary["problemCount"] = (
            summary["down"]
            + summary["disconnected"]
            + summary["noInternet"]
            + summary["degraded"]
        )

        return {
            "nodes": nodes,
            "links": links,
            "summary": summary,
            "logs": topo_logs,
        }

    def add_topology_node(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Invalid topology node payload")
        name = str(payload.get("name") or "").strip()[:120]
        node_type = self._clean_node_type(payload.get("nodeType") or payload.get("type"))
        raw_ip = str(payload.get("ip") or "").strip()
        ip = validate_ip(raw_ip) if raw_ip else ""
        if not ip and node_type != "cloud":
            raise ValueError("A valid IP address is required for network devices")
        if not name:
            name = ip or ("ISP Fiber Uplink" if node_type == "cloud" else "Network Device")

        port = validate_port(payload.get("port") or 80) if ip else 80
        location = str(payload.get("location") or "").strip()[:120]
        vendor = str(payload.get("vendor") or "").strip()[:80]
        device_id = str(payload.get("deviceId") or "").strip()
        monitor_device = payload.get("monitorDevice", True)

        existing_nodes = self._raw_topology_nodes()
        if ip and any(n.get("ip") == ip for n in existing_nodes):
            raise ValueError(f"A topology node with IP {ip} already exists on the map")

        # Enroll or link to monitored device so active 30s probing + down alerts work automatically
        if ip and monitor_device and node_type != "cloud":
            monitored = self.get_devices()
            matched = next(
                (d for d in monitored if (device_id and d["id"] == device_id) or d["ip"] == ip),
                None,
            )
            if matched is None:
                added_dev = self.add_device({
                    "name": name,
                    "ip": ip,
                    "type": "gateway" if node_type == "router" else node_type,
                    "port": port,
                    "location": location or "Office Topology",
                    "critical": bool(payload.get("critical", node_type in {"gateway", "router", "switch", "ap", "firewall"})),
                })
                device_id = added_dev["id"]
                probe_res = self.probe_device(added_dev)
                self.latest_devices[ip] = probe_res
                self.enrich_fleet_diagnostics(list(self.latest_devices.values()))
            else:
                device_id = matched["id"]
                if not location:
                    location = matched.get("location") or ""
                if not vendor:
                    vendor = matched.get("vendor") or ""

        # Compute clean default grid coordinates if x/y not specified
        count = len(existing_nodes)
        try:
            x = float(payload["x"]) if payload.get("x") is not None else float(160 + (count % 5) * 185)
            y = float(payload["y"]) if payload.get("y") is not None else float(110 + (count // 5) * 145)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid coordinates for topology node") from exc

        node_id = f"topo-{uuid.uuid4().hex[:10]}"
        now = utc_now()
        with self._connect() as db:
            db.execute(
                """INSERT INTO topology_nodes
                   (id, device_id, name, ip, node_type, port, location, vendor, x, y, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (node_id, device_id, name, ip, node_type, port, location, vendor, x, y, now),
            )

        self._record_event(
            "TOPOLOGY_NODE_ADDED",
            "INFO",
            f"Topology device added: {name}",
            f"Added {node_type.upper()} node {name}" + (f" ({ip})" if ip else "") + " to Network Topology.",
            ip=ip,
            device_name=name,
        )

        # Optional initial cable link(s) to parent/peer nodes
        valid_existing_ids = {n["id"] for n in existing_nodes}
        self._connect_node_peers(node_id, payload, valid_existing_ids)

        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        node = next((n for n in topo["nodes"] if n["id"] == node_id), None)
        return {"success": True, "node": node, "topology": topo}

    def _connect_node_peers(
        self,
        node_id: str,
        payload: dict,
        valid_ids: set[str],
        skip_ids: set[str] | None = None,
    ) -> None:
        """Create topology cable links from one or more selected peer nodes to node_id."""
        blocked = set(skip_ids or set())
        blocked.add(node_id)
        targets: list[str] = []
        raw_ids = payload.get("connectToIds")
        candidates = list(raw_ids) if isinstance(raw_ids, list) else []
        if payload.get("connectToId"):
            candidates.append(payload.get("connectToId"))
        for cid in candidates:
            cs = str(cid or "").strip()
            if cs and cs in valid_ids and cs not in blocked and cs not in targets:
                targets.append(cs)

        for peer_id in targets:
            try:
                self.add_topology_link({
                    "sourceId": peer_id,
                    "targetId": node_id,
                    "cableType": payload.get("cableType") or "auto",
                    "sourcePort": payload.get("sourcePort") or "",
                    "targetPort": payload.get("targetPort") or "",
                    "autoPorts": True,
                })
            except ValueError:
                pass

    def move_topology_node(self, node_id: str, payload: dict) -> dict:
        try:
            x = max(40.0, min(2400.0, float(payload.get("x", 0))))
            y = max(40.0, min(1600.0, float(payload.get("y", 0))))
        except (TypeError, ValueError) as exc:
            raise ValueError("x and y must be numeric coordinates") from exc
        with self._connect() as db:
            res = db.execute(
                "UPDATE topology_nodes SET x=?, y=? WHERE id=?",
                (round(x, 1), round(y, 1), node_id),
            )
            if res.rowcount == 0:
                raise ValueError("Topology node not found")
        return {"success": True, "id": node_id, "x": x, "y": y}

    def update_topology_node(self, node_id: str, payload: dict) -> dict:
        existing = next((n for n in self._raw_topology_nodes() if n["id"] == node_id), None)
        if existing is None:
            raise ValueError("Topology node not found")

        name = str(payload.get("name") or existing["name"]).strip()[:120]
        if not name:
            raise ValueError("Device name is required")
        node_type = self._clean_node_type(payload.get("nodeType") or existing["node_type"])
        raw_ip = str(payload["ip"]).strip() if "ip" in payload else existing["ip"]
        ip = validate_ip(raw_ip) if raw_ip else ""
        if not ip and node_type != "cloud":
            raise ValueError("A valid IP address is required")
        port = validate_port(payload.get("port", existing["port"])) if ip else 80
        location = str(payload.get("location", existing["location"]) or "").strip()[:120]
        vendor = str(payload.get("vendor", existing["vendor"]) or "").strip()[:80]

        with self._connect() as db:
            db.execute(
                """UPDATE topology_nodes
                   SET name=?, ip=?, node_type=?, port=?, location=?, vendor=?
                   WHERE id=?""",
                (name, ip, node_type, port, location, vendor, node_id),
            )

        if existing.get("device_id") and ip:
            self.update_device(
                existing["device_id"],
                {
                    "name": name,
                    "ip": ip,
                    "port": port,
                    "location": location or "Office Topology",
                    "type": "gateway" if node_type == "router" else node_type,
                },
            )

        # Optional additional cable connection(s) when editing a node
        all_node_ids = {n["id"] for n in self._raw_topology_nodes()}
        linked_peers = {
            ln["target_id"] if ln["source_id"] == node_id else ln["source_id"]
            for ln in self._raw_topology_links()
            if ln["source_id"] == node_id or ln["target_id"] == node_id
        }
        self._connect_node_peers(node_id, payload, all_node_ids, linked_peers)

        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        return {"success": True, "topology": topo}

    def delete_topology_node(self, node_id: str, delete_monitored: bool = False) -> dict:
        existing = next((n for n in self._raw_topology_nodes() if n["id"] == node_id), None)
        if existing is None:
            raise ValueError("Topology node not found")

        with self._connect() as db:
            db.execute(
                "DELETE FROM topology_links WHERE source_id=? OR target_id=?",
                (node_id, node_id),
            )
            db.execute("DELETE FROM topology_nodes WHERE id=?", (node_id,))

        if delete_monitored and existing.get("device_id"):
            self.delete_device(existing["device_id"])

        self._record_event(
            "TOPOLOGY_NODE_REMOVED",
            "INFO",
            f"Topology device removed: {existing['name']}",
            f"Removed {existing['name']} ({existing.get('ip') or 'No IP'}) from topology map.",
            ip=existing.get("ip") or "",
            device_name=existing["name"],
        )
        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        return {"success": True, "topology": topo}

    def add_topology_link(self, payload: dict) -> dict:
        source_id = str(payload.get("sourceId") or "").strip()
        target_id = str(payload.get("targetId") or "").strip()
        if not source_id or not target_id or source_id == target_id:
            raise ValueError("Select two distinct devices to connect with a cable")

        nodes = {n["id"]: n for n in self._raw_topology_nodes()}
        if source_id not in nodes or target_id not in nodes:
            raise ValueError("Selected source or target topology node was not found")

        existing_links = self._raw_topology_links()
        for ln in existing_links:
            if {ln["source_id"], ln["target_id"]} == {source_id, target_id}:
                raise ValueError("These two devices are already cabled together")

        raw_cable = str(payload.get("cableType") or "").strip().lower()
        source_port = str(payload.get("sourcePort") or "").strip()[:32]
        target_port = str(payload.get("targetPort") or "").strip()[:32]
        if raw_cable in ("", "auto") or payload.get("autoPorts"):
            smart_cable, smart_src_port, smart_dst_port = self._default_cable_and_ports(
                nodes[source_id], nodes[target_id], raw_cable, existing_links
            )
            cable_type = smart_cable
            if not source_port:
                source_port = smart_src_port
            if not target_port:
                target_port = smart_dst_port
        else:
            cable_type = self._clean_cable_type(raw_cable)
        label = str(payload.get("label") or "").strip()[:60]
        link_id = f"link-{uuid.uuid4().hex[:10]}"

        with self._connect() as db:
            db.execute(
                """INSERT INTO topology_links
                   (id, source_id, target_id, cable_type, source_port, target_port, label, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (link_id, source_id, target_id, cable_type, source_port, target_port, label, utc_now()),
            )

        self._record_event(
            "TOPOLOGY_LINK_ADDED",
            "INFO",
            "Topology link created",
            f"Connected {nodes[source_id]['name']} ↔ {nodes[target_id]['name']} ({cable_type.upper()}).",
            device_name=nodes[target_id]["name"],
            ip=nodes[target_id].get("ip") or "",
        )
        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        return {"success": True, "linkId": link_id, "topology": topo}

    def delete_topology_link(self, link_id: str) -> dict:
        existing = next((l for l in self._raw_topology_links() if l["id"] == link_id), None)
        if existing is None:
            raise ValueError("Topology cable link not found")
        with self._connect() as db:
            db.execute("DELETE FROM topology_links WHERE id=?", (link_id,))
        self._record_event(
            "TOPOLOGY_LINK_REMOVED",
            "INFO",
            "Topology link disconnected",
            f"Removed cable link {link_id} from topology.",
        )
        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        return {"success": True, "topology": topo}

    def auto_layout_topology(self) -> dict:
        """Arrange mapped network devices neatly into clean rows."""
        nodes = self._raw_topology_nodes()
        if not nodes:
            return {"success": True, "topology": self.get_topology()}

        tier_rank = {
            "cloud": 0,
            "firewall": 1,
            "gateway": 1,
            "router": 1,
            "switch": 2,
            "ap": 3,
            "server": 3,
            "device": 4,
        }
        by_tier: dict[int, list[dict]] = {}
        for n in nodes:
            t = tier_rank.get(n["node_type"], 4)
            by_tier.setdefault(t, []).append(n)

        y_positions = {0: 85.0, 1: 215.0, 2: 350.0, 3: 485.0, 4: 615.0}
        canvas_w = 1040.0
        with self._connect() as db:
            for tier_idx, tier_nodes in sorted(by_tier.items()):
                count = len(tier_nodes)
                spacing = min(195.0, (canvas_w - 140.0) / max(1, count))
                start_x = max(110.0, (canvas_w - (count - 1) * spacing) / 2.0)
                y_val = y_positions.get(tier_idx, 120.0 + tier_idx * 130.0)
                for idx, node in enumerate(tier_nodes):
                    db.execute(
                        "UPDATE topology_nodes SET x=?, y=? WHERE id=?",
                        (round(start_x + idx * spacing, 1), y_val, node["id"]),
                    )
        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        return {"success": True, "topology": topo}

    def clear_topology(self) -> dict:
        """Remove all nodes and cable links from the company topology map."""
        with self._connect() as db:
            node_count = int(db.execute("SELECT COUNT(*) FROM topology_nodes").fetchone()[0] or 0)
            link_count = int(db.execute("SELECT COUNT(*) FROM topology_links").fetchone()[0] or 0)
            db.execute("DELETE FROM topology_links")
            db.execute("DELETE FROM topology_nodes")
        if node_count or link_count:
            self._record_event(
                "TOPOLOGY_CLEARED",
                "INFO",
                "Topology map cleared",
                f"Cleared {node_count} device(s) and {link_count} cable(s) from the network topology map.",
            )
        topo = self.get_topology()
        self.broadcast("topology_update", topo)
        return {
            "success": True,
            "removedNodes": node_count,
            "removedLinks": link_count,
            "topology": topo,
        }

    def import_monitored_to_topology(self) -> dict:
        """Import existing monitored infrastructure devices and wire up subnet hierarchy."""
        devices = self.get_devices()
        existing = self._raw_topology_nodes()
        existing_ips = {n["ip"] for n in existing if n.get("ip")}

        # Ensure an ISP WAN Cloud node exists as root
        cloud_node = next((n for n in existing if n["node_type"] == "cloud"), None)
        if cloud_node is None:
            cloud_id = f"topo-{uuid.uuid4().hex[:10]}"
            with self._connect() as db:
                db.execute(
                    """INSERT INTO topology_nodes
                       (id, device_id, name, ip, node_type, port, location, vendor, x, y, created_at)
                       VALUES (?, '', 'ISP Fiber Internet (WAN)', '', 'cloud', 443, 'External Uplink', 'ISP', 520, 85, ?)""",
                    (cloud_id, utc_now()),
                )
        else:
            cloud_id = cloud_node["id"]

        added = 0
        for dev in devices:
            ip = dev.get("ip") or ""
            if ip in existing_ips:
                continue
            nid = f"topo-{uuid.uuid4().hex[:10]}"
            ntype = self._clean_node_type(dev.get("type"))
            with self._connect() as db:
                db.execute(
                    """INSERT INTO topology_nodes
                       (id, device_id, name, ip, node_type, port, location, vendor, x, y, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 300, 300, ?)""",
                    (
                        nid,
                        dev.get("id") or "",
                        dev.get("name") or ip,
                        ip,
                        ntype,
                        int(dev.get("port") or 80),
                        dev.get("location") or "",
                        dev.get("vendor") or "",
                        utc_now(),
                    ),
                )
            existing_ips.add(ip)
            added += 1

        # Create sensible hierarchical links if nodes aren't yet linked
        all_nodes = self._raw_topology_nodes()
        all_links = self._raw_topology_links()
        linked_targets = {l["target_id"] for l in all_links} | {l["source_id"] for l in all_links}
        gateways = [n for n in all_nodes if n["node_type"] in {"gateway", "firewall"}]
        secondary_routers = [n for n in all_nodes if n["node_type"] == "router"]
        switches = [n for n in all_nodes if n["node_type"] == "switch"]

        def subnet_of(ip_str: str) -> str:
            parts = ip_str.split(".")
            return ".".join(parts[:3]) if len(parts) == 4 else ""

        for gw in gateways:
            if not any({l["source_id"], l["target_id"]} == {cloud_id, gw["id"]} for l in all_links):
                try:
                    self.add_topology_link({
                        "sourceId": cloud_id,
                        "targetId": gw["id"],
                        "cableType": "fiber",
                        "sourcePort": "WAN",
                        "targetPort": "Gi0/0",
                    })
                except ValueError:
                    pass

        for sw in switches:
            if sw["id"] in linked_targets:
                continue
            sub = subnet_of(sw.get("ip", ""))
            parent_gw = next((g for g in gateways if subnet_of(g.get("ip", "")) == sub), None) or (gateways[0] if gateways else None)
            if parent_gw:
                try:
                    self.add_topology_link({
                        "sourceId": parent_gw["id"],
                        "targetId": sw["id"],
                        "cableType": "copper",
                        "sourcePort": "Gi0/1",
                        "targetPort": "Gi1/0/1",
                    })
                except ValueError:
                    pass

        for rtr in secondary_routers:
            if rtr["id"] in linked_targets:
                continue
            parent = switches[0] if switches else (gateways[0] if gateways else None)
            if parent:
                try:
                    self.add_topology_link({
                        "sourceId": parent["id"],
                        "targetId": rtr["id"],
                        "cableType": "copper",
                        "sourcePort": "LAN",
                        "targetPort": "WAN/LAN",
                    })
                except ValueError:
                    pass

        for node in all_nodes:
            if node["node_type"] in {"cloud", "gateway", "router", "firewall", "switch"}:
                continue
            if node["id"] in linked_targets:
                continue
            sub = subnet_of(node.get("ip", ""))
            parent = (
                next((s for s in switches if subnet_of(s.get("ip", "")) == sub), None)
                or next((g for g in gateways if subnet_of(g.get("ip", "")) == sub), None)
                or (switches[0] if switches else (gateways[0] if gateways else None))
            )
            if parent:
                try:
                    self.add_topology_link({
                        "sourceId": parent["id"],
                        "targetId": node["id"],
                        "cableType": "wireless" if node["node_type"] == "device" else "copper",
                        "sourcePort": "Gi0/x",
                        "targetPort": "Eth0",
                    })
                except ValueError:
                    pass

        self.auto_layout_topology()
        topo = self.get_topology()
        self._record_event(
            "TOPOLOGY_IMPORT",
            "INFO",
            f"Imported {added} device(s) into Topology",
            f"Added {added} monitored device(s) onto your network map.",
        )
        return {"success": True, "added": added, "topology": topo}

    def ping_topology_pdu(self, source_id: object, target_id: object) -> dict:
        """Test Ping: checks cable path and sends a live connection check to the target device."""
        topo = self.get_topology()
        node_map = {n["id"]: n for n in topo["nodes"]}
        src_id = str(source_id or "").strip()
        dst_id = str(target_id or "").strip()
        if dst_id not in node_map:
            raise ValueError("Select a valid target device in the topology")
        if not src_id or src_id not in node_map:
            src_id = dst_id

        dst_node = node_map[dst_id]
        src_node = node_map[src_id]

        # Find shortest cabled path between src_id and dst_id via BFS
        adj: dict[str, list[str]] = {}
        for ln in topo["links"]:
            adj.setdefault(ln["sourceId"], []).append(ln["targetId"])
            adj.setdefault(ln["targetId"], []).append(ln["sourceId"])

        path_ids: list[str] = [dst_id]
        if src_id != dst_id:
            queue_bfs: deque[list[str]] = deque([[src_id]])
            visited = {src_id}
            found_path: list[str] | None = None
            while queue_bfs:
                cur_path = queue_bfs.popleft()
                tail = cur_path[-1]
                if tail == dst_id:
                    found_path = cur_path
                    break
                for nxt in adj.get(tail, []):
                    if nxt not in visited:
                        visited.add(nxt)
                        queue_bfs.append(cur_path + [nxt])
            path_ids = found_path if found_path else [src_id, dst_id]

        # Check intermediate hop health along cabled path (excluding src & dst)
        failed_hop = next(
            (node_map[nid] for nid in path_ids[1:-1] if node_map[nid]["healthState"] in {"down", "disconnected"}),
            None,
        )

        # Run live TCP/ICMP probe on target
        reachable = False
        latency_ms = None
        method = "ISP WAN Check"
        if dst_node["node_type"] == "cloud" and not dst_node.get("ip"):
            isp = self.probe_isp()
            reachable = isp.get("overallHealth") != "OUTAGE"
            latency_ms = isp.get("tier1LatencyMs")
        elif dst_node.get("ip"):
            target_ip = dst_node["ip"]
            target_port = int(dst_node.get("port") or 80)
            matched_dev = next((d for d in self.get_devices() if d["ip"] == target_ip), None)
            if matched_dev:
                res = self.probe_device(matched_dev)
                self.latest_devices[target_ip] = res
                self.enrich_fleet_diagnostics(list(self.latest_devices.values()))
                reachable = bool(res.get("alive"))
                latency_ms = res.get("latencyMs")
                method = res.get("probeMethod") or "TCP + ICMP"
            else:
                tcp_open, tcp_rst, tcp_ms = self._probe_tcp_socket(target_ip, target_port, 0.9)
                icmp_ok, icmp_ms = self._probe_icmp(target_ip, timeout_ms=900)
                reachable = tcp_open or tcp_rst or icmp_ok
                latency_ms = icmp_ms if icmp_ok and icmp_ms is not None else tcp_ms
                method = "ICMP Echo" if icmp_ok else "TCP Probe"

        if not reachable and failed_hop:
            msg = f"PING FAILED at {failed_hop['name']} ({failed_hop.get('ip') or 'No IP'}) — this device is OFFLINE."
        elif reachable and dst_node["healthState"] == "no_internet":
            msg = f"LOCAL OK ({latency_ms} ms), NO INTERNET at {dst_node['name']}."
        elif reachable:
            msg = f"PING OK: {src_node['name']} → {dst_node['name']} responded in {latency_ms} ms ({method})."
        else:
            msg = f"NO RESPONSE: {src_node['name']} → {dst_node['name']} ({dst_node.get('ip') or 'internet'}) did not reply."

        self._record_event(
            "TOPOLOGY_PDU_PING",
            "INFO" if reachable else "CRITICAL",
            f"Test Ping {'OK' if reachable else 'Failed'}",
            msg,
            ip=dst_node.get("ip") or "",
            device_name=dst_node["name"],
        )

        return {
            "success": True,
            "reachable": reachable,
            "latencyMs": latency_ms,
            "method": method,
            "pathNodeIds": path_ids,
            "failedAtNodeId": failed_hop["id"] if (not reachable and failed_hop) else None,
            "message": msg,
            "topology": self.get_topology(),
        }
