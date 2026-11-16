"""Nmap & TCP Port Security Auditor: Open Port Detection, Banner Grabbing & Risk Analysis."""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import utc_now, validate_host


PORT_CATALOG: dict[int, dict] = {
    20: {
        "service": "FTP-DATA",
        "category": "File Sharing",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Unencrypted FTP active data transfer channel.",
        "exposureRisk": "Files and directory listings traverse the network in cleartext and can be intercepted via ARP spoofing or packet sniffing.",
        "remediation": "Disable legacy FTP and migrate to SFTP (Port 22) or HTTPS file sharing.",
    },
    21: {
        "service": "FTP",
        "category": "File Sharing",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "File Transfer Protocol control port (cleartext authentication).",
        "exposureRisk": "Credentials and session commands are sent unencrypted. Frequently targeted for anonymous login abuse and brute-force attacks.",
        "remediation": "Stop the FTP daemon immediately; replace with SFTP/SCP over SSH or FTPS with strict TLS 1.3.",
    },
    22: {
        "service": "SSH",
        "category": "Remote Access",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Secure Shell encrypted remote administration.",
        "exposureRisk": "Safe when hardened, but exposed SSH ports with password authentication enabled are primary targets for automated credential stuffing.",
        "remediation": "Enforce Ed25519/RSA key-based authentication, disable PasswordAuthentication and root login, and restrict access via firewall ACLs.",
    },
    23: {
        "service": "Telnet",
        "category": "Remote Access",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Unencrypted legacy terminal remote access.",
        "exposureRisk": "Complete cleartext transmission of admin usernames, passwords, and shell commands. High risk of instant credential compromise on LAN/WAN.",
        "remediation": "Disable Telnet service immediately on routers, switches, and servers; use SSH (Port 22) exclusively.",
    },
    25: {
        "service": "SMTP",
        "category": "Mail & Messaging",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Simple Mail Transfer Protocol relay.",
        "exposureRisk": "Unauthenticated or misconfigured SMTP relays can be abused for internal phishing or external spam blacklisting.",
        "remediation": "Block port 25 on non-mail servers; require STARTTLS and SMTP authentication on mail gateways.",
    },
    53: {
        "service": "DNS",
        "category": "Network Core",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "Domain Name System resolver / authoritative server.",
        "exposureRisk": "Expected on routers and domain controllers; ensure open recursive resolution is not exposed to untrusted networks.",
        "remediation": "Allow DNS queries only from internal LAN subnets and disable zone transfers (AXFR) to unauthorized hosts.",
    },
    67: {
        "service": "DHCP",
        "category": "Network Core",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "Dynamic Host Configuration Protocol server.",
        "exposureRisk": "Normal on main gateway router; rogue DHCP servers on non-gateway devices can hijack LAN routing.",
        "remediation": "Enable DHCP Snooping on managed switches so only the authorized gateway port can respond.",
    },
    69: {
        "service": "TFTP",
        "category": "File Sharing",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Trivial File Transfer Protocol (no authentication).",
        "exposureRisk": "Allows anyone on the network to download or overwrite router/switch configuration files and firmware without a password.",
        "remediation": "Disable TFTP after provisioning hardware or restrict strictly to a provisioning VLAN.",
    },
    80: {
        "service": "HTTP",
        "category": "Web & Admin",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Unencrypted Web / Router Management Interface.",
        "exposureRisk": "Admin logins and session cookies over plain HTTP can be captured on the local network.",
        "remediation": "Redirect HTTP (80) to HTTPS (443) and change default admin credentials on routers, printers, and APs.",
    },
    88: {
        "service": "Kerberos",
        "category": "Directory & Auth",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "Active Directory Kerberos authentication service.",
        "exposureRisk": "Expected on Windows Domain Controllers; unexpected on client workstations.",
        "remediation": "Ensure Domain Controllers are patched and restrict access to internal authenticated VLANs.",
    },
    110: {
        "service": "POP3",
        "category": "Mail & Messaging",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Cleartext Post Office Protocol v3 mail retrieval.",
        "exposureRisk": "Transmits email passwords and messages without encryption.",
        "remediation": "Disable POP3 (110) in favor of POP3S (995) or IMAPS (993).",
    },
    111: {
        "service": "RPCbind / Portmapper",
        "category": "File Sharing",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "ONC RPC portmapper (often paired with NFS).",
        "exposureRisk": "Enumerates internal RPC services and facilitates unauthorized NFS share mounting or amplification.",
        "remediation": "Block port 111 via host firewall unless NFSv3 is explicitly required on an isolated storage VLAN.",
    },
    135: {
        "service": "MS-RPC",
        "category": "Remote Access",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Microsoft Windows RPC Endpoint Mapper.",
        "exposureRisk": "Used for remote WMI/DCOM management; frequently abused for lateral movement across Windows workstations.",
        "remediation": "Restrict port 135 via Windows Defender Firewall to trusted management jump hosts only.",
    },
    139: {
        "service": "NetBIOS-SSN",
        "category": "File Sharing",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Legacy NetBIOS Session Service over TCP.",
        "exposureRisk": "Exposes legacy Windows system names, workgroups, and SMBv1/NetBIOS session attack surfaces.",
        "remediation": "Disable NetBIOS over TCP/IP in network adapter IPv4 advanced WINS settings and block port 139.",
    },
    143: {
        "service": "IMAP",
        "category": "Mail & Messaging",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Unencrypted Internet Message Access Protocol.",
        "exposureRisk": "Cleartext email authentication unless STARTTLS is strictly enforced.",
        "remediation": "Migrate mail clients to IMAPS on port 993.",
    },
    161: {
        "service": "SNMP",
        "category": "Web & Admin",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Simple Network Management Protocol agent.",
        "exposureRisk": "SNMPv1/v2c with default 'public'/'private' community strings leaks full device routing tables, ARP caches, and config.",
        "remediation": "Upgrade to SNMPv3 with encrypted authPriv or restrict SNMP polling to the monitoring server IP.",
    },
    389: {
        "service": "LDAP",
        "category": "Directory & Auth",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Lightweight Directory Access Protocol.",
        "exposureRisk": "Unencrypted LDAP binds expose directory credentials on the wire.",
        "remediation": "Enforce LDAPS (Port 636) and LDAP signing / channel binding.",
    },
    443: {
        "service": "HTTPS",
        "category": "Web & Admin",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "TLS-Encrypted Web / Management Interface.",
        "exposureRisk": "Standard encrypted web transport; verify valid TLS certificates and strong cipher suites.",
        "remediation": "Keep web server and router firmware updated; disable deprecated TLS 1.0/1.1.",
    },
    445: {
        "service": "Microsoft-DS (SMB)",
        "category": "File Sharing",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Server Message Block (Windows File & Print Sharing).",
        "exposureRisk": "Primary vector for ransomware propagation (e.g., WannaCry/EternalBlue), NTLM relay, and unauthorized share enumeration.",
        "remediation": "Disable SMBv1 completely, enforce SMB signing, block port 445 on client workstations, and restrict NAS/Server SMB to trusted VLANs.",
    },
    515: {
        "service": "LPD Printer",
        "category": "IoT & Industrial",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Line Printer Daemon print spooler service.",
        "exposureRisk": "Allows unauthenticated print jobs and banner manipulation on office printers.",
        "remediation": "Segment office printers onto a dedicated VLAN or use IPPS (encrypted printing).",
    },
    554: {
        "service": "RTSP",
        "category": "IoT & Industrial",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Real-Time Streaming Protocol (IP Cameras / NVR).",
        "exposureRisk": "Many IP cameras expose RTSP video feeds with default credentials or unencrypted streams.",
        "remediation": "Isolate IP cameras on a restricted CCTV VLAN and enforce strong unique RTSP passwords.",
    },
    631: {
        "service": "IPP / CUPS",
        "category": "IoT & Industrial",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Internet Printing Protocol / CUPS print server.",
        "exposureRisk": "Exposed CUPS daemons have historically suffered remote command execution vulnerabilities.",
        "remediation": "Bind CUPS to localhost (127.0.0.1) unless the host is a dedicated print server.",
    },
    873: {
        "service": "Rsync",
        "category": "File Sharing",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Rsync file synchronization daemon.",
        "exposureRisk": "Unauthenticated Rsync modules allow full read/write access to backup directories.",
        "remediation": "Run Rsync over SSH (Port 22) rather than as an exposed daemon on port 873.",
    },
    1433: {
        "service": "MS-SQL-S",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Microsoft SQL Server database listener.",
        "exposureRisk": "Direct database exposure allows `sa` brute-forcing and `xp_cmdshell` OS command execution if compromised.",
        "remediation": "Never expose port 1433 to general LAN clients; restrict via firewall to application servers only.",
    },
    1521: {
        "service": "Oracle TNS",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Oracle Database TNS Listener.",
        "exposureRisk": "Direct access to enterprise database listener.",
        "remediation": "Restrict port 1521 strictly to application tier hosts.",
    },
    1883: {
        "service": "MQTT",
        "category": "IoT & Industrial",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Unencrypted MQTT IoT Message Broker.",
        "exposureRisk": "IoT telemetry and smart-office control messages can be read or injected without TLS.",
        "remediation": "Switch to MQTTS (Port 8883) with client authentication.",
    },
    2049: {
        "service": "NFS",
        "category": "File Sharing",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Network File System shared storage.",
        "exposureRisk": "Misconfigured `/etc/exports` (`no_root_squash` or wildcard `*`) allows any LAN host to mount sensitive volumes.",
        "remediation": "Enforce NFSv4 with Kerberos authentication and strict IP export lists.",
    },
    2375: {
        "service": "Docker API",
        "category": "Containers & Dev",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Unencrypted Docker Daemon Remote API.",
        "exposureRisk": "Grants instant unauthenticated root-equivalent control over the host OS by spawning privileged containers.",
        "remediation": "Bind Docker daemon to unix:///var/run/docker.sock or enforce mutual TLS on port 2376.",
    },
    3000: {
        "service": "HTTP-Dev / Dashboard",
        "category": "Web & Admin",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "Web Application / Monitoring Dashboard (Pulse Monitor / Grafana / Node).",
        "exposureRisk": "Local monitoring or development web service; verify authentication if hosting sensitive controls.",
        "remediation": "Restrict external WAN port-forwarding and place behind a reverse proxy with TLS if exposed outside the office.",
    },
    3306: {
        "service": "MySQL / MariaDB",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "MySQL / MariaDB relational database server.",
        "exposureRisk": "Exposed database port permits brute-force attacks and direct data exfiltration.",
        "remediation": "Set `bind-address = 127.0.0.1` in `my.cnf` or restrict port 3306 to specific application servers.",
    },
    3389: {
        "service": "MS-WBT-Server (RDP)",
        "category": "Remote Access",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Microsoft Remote Desktop Protocol (Graphical Login).",
        "exposureRisk": "Top target for ransomware operators, credential brute-forcing, and Pass-the-Hash lateral movement.",
        "remediation": "Require Network Level Authentication (NLA), disable RDP on endpoints that do not need it, and place behind a VPN/RD Gateway.",
    },
    5000: {
        "service": "UPnP / Synology DSM / Flask",
        "category": "Web & Admin",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Synology NAS Admin HTTP / UPnP / Local API.",
        "exposureRisk": "Unencrypted NAS management or UPnP control endpoint.",
        "remediation": "Enforce HTTPS on port 5001 for Synology NAS and disable UPnP on gateway routers.",
    },
    5357: {
        "service": "WSDAPI",
        "category": "IoT & Industrial",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "Web Services for Devices (Windows network discovery/printers).",
        "exposureRisk": "Standard Windows LAN discovery responder.",
        "remediation": "Block on public/untrusted network profiles via Windows Firewall.",
    },
    5432: {
        "service": "PostgreSQL",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "PostgreSQL database server.",
        "exposureRisk": "Direct network exposure of database engine; susceptible to weak `pg_hba.conf` trust rules.",
        "remediation": "Restrict `listen_addresses` in `postgresql.conf` and enforce `scram-sha-256` + SSL in `pg_hba.conf`.",
    },
    5900: {
        "service": "VNC",
        "category": "Remote Access",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Virtual Network Computing remote desktop.",
        "exposureRisk": "Often configured with weak 8-character passwords or no authentication, streaming screen contents in cleartext.",
        "remediation": "Tunnel VNC exclusively over SSH and disable direct LAN/WAN bindings on port 5900.",
    },
    5985: {
        "service": "WinRM-HTTP",
        "category": "Remote Access",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Windows Remote Management (PowerShell Remoting HTTP).",
        "exposureRisk": "Allows remote PowerShell execution across Windows hosts if admin credentials are compromised.",
        "remediation": "Use WinRM-HTTPS (Port 5986) and restrict trusted hosts via Group Policy.",
    },
    6379: {
        "service": "Redis",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Redis in-memory key-value datastore.",
        "exposureRisk": "By default Redis has no authentication if `protected-mode` is off, allowing SSH key injection or cron RCE.",
        "remediation": "Bind Redis to `127.0.0.1`, enable `protected-mode yes`, and configure a strong `requirepass`.",
    },
    7547: {
        "service": "CWMP / TR-069",
        "category": "Web & Admin",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "ISP CPE WAN Management Protocol on routers/modems.",
        "exposureRisk": "Frequently exploited by Mirai-variant botnets to hijack ISP routers.",
        "remediation": "Disable TR-069 / CWMP remote management in your router settings if not required by your ISP.",
    },
    8000: {
        "service": "HTTP-Alt",
        "category": "Web & Admin",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Alternative HTTP development or device web server.",
        "exposureRisk": "Often runs development servers (e.g. `python -m http.server`) exposing local directory trees without auth.",
        "remediation": "Verify which process owns port 8000 and bind development servers to `127.0.0.1`.",
    },
    8080: {
        "service": "HTTP-Proxy / Admin",
        "category": "Web & Admin",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "Secondary HTTP Web Admin / Tomcat / Proxy port.",
        "exposureRisk": "Commonly hosts unencrypted router remote management, Jenkins, or Tomcat manager consoles.",
        "remediation": "Disable remote HTTP management on port 8080 and enforce HTTPS with strong authentication.",
    },
    8291: {
        "service": "MikroTik Winbox",
        "category": "Web & Admin",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "MikroTik RouterOS Winbox administration port.",
        "exposureRisk": "Exposed Winbox services are heavily targeted for credential harvesting and RouterOS exploits.",
        "remediation": "Restrict `/ip service set winbox address=` to a dedicated admin workstation IP.",
    },
    8443: {
        "service": "HTTPS-Alt / UniFi",
        "category": "Web & Admin",
        "riskLevel": "LOW",
        "atRisk": False,
        "summary": "Alternative HTTPS Management Console (UniFi / Omada / Admin UI).",
        "exposureRisk": "Encrypted admin portal; ensure multi-factor authentication and strong admin passwords are used.",
        "remediation": "Keep controller software updated to the latest stable release.",
    },
    9000: {
        "service": "Portainer / PHP-FPM / Sonar",
        "category": "Containers & Dev",
        "riskLevel": "HIGH",
        "atRisk": True,
        "summary": "Container Management UI (Portainer) or FastCGI service.",
        "exposureRisk": "Exposed PHP-FPM or container dashboards can grant arbitrary code execution.",
        "remediation": "Bind FastCGI to localhost and require HTTPS (Port 9443) for Portainer.",
    },
    9100: {
        "service": "JetDirect (RAW Print)",
        "category": "IoT & Industrial",
        "riskLevel": "MEDIUM",
        "atRisk": True,
        "summary": "HP JetDirect raw network printing port.",
        "exposureRisk": "Accepts raw PJL/PostScript commands without authentication, allowing printer filesystem access or display manipulation.",
        "remediation": "Place printers on an isolated VLAN and restrict port 9100 to the print server.",
    },
    9200: {
        "service": "Elasticsearch",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "Elasticsearch REST API HTTP port.",
        "exposureRisk": "Unauthenticated Elasticsearch clusters allow anyone on the network to dump or delete all indexed data.",
        "remediation": "Enable X-Pack Security / TLS authentication and bind to localhost or internal cluster IPs.",
    },
    27017: {
        "service": "MongoDB",
        "category": "Database",
        "riskLevel": "CRITICAL",
        "atRisk": True,
        "summary": "MongoDB NoSQL Database listener.",
        "exposureRisk": "Default unauthenticated MongoDB instances allow full database read/write/ransom by any network peer.",
        "remediation": "Enable `security.authorization: enabled` and bind `net.bindIp` to `127.0.0.1`.",
    },
}

SCAN_PROFILES: dict[str, dict] = {
    "quick_audit": {
        "id": "quick_audit",
        "label": "Quick Security Audit (25 Common & High-Risk Ports)",
        "ports": [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445,
            1433, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017,
        ],
    },
    "at_risk_only": {
        "id": "at_risk_only",
        "label": "At-Risk & Vulnerable Services Only (27 Risk Ports)",
        "ports": [
            20, 21, 23, 25, 69, 110, 111, 135, 139, 143, 161, 445,
            554, 873, 1433, 1521, 1883, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 7547, 9200, 27017,
        ],
    },
    "full_office": {
        "id": "full_office",
        "label": "Full Office & Infrastructure Audit (All 46 Cataloged Ports)",
        "ports": sorted(PORT_CATALOG.keys()),
    },
    "web_admin": {
        "id": "web_admin",
        "label": "Router, Web & Admin Consoles (14 Management Ports)",
        "ports": [22, 23, 53, 80, 161, 443, 3000, 5000, 5985, 7547, 8000, 8080, 8291, 8443],
    },
    "database_storage": {
        "id": "database_storage",
        "label": "Databases & File Shares (15 Storage/DB Ports)",
        "ports": [20, 21, 69, 111, 139, 445, 873, 1433, 1521, 2049, 3306, 5432, 6379, 9200, 27017],
    },
}


class PortScannerMixin:
    """Provides detailed Nmap & TCP port scanning, service banner grabbing, and risk auditing."""

    @staticmethod
    def _find_nmap_binary() -> str | None:
        found = shutil.which("nmap")
        if found:
            return found
        if os.name == "nt":
            for candidate in (
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ):
                if os.path.isfile(candidate):
                    return candidate
        return None

    def _get_portscan_lock(self) -> threading.Lock:
        lock = self.__dict__.get("_portscan_instance_lock")
        if lock is None:
            lock = threading.Lock()
            self.__dict__["_portscan_instance_lock"] = lock
        return lock

    def _get_portscan_history(self) -> list[dict]:
        hist = self.__dict__.get("_portscan_instance_history")
        if hist is None:
            hist = []
            self.__dict__["_portscan_instance_history"] = hist
        return hist

    def _get_portscan_reports(self) -> dict[str, dict]:
        reports = self.__dict__.get("_portscan_instance_reports")
        if reports is None:
            reports = {}
            self.__dict__["_portscan_instance_reports"] = reports
        return reports

    @staticmethod
    def parse_custom_ports(port_spec: str) -> list[int]:
        """Parse a comma-separated list of ports and ranges (e.g. '21-25, 80, 443, 8000-8010')."""
        if not port_spec or not str(port_spec).strip():
            raise ValueError("Please provide at least one port or range (e.g. 22, 80, 443, 8000-8010)")
        ports: set[int] = set()
        for part in str(port_spec).split(","):
            token = part.strip()
            if not token:
                continue
            if "-" in token:
                bounds = token.split("-", 1)
                try:
                    start, end = int(bounds[0].strip()), int(bounds[1].strip())
                except ValueError as exc:
                    raise ValueError(f"Invalid port range: {token}") from exc
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Port range out of bounds (1-65535): {token}")
                if end - start > 250:
                    raise ValueError("Custom port ranges are limited to 250 ports per scan")
                ports.update(range(start, end + 1))
            else:
                try:
                    port = int(token)
                except ValueError as exc:
                    raise ValueError(f"Invalid port number: {token}") from exc
                if not 1 <= port <= 65535:
                    raise ValueError(f"Port out of range (1-65535): {port}")
                ports.add(port)
        if not ports:
            raise ValueError("No valid ports specified")
        if len(ports) > 300:
            raise ValueError("Maximum 300 ports per scan")
        return sorted(ports)

    @staticmethod
    def _port_metadata(port: int) -> dict:
        if port in PORT_CATALOG:
            return dict(PORT_CATALOG[port])
        # Fallback heuristics for uncataloged custom ports
        if port in {8081, 8088, 8888, 9090}:
            return {
                "service": f"HTTP-Alt ({port})",
                "category": "Web & Admin",
                "riskLevel": "MEDIUM",
                "atRisk": True,
                "summary": f"Secondary HTTP web/admin listener on TCP/{port}.",
                "exposureRisk": "Unencrypted secondary web console or API service.",
                "remediation": "Verify service authentication and restrict exposure or enable HTTPS.",
            }
        return {
            "service": f"TCP/{port}",
            "category": "Custom Service",
            "riskLevel": "MEDIUM",
            "atRisk": True,
            "summary": f"Active listener on TCP port {port}.",
            "exposureRisk": "Unclassified open port; verify that the listening daemon is authorized and patched.",
            "remediation": f"Run `netstat -ano | findstr :{port}` on the target host to confirm the owning process and close if unnecessary.",
        }

    @staticmethod
    def _infer_risk_from_service(
        port: int, service_name: str, tunnel: str, meta: dict
    ) -> dict:
        """Refine port risk metadata when Nmap identifies a service on a custom or standard port."""
        if port in PORT_CATALOG:
            return dict(meta)
        svc = (service_name or "").lower()
        is_ssl = (tunnel or "").lower() == "ssl" or svc.startswith("ssl/")
        clean_svc = svc.replace("ssl/", "")

        if clean_svc in {"telnet", "ftp", "tftp", "rexec", "rlogin", "rsh"}:
            return {
                "service": f"{clean_svc.upper()} (Custom TCP/{port})",
                "category": "Cleartext / Legacy",
                "riskLevel": "CRITICAL",
                "atRisk": True,
                "summary": f"Cleartext {clean_svc.upper()} service detected on non-standard port {port}.",
                "exposureRisk": "Credentials and payloads traverse the network unencrypted regardless of port number.",
                "remediation": f"Disable {clean_svc.upper()} or replace with SSH/SFTP (Port 22).",
            }
        if clean_svc in {"ms-wbt-server", "rdp", "vnc", "rfb", "mysql", "postgresql", "ms-sql-s", "mongodb", "mongod", "redis", "docker"}:
            return {
                "service": f"{clean_svc.upper()} (TCP/{port})",
                "category": "Remote / Database",
                "riskLevel": "CRITICAL",
                "atRisk": True,
                "summary": f"Sensitive {clean_svc.upper()} service exposed on TCP/{port}.",
                "exposureRisk": "Direct exposure of database or remote desktop listener increases brute-force and lateral movement risk.",
                "remediation": f"Restrict TCP/{port} via firewall ACLs and place behind a VPN or SSH tunnel.",
            }
        if "http" in clean_svc:
            if is_ssl or port in {443, 8443, 9443}:
                return {
                    "service": f"HTTPS ({port})",
                    "category": "Web & Admin",
                    "riskLevel": "LOW",
                    "atRisk": False,
                    "summary": f"TLS-encrypted web interface on TCP/{port}.",
                    "exposureRisk": "Encrypted web service; ensure strong TLS ciphers and authentication.",
                    "remediation": "Keep web server certificates valid and firmware updated.",
                }
            return {
                "service": f"HTTP ({port})",
                "category": "Web & Admin",
                "riskLevel": "MEDIUM",
                "atRisk": True,
                "summary": f"Unencrypted HTTP service detected on TCP/{port}.",
                "exposureRisk": "Plaintext HTTP admin logins or API traffic can be sniffed on the LAN.",
                "remediation": "Switch listener to HTTPS (TLS) or bind to localhost.",
            }
        if "ssh" in clean_svc:
            return {
                "service": f"SSH (TCP/{port})",
                "category": "Remote Access",
                "riskLevel": "MEDIUM",
                "atRisk": True,
                "summary": f"OpenSSH / SSH daemon detected on TCP/{port}.",
                "exposureRisk": "Relocating SSH does not stop automated scanners if password auth is enabled.",
                "remediation": "Enforce key-based auth and disable root password logins.",
            }
        return dict(meta)

    @staticmethod
    def _grab_service_banner(ip: str, port: int, timeout: float = 0.75) -> str:
        """Attempt a safe, non-intrusive service banner or HTTP Server header read."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port in {80, 3000, 5000, 8000, 8080, 8081, 8888, 9200}:
                    req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: PulseSecurityAuditor/2.0\r\nConnection: close\r\n\r\n"
                    sock.sendall(req.encode("ascii"))
                    raw = sock.recv(768).decode("utf-8", errors="ignore")
                    status_line = raw.splitlines()[0].strip() if raw.splitlines() else ""
                    server_match = re.search(r"^Server:\s*(.+)$", raw, re.I | re.M)
                    loc_match = re.search(r"^Location:\s*(.+)$", raw, re.I | re.M)
                    parts = [p for p in (
                        status_line,
                        f"Server: {server_match.group(1).strip()}" if server_match else "",
                        f"Redirect: {loc_match.group(1).strip()}" if loc_match else "",
                    ) if p]
                    if parts:
                        return " · ".join(parts)[:130]
                elif port in {443, 5001, 8443, 9443}:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                        cipher = tls_sock.cipher()
                        ver = tls_sock.version() or "TLS"
                        req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                        tls_sock.sendall(req.encode("ascii"))
                        raw = tls_sock.recv(512).decode("utf-8", errors="ignore")
                        server_match = re.search(r"^Server:\s*(.+)$", raw, re.I | re.M)
                        srv = f" · {server_match.group(1).strip()}" if server_match else ""
                        cipher_name = cipher[0] if cipher else ""
                        return f"{ver} ({cipher_name}){srv}"[:130]
                else:
                    raw = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    if raw:
                        clean = re.sub(r"[\r\n\t]+", " ", raw)
                        clean = re.sub(r"[^\x20-\x7E]", "", clean).strip()
                        if clean:
                            return clean[:130]
        except OSError:
            pass
        return ""

    @staticmethod
    def _run_nmap_cli(
        nmap_bin: str,
        ip: str,
        ports: list[int],
        timeout_ms: int,
        scan_versions: bool = True,
    ) -> dict:
        """Execute the real Nmap CLI against `ip` and return parsed XML telemetry."""
        if not nmap_bin or not ports:
            return {}
        port_spec = ",".join(str(p) for p in sorted(ports))
        timing = "-T4" if timeout_ms <= 500 else "-T3" if timeout_ms <= 900 else "-T2"
        cmd = [
            nmap_bin,
            "-n",
            "-Pn",
            "-sT",
            "--max-retries",
            "1",
            "--host-timeout",
            "18s",
            timing,
        ]
        if scan_versions:
            cmd.extend(["-sV", "--version-light"])
        cmd.extend(["-p", port_spec, "-oX", "-", ip])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=22,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)}

        xml_raw = (proc.stdout or "").strip()
        if not xml_raw.startswith("<"):
            idx = xml_raw.find("<?xml")
            if idx == -1:
                idx = xml_raw.find("<nmaprun")
            if idx != -1:
                xml_raw = xml_raw[idx:]
        if not xml_raw or "<nmaprun" not in xml_raw:
            return {"error": (proc.stderr or "Nmap produced no XML output").strip()}

        try:
            root = ET.fromstring(xml_raw)
        except ET.ParseError as exc:
            return {"error": f"Nmap XML parse error: {exc}"}

        parsed_ports: dict[int, dict] = {}
        os_guess = ""
        host_latency_ms = None
        host_el = root.find("host")
        if host_el is not None:
            times_el = host_el.find("times")
            if times_el is not None and times_el.attrib.get("srtt"):
                try:
                    host_latency_ms = round(int(times_el.attrib["srtt"]) / 1000.0, 2)
                except ValueError:
                    pass
            os_el = host_el.find("os/osmatch")
            if os_el is not None and os_el.attrib.get("name"):
                os_guess = f"{os_el.attrib['name']} ({os_el.attrib.get('accuracy', '?')}%)"
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for p_el in ports_el.findall("port"):
                    try:
                        p_num = int(p_el.attrib.get("portid", "0"))
                    except ValueError:
                        continue
                    state_el = p_el.find("state")
                    svc_el = p_el.find("service")
                    state = state_el.attrib.get("state", "closed") if state_el is not None else "closed"
                    reason = state_el.attrib.get("reason", "") if state_el is not None else ""
                    svc_name = svc_el.attrib.get("name", "") if svc_el is not None else ""
                    product = svc_el.attrib.get("product", "") if svc_el is not None else ""
                    version = svc_el.attrib.get("version", "") if svc_el is not None else ""
                    extrainfo = svc_el.attrib.get("extrainfo", "") if svc_el is not None else ""
                    tunnel = svc_el.attrib.get("tunnel", "") if svc_el is not None else ""
                    ostype = svc_el.attrib.get("ostype", "") if svc_el is not None else ""
                    if not os_guess and ostype:
                        os_guess = ostype
                    cpes = [
                        c.text.strip()
                        for c in (svc_el.findall("cpe") if svc_el is not None else [])
                        if c.text and c.text.strip()
                    ]
                    ver_parts = [p for p in (product, version, f"({extrainfo})" if extrainfo else "") if p]
                    parsed_ports[p_num] = {
                        "state": state,
                        "reason": reason,
                        "service": f"ssl/{svc_name}" if tunnel == "ssl" and svc_name and not svc_name.startswith("ssl/") else svc_name,
                        "tunnel": tunnel,
                        "versionBanner": " ".join(ver_parts).strip(),
                        "cpes": cpes,
                    }

        fin_el = root.find("runstats/finished")
        summary_line = fin_el.attrib.get("summary", "") if fin_el is not None else ""
        return {
            "version": root.attrib.get("version", ""),
            "args": root.attrib.get("args", ""),
            "hostLatencyMs": host_latency_ms,
            "osGuess": os_guess,
            "summary": summary_line,
            "ports": parsed_ports,
        }

    def _scan_single_port(self, ip: str, port: int, timeout: float = 0.65) -> dict:
        meta = self._port_metadata(port)
        is_open, latency = self._probe_tcp(ip, port, timeout)
        banner = ""
        if is_open:
            banner = self._grab_service_banner(ip, port, timeout=min(0.75, timeout + 0.2))
        state = "open" if is_open else "closed"
        is_at_risk = bool(is_open and meta["atRisk"])
        effective_risk = meta["riskLevel"] if is_open else "NONE"
        return {
            "port": port,
            "protocol": "TCP",
            "state": state,
            "open": is_open,
            "latencyMs": latency,
            "service": meta["service"],
            "category": meta["category"],
            "riskLevel": meta["riskLevel"],
            "effectiveRisk": effective_risk,
            "atRisk": is_at_risk,
            "banner": banner or (f"{meta['service']} listener active" if is_open else "No response / Closed"),
            "summary": meta["summary"],
            "exposureRisk": meta["exposureRisk"],
            "remediation": meta["remediation"],
        }

    def run_port_scan(
        self,
        host: object,
        profile: str = "quick_audit",
        custom_ports: str = "",
        timeout_ms: object = 650,
    ) -> dict:
        """Execute a detailed Nmap / TCP port security audit on the target host."""
        scan_lock = self._get_portscan_lock()
        if not scan_lock.acquire(blocking=False):
            raise RuntimeError("A port scan is already in progress. Please wait a few seconds for it to complete.")

        try:
            target_host = validate_host(host or self.config["router"].get("ip", "192.168.0.1"))
            try:
                resolved_ip = socket.gethostbyname(target_host)
            except OSError as exc:
                raise ValueError(f"Could not resolve target host '{target_host}': {exc}") from exc

            try:
                timeout_ms_int = max(200, min(3000, int(timeout_ms or 650)))
            except (TypeError, ValueError):
                timeout_ms_int = 650
            timeout_sec = timeout_ms_int / 1000.0

            profile_key = str(profile or "quick_audit").strip()
            if profile_key == "custom":
                ports_to_scan = self.parse_custom_ports(custom_ports)
                profile_label = f"Custom Port Scan ({len(ports_to_scan)} Ports)"
            else:
                prof = SCAN_PROFILES.get(profile_key, SCAN_PROFILES["quick_audit"])
                ports_to_scan = list(prof["ports"])
                profile_label = prof["label"]

            started = time.perf_counter()
            total_ports = len(ports_to_scan)
            nmap_bin = self._find_nmap_binary()

            self.broadcast(
                "portscan_progress",
                {
                    "host": target_host,
                    "ip": resolved_ip,
                    "phase": "initializing",
                    "progressPct": 5,
                    "scannedCount": 0,
                    "totalPorts": total_ports,
                    "openCount": 0,
                    "atRiskCount": 0,
                    "message": f"Resolving {target_host} ({resolved_ip}) and initializing {total_ports}-port scan...",
                },
            )

            results_by_port: dict[int, dict] = {}
            scanned_count = 0
            open_count = 0
            at_risk_count = 0
            last_broadcast = time.perf_counter()

            with ThreadPoolExecutor(max_workers=min(48, max(8, total_ports))) as pool:
                future_map = {
                    pool.submit(self._scan_single_port, resolved_ip, port, timeout_sec): port
                    for port in ports_to_scan
                }
                for future in as_completed(future_map):
                    item = future.result()
                    item["reason"] = "syn-ack" if item["open"] else "conn-refused"
                    results_by_port[item["port"]] = item
                    scanned_count += 1
                    if item["open"]:
                        open_count += 1
                    if item["atRisk"]:
                        at_risk_count += 1
                    now_perf = time.perf_counter()
                    if now_perf - last_broadcast >= 0.08 or scanned_count == total_ports:
                        max_pct = 86 if nmap_bin else 96
                        pct = min(max_pct, 8 + int((scanned_count / max(1, total_ports)) * (max_pct - 8)))
                        self.broadcast(
                            "portscan_progress",
                            {
                                "host": target_host,
                                "ip": resolved_ip,
                                "phase": "scanning",
                                "progressPct": pct,
                                "scannedCount": scanned_count,
                                "totalPorts": total_ports,
                                "openCount": open_count,
                                "atRiskCount": at_risk_count,
                                "lastPort": item["port"],
                                "message": (
                                    f"Probing TCP/{item['port']} ({item['service']}) — "
                                    f"{scanned_count}/{total_ports} ports probed ({open_count} open, {at_risk_count} at-risk)"
                                ),
                            },
                        )
                        last_broadcast = now_perf

            # Phase 2: Real Nmap CLI (-sT -sV / firewall state detection) when nmap binary is available
            nmap_meta: dict = {}
            nmap_version = ""
            os_guess = ""
            if nmap_bin:
                phase1_open = [p for p, r in results_by_port.items() if r["open"]]
                nmap_target_ports = phase1_open if phase1_open else (ports_to_scan if total_ports <= 60 else [])
                if nmap_target_ports:
                    self.broadcast(
                        "portscan_progress",
                        {
                            "host": target_host,
                            "ip": resolved_ip,
                            "phase": "fingerprinting",
                            "progressPct": 91,
                            "scannedCount": total_ports,
                            "totalPorts": total_ports,
                            "openCount": open_count,
                            "atRiskCount": at_risk_count,
                            "message": (
                                f"Running Nmap (-sV) service & firewall state inspection on {len(nmap_target_ports)} port(s)..."
                            ),
                        },
                    )
                    nmap_meta = self._run_nmap_cli(
                        nmap_bin,
                        resolved_ip,
                        nmap_target_ports,
                        timeout_ms_int,
                        scan_versions=bool(phase1_open),
                    )
                    nmap_version = nmap_meta.get("version") or ""
                    os_guess = nmap_meta.get("osGuess") or ""
                    for port_num, np in (nmap_meta.get("ports") or {}).items():
                        entry = results_by_port.get(port_num)
                        if not entry:
                            continue
                        n_state = np.get("state") or ""
                        # Preserve ports already proven open by Phase 1; refine closed vs filtered or discover open
                        if not entry["open"] and n_state in {"open", "filtered", "open|filtered"}:
                            if n_state == "open":
                                entry["open"] = True
                                entry["state"] = "open"
                                entry["latencyMs"] = entry["latencyMs"] or nmap_meta.get("hostLatencyMs")
                            else:
                                entry["state"] = n_state
                        if np.get("reason"):
                            entry["reason"] = np["reason"]
                        if entry["open"]:
                            refined = self._infer_risk_from_service(
                                port_num, np.get("service", ""), np.get("tunnel", ""), entry
                            )
                            entry["service"] = refined.get("service", entry["service"])
                            entry["category"] = refined.get("category", entry["category"])
                            entry["riskLevel"] = refined.get("riskLevel", entry["riskLevel"])
                            entry["atRisk"] = bool(refined.get("atRisk", entry["atRisk"]))
                            entry["effectiveRisk"] = entry["riskLevel"]
                            entry["summary"] = refined.get("summary", entry["summary"])
                            entry["exposureRisk"] = refined.get("exposureRisk", entry["exposureRisk"])
                            entry["remediation"] = refined.get("remediation", entry["remediation"])

                            ver_str = np.get("versionBanner") or ""
                            cpes = np.get("cpes") or []
                            if ver_str:
                                base_banner = entry.get("banner") or ""
                                if base_banner.endswith("listener active") or base_banner.startswith("No response"):
                                    entry["banner"] = ver_str[:130]
                                elif ver_str.lower() not in base_banner.lower():
                                    entry["banner"] = f"{ver_str} · {base_banner}"[:130]
                            if cpes:
                                entry["cpe"] = cpes[0]
                            if np.get("service"):
                                entry["nmapService"] = np["service"]
                        elif entry["state"] == "filtered":
                            entry["banner"] = f"Firewall filtered ({entry['reason'] or 'no-response'})"

            engine_used = (
                f"Nmap {nmap_version} (-sT -sV) + Python Banner Auditor"
                if nmap_bin and nmap_version
                else "Nmap Binary + Python TCP Banner Auditor"
                if nmap_bin
                else "Pulse Parallel TCP & Service Banner Engine"
            )

            ordered_ports = [results_by_port[p] for p in sorted(results_by_port)]
            open_ports = [p for p in ordered_ports if p["open"]]
            at_risk_ports = [p for p in open_ports if p["atRisk"]]
            critical_ports = [p for p in open_ports if p["riskLevel"] == "CRITICAL"]
            high_ports = [p for p in open_ports if p["riskLevel"] == "HIGH"]
            medium_ports = [p for p in open_ports if p["riskLevel"] == "MEDIUM"]
            low_ports = [p for p in open_ports if p["riskLevel"] == "LOW"]
            closed_ports = [p for p in ordered_ports if not p["open"]]
            filtered_ports = [p for p in closed_ports if "filtered" in (p.get("state") or "")]

            # Compute Host Security Posture Score (0 - 100)
            penalty = (
                len(critical_ports) * 25
                + len(high_ports) * 14
                + len(medium_ports) * 6
            )
            security_score = max(0, min(100, 100 - penalty))
            if security_score >= 92:
                security_grade = "A"
                posture_verdict = "HARDENED"
                posture_summary = "No critical or high-risk ports were found exposed on this host."
            elif security_score >= 75:
                security_grade = "B"
                posture_verdict = "MODERATE EXPOSURE"
                posture_summary = f"{len(at_risk_ports)} management or service port(s) are open and should be reviewed."
            elif security_score >= 50:
                security_grade = "C"
                posture_verdict = "AT-RISK SERVICES EXPOSED"
                posture_summary = f"Found {len(at_risk_ports)} at-risk open port(s) ({len(critical_ports)} Critical, {len(high_ports)} High) requiring firewall hardening."
            else:
                security_grade = "F"
                posture_verdict = "HIGH SECURITY EXPOSURE"
                posture_summary = f"Critical network services ({', '.join(str(p['port']) + '/' + p['service'] for p in (critical_ports + high_ports)[:4])}) are openly accessible."

            duration_ms = round((time.perf_counter() - started) * 1000)

            # Generate Nmap CLI transcript incorporating real Nmap version/args when run
            header_ver = f"Nmap {nmap_version}" if nmap_version else "Pulse Nmap Security Auditor 2.0"
            nmap_lines = [
                f"Starting {header_ver} ( https://nmap.org ) at {utc_now()}",
                f"Engine: {engine_used}",
                f"Nmap scan report for {target_host} ({resolved_ip})",
                f"Host is up ({open_ports[0]['latencyMs'] / 1000.0:.4f}s latency)." if open_ports and open_ports[0].get("latencyMs") else f"Host scanned ({total_ports} TCP ports).",
            ]
            if os_guess:
                nmap_lines.append(f"Service Info / OS Guess: {os_guess}")
            nmap_lines.append(
                f"Not shown: {len(closed_ports)} non-open tcp ports ({len(closed_ports) - len(filtered_ports)} closed, {len(filtered_ports)} filtered)"
            )
            nmap_lines.append("PORT      STATE  SERVICE               RISK       VERSION / BANNER")
            for p in open_ports:
                port_col = f"{p['port']}/tcp".ljust(9)
                state_col = "open".ljust(6)
                svc_col = (p.get("nmapService") or p["service"])[:21].ljust(21)
                risk_col = p["riskLevel"].ljust(10)
                nmap_lines.append(f"{port_col} {state_col} {svc_col} {risk_col} {p['banner']}")
            if not open_ports:
                nmap_lines.append("All scanned TCP ports on target are closed or filtered.")
            nmap_lines.append(
                f"\nNmap done: 1 IP address (1 host up) scanned in {duration_ms / 1000.0:.2f} seconds"
            )

            # Match device name from monitored devices or inventory if known
            device_label = target_host
            for d in self.get_devices():
                if d["ip"] == resolved_ip:
                    device_label = f"{d['name']} ({resolved_ip})"
                    break
            else:
                for item in self.get_inventory():
                    if item["ip"] == resolved_ip and item.get("name"):
                        device_label = f"{item['name']} ({resolved_ip})"
                        break

            report = {
                "timestamp": utc_now(),
                "host": target_host,
                "ip": resolved_ip,
                "deviceLabel": device_label,
                "profile": profile_key,
                "profileLabel": profile_label,
                "engine": engine_used,
                "nmapAvailable": bool(nmap_bin),
                "nmapVersion": nmap_version or None,
                "osGuess": os_guess or None,
                "durationMs": duration_ms,
                "securityScore": security_score,
                "securityGrade": security_grade,
                "postureVerdict": posture_verdict,
                "postureSummary": posture_summary,
                "counts": {
                    "totalScanned": total_ports,
                    "open": len(open_ports),
                    "closed": len(closed_ports),
                    "filtered": len(filtered_ports),
                    "atRisk": len(at_risk_ports),
                    "critical": len(critical_ports),
                    "high": len(high_ports),
                    "medium": len(medium_ports),
                    "low": len(low_ports),
                },
                "openPorts": open_ports,
                "atRiskPorts": at_risk_ports,
                "allPorts": ordered_ports,
                "nmapTranscript": "\n".join(nmap_lines),
            }

            report_id = f"{resolved_ip}|{report['timestamp']}"
            report["reportId"] = report_id

            with self.lock:
                hist = self._get_portscan_history()
                hist.insert(0, {
                    "reportId": report_id,
                    "timestamp": report["timestamp"],
                    "host": target_host,
                    "ip": resolved_ip,
                    "deviceLabel": device_label,
                    "profileLabel": profile_label,
                    "securityScore": security_score,
                    "securityGrade": security_grade,
                    "postureVerdict": posture_verdict,
                    "openCount": len(open_ports),
                    "atRiskCount": len(at_risk_ports),
                    "criticalCount": len(critical_ports),
                    "durationMs": duration_ms,
                })
                del hist[15:]
                reports_map = self._get_portscan_reports()
                reports_map[report_id] = report
                valid_ids = {item["reportId"] for item in hist}
                for old_id in list(reports_map.keys()):
                    if old_id not in valid_ids:
                        reports_map.pop(old_id, None)

            self._record_event(
                "PORT_SCAN",
                "CRITICAL" if critical_ports else ("WARNING" if at_risk_ports else "INFO"),
                f"Port Audit: {device_label}",
                f"{profile_label} on {resolved_ip}: {len(open_ports)}/{total_ports} open port(s), {len(at_risk_ports)} at-risk · Score {security_score}/100 ({security_grade}).",
                ip=resolved_ip,
                device_name=device_label,
            )
            self.broadcast("portscan_complete", report)
            return report
        finally:
            scan_lock.release()

    def get_portscan_catalog(self) -> dict:
        """Return Nmap availability, scan profiles, recent scan history, and cached reports."""
        nmap_bin = self._find_nmap_binary()
        with self.lock:
            history = list(self._get_portscan_history())
            reports = dict(self._get_portscan_reports())
        return {
            "nmapAvailable": bool(nmap_bin),
            "nmapPath": nmap_bin,
            "profiles": [
                {
                    "id": k,
                    "label": v["label"],
                    "portCount": len(v["ports"]),
                    "ports": v["ports"],
                }
                for k, v in SCAN_PROFILES.items()
            ],
            "history": history,
            "reports": reports,
        }

