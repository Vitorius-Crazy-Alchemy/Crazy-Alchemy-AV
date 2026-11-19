"""
Crazy Alchemy - TrapNet Active Deception & HoneyToken Canary Engine
Provides active network and host deception defense:
1. Multi-protocol fake service listeners (HTTP, FTP, Telnet, Redis, MySQL, SSH, RDP, SMB).
2. Interactive protocol emulation that lures intruders and captures credentials/payloads.
3. HoneyToken Canary file tripwires that detect infostealers and ransomware in real time.
4. One-click defensive deception presets and categorized template catalog.
5. Automated firewall IP banning, forensics capture, and threat classification.
"""

import os
import sys
import time
import socket
import select
import sqlite3
import logging
import threading
import struct
import base64
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Callable, Set, Any, Tuple

logger = logging.getLogger('crazyalchemy.win.honeypot')

# Default deception trap ports mapping: port -> service banner / label
DEFAULT_TRAP_PORTS: Dict[int, str] = {
    22: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    23: "Telnet Service Ready",
    445: "SMBv2 Microsoft-DS",
    1433: "Microsoft SQL Server",
    3306: "5.7.42-MySQL-Community-Server",
    3389: "Remote Desktop Protocol (RDP)",
    5900: "RFB 003.008 (VNC Server)"
}

SAFE_WHITELIST_IPS: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0"
}

# ==============================================================================
# 🎯 COMPREHENSIVE DECOY SERVICE CATALOG
# 26 Decoy Services categorized across 6 operational sectors
# ==============================================================================
DECOY_CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "remote_access": [
        {
            "id": "ssh",
            "name": "OpenSSH Secure Shell (Linux Gateway)",
            "default_port": 22,
            "category": "Remote Administration",
            "protocol": "raw",
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
            "risk_level": "Critical",
            "icon": "🔑",
            "description": "Catches automated SSH brute-force worms, Mirai botnets, and unauthorized credential stuffers.",
            "recommended": True
        },
        {
            "id": "telnet",
            "name": "Cisco / Linux Telnet Management Gateway",
            "default_port": 23,
            "category": "Remote Administration",
            "protocol": "telnet",
            "banner": "\r\nUser Access Verification\r\n\r\nUsername: ",
            "risk_level": "High",
            "icon": "📟",
            "description": "Emulates an interactive router terminal prompt; captures attempted usernames and passwords before dropping.",
            "recommended": True
        },
        {
            "id": "rdp",
            "name": "Windows Remote Desktop Protocol (RDP)",
            "default_port": 3389,
            "category": "Remote Administration",
            "protocol": "raw",
            "banner": "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x00\x00\x00\x00",
            "risk_level": "Critical",
            "icon": "🖥️",
            "description": "Catches ransomware operators and internet-wide port scanners hunting for exposed Windows RDP servers.",
            "recommended": True
        },
        {
            "id": "vnc",
            "name": "VNC Remote Desktop Framebuffer",
            "default_port": 5900,
            "category": "Remote Administration",
            "protocol": "raw",
            "banner": "RFB 003.008\n",
            "risk_level": "High",
            "icon": "🖵",
            "description": "Deceives remote control scanners searching for unauthenticated or default-password virtual desktop servers.",
            "recommended": True
        },
        {
            "id": "winrm",
            "name": "Windows Remote Management (WinRM HTTP)",
            "default_port": 5985,
            "category": "Remote Administration",
            "protocol": "http",
            "banner": "Microsoft-HTTPAPI/2.0",
            "risk_level": "Critical",
            "icon": "⚡",
            "description": "Catches lateral movement attempts using PowerShell Remoting and WinRM management endpoints.",
            "recommended": False
        }
    ],
    "databases": [
        {
            "id": "mysql",
            "name": "MySQL Community Server Database",
            "default_port": 3306,
            "category": "Enterprise Databases",
            "protocol": "mysql",
            "banner": "5.7.42-MySQL-Community-Server",
            "risk_level": "Critical",
            "icon": "🐬",
            "description": "Sends standard MySQL 5.7 protocol handshake; captures automated SQL injection probes and database crawlers.",
            "recommended": True
        },
        {
            "id": "mssql",
            "name": "Microsoft SQL Server TDS Listener",
            "default_port": 1433,
            "category": "Enterprise Databases",
            "protocol": "raw",
            "banner": "\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x02",
            "risk_level": "Critical",
            "icon": "🗄️",
            "description": "Lures MSSQL brute-force worms and corporate database ransomware trying default SA credentials.",
            "recommended": True
        },
        {
            "id": "postgres",
            "name": "PostgreSQL Database Engine",
            "default_port": 5432,
            "category": "Enterprise Databases",
            "protocol": "raw",
            "banner": "E\x00\x00\x00\x54SFATAL\x00C28000\x00Mpassword authentication failed\x00\x00",
            "risk_level": "High",
            "icon": "🐘",
            "description": "Detects automated PostgreSQL database discovery and credential stuffing scripts.",
            "recommended": False
        },
        {
            "id": "redis",
            "name": "Redis In-Memory Key-Value Cache",
            "default_port": 6379,
            "category": "Enterprise Databases",
            "protocol": "redis",
            "banner": "-NOAUTH Authentication required.\r\n",
            "risk_level": "Critical",
            "icon": "🔴",
            "description": "Interactive Redis honeypot that catches crypto-miners and ransomware trying to execute unauthenticated Redis writes.",
            "recommended": True
        },
        {
            "id": "mongodb",
            "name": "MongoDB Document Database",
            "default_port": 27017,
            "category": "Enterprise Databases",
            "protocol": "raw",
            "banner": "{\"ok\": 0.0, \"errmsg\": \"Unauthorized access detected\", \"code\": 13}\r\n",
            "risk_level": "High",
            "icon": "🍃",
            "description": "Catches automated ransomware bots scanning for unauthenticated NoSQL databases to ransom data.",
            "recommended": False
        }
    ],
    "web_cloud": [
        {
            "id": "http_admin",
            "name": "Corporate Router & Gateway Admin Portal",
            "default_port": 80,
            "category": "Web & Cloud Consoles",
            "protocol": "http",
            "banner": "Apache/2.4.58 (Win64) OpenSSL/1.1.1w",
            "risk_level": "Critical",
            "icon": "🌐",
            "description": "Interactive HTTP honeypot: serves fake router login challenge; captures HTTP methods, URIs, User-Agents, and Basic Auth.",
            "recommended": True
        },
        {
            "id": "http_alt",
            "name": "Apache Tomcat / Proxy Alt Web Console",
            "default_port": 8080,
            "category": "Web & Cloud Consoles",
            "protocol": "http",
            "banner": "Apache-Coyote/1.1",
            "risk_level": "High",
            "icon": "🐱",
            "description": "Traps web vulnerability scanners (Nikto, ZAP, Nmap) inspecting alternative HTTP application ports.",
            "recommended": True
        },
        {
            "id": "docker_api",
            "name": "Docker Engine REST API Daemon",
            "default_port": 2375,
            "category": "Web & Cloud Consoles",
            "protocol": "http",
            "banner": "Docker/24.0.7 (linux)",
            "risk_level": "Critical",
            "icon": "🐳",
            "description": "Traps container escape exploits and unauthorized crypto-mining botnets searching for open Docker APIs.",
            "recommended": False
        },
        {
            "id": "actuator",
            "name": "Spring Boot Actuator Microservice",
            "default_port": 8088,
            "category": "Web & Cloud Consoles",
            "protocol": "http",
            "banner": "SpringBoot/3.2.1",
            "risk_level": "High",
            "icon": "🌱",
            "description": "Captures Spring4Shell, Log4j, and actuator environment variable extraction exploits.",
            "recommended": False
        },
        {
            "id": "jenkins",
            "name": "Jenkins CI/CD Automation Server",
            "default_port": 8081,
            "category": "Web & Cloud Consoles",
            "protocol": "http",
            "banner": "Jenkins/2.426.1",
            "risk_level": "High",
            "icon": "⚙️",
            "description": "Catches supply chain attackers and automated tools probing for exposed CI/CD build automation nodes.",
            "recommended": False
        }
    ],
    "file_sharing": [
        {
            "id": "smb",
            "name": "Microsoft SMB File Sharing (SMBv2/v3)",
            "default_port": 445,
            "category": "File Shares & Storage",
            "protocol": "raw",
            "banner": "\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8",
            "risk_level": "Critical",
            "icon": "📁",
            "description": "Primary trap for EternalBlue, WannaCry, and ransomware worms spreading laterally across Windows network shares.",
            "recommended": True
        },
        {
            "id": "ftp",
            "name": "ProFTPD / Microsoft FTP Service",
            "default_port": 21,
            "category": "File Shares & Storage",
            "protocol": "ftp",
            "banner": "220 Microsoft FTP Service Ready.\r\n",
            "risk_level": "High",
            "icon": "📦",
            "description": "Interactive FTP honeypot: prompts for USER and PASS, records the attacker's attempted credentials, then returns 530.",
            "recommended": True
        },
        {
            "id": "nfs",
            "name": "Network File System (NFS Export)",
            "default_port": 2049,
            "category": "File Shares & Storage",
            "protocol": "raw",
            "banner": "\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3",
            "risk_level": "Medium",
            "icon": "💾",
            "description": "Traps automated scans looking for unprotected NFS network storage shares and mounted directories.",
            "recommended": False
        }
    ],
    "iot_industrial": [
        {
            "id": "rtsp",
            "name": "Hikvision RTSP Surveillance IP Camera",
            "default_port": 554,
            "category": "IoT & Network Hardware",
            "protocol": "raw",
            "banner": "RTSP/1.0 401 Unauthorized\r\nServer: Hikvision-Webs\r\nWWW-Authenticate: Digest realm=\"IP Camera\"\r\n\r\n",
            "risk_level": "High",
            "icon": "📹",
            "description": "Emulates an IP surveillance video camera; detects botnets hunting for live video streams and default camera logins.",
            "recommended": True
        },
        {
            "id": "mqtt",
            "name": "MQTT IoT Telemetry Message Broker",
            "default_port": 1883,
            "category": "IoT & Network Hardware",
            "protocol": "raw",
            "banner": "\x20\x02\x00\x05",
            "risk_level": "Medium",
            "icon": "📡",
            "description": "Traps unauthorized IoT subscribers, telemetry sniffers, and smart home sensor hijacking attempts.",
            "recommended": False
        },
        {
            "id": "modbus",
            "name": "Modbus SCADA Industrial PLC Controller",
            "default_port": 502,
            "category": "IoT & Network Hardware",
            "protocol": "raw",
            "banner": "\x00\x00\x00\x00\x00\x03\x01\x81\x01",
            "risk_level": "Critical",
            "icon": "🏭",
            "description": "Deceives industrial espionage scanners probing for critical infrastructure programmable logic controllers (PLCs).",
            "recommended": False
        },
        {
            "id": "snmp",
            "name": "SNMP Agent Community Listener",
            "default_port": 161,
            "category": "IoT & Network Hardware",
            "protocol": "raw",
            "banner": "\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63",
            "risk_level": "Medium",
            "icon": "📊",
            "description": "Detects network discovery scanners searching for default 'public' community strings to harvest system metrics.",
            "recommended": False
        }
    ],
    "mail_directory": [
        {
            "id": "smtp",
            "name": "SMTP Corporate Mail Gateway",
            "default_port": 25,
            "category": "Mail & Directory Services",
            "protocol": "smtp",
            "banner": "220 mail.corp-internal.net ESMTP Postfix Service ready\r\n",
            "risk_level": "High",
            "icon": "📧",
            "description": "Interactive SMTP honeypot: captures spam bots, phishing relays, and automated HELO/EHLO mail probes.",
            "recommended": False
        },
        {
            "id": "ldap",
            "name": "Active Directory LDAP Directory Service",
            "default_port": 389,
            "category": "Mail & Directory Services",
            "protocol": "raw",
            "banner": "\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x31\x04\x00\x04\x00",
            "risk_level": "Critical",
            "icon": "🏢",
            "description": "Catches internal network reconnaissance probing for Active Directory domain controllers and user enumerators.",
            "recommended": False
        }
    ]
}

# ==============================================================================
# 🎯 ONE-CLICK DEFENSIVE DECEPTION PRESETS
# Ready-made configurations for non-technical users
# ==============================================================================
DECEPTION_PRESETS: Dict[str, Dict[str, Any]] = {
    "home_workstation": {
        "title": "Home & SOHO Workstation Baseline",
        "icon": "🛡️",
        "description": "Recommended for home PCs and laptops. Arms decoys for Windows file sharing, remote desktop, and terminal bots.",
        "ports": {
            445: ("SMBv2 Microsoft-DS", "raw"),
            3389: ("Remote Desktop Protocol (RDP)", "raw"),
            22: ("OpenSSH_8.9p1 Ubuntu", "raw"),
            23: ("Telnet Service Ready", "telnet"),
            5900: ("RFB 003.008 (VNC Server)", "raw")
        }
    },
    "enterprise_ad": {
        "title": "Enterprise Active Directory Fortress",
        "icon": "🏢",
        "description": "Defends corporate workstations and servers against lateral movement, database scraping, and domain reconnaissance.",
        "ports": {
            445: ("SMBv2 Microsoft-DS", "raw"),
            1433: ("Microsoft SQL Server", "raw"),
            3389: ("Remote Desktop Protocol (RDP)", "raw"),
            5985: ("WinRM Microsoft-HTTPAPI/2.0", "http"),
            389: ("Active Directory LDAP", "raw"),
            22: ("OpenSSH_8.9p1 Ubuntu", "raw")
        }
    },
    "web_cloud": {
        "title": "Web & Cloud Infrastructure Deception",
        "icon": "🌐",
        "description": "Traps web vulnerability scanners, database crawlers, and API scrapers probing cloud servers.",
        "ports": {
            80: ("Corporate Router Admin Portal", "http"),
            8080: ("Apache Tomcat Alt-Web", "http"),
            3306: ("MySQL Community Server", "mysql"),
            6379: ("Redis Cache In-Memory", "redis"),
            27017: ("MongoDB Document Store", "raw"),
            2375: ("Docker Engine REST API", "http")
        }
    },
    "iot_scada": {
        "title": "Industrial SCADA & IoT Deception Mesh",
        "icon": "🏭",
        "description": "Detects Mirai malware botnets, camera surveillance hijackers, and industrial Modbus PLC probes.",
        "ports": {
            554: ("Hikvision RTSP IP Camera", "raw"),
            1883: ("MQTT IoT Telemetry Broker", "raw"),
            502: ("Modbus SCADA Industrial PLC", "raw"),
            161: ("SNMP Agent Community Listener", "raw"),
            23: ("Cisco Telnet Gateway", "telnet")
        }
    },
    "maximum_spiderweb": {
        "title": "Maximum Deception Spiderweb (All Traps Active)",
        "icon": "🥷",
        "description": "Transforms your workstation into an inescapable minefield. Deploys 12+ high-value decoy listeners simultaneously.",
        "ports": {
            21: ("FTP Service Ready", "ftp"),
            22: ("OpenSSH_8.9p1 Ubuntu", "raw"),
            23: ("Telnet Service Ready", "telnet"),
            80: ("Corporate Router Admin Portal", "http"),
            445: ("SMBv2 Microsoft-DS", "raw"),
            1433: ("Microsoft SQL Server", "raw"),
            3306: ("MySQL Community Server", "mysql"),
            3389: ("Remote Desktop Protocol (RDP)", "raw"),
            5900: ("RFB 003.008 (VNC Server)", "raw"),
            6379: ("Redis Cache In-Memory", "redis"),
            8080: ("Apache Tomcat Alt-Web", "http"),
            8088: ("SpringBoot Actuator", "http")
        }
    }
}


def is_port_in_use(port: int) -> bool:
    """Checks if a TCP port is currently occupied by an active process on this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            res = s.connect_ex(("127.0.0.1", port))
            return res == 0
    except Exception:
        return False


# ==============================================================================
# 🪤 HONEYTOKEN CANARY SYSTEM (OUR OWN INNOVATION)
# Real-time bait credential files with file system tripwires
# ==============================================================================
@dataclass
class HoneyToken:
    token_id: str
    token_name: str
    lure_type: str
    file_path: str
    deployed_at: float
    tripped_at: Optional[float] = None
    status: str = "ACTIVE"  # "ACTIVE", "TRIPPED", "DISARMED"
    sha256_hash: str = ""
    file_size: int = 0
    details: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class HoneyTokenManager:
    """
    Manages HoneyToken canary files placed in bait locations to expose
    infostealers, ransomware lateral movement, and unauthorized insider access.
    """

    TEMPLATES = [
        {
            "id": "passwords_vault",
            "name": "Corporate Password Vault",
            "filename": "passwords_production_backup.xlsx",
            "lure_type": "Credential Vault",
            "description": "Fake encrypted spreadsheet containing honey administrative credentials. Lures infostealers like RedLine and Vidar.",
            "content": (
                "System,URL,Username,Password,Notes\n"
                "Corporate AWS Root,https://aws.amazon.com/console,corp_admin,Tr0ub4dor&3_Honey!,Master Infrastructure Key\n"
                "Primary Domain Controller,ldap://dc01.corp.internal,Administrator,Winter2026_Secure#P@ss,Active Directory Master\n"
                "Production SQL Cluster,mssql://sql01.corp.internal:1433,sa,HoneySqlMaster#992,Customer Billing DB\n"
                "Executive VPN Portal,https://vpn.corp.internal,c_exec_user,AutumnBreeze2026$,Restricted Global Gateway\n"
            ).encode("utf-8")
        },
        {
            "id": "cloud_keys",
            "name": "AWS Production Cloud Access Keys",
            "filename": "aws_master_keys.json",
            "lure_type": "Cloud Credentials",
            "description": "Simulated AWS IAM root access keys. Instantly exposes scripts searching for AWS tokens.",
            "content": (
                "{\n"
                '  "AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE",\n'
                '  "AWSSecretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
                '  "Region": "us-east-1",\n'
                '  "Environment": "Production-Master",\n'
                '  "CanaryTag": "TRAPNET-CANARY-TOKEN-77182"\n'
                "}\n"
            ).encode("utf-8")
        },
        {
            "id": "vpn_credentials",
            "name": "Corporate VPN Access Profile",
            "filename": "corporate_vpn_credentials.env",
            "lure_type": "Network Access Lure",
            "description": "Fake OpenVPN / WireGuard connection parameters. Lures network lateral movement actors.",
            "content": (
                "# Crazy Alchemy Corporate VPN Configuration\n"
                "VPN_GATEWAY=vpn.corp-secure-network.internal\n"
                "VPN_PORT=1194\n"
                "VPN_USER=remote_security_admin\n"
                "VPN_AUTH_TOKEN=HONEY_TOKEN_7b8a1c92d3e4f506a7b8c9d0e1f2\n"
                "CERT_STATUS=ENCRYPTED_VALID\n"
            ).encode("utf-8")
        },
        {
            "id": "database_vault",
            "name": "Database Connection Strings Vault",
            "filename": "database_connection_vault.ini",
            "lure_type": "Database Credentials",
            "description": "Fake database connection strings for MSSQL, Oracle, and MySQL. Catches database harvesters.",
            "content": (
                "[ProductionDB]\n"
                "Server=db01.corp.internal\n"
                "Database=EnterpriseClients\n"
                "User=db_admin\n"
                "Password=V1tor1us_Honey_DB_2026!\n"
                "Provider=SQLNCLI11\n"
            ).encode("utf-8")
        },
        {
            "id": "financial_doc",
            "name": "Executive Financial Audit Report",
            "filename": "executive_audit_q4_confidential.docx",
            "lure_type": "Confidential Document",
            "description": "High-value corporate memo decoy. Lures data-exfiltration and corporate espionage actors.",
            "content": (
                "CONFIDENTIAL EXECUTIVE SUMMARY - Q4 INTERNAL AUDIT\n"
                "===================================================\n"
                "This document contains proprietary corporate audit findings and account balances.\n"
                "Canary Document Reference: TRAPNET-DOC-CANARY-99014\n"
            ).encode("utf-8")
        }
    ]

    def __init__(self, db_path: Path, alert_callback: Optional[Callable[[Dict], None]] = None):
        self.db_path = db_path
        self.alert_callback = alert_callback
        self._running = False
        self._watch_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Default bait directory
        base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~/.local/share"))) / "VitoriusFirewallWin" / "HoneyTokens"
        base.mkdir(parents=True, exist_ok=True)
        self.default_bait_dir = base

        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS honey_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT UNIQUE NOT NULL,
                    token_name TEXT NOT NULL,
                    lure_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    deployed_at REAL NOT NULL,
                    tripped_at REAL,
                    status TEXT NOT NULL,
                    sha256_hash TEXT,
                    file_size INTEGER,
                    details TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to init honey_tokens table: {e}")

    def deploy_canary(self, template_id: str, target_dir: Optional[Path] = None) -> Optional[HoneyToken]:
        """Deploys a single canary lure file and registers its tripwire."""
        template = next((t for t in self.TEMPLATES if t["id"] == template_id), None)
        if not template:
            return None

        out_dir = target_dir or self.default_bait_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        file_path = out_dir / template["filename"]

        try:
            content = template["content"]
            file_path.write_bytes(content)
            sha256 = hashlib.sha256(content).hexdigest()
            size = len(content)

            token = HoneyToken(
                token_id=f"token_{template_id}_{int(time.time())}",
                token_name=template["name"],
                lure_type=template["lure_type"],
                file_path=str(file_path),
                deployed_at=time.time(),
                status="ACTIVE",
                sha256_hash=sha256,
                file_size=size,
                details=template["description"]
            )

            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO honey_tokens
                (token_id, token_name, lure_type, file_path, deployed_at, tripped_at, status, sha256_hash, file_size, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token.token_id, token.token_name, token.lure_type, token.file_path,
                token.deployed_at, None, token.status, token.sha256_hash, token.file_size, token.details
            ))
            conn.commit()
            conn.close()

            logger.info(f"HoneyToken Canary deployed: {file_path}")
            return token
        except Exception as e:
            logger.error(f"Failed to deploy canary {template_id}: {e}")
            return None

    def deploy_all_canaries(self, target_dir: Optional[Path] = None) -> List[HoneyToken]:
        """Deploys all available canary lures in one click."""
        deployed = []
        for t in self.TEMPLATES:
            tok = self.deploy_canary(t["id"], target_dir=target_dir)
            if tok:
                deployed.append(tok)
        return deployed

    def disarm_all_canaries(self) -> int:
        """Safely removes all deployed canary files and disarms their tripwires."""
        tokens = self.get_canaries()
        removed_count = 0
        for tok in tokens:
            p = Path(tok["file_path"])
            if p.exists():
                try:
                    p.unlink()
                    removed_count += 1
                except Exception as e:
                    logger.debug(f"Could not delete canary file {p}: {e}")

        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("UPDATE honey_tokens SET status = 'DISARMED'")
            conn.commit()
            conn.close()
        except Exception:
            pass

        logger.info(f"Disarmed {removed_count} HoneyToken canaries.")
        return removed_count

    def get_canaries(self) -> List[Dict]:
        """Retrieves list of all registered HoneyToken canaries."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            rows = cur.execute("SELECT * FROM honey_tokens ORDER BY deployed_at DESC").fetchall()
            canaries = [dict(r) for r in rows]
            conn.close()
            return canaries
        except Exception as e:
            logger.error(f"Failed to fetch canaries: {e}")
            return []

    def check_canaries(self) -> List[Dict]:
        """
        Polls canary files to verify integrity.
        If a file was modified, truncated, deleted, or its hash changed, trips the wire!
        """
        tripped = []
        tokens = self.get_canaries()
        for tok in tokens:
            if tok["status"] != "ACTIVE":
                continue

            p = Path(tok["file_path"])
            is_tripped = False
            trip_reason = ""

            if not p.exists():
                is_tripped = True
                trip_reason = "Canary bait file was deleted or moved by an unauthorized actor/ransomware!"
            else:
                try:
                    cur_bytes = p.read_bytes()
                    cur_hash = hashlib.sha256(cur_bytes).hexdigest()
                    if cur_hash != tok["sha256_hash"] or len(cur_bytes) != tok["file_size"]:
                        is_tripped = True
                        trip_reason = "Canary bait file content was modified or encrypted (potential ransomware attack)!"
                except Exception as e:
                    is_tripped = True
                    trip_reason = f"Canary bait file access error (locked or quarantined): {e}"

            if is_tripped:
                tok["status"] = "TRIPPED"
                tok["tripped_at"] = time.time()
                tok["details"] = trip_reason
                tripped.append(tok)
                self._mark_tripped(tok["token_id"], trip_reason)

                logger.critical(f"HONEYTOKEN CANARY TRIPPED! File: {tok['file_path']} Reason: {trip_reason}")
                if self.alert_callback:
                    try:
                        self.alert_callback(tok)
                    except Exception:
                        pass

        return tripped

    def _mark_tripped(self, token_id: str, reason: str):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                UPDATE honey_tokens
                SET status = 'TRIPPED', tripped_at = ?, details = ?
                WHERE token_id = ?
            """, (time.time(), reason, token_id))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to update tripped canary {token_id}: {e}")

    def start_watchdog(self):
        """Starts background tripwire polling loop."""
        with self._lock:
            if self._running:
                return
            self._running = True

        def _worker():
            while self._running:
                try:
                    self.check_canaries()
                except Exception as e:
                    logger.debug(f"Canary check loop error: {e}")
                time.sleep(3.0)

        self._watch_thread = threading.Thread(target=_worker, daemon=True, name="honeytoken-watchdog")
        self._watch_thread.start()

    def stop_watchdog(self):
        with self._lock:
            self._running = False


# ==============================================================================
# 🚨 TRAP EVENT & INTRUDER DATA MODEL
# ==============================================================================
@dataclass
class TrapEvent:
    source_ip: str
    source_port: int
    trap_port: int
    trap_service: str
    protocol: str
    timestamp: float
    raw_payload_hex: str
    payload_preview: str
    auto_blocked: bool
    details: str = ""
    attack_type: str = "Reconnaissance"
    captured_credentials: str = ""
    user_agent: str = ""
    request_uri: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ==============================================================================
# 🛡️ TRAPNET DECEPTION HONEYPOT MANAGER
# ==============================================================================
class HoneypotManager:
    """
    Manages deception listening sockets, interactive protocol emulators,
    and automated intruder countermeasures.
    """

    def __init__(self,
                 trap_ports: Optional[Dict[int, str]] = None,
                 block_callback: Optional[Callable[[str], bool]] = None,
                 alert_callback: Optional[Callable[[TrapEvent], None]] = None,
                 db_path: Optional[Path] = None,
                 ban_mode: str = "permanent",
                 auto_whitelist_lan: bool = True):
        self.trap_ports = trap_ports or dict(DEFAULT_TRAP_PORTS)
        # Protocol emulation mode per port: "raw", "http", "ftp", "telnet", "redis", "mysql"
        self.trap_protocols: Dict[int, str] = {}
        for p in self.trap_ports:
            self.trap_protocols[p] = self._infer_protocol(p)

        self.block_callback = block_callback
        self.alert_callback = alert_callback
        self.ban_mode = ban_mode
        self.auto_whitelist_lan = auto_whitelist_lan
        self._running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self._active_trapped_ports: Set[int] = set()
        self._lock = threading.Lock()

        # Database initialization
        if db_path is None:
            base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~/.local/share"))) / "VitoriusFirewallWin"
            base.mkdir(parents=True, exist_ok=True)
            self.db_path = base / "honeypot_events.db"
        else:
            self.db_path = db_path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

        # Initialize HoneyToken Canary Tripwire Manager
        self.honey_token_mgr = HoneyTokenManager(
            db_path=self.db_path,
            alert_callback=self._on_canary_tripped
        )

    def _infer_protocol(self, port: int) -> str:
        """Infers the appropriate interactive protocol emulator for a given port."""
        if port in (80, 8080, 8081, 8088, 2375, 5985):
            return "http"
        if port == 21:
            return "ftp"
        if port == 23:
            return "telnet"
        if port == 6379:
            return "redis"
        if port == 3306:
            return "mysql"
        if port == 25:
            return "smtp"
        return "raw"

    def _init_db(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS trap_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    trap_port INTEGER NOT NULL,
                    trap_service TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    raw_payload_hex TEXT,
                    payload_preview TEXT,
                    auto_blocked INTEGER NOT NULL,
                    details TEXT,
                    attack_type TEXT,
                    captured_credentials TEXT,
                    user_agent TEXT,
                    request_uri TEXT
                )
            """)

            # Ensure columns exist if migrating from older schema
            cur.execute("PRAGMA table_info(trap_events)")
            cols = [col[1] for col in cur.fetchall()]
            if "attack_type" not in cols:
                cur.execute("ALTER TABLE trap_events ADD COLUMN attack_type TEXT DEFAULT 'Reconnaissance'")
            if "captured_credentials" not in cols:
                cur.execute("ALTER TABLE trap_events ADD COLUMN captured_credentials TEXT DEFAULT ''")
            if "user_agent" not in cols:
                cur.execute("ALTER TABLE trap_events ADD COLUMN user_agent TEXT DEFAULT ''")
            if "request_uri" not in cols:
                cur.execute("ALTER TABLE trap_events ADD COLUMN request_uri TEXT DEFAULT ''")

            cur.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON trap_events(source_ip)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON trap_events(timestamp)")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialize honeypot database: {e}")

    def _on_canary_tripped(self, canary_dict: Dict):
        """Dispatches an alert when a HoneyToken canary is tripped."""
        event = TrapEvent(
            source_ip="LOCAL_PROCESS_TRIPWIRE",
            source_port=0,
            trap_port=0,
            trap_service=canary_dict.get("token_name", "HoneyToken Canary"),
            protocol="FILE_SYSTEM",
            timestamp=time.time(),
            raw_payload_hex="",
            payload_preview=f"Canary file breached: {canary_dict.get('file_path')}",
            auto_blocked=False,
            details=canary_dict.get("details", "Canary file touched"),
            attack_type="Infostealer / Ransomware Canary Breach"
        )
        self._record_event(event)

    def is_running(self) -> bool:
        return self._running

    def start(self):
        """Starts all deception listeners and canary tripwires."""
        with self._lock:
            if self._running:
                return
            self._running = True

        for port, service_name in list(self.trap_ports.items()):
            proto = self.trap_protocols.get(port, self._infer_protocol(port))
            t = threading.Thread(
                target=self._listener_worker,
                args=(port, service_name, proto),
                daemon=True,
                name=f"trapnet-{port}"
            )
            self._threads.append(t)
            t.start()

        # Start HoneyToken tripwire watchdog
        if hasattr(self, 'honey_token_mgr') and self.honey_token_mgr:
            self.honey_token_mgr.start_watchdog()

        logger.info(f"TrapNet Deception Honeypot activated with {len(self.trap_ports)} deception ports.")

    def _arm_firewall_rule(self, port: int):
        """Ensure Windows Firewall lets packets reach the deception port."""
        if sys.platform == "win32":
            rule_name = f"VitoriusFW_TrapNet_Allow_{port}_TCP"
            try:
                import subprocess
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}', 'dir=in', 'action=allow',
                    'protocol=TCP', f'localport={port}', 'profile=any'
                ], capture_output=True, creationflags=0x08000000, timeout=5)
            except Exception as e:
                logger.debug(f"Could not add firewall allow rule for trap port {port}: {e}")

    def _disarm_firewall_rule(self, port: int):
        """Removes Windows Firewall rule for the deception port."""
        if sys.platform == "win32":
            rule_name = f"VitoriusFW_TrapNet_Allow_{port}_TCP"
            try:
                import subprocess
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ], capture_output=True, creationflags=0x08000000, timeout=5)
            except Exception as e:
                logger.debug(f"Could not remove firewall allow rule for trap port {port}: {e}")

    def stop(self):
        """Stops all deception listeners and cleans up sockets and rules."""
        with self._lock:
            self._running = False
            for port in list(self._active_trapped_ports):
                self._disarm_firewall_rule(port)
            for s in self._sockets:
                try:
                    s.close()
                except Exception:
                    pass
            self._sockets.clear()
            self._active_trapped_ports.clear()

        if hasattr(self, 'honey_token_mgr') and self.honey_token_mgr:
            self.honey_token_mgr.stop_watchdog()

        logger.info("TrapNet Deception Honeypot stopped.")

    def add_trap_port(self, port: int, service_name: str, protocol: Optional[str] = None) -> bool:
        """Dynamically arms a new deception trap listener."""
        with self._lock:
            if port in self._active_trapped_ports:
                return False
            self.trap_ports[port] = service_name
            self.trap_protocols[port] = protocol or self._infer_protocol(port)

        if self._running:
            proto = self.trap_protocols[port]
            t = threading.Thread(
                target=self._listener_worker,
                args=(port, service_name, proto),
                daemon=True,
                name=f"trapnet-{port}"
            )
            self._threads.append(t)
            t.start()
        return True

    def remove_trap_port(self, port: int) -> bool:
        """Dynamically disarms and closes an active deception listener."""
        with self._lock:
            self.trap_ports.pop(port, None)
            self.trap_protocols.pop(port, None)
            self._active_trapped_ports.discard(port)
            to_remove = []
            for s in self._sockets:
                try:
                    if s.getsockname()[1] == port:
                        s.close()
                        to_remove.append(s)
                except Exception:
                    pass
            for s in to_remove:
                if s in self._sockets:
                    self._sockets.remove(s)

        self._disarm_firewall_rule(port)
        logger.info(f"TrapNet disarmed port {port}")
        return True

    def apply_preset(self, preset_key: str) -> Dict[str, Any]:
        """
        Applies a pre-configured defensive deception profile.
        Safely detects port conflicts before arming.
        """
        preset = DECEPTION_PRESETS.get(preset_key)
        if not preset:
            return {"success": False, "error": f"Unknown preset: {preset_key}"}

        armed_ports = []
        conflicts = []

        for port, (label, proto) in preset["ports"].items():
            # Check if port is already active in our own trapnet
            if port in self._active_trapped_ports:
                armed_ports.append(port)
                continue

            # Check if an external legitimate service is listening
            if is_port_in_use(port):
                conflicts.append(port)
                continue

            if self.add_trap_port(port, label, protocol=proto):
                armed_ports.append(port)
            else:
                conflicts.append(port)

        return {
            "success": True,
            "preset": preset["title"],
            "armed_count": len(armed_ports),
            "armed_ports": armed_ports,
            "conflicts": conflicts
        }

    def get_active_traps_detail(self) -> List[Dict[str, Any]]:
        """Returns details for all configured and active trap ports."""
        traps = []
        stats = self.get_trap_stats()
        counts_by_port = {item["port"]: item["count"] for item in stats.get("port_breakdown", [])}

        for port, label in self.trap_ports.items():
            is_active = port in self._active_trapped_ports
            proto = self.trap_protocols.get(port, self._infer_protocol(port))

            # Match category and risk from catalog
            cat = "Custom Decoy"
            risk = "Medium"
            icon = "🍯"
            for c_list in DECOY_CATALOG.values():
                for item in c_list:
                    if item["default_port"] == port:
                        cat = item["category"]
                        risk = item["risk_level"]
                        icon = item.get("icon", "🍯")
                        break

            traps.append({
                "port": port,
                "label": label,
                "protocol": proto.upper(),
                "category": cat,
                "risk_level": risk,
                "icon": icon,
                "is_active": is_active,
                "hits_count": counts_by_port.get(port, 0)
            })

        return sorted(traps, key=lambda x: (not x["is_active"], x["port"]))

    def _listener_worker(self, port: int, service_name: str, protocol: str = "raw"):
        server_sock = None
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Use SO_EXCLUSIVEADDRUSE on Windows to prevent socket port hijacking
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE') and sys.platform == "win32":
                try:
                    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                except Exception:
                    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            server_sock.settimeout(1.0)
            server_sock.bind(("0.0.0.0", port))
            server_sock.listen(5)

            with self._lock:
                self._sockets.append(server_sock)
                self._active_trapped_ports.add(port)

            # Ensure Windows Firewall passes inbound packets to the listener
            self._arm_firewall_rule(port)
            logger.info(f"TrapNet armed on port {port} ({service_name}) [Mode: {protocol}]")
        except OSError as e:
            logger.warning(f"Could not bind trap port {port} ({service_name}) - occupied: {e}")
            if server_sock:
                try:
                    server_sock.close()
                except Exception:
                    pass
            return

        while self._running:
            try:
                client_sock, (client_ip, client_port) = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Handle intruder in worker thread with protocol emulation
            threading.Thread(
                target=self._handle_intruder,
                args=(client_sock, client_ip, client_port, port, service_name, protocol),
                daemon=True
            ).start()

    # ==========================================================================
    # 🥷 INTERACTIVE PROTOCOL EMULATION HANDLERS (INNOVATION)
    # ==========================================================================
    def _handle_intruder(self, client_sock: socket.socket, client_ip: str, client_port: int,
                          trap_port: int, service_name: str, protocol: str = "raw"):
        raw_hex = ""
        preview = ""
        captured_creds = ""
        user_agent = ""
        request_uri = ""
        attack_type = "Reconnaissance Scan"

        try:
            client_sock.settimeout(3.0)

            if protocol == "http":
                # Interactive HTTP Protocol Emulator
                req_data = client_sock.recv(4096)
                if req_data:
                    raw_hex = req_data[:96].hex()
                    preview = req_data[:96].decode("utf-8", errors="replace")

                    # Parse HTTP request line across full received payload
                    full_req = req_data.decode("utf-8", errors="replace")
                    lines = full_req.split("\r\n")
                    if lines:
                        request_uri = lines[0].strip()

                    # Extract User-Agent and Authorization
                    for line in lines:
                        if line.lower().startswith("user-agent:"):
                            user_agent = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("authorization:"):
                            auth_part = line.split(":", 1)[1].strip()
                            if auth_part.lower().startswith("basic "):
                                try:
                                    b64 = auth_part.split(" ", 1)[1].strip()
                                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                                    captured_creds = f"HTTP Basic Auth: {decoded}"
                                except Exception:
                                    captured_creds = auth_part

                    attack_type = "Web Admin / API Reconnaissance"

                    # Send realistic 401 Unauthorized Challenge
                    resp = (
                        "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: Apache/2.4.58 (Win64) OpenSSL/1.1.1w\r\n"
                        'WWW-Authenticate: Basic realm="Restricted Corporate Gateway"\r\n'
                        "Content-Type: text/html; charset=UTF-8\r\n"
                        "Content-Length: 154\r\n"
                        "Connection: close\r\n\r\n"
                        "<html><head><title>401 Authorization Required</title></head>"
                        "<body><h1>401 Authorization Required</h1><p>Access denied by policy.</p></body></html>"
                    )
                    client_sock.sendall(resp.encode("utf-8"))

            elif protocol == "ftp":
                # Interactive FTP Protocol Emulator
                client_sock.sendall(b"220 Microsoft FTP Service Ready.\r\n")
                user_cmd = client_sock.recv(512).decode("utf-8", errors="replace")
                u_str = ""
                p_str = ""
                if "USER" in user_cmd.upper():
                    u_str = user_cmd.strip()
                    client_sock.sendall(b"331 Password required for user.\r\n")
                    pass_cmd = client_sock.recv(512).decode("utf-8", errors="replace")
                    if "PASS" in pass_cmd.upper():
                        p_str = pass_cmd.strip()
                    client_sock.sendall(b"530 User cannot log in.\r\n")

                captured_creds = f"{u_str} | {p_str}".strip(" |")
                preview = f"FTP Probe: {captured_creds}"
                raw_hex = (u_str + p_str).encode("utf-8")[:64].hex()
                attack_type = "FTP Credential Brute-Force"

            elif protocol == "telnet":
                # Interactive Telnet Protocol Emulator
                client_sock.sendall(b"\r\nUser Access Verification\r\n\r\nUsername: ")
                user_data = client_sock.recv(256).decode("utf-8", errors="replace").strip()
                client_sock.sendall(b"Password: ")
                pass_data = client_sock.recv(256).decode("utf-8", errors="replace").strip()
                client_sock.sendall(b"\r\n% Login invalid\r\n\r\n")

                captured_creds = f"Username: {user_data} | Password: {pass_data}"
                preview = captured_creds
                raw_hex = (user_data + pass_data).encode("utf-8")[:64].hex()
                attack_type = "Telnet IoT / Shell Brute-Force"

            elif protocol == "redis":
                # Interactive Redis Protocol Emulator
                req_data = client_sock.recv(1024)
                if req_data:
                    raw_hex = req_data[:64].hex()
                    preview = req_data[:64].decode("utf-8", errors="replace").strip()
                    if "AUTH" in preview.upper():
                        captured_creds = preview
                    client_sock.sendall(b"-NOAUTH Authentication required.\r\n")
                attack_type = "Redis Database / Crypto-Miner Probe"

            elif protocol == "mysql":
                # Send MySQL 5.7 Server Greeting Handshake Packet
                greeting = (
                    b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x34\x32\x00\x01\x00\x00\x00"
                    b"\x44\x51\x32\x27\x52\x3a\x54\x4b\x00\xff\xf7\x08\x02\x00\x7f\x80"
                )
                client_sock.sendall(greeting)
                handshake_resp = client_sock.recv(1024)
                if handshake_resp:
                    raw_hex = handshake_resp[:64].hex()
                    preview = handshake_resp[:64].decode("utf-8", errors="replace")
                attack_type = "MySQL Database Scraper Probe"

            else:
                # Raw Banner & Payload Sniffer
                banner = self.trap_ports.get(trap_port, "Service Ready\r\n")
                if isinstance(banner, str):
                    try:
                        client_sock.sendall(banner.encode("utf-8", errors="replace"))
                    except Exception:
                        pass
                data = client_sock.recv(1024)
                if data:
                    raw_hex = data[:64].hex()
                    preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:64])

                # Classify specific raw ports
                if trap_port == 445:
                    attack_type = "SMB Worm / EternalBlue Recon"
                elif trap_port == 3389:
                    attack_type = "RDP Terminal Services Recon"
                elif trap_port == 22:
                    attack_type = "SSH Secure Shell Probe"
                elif trap_port == 5900:
                    attack_type = "VNC Framebuffer Recon"
                elif trap_port == 1433:
                    attack_type = "MSSQL Corporate Database Probe"

        except Exception as e:
            logger.debug(f"Protocol emulation notice on port {trap_port}: {e}")
        finally:
            try:
                linger_fmt = 'hh' if sys.platform == "win32" else 'ii'
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(linger_fmt, 1, 0))
                client_sock.close()
            except Exception:
                pass

        # Ignore local whitelisted connections
        if client_ip in SAFE_WHITELIST_IPS:
            return

        # Auto-whitelist local subnet / gateway if requested
        if self.auto_whitelist_lan and self._is_lan_gateway(client_ip):
            logger.info(f"Skipping ban for LAN gateway: {client_ip}")
            return

        auto_blocked = False
        if self.block_callback and self.ban_mode != "alert_only":
            try:
                auto_blocked = self.block_callback(client_ip)
            except Exception as e:
                logger.error(f"Error calling block callback for {client_ip}: {e}")

        event = TrapEvent(
            source_ip=client_ip,
            source_port=client_port,
            trap_port=trap_port,
            trap_service=service_name,
            protocol="TCP",
            timestamp=time.time(),
            raw_payload_hex=raw_hex,
            payload_preview=preview,
            auto_blocked=auto_blocked,
            details=f"Inbound reconnaissance detected on decoy port {trap_port} ({service_name})",
            attack_type=attack_type,
            captured_credentials=captured_creds,
            user_agent=user_agent,
            request_uri=request_uri
        )

        self._record_event(event)

        logger.critical(
            f"DECEPTION TRAP TRIGGERED! Intruder {client_ip}:{client_port} -> Port {trap_port} "
            f"({service_name}). Attack: {attack_type}. Banned: {auto_blocked}"
        )

        if self.alert_callback:
            try:
                self.alert_callback(event)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _is_lan_gateway(self, ip: str) -> bool:
        """Heuristically checks if IP is the local gateway (e.g. *.1 or *.254)."""
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] in ("192", "10", "172"):
            if parts[3] in ("1", "254"):
                return True
        return False

    def _record_event(self, event: TrapEvent):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO trap_events
                (source_ip, source_port, trap_port, trap_service, protocol, timestamp,
                 raw_payload_hex, payload_preview, auto_blocked, details, attack_type,
                 captured_credentials, user_agent, request_uri)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.source_ip,
                event.source_port,
                event.trap_port,
                event.trap_service,
                event.protocol,
                event.timestamp,
                event.raw_payload_hex,
                event.payload_preview,
                1 if event.auto_blocked else 0,
                event.details,
                event.attack_type,
                event.captured_credentials,
                event.user_agent,
                event.request_uri
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to record trap event to database: {e}")

    def get_trap_stats(self) -> Dict:
        """Returns statistical overview of trapped intruders and honeytokens."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            total_traps = cur.execute("SELECT COUNT(*) FROM trap_events").fetchone()[0]
            unique_ips = cur.execute("SELECT COUNT(DISTINCT source_ip) FROM trap_events WHERE source_ip != 'LOCAL_PROCESS_TRIPWIRE'").fetchone()[0]
            day_ago = time.time() - 86400
            traps_24h = cur.execute("SELECT COUNT(*) FROM trap_events WHERE timestamp >= ?", (day_ago,)).fetchone()[0]
            auto_blocked_count = cur.execute("SELECT COUNT(*) FROM trap_events WHERE auto_blocked = 1").fetchone()[0]

            port_breakdown = cur.execute("""
                SELECT trap_port, trap_service, COUNT(*) as cnt
                FROM trap_events GROUP BY trap_port ORDER BY cnt DESC LIMIT 6
            """).fetchall()

            attack_breakdown = cur.execute("""
                SELECT COALESCE(attack_type, 'Reconnaissance'), COUNT(*) as cnt
                FROM trap_events GROUP BY attack_type ORDER BY cnt DESC LIMIT 5
            """).fetchall()

            canaries_deployed = 0
            canaries_tripped = 0
            try:
                canaries_deployed = cur.execute("SELECT COUNT(*) FROM honey_tokens WHERE status = 'ACTIVE'").fetchone()[0]
                canaries_tripped = cur.execute("SELECT COUNT(*) FROM honey_tokens WHERE status = 'TRIPPED'").fetchone()[0]
            except Exception:
                pass

            conn.close()

            return {
                "total_traps": total_traps,
                "unique_ips": unique_ips,
                "traps_24h": traps_24h,
                "auto_blocked_count": auto_blocked_count,
                "active_trap_ports": list(self._active_trapped_ports),
                "port_breakdown": [{"port": r[0], "service": r[1], "count": r[2]} for r in port_breakdown],
                "attack_breakdown": [{"attack_type": r[0], "count": r[1]} for r in attack_breakdown],
                "canaries_deployed": canaries_deployed,
                "canaries_tripped": canaries_tripped
            }
        except Exception as e:
            logger.error(f"Failed to query trap stats: {e}")
            return {
                "total_traps": 0,
                "unique_ips": 0,
                "traps_24h": 0,
                "auto_blocked_count": 0,
                "active_trap_ports": list(self._active_trapped_ports),
                "port_breakdown": [],
                "attack_breakdown": [],
                "canaries_deployed": 0,
                "canaries_tripped": 0
            }

    def get_recent_events(self, limit: int = 50) -> List[Dict]:
        """Returns recent trap events ordered chronologically descending."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            rows = cur.execute("""
                SELECT * FROM trap_events ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
            events = [dict(r) for r in rows]
            conn.close()
            return events
        except Exception as e:
            logger.error(f"Failed to fetch recent trap events: {e}")
            return []

    def export_forensics_report(self, export_format: str = "json") -> str:
        """Exports all intercepted intruder forensic telemetry to JSON or CSV."""
        events = self.get_recent_events(limit=500)
        canaries = self.honey_token_mgr.get_canaries() if hasattr(self, 'honey_token_mgr') else []
        stats = self.get_trap_stats()

        if export_format.lower() == "csv":
            import io
            import csv
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Timestamp", "Source_IP", "Source_Port", "Trap_Port", "Service", "Attack_Type", "Captured_Credentials", "Auto_Blocked"])
            for e in events:
                t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("timestamp", 0)))
                writer.writerow([
                    e.get("id"), t_str, e.get("source_ip"), e.get("source_port"),
                    e.get("trap_port"), e.get("trap_service"), e.get("attack_type"),
                    e.get("captured_credentials"), "BANNED" if e.get("auto_blocked") else "LOGGED"
                ])
            return output.getvalue()
        else:
            report = {
                "report_title": "Crazy Alchemy TrapNet Deception Forensics Report",
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "statistics": stats,
                "active_decoy_ports": self.get_active_traps_detail(),
                "honeytoken_canaries": canaries,
                "intercepted_events": events
            }
            return json.dumps(report, indent=2)

    def clear_events(self):
        """Clears logged intruder events."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("DELETE FROM trap_events")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to clear trap events: {e}")
