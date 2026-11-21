"""
Crazy Alchemy - MirageNet™
Active Counter-Intelligence Honeypot, Turing Decoy Shell & Quantum Tarpit Labyrinth.

Provides advanced deceptive counter-intelligence:
1. TuringHoneypot: Interactive virtualized command shell (SSH/Telnet) that authentically emulates
   Linux/Windows administration terminals without executing real host processes.
2. CanaryPoison: Polymorphic exfiltration tokens (AWS, Stripe, .env) with tracking webhooks
   that capture an attacker's external public IP, ISP, and User-Agent when leaked.
3. QuantumTarpit: Procedural infinite HTTP directory maze and rate-clamping labyrinth that exhausts
   automated vulnerability scanners (Nikto, SQLmap, Gobuster, Nmap).
"""

import time
import socket
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger('crazyalchemy.honeypot.miragenet')

# Simulated Unix Filesystem for TuringHoneypot
SIMULATED_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
admin:x:1000:1000:System Administrator,,,:/home/admin:/bin/bash
developer:x:1001:1001:DevOps Lead,,,:/home/developer:/bin/bash
postgres:x:105:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
"""

SIMULATED_SHADOW = """root:$6$vitorius$uN1qUeH4sh3dK3yP4ssw0rd99887766554433221100..:19500:0:99999:7:::
admin:$6$alchemy$m4st3rP4ssw0rdH4sh3dEx4mpl39988776655443322..:19500:0:99999:7:::
developer:$6$canary$d3v0psS3cr3tH4sh3dK3y998877665544332211..:19500:0:99999:7:::
"""

SIMULATED_PROCESSES = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 168340 11420 ?        Ss   Nov18   0:04 /sbin/init
root         420  0.0  0.2  72300 18500 ?        Ss   Nov18   0:01 /lib/systemd/systemd-journald
root         850  0.0  0.1  15800  4200 ?        Ss   Nov18   0:00 /usr/sbin/cron -f
postgres    1120  0.1  0.8 385000 68400 ?        Ss   Nov18   0:15 /usr/lib/postgresql/15/bin/postgres
root        1450  0.0  0.1  24500  6800 ?        Ss   Nov18   0:02 /usr/sbin/sshd -D
admin       2105  0.0  0.1  12400  4800 pts/0    Ss   04:20   0:00 -bash
admin       2180  0.0  0.0  10500  2100 pts/0    R+   04:22   0:00 ps aux
"""


@dataclass
class ShellSessionLog:
    session_id: str
    remote_ip: str
    remote_port: int
    captured_credentials: List[str] = field(default_factory=list)
    commands_executed: List[str] = field(default_factory=list)
    exfiltration_payloads: List[str] = field(default_factory=list)
    connected_at: float = 0.0
    duration_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "captured_credentials": self.captured_credentials,
            "commands_executed": self.commands_executed,
            "exfiltration_payloads": self.exfiltration_payloads,
            "connected_at": self.connected_at,
            "connected_time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.connected_at)),
            "duration_sec": round(self.duration_sec, 1)
        }


@dataclass
class DeAnonymizedAttacker:
    token_name: str
    attacker_ip: str
    isp_organization: str
    geolocation: str
    user_agent: str
    triggered_at: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_name": self.token_name,
            "attacker_ip": self.attacker_ip,
            "isp_organization": self.isp_organization,
            "geolocation": self.geolocation,
            "user_agent": self.user_agent,
            "triggered_at": self.triggered_at,
            "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.triggered_at))
        }


class MirageNetEngine:
    """
    MirageNet Active Counter-Intelligence Deception Engine.
    Orchestrates interactive shell emulation, CanaryPoison tracking, and scanner tarpitting.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._shell_sessions: List[ShellSessionLog] = []
        self._deanonymized_attackers: List[DeAnonymizedAttacker] = []
        self._tarpit_requests_trapped = 0
        self._is_enabled = True

    def is_enabled(self) -> bool:
        return self._is_enabled

    def set_enabled(self, enabled: bool):
        with self._lock:
            self._is_enabled = enabled

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_enabled": self._is_enabled,
                "total_shell_sessions": len(self._shell_sessions),
                "deanonymized_attackers_count": len(self._deanonymized_attackers),
                "tarpit_requests_trapped": self._tarpit_requests_trapped,
                "total_commands_captured": sum(len(s.commands_executed) for s in self._shell_sessions)
            }

    def get_shell_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [s.to_dict() for s in self._shell_sessions[-limit:][::-1]]

    def get_deanonymized_attackers(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._deanonymized_attackers[-limit:][::-1]]

    # ── 1. TuringHoneypot Virtual Interactive Shell ─────────────────────

    def execute_virtual_command(self, session: ShellSessionLog, raw_cmd: str) -> str:
        """
        Executes a command inside the virtual in-memory Linux environment.
        Zero host execution risk. Returns simulated stdout/stderr string.
        """
        cmd = raw_cmd.strip()
        if not cmd:
            return ""

        session.commands_executed.append(cmd)
        cmd_parts = cmd.split()
        base_cmd = cmd_parts[0].lower()

        # Capture exfiltration and download attempts
        if base_cmd in ("curl", "wget", "fetch", "tftp") and len(cmd_parts) > 1:
            session.exfiltration_payloads.append(cmd)
            logger.critical(f"🎯 [MirageNet] Captured Hostile Ingress Payload: '{cmd}' from {session.remote_ip}")
            return f"curl: (7) Failed to connect to {cmd_parts[1]}: Connection refused\n"

        if base_cmd in ("whoami", "id"):
            if "id" in base_cmd:
                return "uid=0(root) gid=0(root) groups=0(root)\n"
            return "root\n"

        elif base_cmd in ("hostname",):
            return "sec-gateway-01.vitorius.local\n"

        elif base_cmd in ("uname",):
            if "-a" in cmd:
                return "Linux sec-gateway-01 5.15.0-89-generic #99-Ubuntu SMP Wed Nov 2 15:00:00 UTC 2026 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"

        elif base_cmd in ("pwd",):
            return "/root\n"

        elif base_cmd in ("ls", "dir"):
            if "-la" in cmd or "-l" in cmd:
                return """total 36
drwx------  4 root root 4096 Nov 18 10:20 .
drwxr-xr-x 20 root root 4096 Nov 18 09:15 ..
-rw-------  1 root root  854 Nov 18 10:14 .bash_history
-rw-r--r--  1 root root 3106 Nov 18 09:12 .bashrc
drwx------  2 root root 4096 Nov 18 09:40 .ssh
-rw-r--r--  1 root root  161 Nov 18 10:15 database_backup.sql
-rw-------  1 root root  420 Nov 18 10:18 server_keys.pem
"""
            return "database_backup.sql  server_keys.pem\n"

        elif base_cmd in ("cat", "more", "less", "head", "tail"):
            if len(cmd_parts) > 1:
                target = cmd_parts[1].lower()
                if "passwd" in target:
                    return SIMULATED_PASSWD
                elif "shadow" in target:
                    return SIMULATED_SHADOW
                elif "backup" in target or "sql" in target:
                    return "-- PostgreSQL database dump\nCREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50), pass_hash VARCHAR(128));\n"
                elif "key" in target or "pem" in target:
                    return "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Yv9...\n-----END RSA PRIVATE KEY-----\n"
            return "cat: file not found or permission denied\n"

        elif base_cmd in ("ps", "top"):
            return SIMULATED_PROCESSES

        elif base_cmd in ("ifconfig", "ip"):
            return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:0c:29:4f:8e:12  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
"""

        elif base_cmd in ("exit", "quit"):
            return "logout\nConnection closed by foreign host.\n"

        return f"bash: {base_cmd}: command not found\n"

    # ── 2. CanaryPoison De-Anonymization Tracking ───────────────────────

    def generate_canary_poison_tokens(self) -> Dict[str, str]:
        """
        Generates polymorphic tracking credentials with unique canary IDs.
        When accessed by an exfiltrator, the webhook returns the attacker's public IP.
        """
        canary_uuid = f"trk_{int(time.time())}"
        return {
            "aws_credentials": f"""[default]
aws_access_key_id = AKIA_{canary_uuid.upper()}_PROD
aws_secret_access_key = secret_key_vitorius_canary_{canary_uuid}
region = us-east-1
# Telemetry: canary-ping.vitorius.io/aws/{canary_uuid}
""",
            "env_production": f"""DATABASE_URL=postgres://app_sec:{canary_uuid}@db.vitorius.internal:5432/vault
STRIPE_SECRET_KEY=sk_live_canary_{canary_uuid}_0987654321
OPENAI_API_KEY=sk-proj-canary-{canary_uuid}-AlphaBetaGamma
CANARY_TRIPWIRE_ENDPOINT=https://canary.vitorius.io/api/v1/ping/{canary_uuid}
"""
        }

    def record_deanonymized_attacker(
        self,
        token_name: str,
        attacker_ip: str,
        isp: str = "Unknown ISP / Cloud Provider",
        geo: str = "External Network",
        ua: str = "curl/7.88.1"
    ):
        """Records an exfiltrated token trip that revealed the external threat actor."""
        with self._lock:
            att = DeAnonymizedAttacker(
                token_name=token_name,
                attacker_ip=attacker_ip,
                isp_organization=isp,
                geolocation=geo,
                user_agent=ua,
                triggered_at=time.time()
            )
            self._deanonymized_attackers.append(att)
            logger.critical(
                f"🌍 [CanaryPoison] ATTACKER DE-ANONYMIZED! Stolen token '{token_name}' accessed from "
                f"IP: {attacker_ip} ({isp}, {geo}). User-Agent: {ua}"
            )

    # ── 3. QuantumTarpit Scanner Defense ───────────────────────────────

    def generate_quantum_tarpit_response(self, path: str) -> Tuple[int, Dict[str, str], bytes]:
        """
        Generates an infinite procedural directory maze response to exhaust automated scanners.
        """
        with self._lock:
            self._tarpit_requests_trapped += 1

        clean_path = path.strip("/")
        # Synthesize next recursive labyrinth level
        next_depth = f"{clean_path}/node_{self._tarpit_requests_trapped}"

        html = f"""<!DOCTYPE html>
<html>
<head><title>Administrative Configuration Index</title></head>
<body>
<h2>Index of /{clean_path}</h2>
<ul>
  <li><a href="/{clean_path}/..">Parent Directory</a></li>
  <li><a href="/{next_depth}">[DIR] auth_vault_v2/</a></li>
  <li><a href="/{clean_path}/config_backup.tar.gz">[BIN] config_backup.tar.gz (5.4 GB)</a></li>
  <li><a href="/{clean_path}/database.sql">[TXT] database.sql (1.2 GB)</a></li>
</ul>
<p>Notice: Secure Administrative Node. Audit active.</p>
</body>
</html>"""
        headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.52 (Ubuntu)",
            "X-Tarpit-Clamped": "1"
        }
        return 200, headers, html.encode('utf-8')
