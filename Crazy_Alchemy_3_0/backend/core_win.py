"""
Vitorius Firewall Win - Core Backend for Windows 11
Manages Windows Advanced Firewall rules, profiles, per-app permissions,
IP blocking, and the Panic Lockdown protocol via netsh advfirewall and COM.
"""

import subprocess
import os
import re
import ipaddress
import logging
import time
from typing import Optional, List, Dict, Any, Tuple, Set

import sys

from backend.lineage_guard import LineageGuardEngine
from backend.beacon_shaper import BeaconEntropyShaper

logger = logging.getLogger('vitorius.win.core')

RULE_PREFIX = "VitoriusFW_"
RULE_NAME_KEYS = {
    "rule_name", "regelname", "nombre_de_regla", "nom_de_la_règle",
    "nome_regola", "reglename", "имя_правила"
}


def _run_cmd(cmd: List[str], timeout: int = 15) -> subprocess.CompletedProcess:
    """Run shell command safely with timeout, hidden window flags on Windows, and error capturing."""
    kwargs: Dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "check": False,
    }
    if sys.platform == "win32":
        # Suppress flashing console windows in GUI executables
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        return subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        raise


def _send_service_ipc(payload: dict) -> Optional[dict]:
    """Sends JSON command to the Vitorius Background Service named pipe if active."""
    if sys.platform != "win32":
        return None
    try:
        import win32file
        import json
        pipe_path = r"\\.\pipe\VitoriusFirewallWinIPC"
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None
        )
        msg_bytes = json.dumps(payload).encode('utf-8')
        win32file.WriteFile(handle, msg_bytes)
        resp_data = win32file.ReadFile(handle, 64 * 1024)
        win32file.CloseHandle(handle)
        if resp_data and len(resp_data) > 1:
            return json.loads(resp_data[1].decode('utf-8'))
    except Exception:
        pass
    return None


def _run_cmd_elevated(cmd_str: str, timeout: int = 30) -> bool:
    """Executes commands with elevated Administrator token via Windows UAC if possible."""
    if sys.platform != "win32":
        return False
    try:
        ps_cmd = f"Start-Process cmd.exe -ArgumentList '/c {cmd_str}' -Verb RunAs -WindowStyle Hidden -Wait"
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=0x08000000
        )
        return res.returncode == 0
    except Exception as e:
        logger.error(f"Elevated execution failed: {e}")
        return False


PROTECTED_IPS: Set[str] = {
    "127.0.0.1", "::1", "localhost", "0.0.0.0"
}

PROTECTED_DEV_PROCESSES: Set[str] = {
    "antigravity.exe", "code.exe", "cursor.exe", "python.exe", "pythonw.exe",
    "node.exe", "git.exe", "devenv.exe", "idea64.exe", "pycharm64.exe",
    "clion64.exe", "webstorm64.exe", "rider64.exe", "rust-analyzer.exe"
}


def is_protected_ip(ip_str: str) -> bool:
    """Checks if an IP or CIDR is protected (loopback, link-local, multicast, or protected subnet) and must never be blocked."""
    if not ip_str:
        return True
    clean = ip_str.strip().lower()
    if clean in PROTECTED_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_network(clean, strict=False)
        return (
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            clean.startswith("127.") or
            clean == "::1"
        )
    except Exception:
        return clean.startswith("127.") or clean in ("localhost", "::1")


KNOWN_SECURITY_SERVICES: Dict[str, List[Dict[str, str]]] = {
    "CoreNetworking": [
        {"port": "67-68", "protocol": "UDP", "dir": "in", "desc": "DHCP_In"},
        {"port": "67-68", "protocol": "UDP", "dir": "out", "desc": "DHCP_Out"},
        {"port": "53", "protocol": "UDP", "dir": "out", "desc": "DNS_UDP_Out"},
        {"port": "53", "protocol": "TCP", "dir": "out", "desc": "DNS_TCP_Out"},
    ],
    "DNS": [
        {"port": "53", "protocol": "UDP", "dir": "out", "desc": "DNS_UDP_Out"},
        {"port": "53", "protocol": "TCP", "dir": "out", "desc": "DNS_TCP_Out"},
    ],
    "HTTPS": [
        {"port": "443", "protocol": "TCP", "dir": "out", "desc": "HTTPS_Out"},
        {"port": "443", "protocol": "TCP", "dir": "in", "desc": "HTTPS_In"},
    ],
    "HTTP": [
        {"port": "80", "protocol": "TCP", "dir": "out", "desc": "HTTP_Out"},
        {"port": "80", "protocol": "TCP", "dir": "in", "desc": "HTTP_In"},
    ],
    "SSH": [
        {"port": "22", "protocol": "TCP", "dir": "in", "desc": "SSH_In"},
        {"port": "22", "protocol": "TCP", "dir": "out", "desc": "SSH_Out"},
    ],
    "CorporateWork": [
        {"port": "443", "protocol": "TCP", "dir": "out", "desc": "HTTPS_Work_Out"},
        {"port": "80", "protocol": "TCP", "dir": "out", "desc": "HTTP_Work_Out"},
        {"port": "22", "protocol": "TCP", "dir": "out", "desc": "SSH_Git_Out"},
        {"port": "9418", "protocol": "TCP", "dir": "out", "desc": "Git_Protocol_Out"},
        {"port": "8443", "protocol": "TCP", "dir": "out", "desc": "Alt_HTTPS_Out"},
        {"port": "8080", "protocol": "TCP", "dir": "out", "desc": "Dev_Proxy_Out"},
        {"port": "500", "protocol": "UDP", "dir": "out", "desc": "IPSec_IKE_Out"},
        {"port": "4500", "protocol": "UDP", "dir": "out", "desc": "IPSec_NAT_Out"},
    ],
    "FileAndPrinterSharing": [
        {"port": "445", "protocol": "TCP", "dir": "in", "desc": "SMB_In"},
        {"port": "137", "protocol": "UDP", "dir": "in", "desc": "NetBIOS_Name_In"},
        {"port": "138", "protocol": "UDP", "dir": "in", "desc": "NetBIOS_Dgm_In"},
        {"port": "139", "protocol": "TCP", "dir": "in", "desc": "NetBIOS_Ssn_In"},
        {"port": "3702", "protocol": "UDP", "dir": "in", "desc": "WSD_In"},
        {"port": "5357", "protocol": "TCP", "dir": "in", "desc": "WSD_HTTP_In"},
    ],
    "mDNS": [
        {"port": "5353", "protocol": "UDP", "dir": "in", "desc": "mDNS_In"},
        {"port": "5353", "protocol": "UDP", "dir": "out", "desc": "mDNS_Out"},
    ],
    "RemoteDesktopLocal": [
        {"port": "3389", "protocol": "TCP", "dir": "in", "desc": "RDP_TCP_In"},
        {"port": "3389", "protocol": "UDP", "dir": "in", "desc": "RDP_UDP_In"},
    ],
    "SteamClient": [
        {"port": "27015-27030", "protocol": "TCP", "dir": "in", "desc": "Steam_Game_TCP_In"},
        {"port": "27015-27030", "protocol": "TCP", "dir": "out", "desc": "Steam_Game_TCP_Out"},
        {"port": "27015-27030", "protocol": "UDP", "dir": "in", "desc": "Steam_Game_UDP_In"},
        {"port": "27015-27030", "protocol": "UDP", "dir": "out", "desc": "Steam_Game_UDP_Out"},
        {"port": "3478-3480", "protocol": "UDP", "dir": "in", "desc": "Steam_Voice_UDP_In"},
        {"port": "3478-3480", "protocol": "UDP", "dir": "out", "desc": "Steam_Voice_UDP_Out"},
        {"port": "27000-27100", "protocol": "UDP", "dir": "in", "desc": "Steam_Download_UDP_In"},
        {"port": "27000-27100", "protocol": "UDP", "dir": "out", "desc": "Steam_Download_UDP_Out"},
        {"port": "4380", "protocol": "UDP", "dir": "in", "desc": "Steam_Query_UDP_In"},
        {"port": "4380", "protocol": "UDP", "dir": "out", "desc": "Steam_Query_UDP_Out"},
        {"port": "3074", "protocol": "UDP", "dir": "in", "desc": "Steam_XboxLive_UDP_In"},
        {"port": "3074", "protocol": "UDP", "dir": "out", "desc": "Steam_XboxLive_UDP_Out"},
    ],
    "GamingPlatforms": [
        {"port": "50000-65535", "protocol": "UDP", "dir": "out", "desc": "Discord_Voice_Out"},
        {"port": "50000-65535", "protocol": "UDP", "dir": "in", "desc": "Discord_Voice_In"},
        {"port": "5222", "protocol": "TCP", "dir": "out", "desc": "EpicGames_XMPP_Out"},
        {"port": "3478-3479", "protocol": "UDP", "dir": "out", "desc": "EpicGames_STUN_Out"},
        {"port": "1119", "protocol": "TCP", "dir": "out", "desc": "BattleNet_TCP_Out"},
        {"port": "3724", "protocol": "TCP", "dir": "out", "desc": "BattleNet_Auth_Out"},
        {"port": "6112", "protocol": "TCP", "dir": "out", "desc": "BattleNet_Game_Out"},
        {"port": "5000-5500", "protocol": "UDP", "dir": "out", "desc": "Riot_Game_UDP_Out"},
        {"port": "8393-8400", "protocol": "TCP", "dir": "out", "desc": "Riot_PVP_TCP_Out"},
        {"port": "2099", "protocol": "TCP", "dir": "out", "desc": "Riot_Chat_TCP_Out"},
        {"port": "25565", "protocol": "TCP", "dir": "in", "desc": "Minecraft_Server_In"},
        {"port": "25565", "protocol": "TCP", "dir": "out", "desc": "Minecraft_Client_Out"},
        {"port": "3074", "protocol": "UDP", "dir": "in", "desc": "XboxLive_Multiplayer_In"},
        {"port": "3074", "protocol": "UDP", "dir": "out", "desc": "XboxLive_Multiplayer_Out"},
        {"port": "88", "protocol": "UDP", "dir": "out", "desc": "XboxLive_Kerberos_Out"},
    ],
    "DiscordVoice": [
        {"port": "50000-65535", "protocol": "UDP", "dir": "out", "desc": "Discord_Media_Out"},
        {"port": "50000-65535", "protocol": "UDP", "dir": "in", "desc": "Discord_Media_In"},
        {"port": "443", "protocol": "TCP", "dir": "out", "desc": "Discord_Gateway_Out"},
    ],
    "Loopback": [
        {"port": "any", "protocol": "ANY", "dir": "in", "desc": "Loopback_Local_In"},
        {"port": "any", "protocol": "ANY", "dir": "out", "desc": "Loopback_Local_Out"},
    ],
    "NTP": [
        {"port": "123", "protocol": "UDP", "dir": "out", "desc": "NTP_Time_Out"},
    ],
    "UPnP": [
        {"port": "1900", "protocol": "UDP", "dir": "in", "desc": "UPnP_In"},
    ]
}


def _parse_port_spec(p: Any, default_dir: str = "in") -> Optional[Tuple[str, str, str]]:
    """Returns (port_str, protocol, direction) or None from dict, str, or int port spec."""
    if isinstance(p, dict):
        port_num = str(p.get("port", "")).strip()
        proto = str(p.get("protocol", "TCP")).strip().upper()
        dir_val = str(p.get("direction", p.get("dir", default_dir))).strip().lower()
        if dir_val not in ("in", "out"):
            dir_val = default_dir
    elif isinstance(p, (str, int)):
        p_str = str(p).strip()
        if "/" in p_str:
            parts = p_str.split("/", 1)
            port_num = parts[0].strip()
            proto = parts[1].strip().upper()
        else:
            port_num = p_str
            proto = "TCP"
        dir_val = default_dir
    else:
        return None

    if not port_num:
        return None
    return port_num, proto, dir_val


class WindowsFirewallCore:
    """Core firewall interface wrapping Windows Advanced Firewall."""

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._cache_time: Dict[str, float] = {}
        self._panic_active: bool = False
        self._active_profile: str = "Private"
        self._active_profile_rules: List[str] = []

        # Novel Pillar 2 Engines: LineageGuard™ & BeaconEntropyShaper™
        self.lineage_guard = LineageGuardEngine(firewall_block_cb=self.block_ip)
        self.beacon_shaper = BeaconEntropyShaper(tarpit_callback=self._tarpit_c2_endpoint)

        self.ensure_loopback_and_dev_rules()
        self._check_firewall_status()

    def ensure_loopback_and_dev_rules(self):
        """
        Ensures loopback (127.0.0.1 / ::1) is explicitly whitelisted in both inbound
        and outbound directions so local tools, IDEs (Antigravity), and IPC are never blocked.
        """
        try:
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={RULE_PREFIX}Loopback_In', 'dir=in', 'action=allow',
                'remoteip=127.0.0.1,::1', 'profile=any'
            ])
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={RULE_PREFIX}Loopback_Out', 'dir=out', 'action=allow',
                'remoteip=127.0.0.1,::1', 'profile=any'
            ])
            logger.info("Loopback communication rules verified active (127.0.0.1 / ::1).")
        except Exception as e:
            logger.debug(f"Loopback rules verification notice: {e}")

    def _tarpit_c2_endpoint(self, remote_ip: str, remote_port: int, process_name: str = ""):
        """Tarpits suspected C2 endpoints with safety safeguards for protected IPs/tools."""
        try:
            if is_protected_ip(remote_ip):
                logger.debug(f"Skipping tarpit on protected IP {remote_ip}")
                return
            p_lower = (process_name or "").lower()
            if p_lower in PROTECTED_DEV_PROCESSES:
                logger.info(f"Skipping tarpit for protected developer process: {p_lower}")
                return
            logger.critical(f"🛑 [Phantom Tarpit] Quarantining C2 Beacon destination {remote_ip}:{remote_port} ({process_name})")
            self.block_ip(remote_ip)
        except Exception as e:
            logger.error(f"Failed to apply tarpit block on {remote_ip}: {e}")

    def invalidate_cache(self):
        """Invalidate all cached firewall responses."""
        self._cache.clear()
        self._cache_time.clear()

    def _check_firewall_status(self) -> bool:
        """Check if Windows Firewall service is running across English and localized Windows editions."""
        try:
            res = _run_cmd(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'])
            if res.returncode == 0 and res.stdout:
                # Match "State ON" or localized equivalents (Status EIN, État ACTIVÉ, Estado ACTIVO)
                has_active = bool(re.search(r'\b(ON|EIN|ACTIF|ACTIVADO|ACTIVÉ|1)\b', res.stdout, re.IGNORECASE))
                is_running = has_active or ("State" in res.stdout and "OFF" not in res.stdout)
            else:
                is_running = False
            self._cache['is_running'] = is_running
            self._cache_time['is_running'] = time.time()
            return is_running
        except Exception as e:
            logger.warning(f"Could not query firewall status: {e}")
            return False

    def is_running(self, force_refresh: bool = False) -> bool:
        now = time.time()
        if not force_refresh and 'is_running' in self._cache and (now - self._cache_time.get('is_running', 0)) < 10.0:
            return self._cache['is_running']
        return self._check_firewall_status()

    # ── Panic Mode ──────────────────────────────────────────────────

    def get_panic_mode(self, force_refresh: bool = False) -> bool:
        now = time.time()
        if not force_refresh and 'panic_mode' in self._cache and (now - self._cache_time.get('panic_mode', 0)) < 3.0:
            return self._cache['panic_mode']

        # Check if panic rule exists by checking for rule identifier directly (language-agnostic)
        try:
            # 1. Check if Panic block rule exists (both prefix variants)
            res1 = _run_cmd(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={RULE_PREFIX}PANIC_IN'])
            rule_exists = (res1.returncode == 0 and f"{RULE_PREFIX}PANIC_IN" in res1.stdout)
            if not rule_exists:
                res1_alt = _run_cmd(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=VFW_PANIC_IN'])
                rule_exists = (res1_alt.returncode == 0 and "VFW_PANIC_IN" in res1_alt.stdout)

            # 2. Check if allprofiles policy is set to block outbound
            res2 = _run_cmd(['netsh', 'advfirewall', 'show', 'allprofiles', 'firewallpolicy'])
            policy_blocked = False
            if res2.returncode == 0:
                policy_blocked = "blockoutbound" in res2.stdout.lower()

            is_panic = rule_exists or policy_blocked
            self._panic_active = is_panic
            self._cache['panic_mode'] = is_panic
            self._cache_time['panic_mode'] = now
            return is_panic
        except Exception:
            return self._panic_active

    def set_panic_mode(self, enabled: bool) -> bool:
        """Enable or disable emergency Panic Lockdown mode on Windows 11."""
        try:
            if enabled:
                # 1. Enforce strict block on inbound and outbound across all profiles
                res_pol = _run_cmd([
                    'netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound'
                ])
                # 2. Add high-priority catch-all block rules
                res_in = _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}PANIC_IN', 'dir=in', 'action=block', 'profile=any'
                ])
                res_out = _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}PANIC_OUT', 'dir=out', 'action=block', 'profile=any'
                ])

                direct_ok = (res_pol.returncode == 0 or res_in.returncode == 0 or res_out.returncode == 0)
                if not direct_ok:
                    # Attempt via IPC named pipe to LocalSystem background service if active
                    ipc_resp = _send_service_ipc({"action": "SET_PANIC", "enable": True})
                    if ipc_resp and ipc_resp.get("status") == "ok":
                        direct_ok = True
                    else:
                        # Attempt elevated execution via PowerShell RunAs
                        elev_cmd = (
                            f'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound & '
                            f'netsh advfirewall firewall add rule name={RULE_PREFIX}PANIC_IN dir=in action=block profile=any & '
                            f'netsh advfirewall firewall add rule name={RULE_PREFIX}PANIC_OUT dir=out action=block profile=any'
                        )
                        direct_ok = _run_cmd_elevated(elev_cmd)

                # Verify actual panic status if direct command failed
                current_state = self.get_panic_mode(force_refresh=True)
                if not direct_ok and not current_state:
                    logger.error("Failed to enable Windows Panic Lockdown: Administrator privileges required.")
                    return False

                self._panic_active = True
                logger.critical("PANIC LOCKDOWN ACTIVATED on Windows 11 — ALL NETWORK TRAFFIC SEVERED.")
            else:
                # Remove panic block rules (both prefix variants)
                res_del1 = _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={RULE_PREFIX}PANIC_IN'
                ])
                res_del2 = _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={RULE_PREFIX}PANIC_OUT'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=VFW_PANIC_IN'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=VFW_PANIC_OUT'
                ])
                # Restore default profile policy (Block Inbound, Allow Outbound)
                res_pol = _run_cmd([
                    'netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound'
                ])

                direct_ok = (res_pol.returncode == 0 or res_del1.returncode == 0 or res_del2.returncode == 0)
                if not direct_ok:
                    # Attempt via IPC named pipe to LocalSystem background service
                    ipc_resp = _send_service_ipc({"action": "SET_PANIC", "enable": False})
                    if ipc_resp and ipc_resp.get("status") == "ok":
                        direct_ok = True
                    else:
                        # Attempt elevated execution via PowerShell RunAs
                        elev_cmd = (
                            f'netsh advfirewall firewall delete rule name={RULE_PREFIX}PANIC_IN & '
                            f'netsh advfirewall firewall delete rule name={RULE_PREFIX}PANIC_OUT & '
                            f'netsh advfirewall firewall delete rule name=VFW_PANIC_IN & '
                            f'netsh advfirewall firewall delete rule name=VFW_PANIC_OUT & '
                            f'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound'
                        )
                        direct_ok = _run_cmd_elevated(elev_cmd)

                current_state = self.get_panic_mode(force_refresh=True)
                if not direct_ok and current_state:
                    logger.error("Failed to lift Windows Panic Lockdown: Administrator privileges required.")
                    return False

                self._panic_active = False
                logger.info("Panic lockdown lifted on Windows 11 — Network traffic restored.")

            self.invalidate_cache()
            self._cache['panic_mode'] = enabled
            self._cache_time['panic_mode'] = time.time()
            return True
        except Exception as e:
            logger.error(f"Failed to set panic mode ({enabled}): {e}")
            return False

    def enable_panic_mode(self) -> bool:
        return self.set_panic_mode(True)

    def disable_panic_mode(self) -> bool:
        return self.set_panic_mode(False)

    # ── Rules Management ────────────────────────────────────────────

    def add_port_rule(self, port: str, protocol: str = "TCP", action: str = "allow", direction: str = "in") -> bool:
        """Add port rule (e.g. 80, 443, 27015-27030)."""
        rule_name = f"{RULE_PREFIX}Port_{port}_{protocol.upper()}_{direction.upper()}"
        try:
            res = _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                f'dir={direction.lower()}',
                f'action={action.lower()}',
                f'protocol={protocol.upper()}',
                f'localport={port}',
                'profile=any'
            ])
            self.invalidate_cache()
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to add port rule: {e}")
            return False

    def remove_port_rule(self, port: str, protocol: str = "TCP", direction: str = "in") -> bool:
        rule_name = f"{RULE_PREFIX}Port_{port}_{protocol.upper()}_{direction.upper()}"
        try:
            res = _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'
            ])
            self.invalidate_cache()
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to remove port rule: {e}")
            return False

    def block_port(self, port: str, protocol: str = "TCP", direction: str = "in") -> bool:
        """Adds a high-priority block rule for a port or port range."""
        return self.add_port_rule(port, protocol=protocol, action="block", direction=direction)

    def toggle_rule_enabled(self, rule_name: str, enabled: bool) -> bool:
        """Enables or disables an existing Windows Firewall rule by name."""
        try:
            val = "yes" if enabled else "no"
            res = _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'set', 'rule',
                f'name={rule_name}', 'new', f'enable={val}'
            ])
            self.invalidate_cache()
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to toggle rule {rule_name}: {e}")
            return False

    def block_ip(self, ip_or_cidr: str) -> bool:
        """Block an IPv4/IPv6 address or CIDR range in both inbound and outbound directions."""
        clean_ip = ip_or_cidr.strip()
        if is_protected_ip(clean_ip):
            logger.warning(f"Prevented block on protected/loopback IP: {clean_ip}")
            return False

        safe_name = clean_ip.replace('/', '_').replace(':', '_')
        in_rule = f"{RULE_PREFIX}Block_IP_{safe_name}_IN"
        out_rule = f"{RULE_PREFIX}Block_IP_{safe_name}_OUT"

        try:
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={in_rule}', 'dir=in', 'action=block', f'remoteip={clean_ip}', 'profile=any'
            ])
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={out_rule}', 'dir=out', 'action=block', f'remoteip={clean_ip}', 'profile=any'
            ])
            self.invalidate_cache()
            logger.info(f"Blocked IP/Subnet on Windows 11: {clean_ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {clean_ip}: {e}")
            return False

    def unblock_ip(self, ip_or_cidr: str) -> bool:
        clean_ip = ip_or_cidr.strip()
        safe_name = clean_ip.replace('/', '_').replace(':', '_')
        in_rule = f"{RULE_PREFIX}Block_IP_{safe_name}_IN"
        out_rule = f"{RULE_PREFIX}Block_IP_{safe_name}_OUT"

        try:
            _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={in_rule}'])
            _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={out_rule}'])
            self.invalidate_cache()
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP {clean_ip}: {e}")
            return False

    def block_app(self, app_name: str, exec_path: str) -> bool:
        """Block application network access by its executable path on Windows."""
        if not exec_path or not os.path.exists(exec_path):
            logger.warning(f"Executable path not found: {exec_path}")
            return False

        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', app_name)
        in_rule = f"{RULE_PREFIX}App_{safe_name}_IN"
        out_rule = f"{RULE_PREFIX}App_{safe_name}_OUT"

        try:
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={in_rule}', 'dir=in', 'action=block', f'program={exec_path}', 'profile=any'
            ])
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={out_rule}', 'dir=out', 'action=block', f'program={exec_path}', 'profile=any'
            ])
            self.invalidate_cache()
            logger.info(f"Blocked app: {app_name} ({exec_path})")
            return True
        except Exception as e:
            logger.error(f"Failed to block app {app_name}: {e}")
            return False

    def unblock_app(self, app_name: str, exec_path: str = "") -> bool:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', app_name)
        in_rule = f"{RULE_PREFIX}App_{safe_name}_IN"
        out_rule = f"{RULE_PREFIX}App_{safe_name}_OUT"

        try:
            _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={in_rule}'])
            _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={out_rule}'])
            self.invalidate_cache()
            return True
        except Exception as e:
            logger.error(f"Failed to unblock app {app_name}: {e}")
            return False

    def allow_app(self, app_name: str, exec_path: str) -> bool:
        """Create explicit whitelist allow rules for an application binary."""
        if not exec_path or not os.path.exists(exec_path):
            logger.warning(f"Executable path not found: {exec_path}")
            return False

        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', app_name)
        in_rule = f"{RULE_PREFIX}App_Allow_{safe_name}_IN"
        out_rule = f"{RULE_PREFIX}App_Allow_{safe_name}_OUT"

        try:
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={in_rule}', 'dir=in', 'action=allow', f'program={exec_path}', 'profile=any'
            ])
            _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={out_rule}', 'dir=out', 'action=allow', f'program={exec_path}', 'profile=any'
            ])
            self.invalidate_cache()
            logger.info(f"Allowed app: {app_name} ({exec_path})")
            return True
        except Exception as e:
            logger.error(f"Failed to allow app {app_name}: {e}")
            return False

    def empty_caches(self):
        """Flushes Windows DNS resolver cache and ARP cache."""
        try:
            _run_cmd(['ipconfig', '/flushdns'])
            _run_cmd(['arp', '-d', '*'])
            self.invalidate_cache()
            logger.info("Windows DNS & ARP resolver caches flushed successfully.")
        except Exception as e:
            logger.debug(f"Cache flush error: {e}")

    def reload(self) -> bool:
        """Reload and re-verify Windows Firewall state."""
        self.invalidate_cache()
        return self.is_running()

    # ── Summary & Metrics ───────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Return firewall overview metrics matching Linux UI schema."""
        now = time.time()
        if 'summary' in self._cache and (now - self._cache_time.get('summary', 0)) < 3.0:
            return self._cache['summary']

        is_run = self.is_running()
        is_panic = self.get_panic_mode()

        # Count active custom rules
        blocked_ips = 0
        total_ports = 0
        try:
            res = _run_cmd(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'])
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                for line in lines:
                    if f"{RULE_PREFIX}Block_IP_" in line:
                        blocked_ips += 1
                    elif f"{RULE_PREFIX}Port_" in line:
                        total_ports += 1
        except Exception:
            pass

        summary = {
            'running': is_run,
            'active_profile': 'Private (Windows 11)',
            'profiles': ['Private', 'Public', 'Domain'],
            'total_interfaces': 1,
            'total_services': 12,
            'total_ports': total_ports,
            'total_rules': self.get_rule_count(),
            'panic_mode': is_panic,
            'blocked_ips': blocked_ips // 2 if blocked_ips > 0 else 0,
            # Backward compatibility aliases
            'default_zone': 'Private (Windows 11)',
            'active_zones': ['Private', 'Public'],
            'total_rich_rules': blocked_ips,
            'masquerade': False,
        }

        self._cache['summary'] = summary
        self._cache_time['summary'] = now
        return summary

    # ── Rule Enumeration & Management ────────────────────────────────

    def list_all_rules(self, vitorius_only: bool = False) -> List[Dict[str, Any]]:
        """
        Parses and returns rules from Windows Advanced Firewall.
        Matches netsh output blocks into structured dictionaries.
        """
        now = time.time()
        cache_key = f"rules_{vitorius_only}"
        if cache_key in self._cache and (now - self._cache_time.get(cache_key, 0)) < 4.0:
            return self._cache[cache_key]

        rules: List[Dict[str, Any]] = []
        try:
            res = _run_cmd(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'])
            if res.returncode != 0 or not res.stdout:
                return []

            current_rule: Dict[str, Any] = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("---") or line.startswith("Ok."):
                    continue

                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()

                    if key in RULE_NAME_KEYS or "rule_name" in key:
                        if current_rule and "name" in current_rule:
                            is_vit = current_rule["name"].startswith(RULE_PREFIX)
                            if not vitorius_only or is_vit:
                                rules.append(current_rule)
                        current_rule = {
                            "name": val,
                            "direction": "in",
                            "action": "allow",
                            "protocol": "any",
                            "port": "any",
                            "program": "any",
                            "enabled": True,
                            "is_vitorius": val.startswith(RULE_PREFIX)
                        }
                    elif current_rule:
                        if key in ("enabled", "aktiviert", "habilitado", "activé"):
                            current_rule["enabled"] = (val.lower() in ("yes", "ja", "sí", "si", "oui", "1"))
                        elif key in ("direction", "richtung", "dirección"):
                            current_rule["direction"] = "out" if val.lower() in ("out", "aus", "saliente", "sortant") else "in"
                        elif key in ("action", "aktion", "acción"):
                            current_rule["action"] = "block" if val.lower() in ("block", "blockieren", "bloquear", "bloquer") else "allow"
                        elif key in ("protocol", "protokoll", "protocolo", "protocole"):
                            current_rule["protocol"] = val.upper()
                        elif key in ("localport", "local_port", "lokaler_port", "puerto_local"):
                            current_rule["port"] = val
                        elif key in ("program", "service", "programm", "programa"):
                            current_rule["program"] = val

            if current_rule and "name" in current_rule:
                is_vit = current_rule["name"].startswith(RULE_PREFIX)
                if not vitorius_only or is_vit:
                    rules.append(current_rule)

            self._cache[cache_key] = rules
            self._cache_time[cache_key] = now
            return rules
        except Exception as e:
            logger.error(f"Failed to enumerate Windows firewall rules: {e}")
            return []

    def list_vitorius_rules(self) -> List[Dict[str, Any]]:
        """Returns only rules created and managed by Vitorius Firewall."""
        return self.list_all_rules(vitorius_only=True)

    def delete_rule_by_name(self, rule_name: str) -> bool:
        """Deletes any Windows Firewall rule by its exact name."""
        try:
            res = _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'])
            self.invalidate_cache()
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to delete rule {rule_name}: {e}")
            return False

    def add_service_rule(self, service_name: str, port: str, protocol: str = "TCP", action: str = "allow") -> bool:
        """Adds or modifies a rule for a named system service."""
        rule_name = f"{RULE_PREFIX}Svc_{service_name}_{port}_{protocol.upper()}"
        try:
            res = _run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                f'action={action.lower()}',
                f'protocol={protocol.upper()}',
                f'localport={port}',
                'profile=any'
            ])
            self.invalidate_cache()
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to add service rule {service_name}: {e}")
            return False

    def block_icmp(self, block: bool = True) -> bool:
        """Blocks or unblocks ICMP echo requests (ping) on Windows."""
        rule_v4 = f"{RULE_PREFIX}Block_ICMPv4_Echo"
        rule_v6 = f"{RULE_PREFIX}Block_ICMPv6_Echo"
        try:
            if block:
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_v4}', 'dir=in', 'action=block', 'protocol=icmpv4:8,any'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_v6}', 'dir=in', 'action=block', 'protocol=icmpv6:128,any'
                ])
                logger.info("ICMP Echo Requests (Ping) blocked on Windows 11.")
            else:
                _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_v4}'])
                _run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_v6}'])
                logger.info("ICMP Echo Requests unblocked.")
            self.invalidate_cache()
            return True
        except Exception as e:
            logger.error(f"Failed to toggle ICMP: {e}")
            return False

    def apply_profile_rules(self, profile_name: str, profile_data: Dict[str, Any]) -> bool:
        """
        Applies a security profile's configuration to the Windows Firewall:
        1. Purges existing VitoriusFW dynamic profile rules (RULE_PREFIX + Prof_).
        2. Guarantees loopback (127.0.0.1 / ::1) is whitelisted so internal RPC and local developer tools (Antigravity) thrive.
        3. Applies allowed_services rules using KNOWN_SECURITY_SERVICES.
        4. Applies allowed_ports (single ports, port ranges, TCP/UDP, in/out).
        5. Applies blocked_ports (single ports, port ranges, TCP/UDP) with action=block.
        6. Applies blocked_ips.
        7. Configures ICMP stealth mode (block_icmp).
        8. Sets inbound / outbound posture via firewallpolicy (default allowoutbound for productive browsing, gaming, and work).
        """
        try:
            logger.info(f"Applying profile rules for: {profile_name}")

            # 1. Purge existing dynamic profile rules
            res = _run_cmd(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'])
            if res.returncode == 0 and res.stdout:
                rules_to_delete = []
                for line in res.stdout.splitlines():
                    if f"{RULE_PREFIX}Prof_" in line and ":" in line:
                        r_name = line.split(":", 1)[1].strip()
                        rules_to_delete.append(r_name)
                for r_name in rules_to_delete:
                    self.delete_rule_by_name(r_name)

            # 2. Always ensure loopback rules are active
            self.ensure_loopback_and_dev_rules()

            # 3. Apply allowed services
            allowed_services = profile_data.get("allowed_services", [])
            for svc in allowed_services:
                if svc in KNOWN_SECURITY_SERVICES:
                    for spec in KNOWN_SECURITY_SERVICES[svc]:
                        port_spec = str(spec.get("port", "any")).strip()
                        proto = str(spec.get("protocol", "TCP")).strip().upper()
                        direction = spec.get("dir", "in").lower()
                        desc = spec.get("desc", svc)
                        rule_name = f"{RULE_PREFIX}Prof_Svc_{svc}_{desc}_{proto}"

                        cmd = [
                            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            f'name={rule_name}', f'dir={direction}', 'action=allow'
                        ]
                        if proto != "ANY":
                            cmd.append(f'protocol={proto}')
                        if port_spec.lower() != "any":
                            port_arg = f"localport={port_spec}" if direction == "in" else f"remoteport={port_spec}"
                            cmd.append(port_arg)
                        cmd.append('profile=any')
                        _run_cmd(cmd)

            # 4. Apply allowed ports (handles dict, str "port/proto", or int, and port ranges)
            allowed_ports = profile_data.get("allowed_ports", [])
            for p in allowed_ports:
                parsed = _parse_port_spec(p, default_dir="in")
                if not parsed:
                    continue
                port_num, proto, direction = parsed
                clean_port_id = port_num.replace('-', '_')
                rule_name = f"{RULE_PREFIX}Prof_Port_{clean_port_id}_{proto}_{direction}"
                port_arg = f"localport={port_num}" if direction == "in" else f"remoteport={port_num}"
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}', f'dir={direction}', 'action=allow',
                    f'protocol={proto}', port_arg, 'profile=any'
                ])

            # 5. Apply blocked ports
            blocked_ports = profile_data.get("blocked_ports", [])
            for p in blocked_ports:
                parsed = _parse_port_spec(p, default_dir="in")
                if not parsed:
                    continue
                port_num, proto, direction = parsed
                clean_port_id = port_num.replace('-', '_')
                rule_name = f"{RULE_PREFIX}Prof_BlockPort_{clean_port_id}_{proto}"
                port_arg = f"localport={port_num}" if direction == "in" else f"remoteport={port_num}"
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}', f'dir={direction}', 'action=block',
                    f'protocol={proto}', port_arg, 'profile=any'
                ])

            # 6. Apply blocked IPs
            blocked_ips = profile_data.get("blocked_ips", [])
            for ip in blocked_ips:
                self.block_ip(ip)

            # 7. Apply ICMP ping echo stealth posture
            icmp_block = profile_data.get("icmp_block", False)
            self.block_icmp(bool(icmp_block))

            # 8. Set profile policy based on tier/posture
            block_inbound = profile_data.get("block_inbound", True)
            allow_outbound = profile_data.get("allow_outbound", True)

            # Ensure high productivity profiles never lock out outbound by default
            if profile_name in ("Corporate", "Gaming", "Home", "Public"):
                allow_outbound = True

            in_action = "blockinbound" if block_inbound else "allowinbound"
            out_action = "allowoutbound" if allow_outbound else "blockoutbound"
            _run_cmd(['netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', f'{in_action},{out_action}'])

            if not allow_outbound:
                # Essential outbound rules when outbound is restricted
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}Prof_Essential_DNS_UDP', 'dir=out', 'action=allow', 'protocol=UDP', 'remoteport=53'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}Prof_Essential_DNS_TCP', 'dir=out', 'action=allow', 'protocol=TCP', 'remoteport=53'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}Prof_Essential_HTTPS', 'dir=out', 'action=allow', 'protocol=TCP', 'remoteport=443'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}Prof_Essential_HTTP', 'dir=out', 'action=allow', 'protocol=TCP', 'remoteport=80'
                ])
                _run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={RULE_PREFIX}Prof_Essential_Loopback', 'dir=out', 'action=allow', 'remoteip=127.0.0.1,::1'
                ])

            self.invalidate_cache()
            return True
        except Exception as e:
            logger.error(f"Failed to apply profile rules: {e}")
            return False

    def get_rule_count(self) -> int:
        rules = self.list_all_rules()
        return len(rules)
