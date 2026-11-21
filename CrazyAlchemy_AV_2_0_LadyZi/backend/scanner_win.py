"""
Vitorius Firewall Win - Service & Application Scanner for Windows 11
Discovers Windows system services, listening server daemons, and installed desktop applications
via Windows Registry, netsh, sc.exe, and active network telemetry.
"""

import os
import re
import sys
import subprocess
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Dict, Any, Optional, Set

logger = logging.getLogger('vitorius.win.scanner')

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


@dataclass
class ScannedItem:
    id: str                                     # Unique identifier, e.g. "svc:w32time" or "app:steam"
    name: str                                   # Human readable name
    category: str                               # "service" or "app"
    item_type: str                              # "windows_service", "listening_daemon", "desktop_app"
    icon: str                                   # Icon identifier
    description: str                            # Short description
    service_name: str = ""                      # Windows service name if applicable
    exec_name: str = ""                         # Binary name
    exec_path: str = ""                         # Full executable path
    ports: List[Tuple[str, str]] = field(default_factory=list) # List of (port, protocol)
    is_running: bool = False
    pids: List[int] = field(default_factory=list)
    is_enabled: bool = True                     # Allowed through firewall
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


KNOWN_WINDOWS_SERVICES = {
    'sshd': {
        'name': 'OpenSSH SSH Server',
        'desc': 'Secure remote terminal server',
        'ports': [('22', 'tcp')],
        'category': 'service'
    },
    'LanmanServer': {
        'name': 'Server (SMB File Sharing)',
        'desc': 'Supports file, print, and named-pipe sharing',
        'ports': [('445', 'tcp'), ('139', 'tcp')],
        'category': 'service'
    },
    'W32Time': {
        'name': 'Windows Time Service',
        'desc': 'Maintains date and time synchronization (NTP)',
        'ports': [('123', 'udp')],
        'category': 'service'
    },
    'Dnscache': {
        'name': 'DNS Client',
        'desc': 'Resolves and caches Domain Name System names',
        'ports': [('53', 'udp')],
        'category': 'service'
    },
    'TermService': {
        'name': 'Remote Desktop Services (RDP)',
        'desc': 'Allows users to connect remotely to this computer',
        'ports': [('3389', 'tcp'), ('3389', 'udp')],
        'category': 'service'
    },
    'W3SVC': {
        'name': 'Internet Information Services (IIS)',
        'desc': 'Provides Web and HTTP server infrastructure',
        'ports': [('80', 'tcp'), ('443', 'tcp')],
        'category': 'service'
    }
}

KNOWN_DESKTOP_APPS = {
    'steam.exe': ('Steam Client', 'Digital gaming distribution client', 'app', [('27015-27030', 'udp')]),
    'discord.exe': ('Discord', 'Voice, video, and text communication service', 'app', [('50001', 'udp')]),
    'chrome.exe': ('Google Chrome', 'Web browser', 'app', []),
    'firefox.exe': ('Mozilla Firefox', 'Web browser', 'app', []),
    'brave.exe': ('Crazy Browser', 'Privacy web browser', 'app', []),
    'msedge.exe': ('Microsoft Edge', 'Web browser', 'app', []),
    'qbittorrent.exe': ('qBittorrent', 'P2P BitTorrent client', 'app', [('6881', 'tcp'), ('6881', 'udp')]),
    'spotify.exe': ('Spotify Music', 'Music streaming client', 'app', []),
    'Plex Media Server.exe': ('Plex Media Server', 'Personal media streaming server', 'service', [('32400', 'tcp')]),
    'code.exe': ('Visual Studio Code', 'Development environment', 'app', []),
}


class WindowsServiceAppScanner:
    """Discovers installed applications, active network sockets, and Windows network services."""

    def __init__(self):
        self._cached_items: List[ScannedItem] = []

    def get_cached_items(self) -> List[ScannedItem]:
        return list(self._cached_items)

    def scan_registry_installed_apps(self) -> List[ScannedItem]:
        """Scans Windows Registry uninstall keys to enumerate installed software inventory."""
        if not HAS_WINREG:
            return []

        installed_items: List[ScannedItem] = []
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]

        seen_names: Set[str] = set()

        for root_key, subkey_str in reg_paths:
            try:
                with winreg.OpenKey(root_key, subkey_str) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as app_key:
                                try:
                                    display_name = winreg.QueryValueEx(app_key, "DisplayName")[0]
                                except OSError:
                                    continue

                                if not display_name or display_name in seen_names:
                                    continue

                                # Skip Windows updates and KB packages
                                if display_name.startswith("KB") or "Security Update" in display_name:
                                    continue

                                install_loc = ""
                                try:
                                    install_loc = winreg.QueryValueEx(app_key, "InstallLocation")[0].strip('"')
                                except OSError:
                                    pass

                                # Fallback: extract executable path from DisplayIcon
                                if not install_loc:
                                    try:
                                        icon_val = winreg.QueryValueEx(app_key, "DisplayIcon")[0].strip('"')
                                        if "," in icon_val:
                                            icon_val = icon_val.split(",", 1)[0].strip()
                                        if icon_val.lower().endswith(".exe"):
                                            install_loc = icon_val
                                    except OSError:
                                        pass

                                display_version = ""
                                try:
                                    display_version = winreg.QueryValueEx(app_key, "DisplayVersion")[0]
                                except OSError:
                                    pass

                                seen_names.add(display_name)
                                s_id = f"reg:{re.sub(r'[^a-zA-Z0-9_]', '_', display_name.lower())[:32]}"

                                installed_items.append(ScannedItem(
                                    id=s_id,
                                    name=display_name,
                                    category="app",
                                    item_type="desktop_app",
                                    icon="application-x-executable",
                                    description=f"Installed software v{display_version}" if display_version else "Installed software",
                                    exec_path=install_loc,
                                    is_running=False,
                                    is_enabled=True,
                                    details={"version": display_version, "location": install_loc}
                                ))
                        except OSError:
                            continue
            except OSError:
                continue

        return installed_items

    def scan(self, fw_core=None, profiles=None, monitor=None) -> List[ScannedItem]:
        """Perform comprehensive system discovery scan on Windows 11."""
        items: List[ScannedItem] = []
        found_ids = set()

        # 1. Discover known Windows services
        for svc_name, meta in KNOWN_WINDOWS_SERVICES.items():
            s_id = f"svc:{svc_name.lower()}"
            if s_id in found_ids:
                continue

            item = ScannedItem(
                id=s_id,
                name=meta['name'],
                category=meta['category'],
                item_type="windows_service",
                icon="network-server",
                description=meta['desc'],
                service_name=svc_name,
                ports=meta.get('ports', []),
                is_running=False,
                is_enabled=True
            )
            items.append(item)
            found_ids.add(s_id)

        # 2. Discover running processes with active network sockets
        if monitor:
            active_conns = monitor.get_connections()
            for c in active_conns:
                prog = c.program
                if not prog or prog in ("System", "Unknown"):
                    continue

                p_lower = prog.lower()
                s_id = f"app:{p_lower.replace('.exe', '')}"
                if s_id in found_ids:
                    continue

                meta = KNOWN_DESKTOP_APPS.get(prog) or KNOWN_DESKTOP_APPS.get(prog.lower())
                if meta:
                    name, desc, cat, ports = meta
                else:
                    name = prog
                    desc = f"Active Windows application (PID {c.pid})"
                    cat = "app"
                    ports = [(str(c.local_port), c.protocol.lower())] if c.local_port else []

                item = ScannedItem(
                    id=s_id,
                    name=name,
                    category=cat,
                    item_type="desktop_app" if cat == "app" else "listening_daemon",
                    icon="application-x-executable",
                    description=desc,
                    exec_name=prog,
                    ports=ports,
                    is_running=True,
                    pids=[c.pid] if c.pid else [],
                    is_enabled=True
                )
                items.append(item)
                found_ids.add(s_id)

        # 3. Discover registry installed programs
        registry_apps = self.scan_registry_installed_apps()
        for reg_app in registry_apps:
            if reg_app.id not in found_ids:
                items.append(reg_app)
                found_ids.add(reg_app.id)

        self._cached_items = items
        return items
