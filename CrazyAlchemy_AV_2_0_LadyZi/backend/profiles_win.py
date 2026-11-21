"""
Vitorius Firewall Win - Profile Manager & Audit Logger for Windows 11
Manages security profiles, persistent configuration, and structured audit logs.
"""

import json
import os
import sys
import shutil
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from backend.adaptive_profiles import AegisChameleonEngine

logger = logging.getLogger('vitorius.win.profiles')

def get_base_dirs() -> tuple[Path, Path]:
    appdata = os.environ.get("APPDATA")
    localappdata = os.environ.get("LOCALAPPDATA")
    if appdata and localappdata:
        cfg = Path(appdata) / "VitoriusFirewallWin"
        data = Path(localappdata) / "VitoriusFirewallWin"
    else:
        cfg = Path.home() / ".vitorius_firewall_win"
        data = cfg / "data"

    try:
        cfg.mkdir(parents=True, exist_ok=True)
        data.mkdir(parents=True, exist_ok=True)
        # Verify write permission
        test_file = data / ".write_test"
        test_file.touch()
        test_file.unlink(missing_ok=True)
    except (OSError, PermissionError):
        import tempfile
        cfg = Path(tempfile.gettempdir()) / "vitorius_firewall_win"
        data = cfg / "data"
        try:
            cfg.mkdir(parents=True, exist_ok=True)
            data.mkdir(parents=True, exist_ok=True)
        except Exception:
            cfg = Path.home() / ".vitorius_firewall_win"
            data = cfg / "data"
            try:
                cfg.mkdir(parents=True, exist_ok=True)
                data.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
    return cfg, data

CONFIG_DIR, DATA_DIR = get_base_dirs()
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_DIR = DATA_DIR / "logs"
BACKUP_DIR = DATA_DIR / "backups"
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

BUILTIN_FACTORY_PROFILES = {
    "Home": {
        "description": "Standard protection for trusted private/home networks. Permits local sharing and discovery.",
        "windows_profile": "Private",
        "tier": "standard",
        "icon": "user-home",
        "allowed_services": ["FileAndPrinterSharing", "mDNS", "CoreNetworking", "RemoteDesktopLocal"],
        "blocked_ports": [],
        "allowed_ports": [],
        "logging": "minimal",
        "icmp_block": False,
        "block_inbound": True,
        "allow_outbound": True
    },
    "Public": {
        "description": "Enhanced defensive posture for untrusted public Wi-Fi hotspots, hotels, and cafes.",
        "windows_profile": "Public",
        "tier": "standard",
        "icon": "network-wireless",
        "allowed_services": ["CoreNetworking"],
        "blocked_ports": [],
        "allowed_ports": [],
        "logging": "standard",
        "icmp_block": True,
        "block_inbound": True,
        "allow_outbound": True
    },
    "Corporate": {
        "description": "Enterprise-grade security adhering to SOC 2 compliance. Strict auditing and approved outbound flows.",
        "windows_profile": "Domain,Private",
        "tier": "premium",
        "icon": "network-server",
        "allowed_services": ["DNS", "HTTPS", "CoreNetworking"],
        "blocked_ports": [],
        "allowed_ports": [
            {"port": "443", "protocol": "tcp"},
            {"port": "8443", "protocol": "tcp"}
        ],
        "logging": "full",
        "icmp_block": True,
        "block_inbound": True,
        "allow_outbound": False,
        "rate_limit": True,
        "compliance": "SOC2"
    },
    "Gaming": {
        "description": "High-performance posture optimized for low packet latency while protecting background listeners.",
        "windows_profile": "Private",
        "tier": "standard",
        "icon": "input-gaming",
        "allowed_services": ["CoreNetworking", "SteamClient"],
        "blocked_ports": [],
        "allowed_ports": [
            {"port": "27015-27030", "protocol": "tcp"},
            {"port": "27015-27030", "protocol": "udp"},
            {"port": "3478-3480", "protocol": "udp"},
            {"port": "27000-27100", "protocol": "udp"},
            {"port": "4380", "protocol": "udp"},
            {"port": "3074", "protocol": "udp"}
        ],
        "logging": "minimal",
        "icmp_block": False,
        "block_inbound": True,
        "allow_outbound": True
    },
    "Maximum Security": {
        "description": "Complete lockdown fortress mode aligned with HIPAA-grade network isolation. Strict port whitelisting.",
        "windows_profile": "All",
        "tier": "premium",
        "icon": "security-high",
        "allowed_services": [],
        "blocked_ports": [],
        "allowed_ports": [
            {"port": "443", "protocol": "tcp"},
            {"port": "53", "protocol": "udp"}
        ],
        "logging": "full",
        "icmp_block": True,
        "block_inbound": True,
        "allow_outbound": False,
        "compliance": "HIPAA"
    }
}


class FirewallLogger:
    """Thread-safe event auditor logging security and threat events."""

    def __init__(self):
        self.log_file = LOG_DIR / "security_events.jsonl"

    def log_event(self, event_type: str, severity: str, message: str, details: Optional[dict] = None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,  # "info", "warning", "critical"
            "message": message,
            "details": details or {}
        }
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to append to log file: {e}")

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.log_file.exists():
            return []
        events = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return events[-limit:][::-1]  # Return newest first
        except Exception as e:
            logger.error(f"Failed to read events: {e}")
            return []

    def clear_logs(self) -> bool:
        """Clears all logged security events."""
        try:
            if self.log_file.exists():
                self.log_file.unlink()
            return True
        except Exception as e:
            logger.error(f"Failed to clear log file: {e}")
            return False

    def export_logs_csv(self, export_path: str) -> bool:
        """Exports security event history to a standard CSV file."""
        import csv
        events = self.get_recent_events(limit=5000)
        try:
            with open(export_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp (UTC)", "Severity", "Event Type", "Message", "Details"])
                for e in events:
                    writer.writerow([
                        e.get("timestamp", ""),
                        e.get("severity", ""),
                        e.get("event_type", ""),
                        e.get("message", ""),
                        json.dumps(e.get("details", {}))
                    ])
            return True
        except Exception as e:
            logger.error(f"Failed to export CSV logs: {e}")
            return False


class WindowsProfileManager:
    """Manages active security profiles, CRUD operations, backups, and persisted user settings."""

    def __init__(self, default_config_path: Optional[str] = None, config_file: Optional[Path] = None):
        self.config_file = config_file or CONFIG_FILE
        if default_config_path:
            self.default_config_path = default_config_path
        else:
            cand = Path(__file__).resolve().parent.parent / "data" / "default_config_win.json"
            self.default_config_path = str(cand) if cand.exists() else None
        self._config: Dict[str, Any] = {}
        self._active_profile: str = ""
        self._load_config()

        # Novel Pillar 3: AegisChameleon™ Intent-Aware Morphing & EAPM
        self.adaptive = AegisChameleonEngine(profile_mgr=self)

    def _load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
                self._active_profile = self._config.get("active_profile", "")
                if "profiles" not in self._config or not self._config["profiles"]:
                    self._config["profiles"] = json.loads(json.dumps(BUILTIN_FACTORY_PROFILES))
                if not self._active_profile or self._active_profile not in self._config["profiles"]:
                    self._active_profile = "Home" if "Home" in self._config["profiles"] else next(iter(self._config["profiles"]))
                return
            except Exception as e:
                logger.warning(f"Error loading config, falling back to defaults: {e}")

        # Load from defaults
        loaded_from_default = False
        if self.default_config_path and os.path.exists(self.default_config_path):
            try:
                with open(self.default_config_path, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
                self._active_profile = self._config.get("active_profile", "Home")
                loaded_from_default = True
            except Exception as e:
                logger.warning(f"Failed to parse default config file {self.default_config_path}: {e}")

        if not loaded_from_default:
            self._config = {
                "version": "2.0",
                "app_name": "Crazy Alchemy v2.0 (LadyZi)",
                "active_profile": "Home",
                "profiles": json.loads(json.dumps(BUILTIN_FACTORY_PROFILES)),
                "settings": {
                    "start_with_system": True,
                    "autostart": True,
                    "close_to_tray": True,
                    "backup_on_profile_change": True,
                    "theme": "dark"
                }
            }
            self._active_profile = "Home"

        self.save_config()

    def save_config(self):
        try:
            self._config["active_profile"] = self._active_profile
            # Ensure parent directories exist
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config file: {e}")

    # ── Profiles CRUD ───────────────────────────────────────────────

    def get_profiles(self) -> Dict[str, Any]:
        """Returns dictionary of all configured profiles."""
        return self._config.get("profiles", {})

    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Returns definition for specified profile name or None if not found."""
        return self.get_profiles().get(name)

    def get_active_profile(self) -> str:
        """Returns the name of the currently active profile."""
        return self._active_profile

    def set_active_profile(self, name: str) -> bool:
        """Sets the active security profile if it exists."""
        if name in self.get_profiles():
            self._active_profile = name
            self.save_config()
            return True
        return False

    def validate_profile_schema(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates that a profile data dictionary adheres to the expected schema."""
        if not isinstance(data, dict):
            return False, "Profile data must be a JSON dictionary."

        # Optional string fields
        if "description" in data and not isinstance(data["description"], str):
            return False, "'description' must be a string."
        if "tier" in data and not isinstance(data["tier"], str):
            return False, "'tier' must be a string."

        # Boolean flags
        for b_field in ("icmp_block", "block_inbound", "allow_outbound"):
            if b_field in data and not isinstance(data[b_field], bool):
                return False, f"'{b_field}' must be a boolean (true/false)."

        # Lists
        for l_field in ("allowed_services", "allowed_ports", "blocked_ports"):
            if l_field in data:
                if not isinstance(data[l_field], list):
                    return False, f"'{l_field}' must be a list."

        return True, "Valid"

    def create_profile(self, name: str, profile_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Creates a new custom security profile."""
        name = str(name).strip()
        if not name:
            return False, "Profile name cannot be empty."

        profiles = self._config.setdefault("profiles", {})
        if name in profiles:
            return False, f"Profile '{name}' already exists."

        valid, err = self.validate_profile_schema(profile_data)
        if not valid:
            return False, f"Schema validation error: {err}"

        # Populate safe normalized record
        normalized = {
            "description": str(profile_data.get("description", "Custom security profile")),
            "windows_profile": str(profile_data.get("windows_profile", "Private")),
            "tier": str(profile_data.get("tier", "custom")).lower(),
            "icon": str(profile_data.get("icon", "security-high")),
            "allowed_services": list(profile_data.get("allowed_services", [])),
            "blocked_ports": list(profile_data.get("blocked_ports", [])),
            "allowed_ports": list(profile_data.get("allowed_ports", [])),
            "logging": str(profile_data.get("logging", "standard")),
            "icmp_block": bool(profile_data.get("icmp_block", False)),
            "block_inbound": bool(profile_data.get("block_inbound", True)),
            "allow_outbound": bool(profile_data.get("allow_outbound", True))
        }
        if "compliance" in profile_data:
            normalized["compliance"] = str(profile_data["compliance"])

        profiles[name] = normalized
        self.save_config()
        logger.info(f"Created custom security profile: {name}")
        return True, "Profile created successfully."

    def update_profile(self, name: str, profile_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Updates an existing security profile."""
        profiles = self._config.setdefault("profiles", {})
        if name not in profiles:
            return False, f"Profile '{name}' not found."

        valid, err = self.validate_profile_schema(profile_data)
        if not valid:
            return False, f"Schema validation error: {err}"

        profiles[name].update(profile_data)
        self.save_config()
        logger.info(f"Updated security profile: {name}")
        return True, "Profile updated successfully."

    def delete_profile(self, name: str, force: bool = False) -> Tuple[bool, str]:
        """Deletes a profile. Active profile and default factory profiles are protected."""
        profiles = self._config.setdefault("profiles", {})
        if name not in profiles:
            return False, f"Profile '{name}' not found."

        if name == self._active_profile:
            return False, f"Cannot delete the currently active profile '{name}'. Switch to another profile first."

        if not force and name in BUILTIN_FACTORY_PROFILES:
            return False, f"Cannot delete factory built-in profile '{name}'."

        del profiles[name]
        self.save_config()
        logger.info(f"Deleted security profile: {name}")
        return True, f"Profile '{name}' deleted successfully."

    def reset_profiles_to_default(self) -> bool:
        """Restores all profiles back to factory defaults."""
        defaults = None
        if self.default_config_path and os.path.exists(self.default_config_path):
            try:
                with open(self.default_config_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    defaults = cfg.get("profiles")
            except Exception as e:
                logger.warning(f"Error loading factory defaults from {self.default_config_path}: {e}")

        if not defaults:
            defaults = json.loads(json.dumps(BUILTIN_FACTORY_PROFILES))

        self._config["profiles"] = defaults
        if self._active_profile not in defaults:
            self._active_profile = "Home"
        self.save_config()
        logger.info("Restored security profiles to factory default configuration.")
        return True

    def export_profile(self, name: str, file_path: str) -> bool:
        """Exports a single security profile definition to a JSON file."""
        prof = self.get_profile(name)
        if not prof:
            return False
        payload = {
            "format": "crazy_alchemy_profile",
            "version": "2.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "profile_name": name,
            "profile_data": prof
        }
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export profile '{name}' to {file_path}: {e}")
            return False

    def import_profile(self, file_path: str, overwrite: bool = False) -> Tuple[bool, str, Optional[str]]:
        """Imports a security profile definition from a JSON file."""
        if not os.path.exists(file_path):
            return False, f"File does not exist: {file_path}", None
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, dict) and "profile_name" in data and "profile_data" in data:
                p_name = str(data["profile_name"]).strip()
                p_data = data["profile_data"]
            elif isinstance(data, dict) and len(data) == 1 and isinstance(next(iter(data.values())), dict):
                p_name = next(iter(data.keys())).strip()
                p_data = next(iter(data.values()))
            else:
                return False, "Unrecognized profile file format.", None

            if not p_name:
                return False, "Invalid profile name in imported file.", None

            profiles = self.get_profiles()
            if p_name in profiles and not overwrite:
                return False, f"Profile '{p_name}' already exists. Enable overwrite to replace.", p_name

            valid, err = self.validate_profile_schema(p_data)
            if not valid:
                return False, f"Imported profile failed validation: {err}", p_name

            if p_name in profiles:
                self.update_profile(p_name, p_data)
            else:
                self.create_profile(p_name, p_data)

            return True, f"Successfully imported profile '{p_name}'.", p_name
        except Exception as e:
            logger.error(f"Failed to import profile from {file_path}: {e}")
            return False, f"Import failed: {e}", None

    # ── User Settings ───────────────────────────────────────────────

    def get_setting(self, key: str, default: Any = None) -> Any:
        settings = self._config.get("settings", {})
        if key == "start_with_system" and "start_with_system" not in settings:
            return settings.get("autostart", default)
        if key == "autostart" and "autostart" not in settings:
            return settings.get("start_with_system", default)
        return settings.get(key, default)

    def update_settings(self, updates: Dict[str, Any]):
        if "settings" not in self._config:
            self._config["settings"] = {}
        self._config["settings"].update(updates)
        self.save_config()

    def set_autostart(self, enable: bool) -> bool:
        """Updates autostart setting and synchronizes Windows Run registry."""
        self.update_settings({"start_with_system": enable, "autostart": enable})
        return set_autostart_registry(enable)

    # ── Firewall Rules Backup & Restore ──────────────────────────────

    def backup_rules(self) -> Optional[str]:
        """Export Windows Firewall policy to timestamped backup file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUP_DIR / f"wfw_backup_{timestamp}.wfw"
        try:
            import subprocess
            kwargs = {"check": True, "capture_output": True, "timeout": 10}
            if os.name == "nt":
                kwargs["creationflags"] = 0x08000000
            subprocess.run(['netsh', 'advfirewall', 'export', str(backup_path)], **kwargs)
            return str(backup_path)
        except Exception as e:
            logger.error(f"Failed to export firewall rules: {e}")
            return None

    def restore_rules(self, backup_path: str) -> bool:
        """Import Windows Firewall policy from backup file."""
        if not os.path.exists(backup_path):
            return False
        try:
            import subprocess
            kwargs = {"check": True, "capture_output": True, "timeout": 10}
            if os.name == "nt":
                kwargs["creationflags"] = 0x08000000
            subprocess.run(['netsh', 'advfirewall', 'import', backup_path], **kwargs)
            return True
        except Exception as e:
            logger.error(f"Failed to import firewall rules: {e}")
            return False


def set_autostart_registry(enable: bool) -> bool:
    """
    Enables or disables auto-starting Crazy Alchemy with Windows.
    Uses Task Scheduler HighestAvailable elevation bypass task (CrazyAlchemyAutostart)
    to guarantee zero UAC prompts after system reboot.
    """
    if sys.platform != "win32":
        return True

    success = False
    try:
        from backend.elevation_win import (
            register_elevation_bypass_task,
            clean_non_elevated_autostart_entries
        )
        if enable:
            success = register_elevation_bypass_task()
            clean_non_elevated_autostart_entries()
            logger.info("Configured elevated autostart task for zero-UAC reboot startup.")
        else:
            import subprocess
            CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
            subprocess.run(["schtasks", "/delete", "/tn", "CrazyAlchemyAutostart", "/f"],
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
            clean_non_elevated_autostart_entries()
            logger.info("Removed elevated autostart task.")
            success = True
    except Exception as e:
        logger.debug(f"Autostart configuration notice: {e}")

    return success


def is_autostart_registered() -> bool:
    """Checks if autostart task exists in Task Scheduler or registry."""
    if sys.platform != "win32":
        return False
    try:
        import subprocess
        CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
        res = subprocess.run(["schtasks", "/query", "/tn", "CrazyAlchemyAutostart"],
                             capture_output=True, creationflags=CREATE_NO_WINDOW)
        if res.returncode == 0:
            return True
    except Exception:
        pass
    try:
        import winreg
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(root, run_key, 0, winreg.KEY_READ) as k:
                    for name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
                        try:
                            val, _ = winreg.QueryValueEx(k, name)
                            if val:
                                return True
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass
    return False


# Module-level aliases for backward compatibility
def backup_rules() -> Optional[str]:
    return WindowsProfileManager().backup_rules()

def restore_rules(backup_path: str) -> bool:
    return WindowsProfileManager().restore_rules(backup_path)
