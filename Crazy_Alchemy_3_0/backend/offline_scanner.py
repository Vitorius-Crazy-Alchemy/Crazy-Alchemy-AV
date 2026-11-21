"""
Vitorius Antivirus - Offline Reboot Scanner Subsystem
Implements Microsoft Defender Offline-style pre-boot/reboot threat remediation:
1. Schedules offline scan execution upon system restart (RunOnce + Task Scheduler)
2. Severance of all network connectivity (Panic Mode) to isolate active malware and prevent C2 beaconing
3. Deep multi-engine scanning of system hotspots, drivers, startup tasks, and memory artifacts
4. Automated threat remediation (process killing, encrypted quarantine, MoveFileEx reboot deletion, autorun cleanup)
5. Comprehensive audit logging and post-boot GUI remediation reporting
"""

import os
import sys
import json
import time
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger('vitorius.win.offline')

from backend.profiles_win import DATA_DIR, CONFIG_DIR, FirewallLogger
from backend.core_win import WindowsFirewallCore
from backend.antivirus import (
    AntivirusEngine, ThreatDetection, QuarantineManager,
    verify_file_signature, is_antivirus_program_file, is_antivirus_process
)

MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004


def mark_file_for_reboot_deletion(file_path: str) -> bool:
    """
    Registers a locked file to be deleted on next Windows reboot using
    Win32 MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT.
    """
    if sys.platform != "win32":
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            return True
        except Exception:
            return False

    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        res = kernel32.MoveFileExW(str(file_path), None, MOVEFILE_DELAY_UNTIL_REBOOT)
        if res:
            logger.info(f"Marked locked file for reboot deletion: {file_path}")
            return True
        else:
            err = ctypes.GetLastError()
            logger.warning(f"MoveFileExW failed for {file_path} with error code {err}")
            # Fallback: if running without Administrator elevation or file is not locked, delete directly
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Directly deleted file as MoveFileEx fallback: {file_path}")
                    return True
            except Exception:
                pass
            return False
    except Exception as e:
        logger.error(f"Failed to schedule reboot deletion for {file_path}: {e}")
        return False


def clean_autorun_persistence(target_path: str):
    """
    Removes any Run / RunOnce registry persistence keys referencing the malicious binary.
    """
    if sys.platform != "win32":
        return

    try:
        import winreg
        target_norm = os.path.abspath(target_path).lower()
        keys_to_check = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        ]

        for root_key, subkey in keys_to_check:
            try:
                with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
                    num_values = winreg.QueryInfoKey(k)[1]
                    to_delete = []
                    for i in range(num_values):
                        try:
                            val_name, val_data, _ = winreg.EnumValue(k, i)
                            if val_data and target_norm in str(val_data).lower():
                                to_delete.append(val_name)
                        except Exception:
                            continue
                    for val_name in to_delete:
                        winreg.DeleteValue(k, val_name)
                        logger.info(f"Cleaned malicious autorun persistence: {subkey}\\{val_name}")
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"Autorun registry cleanup error: {e}")


class OfflineScanManager:
    """
    Coordinates offline scan scheduling, pre-boot task dispatching,
    network-severed scanning, and automatic threat remediation.
    """

    def __init__(self, data_dir: Optional[Path] = None, fw_core=None, av_engine=None, fw_logger=None):
        self.data_dir = data_dir or DATA_DIR
        self.pending_file = self.data_dir / "offline_scan_pending.json"
        self.results_file = self.data_dir / "offline_scan_results.json"
        self.fw_core = fw_core or WindowsFirewallCore()
        self.av_engine = av_engine or AntivirusEngine(data_dir=self.data_dir)
        self.fw_logger = fw_logger or FirewallLogger()

    def find_builtin_repositories(self) -> List[Path]:
        """
        Locates built-in malware database repositories bundled with the application.
        Checks project directory, installation directory, PyInstaller bundle, and ProgramData.
        """
        candidates: List[Path] = []

        # 1. Source / development tree
        proj_dir = Path(__file__).resolve().parent.parent / "data" / "signatures"
        candidates.append(proj_dir)

        # 2. Executable parent directory (installed application)
        exe_dir = Path(sys.executable).parent / "data" / "signatures"
        candidates.append(exe_dir)

        # 3. PyInstaller bundle if frozen
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            candidates.append(Path(sys._MEIPASS) / "data" / "signatures")

        # 4. Standard Windows install paths
        for env_var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"]:
            base = os.environ.get(env_var)
            if base:
                candidates.append(Path(base) / "Crazy Alchemy" / "data" / "signatures")
                candidates.append(Path(base) / "Vitorius Firewall Win" / "data" / "signatures")

        valid_repos: List[Path] = []
        for c in candidates:
            if c.exists() and ((c / "malware_hashes.db").exists() or (c / "seed_hashes.py").exists() or (c / "rules").exists()):
                if c not in valid_repos:
                    valid_repos.append(c)

        return valid_repos

    def sync_builtin_malware_database(self) -> Dict[str, Any]:
        """
        Ensures the offline scanner has the complete malware database and YARA rules
        from the program's built-in repositories. Copies missing databases, ingests
        seed hashes, and recompiles YARA rules into the active scanning engine.
        """
        import shutil
        import sqlite3

        target_sig_dir = self.data_dir / "signatures"
        target_sig_dir.mkdir(parents=True, exist_ok=True)
        target_db = target_sig_dir / "malware_hashes.db"
        target_rules_dir = target_sig_dir / "rules"
        target_rules_dir.mkdir(parents=True, exist_ok=True)

        repos = self.find_builtin_repositories()
        source_repo_used = None
        copied_db = False
        copied_rules = 0

        for repo in repos:
            repo_db = repo / "malware_hashes.db"
            if repo_db.exists() and repo_db.resolve() != target_db.resolve():
                # If target DB doesn't exist or is smaller than the built-in repository, copy it
                if not target_db.exists() or target_db.stat().st_size < repo_db.stat().st_size:
                    try:
                        shutil.copy2(str(repo_db), str(target_db))
                        copied_db = True
                        source_repo_used = str(repo)
                    except Exception as e:
                        logger.debug(f"Could not copy repo DB from {repo}: {e}")

            repo_rules = repo / "rules"
            if repo_rules.exists() and repo_rules.resolve() != target_rules_dir.resolve():
                for yar in repo_rules.glob("*.yar"):
                    dest_yar = target_rules_dir / yar.name
                    if not dest_yar.exists() or dest_yar.stat().st_size != yar.stat().st_size:
                        try:
                            shutil.copy2(str(yar), str(dest_yar))
                            copied_rules += 1
                            if not source_repo_used:
                                source_repo_used = str(repo)
                        except Exception as e:
                            logger.debug(f"Could not copy YARA rule {yar}: {e}")

        # Ensure SQLite tables and ingest built-in seed hashes catalog (CORE_BASELINE_THREATS)
        active_signatures = 0
        try:
            conn = sqlite3.connect(str(target_db), timeout=15.0)
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                hash_sha256 TEXT PRIMARY KEY,
                hash_md5 TEXT,
                malware_family TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'critical',
                source TEXT NOT NULL,
                date_added TEXT NOT NULL
            );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sig_md5 ON signatures(hash_md5);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sig_family ON signatures(malware_family);")

            # Ingest CORE_BASELINE_THREATS
            try:
                from data.signatures.seed_hashes import CORE_BASELINE_THREATS
                now_iso = datetime.now(timezone.utc).isoformat()
                for sha, md5, fam, cat, sev, src in CORE_BASELINE_THREATS:
                    cur.execute(
                        "INSERT OR IGNORE INTO signatures (hash_sha256, hash_md5, malware_family, threat_category, severity, source, date_added) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (sha, md5, fam, cat, sev, src, now_iso)
                    )
                conn.commit()
            except Exception as e:
                logger.debug(f"Seed hashes ingest notice: {e}")

            cur.execute("SELECT COUNT(*) FROM signatures")
            row = cur.fetchone()
            active_signatures = row[0] if row else 0
            conn.close()
        except Exception as e:
            logger.error(f"Error initializing offline signatures database: {e}")

        # Update and recompile engine rules
        self.av_engine.db_path = target_db
        self.av_engine.rules_dir = target_rules_dir
        self.av_engine._load_yara_rules()

        active_yara_count = 0
        if target_rules_dir.exists():
            active_yara_count = len(list(target_rules_dir.glob("*.yar")))

        logger.info(
            f"Built-in malware repository verified: {active_signatures} active signatures, "
            f"{active_yara_count} YARA bundles loaded. Source: {source_repo_used or 'Internal'}"
        )

        return {
            "synced": True,
            "db_path": str(target_db),
            "active_signatures": active_signatures,
            "active_yara_rules": active_yara_count,
            "source_repository": source_repo_used or "Built-in Application Repository",
            "copied_db": copied_db,
            "copied_rules": copied_rules
        }

    def is_pending(self) -> bool:
        """Returns True if an offline scan is scheduled for next boot."""
        return self.pending_file.exists()

    def get_pending_details(self) -> Optional[Dict[str, Any]]:
        """Returns metadata for the currently scheduled offline scan."""
        if not self.is_pending():
            return None
        try:
            with open(self.pending_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading pending offline scan: {e}")
            return None

    def schedule_scan(
        self,
        reboot_now: bool = False,
        scan_targets: Optional[List[str]] = None,
        check_builtin_db: bool = True,
        validate_signatures: bool = True
    ) -> Tuple[bool, str]:
        """
        Schedules an offline scan to execute upon next reboot via Windows RunOnce
        and Task Scheduler, with an option to immediately restart the PC.
        Pre-synchronizes malware database from built-in repositories if enabled.
        """
        # Pre-seed offline database from built-in repository if requested
        if check_builtin_db:
            try:
                self.sync_builtin_malware_database()
            except Exception as e:
                logger.debug(f"Pre-sync notice during scheduling: {e}")

        payload = {
            "scheduled_at": datetime.now(timezone.utc).isoformat(),
            "reboot_requested": reboot_now,
            "custom_dirs": scan_targets or [],
            "check_builtin_db": check_builtin_db,
            "validate_signatures": validate_signatures,
            "status": "pending",
            "acknowledged": False
        }

        try:
            with open(self.pending_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            return False, f"Failed to save offline scan task: {e}"

        # Generate an explicit runner batch script to guarantee correct working directory & python environment
        runner_bat = self._create_runner_batch_script()
        cmd = f'cmd.exe /c "{runner_bat}"'

        # 1. Register with Windows RunOnce (Current User & Local Machine)
        self._register_runonce(cmd)

        # 2. Register elevated Task Scheduler fallback (interactive user logon)
        self._create_boot_task(cmd)

        self.fw_logger.log_event(
            "offline_scan_scheduled", "info",
            f"Crazy Alchemy Offline Antivirus Scan scheduled for next boot (Reboot now: {reboot_now})"
        )

        if reboot_now:
            reboot_ok = self._trigger_reboot(delay_sec=5, reason="Crazy Alchemy — Initiating Offline Reboot Scan...")
            if not reboot_ok:
                return True, "Scan scheduled for next boot, but automated restart failed. Please restart manually."
            return True, "Offline scan scheduled. Your device will restart in 5 seconds..."

        return True, "Offline scan scheduled successfully. It will run automatically when the PC restarts."

    def cancel_scan(self) -> Tuple[bool, str]:
        """Cancels a scheduled offline scan and removes registry/task entries."""
        if self.pending_file.exists():
            try:
                self.pending_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to remove pending file: {e}")

        # Also remove runner batch script if present
        runner_bat = self.data_dir / "run_offline_scan.bat"
        if runner_bat.exists():
            try:
                runner_bat.unlink()
            except Exception:
                pass

        self._unregister_runonce()
        self._delete_boot_task()

        # If a reboot was queued, attempt to abort it
        if sys.platform == "win32":
            try:
                kwargs = {"capture_output": True}
                if os.name == "nt":
                    kwargs["creationflags"] = 0x08000000
                subprocess.run(["shutdown", "/a"], **kwargs)
            except Exception:
                pass

        self.fw_logger.log_event("offline_scan_cancelled", "info", "Scheduled offline scan cancelled by user")
        return True, "Scheduled offline scan has been cancelled."

    def _create_runner_batch_script(self) -> str:
        """
        Generates an explicit run_offline_scan.bat script in data_dir.
        This completely eliminates quoting issues, path resolution errors,
        and ensures the correct working directory and Python environment.
        """
        runner_path = self.data_dir / "run_offline_scan.bat"
        project_dir = Path(__file__).resolve().parent.parent
        main_script = project_dir / "main_win.py"
        python_exe = sys.executable

        bat_content = f"""@echo off
setlocal
cd /d "{project_dir}"
set "PYTHONPATH={project_dir}"
"{python_exe}" "{main_script}" --offline-scan
"""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(runner_path, "w", encoding="utf-8") as f:
                f.write(bat_content)
        except Exception as e:
            logger.warning(f"Failed to write runner batch script: {e}")

        return str(runner_path)

    def _get_offline_command(self) -> str:
        """Determines the exact command line required to trigger --offline-scan."""
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}" --offline-scan'
        project_dir = Path(__file__).resolve().parent.parent
        main_script = project_dir / "main_win.py"
        return f'"{sys.executable}" "{main_script}" --offline-scan'

    def _register_runonce(self, cmd: str) -> bool:
        if sys.platform != "win32":
            return True
        success = False
        try:
            import winreg
            for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0, winreg.KEY_SET_VALUE) as k:
                        winreg.SetValueEx(k, "CrazyAlchemyOfflineScan", 0, winreg.REG_SZ, cmd)
                        winreg.SetValueEx(k, "VitoriusOfflineScan", 0, winreg.REG_SZ, cmd)
                        success = True
                except Exception as ex:
                    logger.debug(f"RunOnce registration error on {root}: {ex}")
        except Exception as e:
            logger.debug(f"RunOnce registration error: {e}")
        return success

    def _unregister_runonce(self) -> bool:
        if sys.platform != "win32":
            return True
        try:
            import winreg
            for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0, winreg.KEY_SET_VALUE) as k:
                        for val_name in ["CrazyAlchemyOfflineScan", "VitoriusOfflineScan"]:
                            try:
                                winreg.DeleteValue(k, val_name)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass
        return True

    def _create_boot_task(self, cmd: str) -> bool:
        if sys.platform != "win32":
            return True
        try:
            kwargs = {"capture_output": True, "timeout": 10}
            if os.name == "nt":
                kwargs["creationflags"] = 0x08000000
            # Register ONLOGON with HIGHEST privileges so it launches interactively with GUI in user desktop
            subprocess.run(
                ["schtasks", "/create", "/tn", "CrazyAlchemyOfflineScan", "/tr", cmd, "/sc", "ONLOGON", "/rl", "HIGHEST", "/f"],
                **kwargs
            )
            return True
        except Exception as e:
            logger.debug(f"schtasks creation notice: {e}")
            return False

    def _delete_boot_task(self) -> bool:
        if sys.platform != "win32":
            return True
        try:
            kwargs = {"capture_output": True, "timeout": 5}
            if os.name == "nt":
                kwargs["creationflags"] = 0x08000000
            for tn in ["CrazyAlchemyOfflineScan", "VitoriusOfflineScan"]:
                subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"], **kwargs)
            return True
        except Exception:
            return False

    def _trigger_reboot(self, delay_sec: int = 5, reason: str = "") -> bool:
        try:
            if sys.platform == "win32":
                kwargs = {"capture_output": True}
                if os.name == "nt":
                    kwargs["creationflags"] = 0x08000000
                subprocess.run(["shutdown", "/r", "/t", str(delay_sec), "/c", reason], **kwargs)
                return True
            else:
                logger.info(f"Simulating reboot trigger (delay={delay_sec}s): {reason}")
                return True
        except Exception as e:
            logger.error(f"Reboot trigger error: {e}")
            return False

    def get_offline_scan_hotspots(self) -> List[str]:
        """
        Enumerates all critical offline system locations that malware frequently abuses:
        drivers, scheduled tasks, startup folders, temp directories, user downloads, and appdata.
        """
        hotspots = []
        if sys.platform == "win32":
            windir = os.environ.get("SystemRoot", "C:\\Windows")
            drivers_dir = os.path.join(windir, "System32", "drivers")
            tasks_dir = os.path.join(windir, "System32", "Tasks")
            sys_temp = os.path.join(windir, "Temp")

            prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
            common_startup = os.path.join(prog_data, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

            appdata = os.environ.get("APPDATA", "")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            user_startup = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup") if appdata else ""
            user_temp = os.path.join(localappdata, "Temp") if localappdata else ""

            user_profile = os.environ.get("USERPROFILE", "")
            user_downloads = os.path.join(user_profile, "Downloads") if user_profile else ""

            for p in [drivers_dir, tasks_dir, common_startup, user_startup, sys_temp, user_temp, user_downloads]:
                if p and os.path.isdir(p):
                    hotspots.append(p)
        else:
            # Cross-platform / Linux testing directories
            temp_dir = os.environ.get("TMPDIR", "/tmp")
            home = str(Path.home())
            downloads = os.path.join(home, "Downloads")
            for p in [temp_dir, downloads]:
                if os.path.isdir(p):
                    hotspots.append(p)

        # Include any custom directories specified in pending scan
        pending = self.get_pending_details()
        if pending and "custom_dirs" in pending:
            for c in pending["custom_dirs"]:
                if os.path.isdir(c) and c not in hotspots:
                    hotspots.append(c)

        return hotspots

    def clean_threat(self, threat: ThreatDetection, validate_signatures: bool = True) -> Dict[str, Any]:
        """
        Remediates and neutralizes a detected threat:
        1. Validates digital signature on the target file. If properly signed and valid,
           suppresses false-positive detection and prevents isolation/deletion.
        2. Kills any running processes locking or executing the file.
        3. Encrypts and isolates the file into the Quarantine Vault.
        4. If file is locked, nullifies writable bytes and schedules MoveFileExW reboot deletion.
        5. Cleans associated autorun registry keys.
        """
        file_path = threat.file_path
        file_norm = os.path.abspath(file_path)
        action_taken = "quarantined"
        process_killed = False

        # -1. Antivirus suite protection: Never quarantine or kill application files
        if is_antivirus_program_file(file_path):
            logger.warning(
                f"OFFLINE SCAN SUPPRESSED: '{threat.threat_name}' in '{file_path}' "
                "belongs to the Crazy Alchemy / Vitorius Firewall suite. Suppressed to prevent false positives."
            )
            return {
                "file_path": file_path,
                "threat_name": threat.threat_name,
                "category": threat.threat_category,
                "severity": threat.severity,
                "action": "suppressed_antivirus_suite",
                "signature_status": "AntivirusSuiteFile",
                "process_killed": False,
                "is_false_positive": True,
                "cleaned_at": datetime.now(timezone.utc).isoformat()
            }

        # 0. Digital signature validation to eliminate false positives on legitimate software
        if validate_signatures:
            is_signed, sig_info = verify_file_signature(file_path)
            if is_signed:
                logger.warning(
                    f"OFFLINE SCAN FALSE-POSITIVE SUPPRESSED: '{threat.threat_name}' in '{file_path}' "
                    f"has a valid, properly validated digital signature ({sig_info}). File protected from quarantine/deletion."
                )
                remediation_record = {
                    "file_path": file_path,
                    "threat_name": threat.threat_name,
                    "category": threat.threat_category,
                    "severity": threat.severity,
                    "action": "suppressed_valid_signature",
                    "signature_status": sig_info,
                    "process_killed": False,
                    "is_false_positive": True,
                    "cleaned_at": datetime.now(timezone.utc).isoformat()
                }
                self.fw_logger.log_event(
                    "offline_false_positive_suppressed", "info",
                    f"Offline threat suppressed on validated signed file: {threat.threat_name} in {file_path} ({sig_info})",
                    details=remediation_record
                )
                return remediation_record

        # 1. Kill locking process
        try:
            import psutil
            target_lower = file_norm.lower()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if is_antivirus_process(proc):
                    continue
                try:
                    exe = (proc.info.get('exe') or '').lower()
                    if exe and os.path.abspath(exe).lower() == target_lower:
                        proc.kill()
                        process_killed = True
                        logger.info(f"Terminated malicious process PID {proc.pid} ({proc.info.get('name')})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process termination notice: {e}")

        # 2. Quarantine into encrypted vault
        quarantined = self.av_engine.quarantine.quarantine_file(file_path, threat)
        if not quarantined:
            # Quarantine refused (e.g. signature/rules definition asset or exclusion)
            logger.warning(f"Quarantine aborted for '{file_path}'. Skipping destructive neutralization.")
            return {
                "file_path": file_path,
                "threat_name": threat.threat_name,
                "category": threat.threat_category,
                "severity": threat.severity,
                "action": "quarantine_aborted",
                "process_killed": process_killed,
                "is_false_positive": False,
                "cleaned_at": datetime.now(timezone.utc).isoformat()
            }

        # 3. Handle locked files ONLY if quarantine succeeded and file remained on disk
        if os.path.exists(file_path):
            try:
                # Attempt to neutralize by overwriting with zeros
                with open(file_path, "wb") as f:
                    f.write(b"\x00" * min(8192, max(1, os.path.getsize(file_path))))
                os.remove(file_path)
                action_taken = "neutralized_and_deleted"
            except Exception:
                # File is locked by OS: schedule MoveFileExW reboot deletion
                mark_file_for_reboot_deletion(file_path)
                action_taken = "scheduled_reboot_deletion"

        # 4. Remove autorun registry keys
        clean_autorun_persistence(file_path)

        remediation_record = {
            "file_path": file_path,
            "threat_name": threat.threat_name,
            "category": threat.threat_category,
            "severity": threat.severity,
            "action": action_taken,
            "process_killed": process_killed,
            "is_false_positive": False,
            "cleaned_at": datetime.now(timezone.utc).isoformat()
        }

        self.fw_logger.log_event(
            "offline_malware_cleaned", "critical",
            f"Offline Remediation: {threat.threat_name} in {file_path} -> Action: {action_taken}",
            details=remediation_record
        )

        return remediation_record

    def execute_offline_scan(
        self,
        progress_cb=None,
        threat_cb=None,
        status_cb=None,
        cancel_event=None,
        check_builtin_db: Optional[bool] = None,
        validate_signatures: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Executes the offline scan:
        1. Checks and synchronizes malware database from built-in repositories if enabled.
        2. Engages Panic Mode (network severance).
        3. Scans all hotspot directories.
        4. Validates digital signatures on flagged files to prevent false positives.
        5. Cleans and remediates verified malware threats.
        6. Saves structured results and restores network connectivity.
        """
        start_time = time.time()
        logger.info("=== STARTING VITORIUS OFFLINE ANTIMALWARE SCAN ===")

        pending = self.get_pending_details() or {}
        if check_builtin_db is None:
            check_builtin_db = pending.get("check_builtin_db", True)
        if validate_signatures is None:
            validate_signatures = pending.get("validate_signatures", True)

        # 1. Check and synchronize malware database in built-in repositories
        repo_info = {"synced": False, "active_signatures": 0, "active_yara_rules": 0}
        if check_builtin_db:
            if status_cb:
                status_cb("Checking malware database in built-in program repositories...")
            try:
                repo_info = self.sync_builtin_malware_database()
                logger.info(f"Built-in repository check complete: {repo_info}")
            except Exception as e:
                logger.warning(f"Error checking built-in malware repository: {e}")

        if status_cb:
            status_cb("Engaging network isolation (Panic Lockdown)...")

        # 2. Network isolation (Panic Mode) so malware cannot communicate
        self.fw_core.enable_panic_mode()

        hotspots = self.get_offline_scan_hotspots()
        logger.info(f"Offline scan targeting {len(hotspots)} system hotspot directories: {hotspots}")

        total_files_scanned = 0
        cleaned_threats: List[Dict[str, Any]] = []
        suppressed_false_positives: List[Dict[str, Any]] = []

        try:
            for idx, target_dir in enumerate(hotspots):
                if cancel_event and cancel_event.is_set():
                    logger.info("Offline scan cancelled by user event.")
                    break

                if status_cb:
                    status_cb(f"Scanning hotspot ({idx + 1}/{len(hotspots)}): {target_dir}")

                def on_file_scanned(cur, total, path):
                    nonlocal total_files_scanned
                    total_files_scanned += 1
                    if progress_cb:
                        pct = int(((idx + (cur / max(1, total))) / max(1, len(hotspots))) * 100)
                        progress_cb(min(100, pct), path)

                def on_threat_detected(threat: ThreatDetection):
                    logger.warning(f"OFFLINE SCAN THREAT DETECTED: {threat.threat_name} in {threat.file_path}")
                    remediation = self.clean_threat(threat, validate_signatures=validate_signatures)
                    if remediation.get("is_false_positive"):
                        suppressed_false_positives.append(remediation)
                        if threat_cb:
                            threat_cb(threat, remediation)
                    else:
                        cleaned_threats.append(remediation)
                        if threat_cb:
                            threat_cb(threat, remediation)

                self.av_engine.scan_directory(
                    target_dir,
                    progress_cb=on_file_scanned,
                    threat_cb=on_threat_detected,
                    cancel_event=cancel_event
                )

        finally:
            # Always restore network traffic upon scan completion
            if status_cb:
                status_cb("Restoring network adapter connectivity...")
            self.fw_core.disable_panic_mode()

        duration = round(time.time() - start_time, 2)
        results = {
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": duration,
            "hotspots_scanned": hotspots,
            "files_scanned": total_files_scanned,
            "threats_found": len(cleaned_threats) + len(suppressed_false_positives),
            "threats_cleaned": len(cleaned_threats),
            "false_positives_suppressed": len(suppressed_false_positives),
            "cleaned_items": cleaned_threats,
            "suppressed_items": suppressed_false_positives,
            "builtin_db_synced": repo_info.get("synced", False),
            "active_signatures": repo_info.get("active_signatures", 0),
            "active_yara_rules": repo_info.get("active_yara_rules", 0),
            "acknowledged": False
        }

        # Write results to file
        try:
            with open(self.results_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write offline scan results: {e}")

        # Clean up pending marker and boot triggers
        if self.pending_file.exists():
            try:
                self.pending_file.unlink()
            except Exception:
                pass

        self._unregister_runonce()
        self._delete_boot_task()

        self.fw_logger.log_event(
            "offline_scan_completed",
            "critical" if cleaned_threats else "info",
            f"Offline Antivirus Scan finished in {duration}s. Scanned: {total_files_scanned} files. "
            f"Cleaned: {len(cleaned_threats)} threats."
        )

        logger.info(f"=== OFFLINE SCAN FINISHED: {len(cleaned_threats)} THREATS CLEANED ===")
        return results

    def get_last_results(self) -> Optional[Dict[str, Any]]:
        """Returns the most recent offline scan results if unacknowledged."""
        if not self.results_file.exists():
            return None
        try:
            with open(self.results_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not data.get("acknowledged", False):
                return data
            return None
        except Exception as e:
            logger.debug(f"Error reading offline scan results: {e}")
            return None

    def acknowledge_results(self):
        """Marks the latest offline scan results as seen by the user."""
        if not self.results_file.exists():
            return
        try:
            with open(self.results_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["acknowledged"] = True
            with open(self.results_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"Error acknowledging offline scan results: {e}")


def run_offline_scan_cli() -> int:
    """
    CLI / Pre-Boot entry point for --offline-scan.
    Launches a dedicated graphical splash/progress dialog if PyQt6 is present,
    or falls back to console progress output.
    """
    logger.info("Initializing Crazy Alchemy Offline Antivirus Scanner (Post-Reboot)...")
    mgr = OfflineScanManager()

    # Try graphical interface first
    try:
        from PyQt6.QtWidgets import (
            QApplication, QDialog, QVBoxLayout, QHBoxLayout, QLabel,
            QProgressBar, QPushButton, QFrame, QCheckBox
        )
        from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
        from PyQt6.QtGui import QFont, QIcon
        import threading

        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

        class OfflineWorkerSignals(QObject):
            progress = pyqtSignal(int, str)
            status = pyqtSignal(str)
            threat = pyqtSignal(str, str)
            fp_suppressed = pyqtSignal(str, str)
            repo_status = pyqtSignal(str)
            finished = pyqtSignal(dict)

        signals = OfflineWorkerSignals()

        dialog = QDialog()
        dialog.setWindowTitle("Crazy Alchemy Antivirus — Offline Scan")
        dialog.setFixedSize(700, 520)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: 'Segoe UI Variable', 'Segoe UI', sans-serif;
            }
            QFrame.card {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 14px;
            }
            QProgressBar {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                text-align: center;
                color: #ffffff;
                height: 20px;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 5px;
            }
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 24px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #30363d;
                border-radius: 3px;
                background-color: #21262d;
            }
            QCheckBox::indicator:checked {
                background-color: #238636;
                border-color: #238636;
            }
        """)

        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(12)

        header_lay = QHBoxLayout()
        icon_lbl = QLabel("🛡️")
        icon_lbl.setStyleSheet("font-size: 38px;")
        header_lay.addWidget(icon_lbl)

        title_lay = QVBoxLayout()
        t1 = QLabel("Crazy Alchemy Antivirus — Offline Reboot Scanner")
        t1.setStyleSheet("font-size: 17px; font-weight: bold; color: #58a6ff;")
        t2 = QLabel("Network isolated (Panic Mode) • Scanning and cleaning persistent threats")
        t2.setStyleSheet("font-size: 12px; color: #8b949e;")
        title_lay.addWidget(t1)
        title_lay.addWidget(t2)
        header_lay.addLayout(title_lay, stretch=1)
        lay.addLayout(header_lay)

        # ── Built-in Malware Repository & False-Positive Guard Card ──
        opt_card = QFrame()
        opt_card.setProperty("class", "card")
        o_lay = QVBoxLayout(opt_card)
        o_lay.setSpacing(6)

        chk_repo = QCheckBox("Check & synchronize malware database from program's built-in repositories")
        chk_repo.setChecked(True)
        chk_repo.setStyleSheet("color: #e6edf3; font-weight: bold; font-size: 12px;")
        o_lay.addWidget(chk_repo)

        repo_lbl = QLabel("📦 Built-in Repositories: Ready to verify definitions")
        repo_lbl.setStyleSheet("color: #58a6ff; font-size: 11px; margin-left: 24px;")
        o_lay.addWidget(repo_lbl)

        chk_sig = QCheckBox("Validate digital signatures on detected files to prevent false positives")
        chk_sig.setChecked(True)
        chk_sig.setStyleSheet("color: #e6edf3; font-weight: bold; font-size: 12px;")
        o_lay.addWidget(chk_sig)

        sig_lbl = QLabel("🛡️ Valid Authenticode & Windows Catalog binaries will be protected from quarantine")
        sig_lbl.setStyleSheet("color: #8b949e; font-size: 11px; margin-left: 24px;")
        o_lay.addWidget(sig_lbl)

        lay.addWidget(opt_card)

        # ── Scan Progress Card ──
        card = QFrame()
        card.setProperty("class", "card")
        c_lay = QVBoxLayout(card)
        c_lay.setSpacing(8)

        status_lbl = QLabel("Initializing offline antimalware engine...")
        status_lbl.setStyleSheet("font-weight: bold; color: #f0f6fc; font-size: 12px;")
        c_lay.addWidget(status_lbl)

        pbar = QProgressBar()
        pbar.setValue(0)
        c_lay.addWidget(pbar)

        file_lbl = QLabel("Preparing system hotspots...")
        file_lbl.setStyleSheet("font-size: 11px; color: #8b949e;")
        c_lay.addWidget(file_lbl)

        stats_row = QHBoxLayout()
        threats_lbl = QLabel("Threats Cleaned: 0")
        threats_lbl.setStyleSheet("font-size: 12px; font-weight: bold; color: #7ee787;")
        stats_row.addWidget(threats_lbl)

        fp_lbl = QLabel("Legitimate Files Protected (Valid Signatures): 0")
        fp_lbl.setStyleSheet("font-size: 12px; font-weight: bold; color: #58a6ff;")
        stats_row.addWidget(fp_lbl, alignment=Qt.AlignmentFlag.AlignRight)
        c_lay.addLayout(stats_row)

        lay.addWidget(card)

        btn_continue = QPushButton("Continue to Windows")
        btn_continue.setEnabled(False)
        btn_continue.clicked.connect(dialog.accept)
        lay.addWidget(btn_continue, alignment=Qt.AlignmentFlag.AlignRight)

        threat_count = 0
        fp_count = 0

        def on_prog(pct, p):
            signals.progress.emit(pct, p)

        def on_stat(s):
            signals.status.emit(s)

        def on_threat(t, rem):
            if rem.get("is_false_positive"):
                signals.fp_suppressed.emit(t.threat_name, rem.get("signature_status", "Valid Signature"))
            else:
                signals.threat.emit(t.threat_name, rem.get("action", "cleaned"))

        signals.progress.connect(lambda pct, path: (pbar.setValue(pct), file_lbl.setText(f"Scanning: {path}")))
        signals.status.connect(status_lbl.setText)
        signals.repo_status.connect(repo_lbl.setText)

        def handle_threat(name, action):
            nonlocal threat_count
            threat_count += 1
            threats_lbl.setText(f"Threats Found & Cleaned: {threat_count} (Latest: {name} - {action})")
            threats_lbl.setStyleSheet("font-size: 12px; font-weight: bold; color: #f85149;")

        def handle_fp(name, sig_info):
            nonlocal fp_count
            fp_count += 1
            fp_lbl.setText(f"Legitimate Files Protected (Valid Signatures): {fp_count} (Latest: {name} - {sig_info})")

        signals.threat.connect(handle_threat)
        signals.fp_suppressed.connect(handle_fp)

        def on_done(res):
            pbar.setValue(100)
            cleaned = res.get('threats_cleaned', 0)
            fps = res.get('false_positives_suppressed', 0)
            dur = res.get('duration_seconds', 0)
            sigs = res.get('active_signatures', 0)
            status_lbl.setText(f"Offline Scan Complete! Cleaned {cleaned} threat(s) in {dur}s.")
            file_lbl.setText(f"Total files audited: {res.get('files_scanned', 0):,} • Active signatures: {sigs:,}")
            if res.get('builtin_db_synced'):
                repo_lbl.setText(f"📦 Built-in Repositories: {sigs:,} signatures active & verified")
            btn_continue.setEnabled(True)
            # Auto-continue after 6 seconds
            QTimer.singleShot(6000, dialog.accept)

        signals.finished.connect(on_done)

        def scan_worker():
            results = mgr.execute_offline_scan(
                progress_cb=on_prog,
                status_cb=on_stat,
                threat_cb=on_threat,
                check_builtin_db=chk_repo.isChecked(),
                validate_signatures=chk_sig.isChecked()
            )
            signals.finished.emit(results)

        threading.Thread(target=scan_worker, daemon=True).start()
        dialog.exec()
        return 0

    except ImportError:
        # Headless console runner
        print("\n" + "=" * 60)
        print(" CRAZY ALCHEMY ANTIMALWARE OFFLINE SCANNER (PRE-BOOT / REBOOT)")
        print("=" * 60)
        print("[*] Checking malware database in built-in program repositories...")
        repo_info = mgr.sync_builtin_malware_database()
        print(f"[✓] Active definitions: {repo_info.get('active_signatures')} signatures, {repo_info.get('active_yara_rules')} YARA rules.")
        print("[*] Digital signature validation active (false-positive suppression enabled).")
        print("[*] Engaging Network Panic Lockdown...")

        def console_progress(pct, path):
            if pct % 10 == 0:
                print(f"[*] Progress: {pct}% -> {path}")

        def console_status(s):
            print(f"[*] {s}")

        def console_threat(t, rem):
            if rem.get("is_false_positive"):
                print(f"[i] FALSE POSITIVE PROTECTED: {t.threat_name} in {t.file_path} ({rem.get('signature_status')})")
            else:
                print(f"[!] THREAT CLEANED: {t.threat_name} -> {rem.get('action')}")

        res = mgr.execute_offline_scan(
            progress_cb=console_progress,
            status_cb=console_status,
            threat_cb=console_threat,
            check_builtin_db=True,
            validate_signatures=True
        )

        print("\n[+] Offline Scan Finished!")
        print(f"[+] Files Scanned: {res.get('files_scanned')}")
        print(f"[+] Threats Cleaned: {res.get('threats_cleaned')}")
        print(f"[+] Protected Validated Files: {res.get('false_positives_suppressed')}")
        print("=" * 60 + "\n")
        return 0
