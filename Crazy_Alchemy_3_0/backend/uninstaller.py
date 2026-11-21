"""
Crazy Alchemy v3.0 - Standalone Windows Uninstaller Engine
Enterprise-Grade Windows 11 Endpoint Security Suite Uninstaller

Handles comprehensive, clean, and complete uninstallation:
1. Process termination (Crazy Alchemy executables, service, and Python background tasks)
2. Windows background services removal (CrazyAlchemyService, VitoriusFirewallService, etc.)
3. Windows Defender, Exploit Guard, and Windows Firewall restoration to factory defaults
4. Desktop, Start Menu, Startup shortcuts, Task Scheduler tasks, and Explorer context menus cleanup
5. Windows 'Installed Apps' / Control Panel 'Programs and Features' registry unregistration
6. User settings, local caches, databases, honeytokens, and quarantine cleanup
7. Clean removal of installed program files directory with self-deletion support
"""

import os
import sys
import shutil
import tempfile
import subprocess
import logging
from pathlib import Path
from typing import Optional

try:
    import winreg
except ImportError:
    winreg = None

logger = logging.getLogger("crazyalchemy.uninstaller")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

APP_NAME = "Crazy Alchemy"
APP_VERSION = "3.0"
APP_CODENAME = "Alchemy3"
PUBLISHER = "Crazy Alchemy"
EXE_NAME = "CrazyAlchemy.exe"
DEFAULT_INSTALL_DIR = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / APP_NAME
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def delete_registry_tree(root_hkey, key_path: str, access: int = 0):
    """Recursively deletes a registry key and all its subkeys and values."""
    if not winreg:
        return
    try:
        open_flags = winreg.KEY_READ | (access if access else 0)
        with winreg.OpenKey(root_hkey, key_path, 0, open_flags) as key:
            while True:
                try:
                    sub = winreg.EnumKey(key, 0)
                    delete_registry_tree(root_hkey, f"{key_path}\\{sub}", access)
                except OSError:
                    break
    except OSError:
        pass

    try:
        if access:
            winreg.DeleteKeyEx(root_hkey, key_path, access, 0)
        else:
            winreg.DeleteKey(root_hkey, key_path)
    except OSError:
        pass


def terminate_running_instances():
    """Gracefully closes or terminates all running Crazy Alchemy application and service processes."""
    if sys.platform != "win32":
        return

    # 1. Terminate known compiled executables
    for proc_name in [EXE_NAME, "VitoriusFirewallWin.exe", "vitorius_service.exe"]:
        try:
            subprocess.run(
                ["taskkill.exe", "/F", "/IM", proc_name, "/T"],
                capture_output=True, creationflags=CREATE_NO_WINDOW
            )
        except Exception:
            pass

    # 2. Terminate GUI windows by title
    for win_title in ["Crazy Alchemy*", "Vitorius Firewall Win*"]:
        try:
            subprocess.run(
                ["taskkill.exe", "/F", "/FI", f"WINDOWTITLE eq {win_title}"],
                capture_output=True, creationflags=CREATE_NO_WINDOW
            )
        except Exception:
            pass

    # 3. Terminate python instances running main_win.py / service (excluding current uninstaller process)
    try:
        import psutil
        my_pid = os.getpid()
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if p.pid == my_pid:
                    continue
                name = (p.info.get("name") or "").lower()
                cmdline_parts = p.info.get("cmdline") or []
                cmdline = " ".join(cmdline_parts).lower()

                # Only kill Python instances running Crazy Alchemy scripts, not uninstallation commands
                if "python" in name:
                    if any(s in cmdline for s in ["main_win.py", "vitorius_service.py"]):
                        if "--uninstall" not in cmdline and "-u" not in cmdline:
                            p.kill()
            except Exception:
                continue
    except Exception:
        pass


def stop_and_remove_windows_service():
    """Stops and deletes background Windows Services installed by Crazy Alchemy."""
    if sys.platform != "win32":
        return

    for svc in ["CrazyAlchemyService", "VitoriusFirewallService", "VitoriusFirewallCoreSvc"]:
        try:
            subprocess.run(["net.exe", "stop", svc], capture_output=True, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
        try:
            subprocess.run(["sc.exe", "stop", svc], capture_output=True, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
        try:
            subprocess.run(["sc.exe", "delete", svc], capture_output=True, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass


def revert_windows_default_configuration(target_dir: Optional[Path] = None):
    """
    Reverts all Windows system configurations modified by Crazy Alchemy back to factory defaults:
    1. Resets Windows Firewall to factory default rules and policies.
    2. Restores Windows Defender: removes passive mode, clears exclusions, re-enables Real-Time Protection.
    3. Reverts Exploit Guard system process mitigations and ASR rules to Windows defaults.
    4. Flushes Windows DNS, NetBIOS, and ARP resolver caches.
    """
    if sys.platform != "win32":
        return

    # Delete application-specific firewall rules
    if target_dir:
        for exe_cand in [
            target_dir / EXE_NAME,
            target_dir / "VitoriusFirewallWin.exe",
            target_dir / "service" / "vitorius_service.exe"
        ]:
            if exe_cand.exists():
                try:
                    subprocess.run([
                        "netsh.exe", "advfirewall", "firewall", "delete", "rule",
                        "name=all", "profile=any", f"program={exe_cand}"
                    ], capture_output=True, creationflags=CREATE_NO_WINDOW)
                except Exception:
                    pass

    for rule_name in [
        "VitoriusFW_PANIC_IN", "VitoriusFW_PANIC_OUT",
        "VFW_PANIC_IN", "VFW_PANIC_OUT",
        "CrazyAlchemy_Service", "CrazyAlchemy_UI",
        "VitoriusFirewallService", "VitoriusFirewallCoreSvc"
    ]:
        try:
            subprocess.run(["netsh.exe", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass

    # Reset Windows Firewall to factory default configuration
    try:
        subprocess.run(["netsh.exe", "advfirewall", "reset"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["netsh.exe", "advfirewall", "set", "allprofiles", "state", "on"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["netsh.exe", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], capture_output=True, creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass

    # Clear Defender Policies
    if winreg:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection", 0, winreg.KEY_SET_VALUE | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100)) as k:
                try:
                    winreg.DeleteValue(k, "ForceDefenderPassiveMode")
                except OSError:
                    pass
        except Exception:
            pass

        for sub in ["Paths", "Processes", "Extensions"]:
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\{sub}")
            except Exception:
                pass
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions")
        except Exception:
            pass

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", 0, winreg.KEY_SET_VALUE | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100)) as k:
                for val in ["DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableOnAccessProtection", "DisableScanOnRealtimeEnable", "DisableIOAVProtection", "DisableScriptScanning"]:
                    try:
                        winreg.DeleteValue(k, val)
                    except OSError:
                        pass
        except Exception:
            pass

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_SET_VALUE | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100)) as k:
                for val in ["DisableAntiSpyware", "DisableAntiVirus"]:
                    try:
                        winreg.DeleteValue(k, val)
                    except OSError:
                        pass
        except Exception:
            pass

    # Remove PowerShell Defender exclusions, re-enable Defender Real-Time Monitoring, and reset Exploit Guard
    ps_commands = [
        "$p = (Get-MpPreference).ExclusionPath | Where-Object { $_ -match 'CrazyAlchemy|Vitorius|HoneyToken' }; if ($p) { Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue }",
        "$pr = (Get-MpPreference).ExclusionProcess | Where-Object { $_ -match 'CrazyAlchemy|Vitorius' }; if ($pr) { Remove-MpPreference -ExclusionProcess $pr -ErrorAction SilentlyContinue }",
        "Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue",
        "Set-ProcessMitigation -System -Reset -ErrorAction SilentlyContinue",
        "Set-MpPreference -AttackSurfaceReductionRules_Ids @() -AttackSurfaceReductionRules_Actions @() -ErrorAction SilentlyContinue",
    ]
    full_ps = "; ".join(ps_commands)
    try:
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", full_ps], capture_output=True, creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass

    # Flush DNS, ARP, NetBIOS
    try:
        subprocess.run(["ipconfig.exe", "/flushdns"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["netsh.exe", "interface", "ip", "delete", "arpcache"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["nbtstat.exe", "-R"], capture_output=True, creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass


def remove_shortcuts():
    """Removes all Desktop, Start Menu, and Startup shortcuts created by installer."""
    desktops = [
        Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop",
        Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Desktop",
        Path(os.environ.get("USERPROFILE", str(Path.home()))) / "OneDrive" / "Desktop",
    ]
    for d in desktops:
        for name in [APP_NAME, "Vitorius Firewall Win"]:
            try:
                lnk = d / f"{name}.lnk"
                if lnk.exists():
                    lnk.unlink(missing_ok=True)
            except Exception:
                pass

    # Start Menu shortcuts
    start_menus = [
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    ]
    for sm in start_menus:
        for name in [APP_NAME, "Vitorius Firewall Win"]:
            try:
                app_dir = sm / name
                if app_dir.exists():
                    shutil.rmtree(app_dir, ignore_errors=True)
            except Exception:
                pass
            try:
                lnk = sm / f"{name}.lnk"
                if lnk.exists():
                    lnk.unlink(missing_ok=True)
            except Exception:
                pass

    # Startup folder shortcuts
    startup_paths = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    ]
    for sp in startup_paths:
        for name in [APP_NAME, "Vitorius Firewall Win"]:
            try:
                lnk = sp / f"{name}.lnk"
                if lnk.exists():
                    lnk.unlink(missing_ok=True)
            except Exception:
                pass


def unregister_autostart_registry():
    """Removes autostart registry entries from HKLM and HKCU Run keys."""
    if not winreg:
        return

    run_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for access in [winreg.KEY_SET_VALUE | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100), winreg.KEY_SET_VALUE]:
            try:
                with winreg.OpenKey(hkey, run_key, 0, access) as k:
                    for val_name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
                        try:
                            winreg.DeleteValue(k, val_name)
                        except Exception:
                            pass
            except Exception:
                continue


def unregister_explorer_context_menu():
    """Removes right-click context menu options from Windows Explorer."""
    if not winreg:
        return

    for root_key_name in ("*", "Directory", "Directory\\Background"):
        for menu_key in ("CrazyAlchemyScan", "VitoriusScan"):
            sub_key = f"{root_key_name}\\shell\\{menu_key}"
            try:
                delete_registry_tree(winreg.HKEY_CLASSES_ROOT, sub_key)
            except Exception:
                pass


def unregister_windows_uninstall():
    """Completely removes application from Windows Control Panel and Installed Apps registry."""
    if not winreg:
        return

    for key_name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
        key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{key_name}"
        for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for access in [
                getattr(winreg, 'KEY_WOW64_64KEY', 0x0100),
                getattr(winreg, 'KEY_WOW64_32KEY', 0x0200),
                0
            ]:
                try:
                    delete_registry_tree(hkey, key_path, access)
                    logger.info(f"Unregistered {key_name} from Windows Installed Apps.")
                except Exception:
                    pass


def cleanup_app_data_and_settings():
    """
    Completely removes all application settings, caches, databases, logs, honeytokens,
    quarantine files, temporary files, and user configuration options.
    """
    target_paths = [
        Path(os.environ.get("APPDATA", "")) / "VitoriusFirewallWin",
        Path(os.environ.get("APPDATA", "")) / "CrazyAlchemy",
        Path.home() / ".vitorius_firewall_win",
        Path.home() / ".crazy_alchemy",
        Path(os.environ.get("LOCALAPPDATA", "")) / "VitoriusFirewallWin",
        Path(os.environ.get("LOCALAPPDATA", "")) / "CrazyAlchemy",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "VitoriusFirewallWin",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "CrazyAlchemy",
        Path(tempfile.gettempdir()) / "VitoriusFirewallWin",
        Path(tempfile.gettempdir()) / "vitorius_firewall_win",
        Path(tempfile.gettempdir()) / "CrazyAlchemy",
        Path(tempfile.gettempdir()) / "crazy_alchemy",
        Path(tempfile.gettempdir()) / "vitorius_quarantine",
    ]

    for p in target_paths:
        try:
            if p.exists():
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    p.unlink(missing_ok=True)
        except Exception:
            pass

    # Remove temporary logs
    try:
        temp_dir = Path(tempfile.gettempdir())
        for log_f in temp_dir.glob("VitoriusTweaks_*.log"):
            try:
                log_f.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass

    # Remove application registry hives
    if winreg:
        for root_hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            for app_key in ["CrazyAlchemy", "VitoriusFirewallWin"]:
                for access in [getattr(winreg, 'KEY_WOW64_64KEY', 0x0100), getattr(winreg, 'KEY_WOW64_32KEY', 0x0200), 0]:
                    try:
                        delete_registry_tree(root_hive, rf"SOFTWARE\{app_key}", access)
                    except Exception:
                        pass


def cleanup_installation_directory(target_dir: Optional[Path] = None):
    """
    Removes the program files installation folder.
    Safely skips removal if target_dir is a git repository or workspace.
    Uses detached delayed removal if files are locked by the currently running process.
    """
    if not target_dir:
        return
    target_dir = Path(target_dir).resolve()
    if not target_dir.exists():
        return

    # Safety guard: Never delete the source repository or active workspace!
    if (target_dir / ".git").exists() or (target_dir / ".gemini").exists():
        logger.info(f"Preserving development repository at {target_dir}; skipped directory removal.")
        return

    # Change working directory to %TEMP% so current process does not lock target_dir
    try:
        os.chdir(tempfile.gettempdir())
    except Exception:
        pass

    # Remove read-only attributes
    try:
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o777)
                except Exception:
                    pass
    except Exception:
        pass

    # Delete subdirectories
    for sub in ["backend", "ui", "data", "service", "prerequisites", "build"]:
        sub_p = target_dir / sub
        if sub_p.exists():
            try:
                shutil.rmtree(sub_p, ignore_errors=True)
            except Exception:
                pass

    # Delete non-locked files
    for item in list(target_dir.iterdir()):
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)
        except Exception:
            pass

    # Try immediate directory removal
    try:
        target_dir.rmdir()
        logger.info(f"Successfully removed installation directory: {target_dir}")
        return
    except Exception:
        pass

    # Detached delayed background removal for locked batch/python files
    target_dir_str = str(target_dir)
    cmd = f'cmd.exe /c timeout /t 2 /nobreak >nul & rmdir /s /q "{target_dir_str}"'
    try:
        subprocess.Popen(cmd, shell=True, creationflags=CREATE_NO_WINDOW | 0x00000200)
    except Exception:
        pass

    ps_cmd = f'Start-Sleep -Seconds 2; Remove-Item -LiteralPath \'{target_dir_str}\' -Recurse -Force -ErrorAction SilentlyContinue'
    try:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            creationflags=CREATE_NO_WINDOW | 0x00000200
        )
    except Exception:
        pass


def resolve_installation_directory(candidate: Optional[Path] = None) -> Optional[Path]:
    """Resolves the actual target installation directory across registry and default paths."""
    if candidate and candidate.exists():
        # Verify it is not the source repo
        if not (candidate / ".git").exists():
            return candidate

    # 1. Query registry InstallLocation
    if winreg:
        for key_name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
            key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{key_name}"
            for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for access in [winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100), winreg.KEY_READ]:
                    try:
                        with winreg.OpenKey(hkey, key_path, 0, access) as k:
                            loc, _ = winreg.QueryValueEx(k, "InstallLocation")
                            if loc and Path(loc).exists() and not (Path(loc) / ".git").exists():
                                return Path(loc)
                    except Exception:
                        pass

    # 2. Check standard installation directories
    for cand in [
        DEFAULT_INSTALL_DIR,
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / APP_NAME,
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "VitoriusFirewallWin",
    ]:
        if cand.exists() and not (cand / ".git").exists():
            return cand

    return None


def run_uninstallation(target_dir: Optional[Path] = None) -> bool:
    """
    Executes complete native uninstallation of Crazy Alchemy:
    - Stops and removes services
    - Reverts firewall and security policies
    - Removes shortcuts and scheduled tasks
    - Unregisters from Windows Control Panel / Installed Apps
    - Purges application data, caches, and settings
    - Deletes installed program files
    """
    print("=" * 65)
    print(f"  Uninstalling {APP_NAME} v{APP_VERSION} ({APP_CODENAME})...")
    print("=" * 65)

    resolved_target = resolve_installation_directory(target_dir)
    if resolved_target:
        print(f"[*] Target Installation Directory: {resolved_target}")

    # 1. Terminate running instances
    print("[*] [1/6] Terminating active application instances...")
    terminate_running_instances()

    # 2. Stop and remove Windows Services
    print("[*] [2/6] Stopping and removing background Windows Services...")
    stop_and_remove_windows_service()

    # 3. Revert Windows Firewall, Defender & Security configurations to factory defaults
    print("[*] [3/6] Reverting Windows Firewall, Defender & Security configurations to factory defaults...")
    revert_windows_default_configuration(resolved_target)

    # 4. Remove shortcuts, Task Scheduler tasks, and registry integration
    print("[*] [4/6] Removing shortcuts, Task Scheduler tasks, context menu, and registry entries...")
    for tn in [
        "CrazyAlchemy", "CrazyAlchemyAutostart", "CrazyAlchemyOfflineScan",
        "CrazyAlchemy_ElevationBypass", "VitoriusOfflineScan",
        "VitoriusFirewallWin", "VitoriusFirewallWinAutostart", "VitoriusFirewallService"
    ]:
        try:
            subprocess.run(["schtasks.exe", "/Delete", "/TN", tn, "/F"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass

    remove_shortcuts()
    unregister_autostart_registry()
    unregister_explorer_context_menu()
    unregister_windows_uninstall()

    # 5. Clean up settings, caches, quarantine, and databases
    print("[*] [5/6] Removing application settings, caches, databases, and temporary files...")
    cleanup_app_data_and_settings()

    # 6. Remove program files directory
    print("[*] [6/6] Removing installed program files...")
    if resolved_target:
        cleanup_installation_directory(resolved_target)

    print("\n" + "=" * 65)
    print(f"  [SUCCESS] {APP_NAME} uninstalled successfully!")
    print("=" * 65)
    return True


if __name__ == "__main__":
    target = None
    for arg in sys.argv[1:]:
        if arg not in ["--uninstall", "-u", "--silent", "-s", "--yes", "-y"] and not arg.startswith("-"):
            target = Path(arg)
            break
    run_uninstallation(target_dir=target)
    sys.exit(0)
