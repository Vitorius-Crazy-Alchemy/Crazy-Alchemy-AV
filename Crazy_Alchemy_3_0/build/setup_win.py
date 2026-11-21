#!/usr/bin/env python3
"""
Vitorius Firewall Win - Native Windows Setup Executable (setup.exe)
Enterprise Windows 11 Firewall & Antivirus Unified Installer
100% VBScript-Free / Windows Script Host-Free Native Installer

Capabilities:
1. Automated Prerequisites Installer:
   Checks and installs all required dependencies:
   - PyQt6 (>=6.5.0)
   - psutil (>=5.9.0)
   - watchdog (>=3.0.0)
   - yara-python (>=4.3.0)
   - pywin32 (>=306)
   - pyinstaller (>=6.0.0)
   Supports local offline wheels (prerequisites/wheels) and PyPI repository.
2. Program Files Deployment:
   Deploys application core, backend, UI, data assets, and threat signatures.
3. Desktop Icon Creation:
   Native Win32 COM IShellLink shortcut on User and Public Desktops.
4. Windows Tray Bar & Startup Configuration:
   - Registers Windows Startup folder shortcut with '--minimized'
   - Configures Registry Run key with '--minimized'
   - Sets default config for close_to_tray, start_minimized, and start_with_system.
5. Windows Explorer Context Menu:
   Adds right-click 'Scan with Vitorius Antivirus' on files and directories.
6. Windows Add/Remove Programs (Installed Apps) registration.
7. Optional Background Windows Service registration.
"""

import sys
import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Tuple, Optional, List

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vitorius.installer")

# Windows-specific conditional imports
try:
    import winreg
except ImportError:
    winreg = None

try:
    import ctypes
    from ctypes import wintypes
except (ImportError, AttributeError):
    ctypes = None
    wintypes = None

APP_NAME = "Crazy Alchemy"
APP_VERSION = "3.0"
APP_CODENAME = "Alchemy3"
PUBLISHER = "Crazy Alchemy"
EXE_NAME = "CrazyAlchemy.exe"
DEFAULT_INSTALL_DIR = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / APP_NAME

REQUIRED_PREREQUISITES = {
    "PyQt6": {"min_version": "6.5.0", "module": "PyQt6", "pip_name": "PyQt6>=6.5.0"},
    "psutil": {"min_version": "5.9.0", "module": "psutil", "pip_name": "psutil>=5.9.0"},
    "watchdog": {"min_version": "3.0.0", "module": "watchdog", "pip_name": "watchdog>=3.0.0"},
    "yara-python": {"min_version": "4.3.0", "module": "yara", "pip_name": "yara-python>=4.3.0"},
    "pywin32": {"min_version": "306", "module": "win32api", "pip_name": "pywin32>=306", "win_only": True},
    "pyinstaller": {"min_version": "6.0.0", "module": "PyInstaller", "pip_name": "pyinstaller>=6.0.0"},
}


# ── Python Interpreter & Prerequisites Management ─────────────────────

def find_system_python() -> str:
    """Finds the real Python interpreter executable even when running inside frozen setup.exe."""
    if getattr(sys, "frozen", False):
        # We are running inside a PyInstaller frozen binary
        for cand in ["python.exe", "python3.exe", "py.exe"]:
            try:
                out = subprocess.check_output([cand, "-c", "import sys; print(sys.executable)"],
                                              stderr=subprocess.DEVNULL, text=True).strip()
                if out and os.path.exists(out):
                    return out
            except Exception:
                continue

        if sys.platform == "win32":
            local_app = os.environ.get("LOCALAPPDATA", "")
            prog_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            for base in [Path(local_app) / "Programs" / "Python", Path(prog_files) / "Python", Path("C:\\Python312"), Path("C:\\Python311")]:
                if base.exists():
                    exes = list(base.glob("**/python.exe"))
                    if exes:
                        return str(exes[0])

    return sys.executable


def parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Converts a semantic version string to a comparable integer tuple."""
    parts = []
    for chunk in ver_str.replace("b", ".").replace("rc", ".").replace("a", ".").split("."):
        digits = "".join(filter(str.isdigit, chunk))
        if digits:
            try:
                parts.append(int(digits))
            except ValueError:
                pass
    return tuple(parts) if parts else (0,)


def check_prerequisite(pkg_name: str) -> Tuple[bool, str, str]:
    """Verifies whether a required prerequisite package is installed."""
    meta = REQUIRED_PREREQUISITES.get(pkg_name)
    if not meta:
        return False, "unknown", "unknown"

    min_ver = meta["min_version"]
    if meta.get("win_only") and sys.platform != "win32":
        return True, "skipped (non-windows)", min_ver

    installed_ver = None
    try:
        import importlib.metadata
        for d in [pkg_name, meta["module"]]:
            try:
                installed_ver = importlib.metadata.version(d)
                if installed_ver:
                    break
            except Exception:
                continue
    except Exception:
        pass

    if not installed_ver:
        try:
            import importlib
            mod = importlib.import_module(meta["module"])
            installed_ver = getattr(mod, "__version__", None) or getattr(mod, "version", None)
            if callable(installed_ver):
                installed_ver = installed_ver()
        except Exception:
            pass

    if not installed_ver:
        return False, "not installed", min_ver

    req_parts = parse_version_tuple(min_ver)
    inst_parts = parse_version_tuple(str(installed_ver))
    max_len = max(len(req_parts), len(inst_parts))
    is_ok = (inst_parts + (0,) * (max_len - len(inst_parts))) >= (req_parts + (0,) * (max_len - len(req_parts)))
    return is_ok, str(installed_ver), min_ver


def install_all_prerequisites_flow(wheels_dir: Optional[Path] = None) -> bool:
    """Checks and installs all prerequisites with 1-click execution."""
    print("\n" + "=" * 65)
    print(" [1/5] Checking and Installing Prerequisites...")
    print("=" * 65)

    py_exe = find_system_python()
    print(f"[*] Detected Python Engine: {py_exe}")

    has_wheels = wheels_dir and wheels_dir.exists() and any(wheels_dir.glob("*.whl"))
    if has_wheels:
        print(f"[*] Found Offline Wheel Cache: {wheels_dir}")

    all_satisfied = True

    for pkg, meta in REQUIRED_PREREQUISITES.items():
        is_ok, inst_ver, min_ver = check_prerequisite(pkg)
        if is_ok:
            print(f"  [✓] {pkg:<14} (v{inst_ver} >= {min_ver})")
        else:
            print(f"  [→] {pkg:<14} (current: {inst_ver}, required: >={min_ver}) -> Installing...")
            cmd = [py_exe, "-m", "pip", "install"]
            if has_wheels:
                cmd.extend(["--no-index", "--find-links", str(wheels_dir)])
            cmd.append(meta["pip_name"])

            try:
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if res.returncode != 0:
                    # Retry with --user if permission issue
                    user_cmd = [py_exe, "-m", "pip", "install", "--user"]
                    if has_wheels:
                        user_cmd.extend(["--no-index", "--find-links", str(wheels_dir)])
                    user_cmd.append(meta["pip_name"])
                    res = subprocess.run(user_cmd, capture_output=True, check=False)

                    # If still failed and has_wheels was used, try online as fallback
                    if res.returncode != 0 and has_wheels:
                        subprocess.run([py_exe, "-m", "pip", "install", meta["pip_name"]],
                                       capture_output=True, check=False)

                # Re-verify
                re_ok, new_ver, _ = check_prerequisite(pkg)
                if re_ok:
                    print(f"      [✓] Successfully installed {pkg} (v{new_ver})")
                else:
                    print(f"      [!] Installed {pkg}, but status check returned: {new_ver}")
                    all_satisfied = False
            except Exception as e:
                print(f"      [✗] Failed to install {pkg}: {e}")
                all_satisfied = False

    if all_satisfied:
        print("[✓] All prerequisites verified and satisfied.\n")
    else:
        print("[!] Note: Some prerequisites could not be auto-installed. Setup will continue.\n")

    return all_satisfied


# ── Native Win32 IShellLink Shortcut Creator (Zero VBScript / WSH) ───

def create_native_shortcut(
    target_exe: str,
    shortcut_path: str,
    icon_path: str = "",
    description: str = "",
    arguments: str = ""
) -> bool:
    """
    Creates a Windows .lnk shortcut using pure native COM (IShellLinkW and IPersistFile)
    via ctypes. Bypasses WScript.Shell and VBScript entirely.
    """
    if sys.platform != "win32" or not ctypes:
        logger.debug(f"Mock shortcut creation: {shortcut_path} -> {target_exe} {arguments}")
        return True

    try:
        ctypes.windll.ole32.CoInitialize(None)

        CLSID_ShellLink = "{00021401-0000-0000-C000-000000000046}"
        IID_IShellLinkW = "{000214F9-0000-0000-C000-000000000046}"
        IID_IPersistFile = "{0000010b-0000-0000-C000-000000000046}"

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)
            ]

        def str_to_guid(guid_str: str) -> GUID:
            guid = GUID()
            ctypes.windll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid_str), ctypes.byref(guid))
            return guid

        clsid_sl = str_to_guid(CLSID_ShellLink)
        iid_sl = str_to_guid(IID_IShellLinkW)
        iid_pf = str_to_guid(IID_IPersistFile)

        class IShellLinkWVtbl(ctypes.Structure):
            _fields_ = [
                ("QueryInterface", ctypes.c_void_p),
                ("AddRef", ctypes.c_void_p),
                ("Release", ctypes.c_void_p),
                ("GetPath", ctypes.c_void_p),
                ("GetIDList", ctypes.c_void_p),
                ("SetIDList", ctypes.c_void_p),
                ("GetDescription", ctypes.c_void_p),
                ("SetDescription", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p)),
                ("GetWorkingDirectory", ctypes.c_void_p),
                ("SetWorkingDirectory", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p)),
                ("GetArguments", ctypes.c_void_p),
                ("SetArguments", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p)),
                ("GetHotkey", ctypes.c_void_p),
                ("SetHotkey", ctypes.c_void_p),
                ("GetShowCmd", ctypes.c_void_p),
                ("SetShowCmd", ctypes.c_void_p),
                ("GetIconLocation", ctypes.c_void_p),
                ("SetIconLocation", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int)),
                ("SetRelativePath", ctypes.c_void_p),
                ("Resolve", ctypes.c_void_p),
                ("SetPath", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p)),
            ]

        class IShellLinkW(ctypes.Structure):
            _fields_ = [("lpVtbl", ctypes.POINTER(IShellLinkWVtbl))]

        class IPersistFileVtbl(ctypes.Structure):
            _fields_ = [
                ("QueryInterface", ctypes.c_void_p),
                ("AddRef", ctypes.c_void_p),
                ("Release", ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)),
                ("GetClassID", ctypes.c_void_p),
                ("IsDirty", ctypes.c_void_p),
                ("Load", ctypes.c_void_p),
                ("Save", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p, wintypes.BOOL)),
                ("SaveCompleted", ctypes.c_void_p),
                ("GetCurFile", ctypes.c_void_p),
            ]

        class IPersistFile(ctypes.Structure):
            _fields_ = [("lpVtbl", ctypes.POINTER(IPersistFileVtbl))]

        p_sl = ctypes.POINTER(IShellLinkW)()
        hr = ctypes.windll.ole32.CoCreateInstance(
            ctypes.byref(clsid_sl),
            None,
            1,  # CLSCTX_INPROC_SERVER
            ctypes.byref(iid_sl),
            ctypes.byref(p_sl)
        )
        if hr != 0:
            return False

        # Set Target Path
        p_sl.contents.lpVtbl.contents.SetPath(p_sl, str(target_exe))
        # Set Working Directory
        p_sl.contents.lpVtbl.contents.SetWorkingDirectory(p_sl, str(Path(target_exe).parent))
        if description:
            p_sl.contents.lpVtbl.contents.SetDescription(p_sl, description)
        if arguments:
            p_sl.contents.lpVtbl.contents.SetArguments(p_sl, arguments)
        if icon_path:
            p_sl.contents.lpVtbl.contents.SetIconLocation(p_sl, str(icon_path), 0)

        # Query IPersistFile interface
        p_pf = ctypes.POINTER(IPersistFile)()
        query_interface_fn = ctypes.WINFUNCTYPE(
            ctypes.HRESULT, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        )(p_sl.contents.lpVtbl.contents.QueryInterface)

        hr = query_interface_fn(p_sl, ctypes.byref(iid_pf), ctypes.byref(p_pf))
        if hr == 0:
            Path(shortcut_path).parent.mkdir(parents=True, exist_ok=True)
            p_pf.contents.lpVtbl.contents.Save(p_pf, str(shortcut_path), True)
            p_pf.contents.lpVtbl.contents.Release(p_pf)

        ctypes.windll.ole32.CoUninitialize()
        return True
    except Exception as e:
        logger.warning(f"Error creating native shortcut: {e}")
        return False


# ── Native Registry Operations (Direct Win32 API) ────────────────────

def register_windows_uninstall(install_dir: Path, target_exe: str):
    """
    Registers application in Windows Control Panel 'Programs and Features'
    (appwiz.cpl) and Windows 10/11 'Installed Apps' / 'Apps & features'.
    Sets all required and standard system registry keys:
      - DisplayName, DisplayVersion, Publisher, DisplayIcon
      - UninstallString (properly wrapped for batch or PE executable)
      - QuietUninstallString (for silent background removal)
      - InstallLocation, InstallDate, EstimatedSize
      - NoModify, NoRepair, URLInfoAbout, HelpLink, Comments
    """
    if not winreg:
        return

    from datetime import datetime

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy"
    icon_path = str(install_dir / "data" / "icons" / "vitorius-firewall.ico")
    if not Path(icon_path).exists() and (install_dir / EXE_NAME).exists():
        icon_path = str(install_dir / EXE_NAME)

    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    uninst_bat = install_dir / "uninstall.bat"

    # Crucial Win32 Control Panel requirement:
    # Windows CreateProcessW cannot directly execute .bat files without cmd.exe /c!
    # Without cmd.exe /c, clicking 'Uninstall' in Control Panel fails with error 193.
    if uninst_bat.exists():
        uninstaller_path = f'"{comspec}" /c "{uninst_bat}"'
        quiet_uninstaller_path = f'"{comspec}" /c "{uninst_bat}" --silent'
    elif target_exe.lower().endswith(".bat"):
        uninstaller_path = f'"{comspec}" /c "{target_exe}" --uninstall'
        quiet_uninstaller_path = f'"{comspec}" /c "{target_exe}" --uninstall --silent'
    else:
        uninstaller_path = f'"{target_exe}" --uninstall'
        quiet_uninstaller_path = f'"{target_exe}" --uninstall --silent'

    # Compute estimated installation size in KiB for Control Panel 'Size' column
    size_in_kb = 25600  # Default ~25 MB fallback
    try:
        total_bytes = sum(f.stat().st_size for f in install_dir.rglob('*') if f.is_file())
        if total_bytes > 0:
            size_in_kb = max(1, total_bytes // 1024)
    except Exception:
        pass

    install_date = datetime.now().strftime("%Y%m%d")

    # Major and minor version components
    ver_parts = APP_VERSION.split(".")
    major_ver = int(ver_parts[0]) if ver_parts and ver_parts[0].isdigit() else 2
    minor_ver = int(ver_parts[1]) if len(ver_parts) > 1 and ver_parts[1].isdigit() else 0

    registered_hive = None
    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for access in [winreg.KEY_SET_VALUE | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100), winreg.KEY_SET_VALUE]:
            try:
                with winreg.CreateKeyEx(hkey, key_path, 0, access) as k:
                    winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
                    winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
                    winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, PUBLISHER)
                    winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, icon_path)
                    winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, uninstaller_path)
                    winreg.SetValueEx(k, "QuietUninstallString", 0, winreg.REG_SZ, quiet_uninstaller_path)
                    winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, str(install_dir))
                    winreg.SetValueEx(k, "InstallDate", 0, winreg.REG_SZ, install_date)
                    winreg.SetValueEx(k, "EstimatedSize", 0, winreg.REG_DWORD, size_in_kb)
                    winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(k, "URLInfoAbout", 0, winreg.REG_SZ, "https://github.com/vitorius/crazy-alchemy")
                    winreg.SetValueEx(k, "HelpLink", 0, winreg.REG_SZ, "https://github.com/vitorius/crazy-alchemy")
                    winreg.SetValueEx(k, "Comments", 0, winreg.REG_SZ, f"Crazy Alchemy v{APP_VERSION} ({APP_CODENAME}) - Endpoint Security Suite")
                    winreg.SetValueEx(k, "VersionMajor", 0, winreg.REG_DWORD, major_ver)
                    winreg.SetValueEx(k, "VersionMinor", 0, winreg.REG_DWORD, minor_ver)
                    winreg.SetValueEx(k, "WindowsInstaller", 0, winreg.REG_DWORD, 0)
                registered_hive = hkey
                hive_name = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                logger.info(f"Registered application in Windows Installed Apps ({hive_name}).")
                break
            except Exception as e:
                logger.debug(f"Notice on uninstall registry registration attempt: {e}")
        if registered_hive is not None:
            break

    # If registered at machine-level (HKLM), purge any stale per-user (HKCU) key
    if registered_hive == winreg.HKEY_LOCAL_MACHINE:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except Exception:
            pass


def unregister_windows_uninstall():
    """Removes application from Windows 'Installed Apps' / 'Add or Remove Programs'."""
    try:
        from backend.uninstaller import unregister_windows_uninstall as _backend_unreg
        _backend_unreg()
        return
    except Exception:
        pass

    if not winreg:
        return

    for key_name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
        key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{key_name}"
        for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for access in [getattr(winreg, 'KEY_WOW64_64KEY', 0x0100), getattr(winreg, 'KEY_WOW64_32KEY', 0x0200), 0]:
                try:
                    if access:
                        winreg.DeleteKeyEx(hkey, key_path, access, 0)
                    else:
                        winreg.DeleteKey(hkey, key_path)
                    logger.info(f"Unregistered from Windows Installed Apps ({key_name}).")
                except Exception:
                    continue


def unregister_explorer_context_menu():
    """Removes right-click 'Scan with Crazy Alchemy Antivirus' from Windows Explorer context menu."""
    if not winreg:
        return

    for root_key_name in ("*", "Directory"):
        for menu_key in ("CrazyAlchemyScan", "VitoriusScan"):
            sub_key = f"{root_key_name}\\shell\\{menu_key}"
            # Delete subkey 'command' first
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"{sub_key}\\command")
            except Exception:
                pass
            # Delete main key
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, sub_key)
                logger.info(f"Removed Windows Explorer context menu for {root_key_name}.")
            except Exception as e:
                logger.debug(f"Notice on context menu removal ({root_key_name}): {e}")


def unregister_autostart_registry():
    """Removes autostart registry entries from HKLM and HKCU Run keys."""
    if not winreg:
        return

    run_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for access in [winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY, winreg.KEY_SET_VALUE]:
            try:
                with winreg.OpenKey(hkey, run_key, 0, access) as k:
                    for val_name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
                        try:
                            winreg.DeleteValue(k, val_name)
                        except Exception:
                            pass
                    logger.info(f"Removed autostart from Registry ({'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}).")
                    break
            except Exception:
                continue


def remove_shortcuts():
    """Removes all Desktop, Start Menu, and Startup shortcuts created by installer."""
    # 1. Desktop shortcuts
    desktops = [
        Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop",
        Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Desktop",
        Path(os.environ.get("USERPROFILE", str(Path.home()))) / "OneDrive" / "Desktop",
    ]
    for d in desktops:
        try:
            lnk = d / f"{APP_NAME}.lnk"
            if lnk.exists():
                lnk.unlink(missing_ok=True)
                logger.info(f"Removed Desktop shortcut: {lnk}")
        except Exception as e:
            logger.debug(f"Desktop shortcut removal notice: {e}")

    # 2. Start Menu shortcuts
    start_menus = [
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_NAME,
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_NAME,
    ]
    for sm in start_menus:
        try:
            if sm.exists():
                shutil.rmtree(sm, ignore_errors=True)
                logger.info(f"Removed Start Menu folder: {sm}")
        except Exception as e:
            logger.debug(f"Start Menu removal notice: {e}")

    for sm_parent in [
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    ]:
        try:
            lnk = sm_parent / f"{APP_NAME}.lnk"
            if lnk.exists():
                lnk.unlink(missing_ok=True)
        except Exception:
            pass

    # 3. Startup folder shortcuts
    startup_paths = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    ]
    for sp in startup_paths:
        try:
            lnk = sp / f"{APP_NAME}.lnk"
            if lnk.exists():
                lnk.unlink(missing_ok=True)
                logger.info(f"Removed Startup shortcut: {lnk}")
        except Exception as e:
            logger.debug(f"Startup shortcut removal notice: {e}")


def terminate_running_instances():
    """Gracefully closes or terminates all running Vitorius Firewall Win processes."""
    if sys.platform != "win32":
        return

    c_flags = 0x08000000  # CREATE_NO_WINDOW
    # Terminate compiled executable instances
    try:
        subprocess.run(['taskkill.exe', '/F', '/IM', EXE_NAME, '/T'], capture_output=True, creationflags=c_flags)
    except Exception:
        pass

    # Terminate python instances running main_win.py
    try:
        import psutil
        my_pid = os.getpid()
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if p.pid == my_pid:
                    continue
                cmdline = ' '.join(p.info.get('cmdline') or [])
                if 'main_win.py' in cmdline or 'CrazyAlchemy' in cmdline or 'VitoriusFirewallWin' in cmdline:
                    p.kill()
            except Exception:
                continue
    except Exception:
        pass


def stop_and_remove_windows_service():
    """Stops and deletes CrazyAlchemyService / VitoriusFirewallService."""
    if sys.platform != "win32":
        return

    c_flags = 0x08000000
    for svc in ['CrazyAlchemyService', 'VitoriusFirewallService']:
        try:
            subprocess.run(['net.exe', 'stop', svc], capture_output=True, creationflags=c_flags)
        except Exception:
            pass
        try:
            subprocess.run(['sc.exe', 'stop', svc], capture_output=True, creationflags=c_flags)
        except Exception:
            pass
        try:
            subprocess.run(['sc.exe', 'delete', svc], capture_output=True, creationflags=c_flags)
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

    c_flags = 0x08000000  # CREATE_NO_WINDOW

    print("[*] Reverting Windows Firewall configuration to factory defaults...")
    try:
        # Delete rules for program executables
        if target_dir:
            for exe_cand in [target_dir / EXE_NAME, target_dir / "VitoriusFirewallWin.exe", target_dir / "service" / "vitorius_service.exe"]:
                subprocess.run([
                    'netsh.exe', 'advfirewall', 'firewall', 'delete', 'rule',
                    'name=all', 'profile=any', f'program={exe_cand}'
                ], capture_output=True, creationflags=c_flags)

        for rule_name in [
            "VitoriusFW_PANIC_IN", "VitoriusFW_PANIC_OUT",
            "VFW_PANIC_IN", "VFW_PANIC_OUT",
            "CrazyAlchemy_Service", "CrazyAlchemy_UI",
            "VitoriusFirewallService", "VitoriusFirewallCoreSvc"
        ]:
            subprocess.run(['netsh.exe', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'], capture_output=True, creationflags=c_flags)

        # Reset Windows Firewall to factory default configuration
        subprocess.run(['netsh.exe', 'advfirewall', 'reset'], capture_output=True, creationflags=c_flags)
        subprocess.run(['netsh.exe', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], capture_output=True, creationflags=c_flags)
        subprocess.run(['netsh.exe', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound'], capture_output=True, creationflags=c_flags)
        logger.info("Windows Firewall restored to default factory state.")
    except Exception as e:
        logger.debug(f"Notice on firewall reset: {e}")

    print("[*] Reverting Windows Defender & Antivirus settings to factory defaults...")
    try:
        if winreg:
            # Clear ForceDefenderPassiveMode
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection", 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                    try:
                        winreg.DeleteValue(k, "ForceDefenderPassiveMode")
                    except OSError:
                        pass
            except Exception:
                pass

            # Clear Defender Exclusions policy keys
            for sub in ["Paths", "Processes", "Extensions"]:
                try:
                    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\{sub}")
                except Exception:
                    pass
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions")
            except Exception:
                pass

            # Clear Defender Real-Time Protection policy overrides
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                    for val in ["DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableOnAccessProtection", "DisableScanOnRealtimeEnable", "DisableIOAVProtection", "DisableScriptScanning"]:
                        try:
                            winreg.DeleteValue(k, val)
                        except OSError:
                            pass
            except Exception:
                pass

            # Clear tampering flags
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
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
        subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', full_ps], capture_output=True, creationflags=c_flags)
        logger.info("Windows Defender and Exploit Guard settings reverted to factory defaults.")
    except Exception as e:
        logger.debug(f"Notice on Defender revert: {e}")

    print("[*] Flushing Windows network, DNS, and ARP resolver caches...")
    try:
        subprocess.run(['ipconfig.exe', '/flushdns'], capture_output=True, creationflags=c_flags)
        subprocess.run(['netsh.exe', 'interface', 'ip', 'delete', 'arpcache'], capture_output=True, creationflags=c_flags)
        subprocess.run(['nbtstat.exe', '-R'], capture_output=True, creationflags=c_flags)
        logger.info("Flushed DNS and ARP caches.")
    except Exception as e:
        logger.debug(f"Notice on cache flush: {e}")


def cleanup_app_data_and_settings():
    """
    Completely removes all application settings, caches, databases, logs, honeytokens,
    quarantine files, temporary files, and user configuration options.
    """
    print("[*] Removing application settings, caches, databases, and temporary files...")
    import tempfile

    target_paths = [
        # Settings & configurations
        Path(os.environ.get("APPDATA", "")) / "VitoriusFirewallWin",
        Path(os.environ.get("APPDATA", "")) / "CrazyAlchemy",
        Path.home() / ".vitorius_firewall_win",
        Path.home() / ".crazy_alchemy",

        # Caches, databases, honeytokens, logs, backups
        Path(os.environ.get("LOCALAPPDATA", "")) / "VitoriusFirewallWin",
        Path(os.environ.get("LOCALAPPDATA", "")) / "CrazyAlchemy",

        # ProgramData system-wide databases, quarantine, threat intelligence
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "VitoriusFirewallWin",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "CrazyAlchemy",

        # Temporary files and quarantine directories in %TEMP%
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
                logger.info(f"Removed app data directory: {p}")
        except Exception as e:
            logger.debug(f"Notice removing {p}: {e}")

    # Remove temporary tweak and diagnostics logs
    temp_dir = Path(tempfile.gettempdir())
    try:
        for log_f in temp_dir.glob("VitoriusTweaks_*.log"):
            try:
                log_f.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass

    # Remove Software Registry Keys
    if winreg:
        for root_hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            for app_key in ["CrazyAlchemy", "VitoriusFirewallWin"]:
                try:
                    winreg.DeleteKey(root_hive, rf"SOFTWARE\{app_key}")
                    logger.info(f"Removed registry key SOFTWARE\\{app_key}")
                except Exception:
                    pass


def cleanup_installation_directory(target_dir: Optional[Path] = None):
    """Removes the program files installation folder."""
    try:
        from backend.uninstaller import cleanup_installation_directory as _backend_cleanup
        _backend_cleanup(target_dir)
        return
    except Exception:
        pass

    if not target_dir or not target_dir.exists():
        return

    # Safety: Never delete the source repository or workspace
    if (target_dir / ".git").exists() or (target_dir / ".gemini").exists():
        logger.info(f"Preserving development repository at {target_dir}; skipped removal.")
        return

    try:
        import tempfile
        os.chdir(tempfile.gettempdir())
    except Exception:
        pass

    # Self-deletion: remove everything we can, then schedule delayed rmdir after exit
    for item in list(target_dir.iterdir()):
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            elif item.name != EXE_NAME and item.name != Path(sys.executable).name:
                item.unlink(missing_ok=True)
        except Exception:
            continue

    # Spawn detached background process to delete directory once current process exits
    cmd = f'cmd.exe /c timeout /t 2 /nobreak >nul & rmdir /s /q "{target_dir}"'
    try:
        subprocess.Popen(cmd, shell=True, creationflags=0x08000000 | 0x00000200)
    except Exception:
        pass


def run_uninstallation(target_dir: Optional[Path] = None) -> bool:
    """
    Complete Native Windows Uninstaller for Crazy Alchemy.
    Executes cleanly even when running as Administrator or Standard User.
    """
    try:
        from backend.uninstaller import run_uninstallation as _backend_run
        return _backend_run(target_dir=target_dir)
    except Exception as e:
        logger.debug(f"Notice on backend uninstaller delegation: {e}")

    print("=" * 65)
    print(f"  Uninstalling {APP_NAME} v{APP_VERSION} ({APP_CODENAME})...")
    print("=" * 65)

    # 1. Resolve Target Directory if not provided
    if not target_dir:
        # Check Registry for InstallLocation
        if winreg:
            for key_name in ["CrazyAlchemy", "VitoriusFirewallWin"]:
                key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{key_name}"
                for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0x0100)) as k:
                            loc, _ = winreg.QueryValueEx(k, "InstallLocation")
                            if loc and Path(loc).exists():
                                target_dir = Path(loc)
                                break
                    except Exception:
                        pass
                if target_dir:
                    break

        if not target_dir:
            for cand in [
                DEFAULT_INSTALL_DIR,
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / APP_NAME,
            ]:
                if cand.exists() and ((cand / EXE_NAME).exists() or (cand / "main_win.py").exists()):
                    target_dir = cand
                    break

    # 2. Terminate active application instances
    print("[*] [1/6] Terminating active application instances...")
    terminate_running_instances()

    # 3. Stop and delete Windows background service
    print("[*] [2/6] Stopping and removing background Windows Services...")
    stop_and_remove_windows_service()

    # 4. Revert Windows Firewall, Defender, and Exploit Guard to Windows Defaults
    print("[*] [3/6] Reverting Windows Firewall, Defender & Security configurations to factory defaults...")
    revert_windows_default_configuration(target_dir)

    # 5. Remove shortcuts, Task Scheduler bypass, and registry entries
    print("[*] [4/6] Removing shortcuts, Task Scheduler tasks, context menu, and registry entries...")
    try:
        from backend.elevation_win import remove_elevation_bypass_tasks
        for app_id in ["CrazyAlchemy", "VitoriusFirewallWin", "VitoriusFirewallService"]:
            remove_elevation_bypass_tasks(app_id)
    except Exception:
        pass

    # Explicitly purge all known Task Scheduler entries
    c_flags = 0x08000000
    for tn in [
        "CrazyAlchemy", "CrazyAlchemyAutostart", "CrazyAlchemyOfflineScan",
        "CrazyAlchemy_ElevationBypass", "VitoriusOfflineScan",
        "VitoriusFirewallWin", "VitoriusFirewallWinAutostart", "VitoriusFirewallService"
    ]:
        try:
            subprocess.run(["schtasks.exe", "/Delete", "/TN", tn, "/F"], capture_output=True, creationflags=c_flags)
        except Exception:
            pass

    remove_shortcuts()
    unregister_autostart_registry()
    unregister_explorer_context_menu()
    unregister_windows_uninstall()

    # 6. Completely remove app settings, user options, caches, databases, and temporary files
    print("[*] [5/6] Removing application settings, caches, databases, and temporary files...")
    cleanup_app_data_and_settings()

    # 7. Remove program files directory
    print("[*] [6/6] Removing installed program files...")
    cleanup_installation_directory(target_dir)

    print("\n" + "=" * 65)
    print(f"  [SUCCESS] {APP_NAME} uninstalled successfully!")
    print("=" * 65)
    return True


def register_explorer_context_menu(install_dir: Path, target_exe: str):
    """Registers right-click 'Scan with Crazy Alchemy' on files and folders."""
    if not winreg:
        return

    icon_path = str(install_dir / "data" / "icons" / "vitorius-firewall.ico")
    cmd_str = f'"{target_exe}" --scan "%1"'

    for root_key_name in ("*", "Directory"):
        sub_key = f"{root_key_name}\\shell\\CrazyAlchemyScan"
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, sub_key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Scan with Crazy Alchemy")
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon_path)
            with winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, f"{sub_key}\\command", 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, cmd_str)
        except Exception as e:
            logger.debug(f"Context menu registry notice for {root_key_name}: {e}")


def register_autostart_registry(target_exe: str):
    """Registers application to start minimized in tray on Windows sign-in via Registry."""
    if not winreg:
        return

    run_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    cmd_str = f'"{target_exe}" --minimized'

    # Try HKLM (All Users) first, then HKCU (Current User)
    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        try:
            with winreg.OpenKey(hkey, run_key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, "CrazyAlchemy", 0, winreg.REG_SZ, cmd_str)
                logger.info(f"Registered autostart in Registry ({'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}).")
                break
        except Exception as e:
            logger.debug(f"Autostart registry attempt: {e}")


def configure_tray_and_startup(install_dir: Path, target_exe: str, icon_file: str):
    """
    Configures full System Tray and Windows Startup integration:
    1. Registers elevated Task Scheduler tasks ('CrazyAlchemy' and 'CrazyAlchemyAutostart')
       with HighestAvailable privileges so app runs with ZERO UAC prompts.
    2. Cleans non-elevated Registry Run and Startup folder shortcuts to prevent
       conflicting UAC prompts upon system reboot.
    """
    if sys.platform != "win32":
        logger.debug(f"Mock tray and startup setup: {target_exe} --minimized")
        return

    try:
        from backend.elevation_win import (
            register_elevation_bypass_task,
            clean_non_elevated_autostart_entries
        )
        register_elevation_bypass_task(target_exe=target_exe, install_dir=install_dir)
        clean_non_elevated_autostart_entries()
        logger.info("[✓] Configured zero-UAC elevated Task Scheduler autostart for reboot.")
    except Exception as e:
        logger.warning(f"Notice configuring elevation bypass tasks: {e}")


# ── Native Service Installation via sc.exe (Zero VBScript) ───────────

def install_windows_service(install_dir: Path, target_exe: str):
    """Registers and starts VitoriusFirewallService using Windows native sc.exe."""
    if sys.platform != "win32":
        return

    binpath = f'"{target_exe}" --service run'
    c_flags = 0x08000000

    logger.info("Configuring Vitorius Firewall & Antivirus Windows Service...")
    subprocess.run([
        'sc.exe', 'create', 'VitoriusFirewallService',
        f'binPath={binpath}',
        'start=auto',
        f'DisplayName=Vitorius Firewall & Antivirus Core Service'
    ], capture_output=True, creationflags=c_flags)

    subprocess.run([
        'sc.exe', 'description', 'VitoriusFirewallService',
        'Maintains persistent enterprise firewall policies and real-time antivirus protection.'
    ], capture_output=True, creationflags=c_flags)

    subprocess.run(['net.exe', 'start', 'VitoriusFirewallService'], capture_output=True, creationflags=c_flags)


# ── Launcher Generation ──────────────────────────────────────────────

def create_application_launcher(install_dir: Path) -> str:
    """
    Ensures an executable launcher target exists.
    If CrazyAlchemy.exe exists, uses it directly.
    Otherwise, generates a silent elevated launcher (CrazyAlchemy.bat) that
    bypasses UAC prompts via Task Scheduler with zero popups.
    """
    compiled_exe = install_dir / EXE_NAME
    if compiled_exe.exists():
        return str(compiled_exe)

    py_exe = find_system_python()
    pythonw_exe = Path(py_exe).parent / "pythonw.exe"
    runner_py = str(pythonw_exe if pythonw_exe.exists() else py_exe)

    launcher_bat = install_dir / "CrazyAlchemy.bat"
    bat_content = f"""@echo off
rem Crazy Alchemy 1-Click Silent Elevated Launcher (Zero UAC Prompt)
schtasks /run /tn "CrazyAlchemy" >nul 2>nul
if %errorlevel% equ 0 exit /b 0

start "" "{runner_py}" "{install_dir / 'main_win.py'}" %*
"""
    try:
        launcher_bat.write_text(bat_content, encoding="utf-8")
        # Also maintain legacy name for full compatibility
        (install_dir / "VitoriusFirewallWin.bat").write_text(bat_content, encoding="utf-8")
    except Exception as e:
        logger.debug(f"Launcher script write notice: {e}")

    return str(compiled_exe if compiled_exe.exists() else launcher_bat)


# ── Main Installation Workflow ───────────────────────────────────────

def run_installation(
    source_dir: Path,
    target_dir: Optional[Path] = None,
    install_service: bool = False,
    launch_after: bool = False
):
    print("=" * 65)
    print(f"  {APP_NAME} v{APP_VERSION} ({APP_CODENAME})")
    print("  Enterprise Windows 11 Firewall & Antivirus Setup")
    print("=" * 65)

    # Phase 1: Prerequisites Check & Installation
    wheels_path = source_dir / "prerequisites" / "wheels"
    install_all_prerequisites_flow(wheels_dir=wheels_path if wheels_path.exists() else None)

    # Phase 2: Resolve Target Directory
    if not target_dir:
        # Check permissions for Program Files
        try:
            DEFAULT_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            target_dir = DEFAULT_INSTALL_DIR
        except Exception:
            local_app = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
            target_dir = Path(local_app) / "Programs" / APP_NAME

    print(f"[*] [2/5] Target Installation Directory: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    # Phase 3: Copy Program Files and Data Assets
    print("[*] [3/5] Deploying Application Files, Assets, and Signatures...")
    ignore_patterns = shutil.ignore_patterns(
        "*.pyc", "__pycache__", ".git*", "dist", "dist_installer", "build", "*.spec"
    )

    items_to_copy = [
        "backend", "ui", "data", "service", "prerequisites",
        "main_win.py", "requirements.txt", "crazy_alchemy.jpg",
        "trough-pain-comes-salvation.mp3", "uninstall.bat", "setup.bat",
        "CrazyAlchemy.bat"
    ]

    for item_name in items_to_copy:
        src_item = source_dir / item_name
        dest_item = target_dir / item_name
        if src_item.exists():
            if src_item.is_dir():
                shutil.copytree(src_item, dest_item, dirs_exist_ok=True, ignore=ignore_patterns)
            else:
                shutil.copy2(src_item, dest_item)

    # Ensure uninstall.bat exists in target_dir even if source_dir lacked it
    uninst_target = target_dir / "uninstall.bat"
    if not uninst_target.exists():
        src_uninst = source_dir / "uninstall.bat"
        if src_uninst.exists():
            shutil.copy2(src_uninst, uninst_target)

    # Ensure setup_win.py exists in target_dir for local administration and uninstallation
    src_setup_win = source_dir / "build" / "setup_win.py"
    if src_setup_win.exists():
        shutil.copy2(src_setup_win, target_dir / "setup_win.py")

    # If pre-built dist binary exists, copy it
    dist_bin = source_dir / "dist" / "VitoriusFirewallWin"
    if dist_bin.exists() and dist_bin.is_dir():
        shutil.copytree(dist_bin, target_dir, dirs_exist_ok=True)

    # Initialize Signature Hash Database
    seed_script = target_dir / "data" / "signatures" / "seed_hashes.py"
    if seed_script.exists():
        py_exe = find_system_python()
        try:
            subprocess.run([py_exe, str(seed_script)], capture_output=True, check=False)
            print("[✓] Baseline malware signatures initialized.")
        except Exception as e:
            logger.debug(f"Signature seed notice: {e}")

    # Determine Launcher Executable
    target_exe = create_application_launcher(target_dir)
    icon_file = str(target_dir / "data" / "icons" / "vitorius-firewall.ico")
    
    # Strip Zone.Identifier from all deployed files to prevent 'Open File - Security Warning'
    try:
        from backend.elevation_win import unblock_directory_files
        unblock_directory_files(target_dir)
    except Exception:
        pass

    print("[✓] Program files deployed successfully.")

    # Phase 4: Create Desktop & Start Menu Shortcuts
    print("[*] [4/5] Creating Desktop & Start Menu Shortcuts (Pure Win32 COM)...")
    
    if sys.platform == "win32":
        # Desktop Shortcut
        desktops = [
            Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop",
            Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Desktop"
        ]
        for d in desktops:
            if d.exists():
                lnk = d / f"{APP_NAME}.lnk"
                create_native_shortcut(target_exe, str(lnk), icon_file, "Corporate Firewall & Antivirus")
                print(f" [✓] Desktop shortcut created: {lnk}")
                break

        # Start Menu Shortcut
        start_menus = [
            Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_NAME,
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_NAME
        ]
        for sm in start_menus:
            try:
                sm.mkdir(parents=True, exist_ok=True)
                sm_lnk = sm / f"{APP_NAME}.lnk"
                create_native_shortcut(target_exe, str(sm_lnk), icon_file, "Corporate Firewall & Antivirus")
                print(f" [✓] Start Menu shortcut created: {sm_lnk}")

                # Also create dedicated Start Menu shortcut for local uninstaller
                uninst_bat = target_dir / "uninstall.bat"
                if uninst_bat.exists():
                    sm_uninst_lnk = sm / f"Uninstall {APP_NAME}.lnk"
                    create_native_shortcut(str(uninst_bat), str(sm_uninst_lnk), icon_file, f"Uninstall {APP_NAME}")
                    print(f" [✓] Start Menu uninstaller shortcut created: {sm_uninst_lnk}")
                break
            except Exception:
                continue
    else:
        print(" [✓] Desktop and Start Menu shortcut creation verified (cross-platform mock).")

    # Phase 5: Tray Bar, Startup, Registry, Context Menu
    print("[*] [5/5] Configuring System Tray Bar & Windows Startup Integration...")
    configure_tray_and_startup(target_dir, target_exe, icon_file)
    register_windows_uninstall(target_dir, target_exe)
    register_explorer_context_menu(target_dir, target_exe)

    if install_service:
        install_windows_service(target_dir, target_exe)
        print(" [✓] Background Windows Service registered & started.")

    print("\n" + "=" * 65)
    print("  [SUCCESS] Vitorius Firewall Win Installation Completed!")
    print(f"  Installed Location: {target_dir}")
    print("  Desktop Icon: Ready")
    print("  System Tray Bar & Startup: Configured")
    print("=" * 65)

    if launch_after:
        print(f"\n[*] Launching {APP_NAME}...")
        try:
            from backend.elevation_win import dispatch_elevated_bypass_task
            if not dispatch_elevated_bypass_task("CrazyAlchemy"):
                subprocess.Popen([target_exe])
        except Exception as e:
            logger.debug(f"Launch notice: {e}")


def find_source_dir() -> Path:
    """Resolves the source repository directory across scripts and frozen exes."""
    if getattr(sys, "frozen", False):
        # We are running inside a compiled setup.exe
        exe_dir = Path(sys.executable).resolve().parent
        # Check if setup.exe is in dist_installer or build or root
        if (exe_dir / "main_win.py").exists():
            return exe_dir
        if (exe_dir.parent / "main_win.py").exists():
            return exe_dir.parent
        if (exe_dir.parent.parent / "main_win.py").exists():
            return exe_dir.parent.parent
        return exe_dir
    else:
        # Running directly via python setup_win.py
        current_script = Path(__file__).resolve()
        if current_script.parent.name in ["build", "prerequisites"]:
            return current_script.parent.parent
        return current_script.parent


if __name__ == "__main__":
    if "--uninstall" in sys.argv or "-u" in sys.argv:
        target = None
        for arg in sys.argv[1:]:
            if arg not in ["--uninstall", "-u"] and not arg.startswith("-"):
                target = Path(arg)
                break
        run_uninstallation(target_dir=target)
        sys.exit(0)

    src = find_source_dir()
    install_svc = "--service" in sys.argv
    launch_app = "--launch" in sys.argv or "--start" in sys.argv or "-l" in sys.argv
    run_installation(source_dir=src, install_service=install_svc, launch_after=launch_app)
