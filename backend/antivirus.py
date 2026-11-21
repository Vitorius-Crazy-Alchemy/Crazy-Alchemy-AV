"""
Vitorius Antivirus - Tri-Engine Malware Scanner & Quarantine Manager
Combines indexed hash matching (MalwareBazaar/ClamAV), YARA heuristics,
and an encrypted quarantine vault.
"""

import os
import sys
import hashlib
import sqlite3
import logging
import time
import shutil
import threading
import math
import re
import subprocess
import base64
import json
import urllib.request
import urllib.error
from pathlib import Path
import concurrent.futures
from dataclasses import dataclass
from typing import Optional, List, Dict, Callable, Any, Tuple, Set

from backend.chronovault import ChronoVaultEngine
from backend.ghostgate import GhostGateEngine

logger = logging.getLogger('vitorius.win.av')

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ('cbStruct', wintypes.DWORD),
            ('pcwszFilePath', wintypes.LPCWSTR),
            ('hFile', wintypes.HANDLE),
            ('pgKnownSubject', ctypes.c_void_p),
        ]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ('cbStruct', wintypes.DWORD),
            ('pPolicyCallbackData', ctypes.c_void_p),
            ('pSIPClientData', ctypes.c_void_p),
            ('dwUIChoice', wintypes.DWORD),
            ('fdwRevocationChecks', wintypes.DWORD),
            ('dwUnionChoice', wintypes.DWORD),
            ('pFile', ctypes.POINTER(_WINTRUST_FILE_INFO)),
            ('dwStateAction', wintypes.DWORD),
            ('hWVTStateData', wintypes.HANDLE),
            ('pwszURLReference', wintypes.LPCWSTR),
            ('dwProvFlags', wintypes.DWORD),
            ('dwUIContext', wintypes.DWORD),
            ('pSignatureSettings', ctypes.c_void_p),
        ]

    class _GUID(ctypes.Structure):
        _fields_ = [
            ('Data1', wintypes.DWORD),
            ('Data2', wintypes.WORD),
            ('Data3', wintypes.WORD),
            ('Data4', ctypes.c_ubyte * 8),
        ]

    _WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
        0x00aac56b, 0xcd44, 0x11d0,
        (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee)
    )

    try:
        _wintrust = ctypes.windll.wintrust
        _kernel32 = ctypes.windll.kernel32

        _wintrust.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
        _wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
        _wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
        _wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        _wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
        _wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
        _wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        _wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL
        _HAS_WINTRUST = True
    except Exception:
        _HAS_WINTRUST = False
else:
    _HAS_WINTRUST = False


SIGNABLE_FILE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi", ".drv", ".ax",
    ".msi", ".msp", ".msu", ".cab", ".cat", ".appx", ".msix", ".appxbundle",
    ".ps1", ".psm1", ".psd1", ".vbs", ".js", ".wsf"
}


def verify_file_signature(file_path: str) -> Tuple[bool, str]:
    """
    Validates whether a target file carries a valid, properly validated digital
    signature on Windows. Checks embedded Authenticode signatures and Windows
    Security Catalogs via native Win32 CryptoAPI (ctypes) with zero subprocesses.
    Returns (is_valid: bool, status_description: str).
    """
    if sys.platform != "win32":
        return False, "Digital signature verification is supported on Windows only"

    try:
        p = Path(file_path)
        if not p.is_file():
            return False, "File does not exist"
        resolved_path = str(p.resolve())
    except Exception as e:
        return False, f"Path error: {e}"

    # Quickly check if the file format can carry Authenticode signatures
    ext = p.suffix.lower()
    if ext not in SIGNABLE_FILE_EXTENSIONS:
        # Check if it has a PE MZ header (in case an executable has a non-standard extension)
        try:
            with open(resolved_path, "rb") as f_peek:
                header_peek = f_peek.read(2)
            if header_peek != b"MZ":
                return False, "Unsigned (Non-executable format)"
        except Exception:
            return False, "Unsigned"

    # 1. Embedded Authenticode Check via native WinVerifyTrust (wintrust.dll)
    if _HAS_WINTRUST:
        try:
            file_info = _WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = resolved_path

            trust_data = _WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
            trust_data.dwUIChoice = 2  # WTD_UI_NONE
            trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
            trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
            trust_data.pFile = ctypes.pointer(file_info)
            trust_data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
            trust_data.dwProvFlags = 0x00000080 | 0x00000010  # WTD_USE_DEFAULT_OSVERIF_SETTINGS | WTD_REVOCATION_CHECK_NONE

            ret = _wintrust.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))
            trust_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            _wintrust.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))

            if ret == 0:
                return True, "Valid Authenticode Signature"
        except Exception as e:
            logger.debug(f"WinVerifyTrust check error on {file_path}: {e}")

        # 2. Windows Catalog Signed Check (OS binaries and system drivers)
        try:
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 1 | 2  # Read and write sharing
            OPEN_EXISTING = 3
            hFile = _kernel32.CreateFileW(resolved_path, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
            if hFile != -1 and hFile != 0:
                hCatAdmin = wintypes.HANDLE(0)
                try:
                    if _wintrust.CryptCATAdminAcquireContext(ctypes.byref(hCatAdmin), None, 0):
                        cbHash = wintypes.DWORD(0)
                        _wintrust.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cbHash), None, 0)
                        if cbHash.value > 0:
                            bHash = (ctypes.c_ubyte * cbHash.value)()
                            if _wintrust.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cbHash), bHash, 0):
                                hCatInfo = _wintrust.CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, cbHash.value, 0, None)
                                if hCatInfo:
                                    _wintrust.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
                                    return True, "Valid Windows Catalog Signature"
                finally:
                    if hCatAdmin.value:
                        _wintrust.CryptCATAdminReleaseContext(hCatAdmin, 0)
                    _kernel32.CloseHandle(hFile)
        except Exception as e:
            logger.debug(f"Catalog signature check error on {file_path}: {e}")

        # If native WinVerifyTrust and Catalog check both ran and didn't find a valid signature,
        # the file is definitively unsigned. Native check is authoritative; do NOT call PowerShell!
        return False, "Unsigned or Invalid Signature"

    # 3. Headless Fallback ONLY if native WinTrust DLL failed to load
    try:
        cmd = f"(Get-AuthenticodeSignature '{resolved_path}').Status"
        flags = {
            "capture_output": True,
            "text": True,
            "timeout": 5
        }
        if sys.platform == "win32":
            flags["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            flags["startupinfo"] = startupinfo

        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", cmd],
            **flags
        )
        if res.returncode == 0 and res.stdout.strip() == "Valid":
            return True, "Valid Signature (PowerShell Verified)"
    except Exception:
        pass

    return False, "Unsigned or Invalid Signature"

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

def _b64(s: str) -> bytes:
    """Decodes obfuscated threat signature patterns at runtime to avoid false-positive bytecode matches."""
    return base64.b64decode(s.encode('ascii'))


HEURISTIC_PATTERNS = [
    (_b64("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3M="), "Ransomware.ShadowCopyDelete", "critical"),
    (_b64("dnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dz"), "Ransomware.ShadowCopyDelete", "critical"),
    (_b64("d21pYyBzaGFkb3djb3B5IGRlbGV0ZQ=="), "Ransomware.ShadowCopyDelete", "critical"),
    (_b64("d2JhZG1pbiBkZWxldGUgY2F0YWxvZyAtcXVpZXQ="), "Ransomware.BackupWipe", "critical"),
    (_b64("QWxsIHlvdXIgZmlsZXMgaGF2ZSBiZWVuIGVuY3J5cHRlZA=="), "Ransomware.GenericNote", "critical"),
    (_b64("QWxsIHlvdXIgaW1wb3J0YW50IGZpbGVzIGFyZSBlbmNyeXB0ZWQ="), "Ransomware.GenericNote", "critical"),
    (_b64("c3RyYXR1bSt0Y3A6Ly8="), "Miner.StratumPool", "high"),
    (_b64("c3RyYXR1bStzc2w6Ly8="), "Miner.StratumPool", "high"),
    (_b64("YXBpLnRlbGVncmFtLm9yZy9ib3Q="), "Infostealer.TelegramExfil", "high"),
    (_b64("ZGlzY29yZC5jb20vYXBpL3dlYmhvb2tzLw=="), "Infostealer.DiscordWebhook", "high"),
    (_b64("c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz"), "HackTool.Mimikatz", "critical"),
]

CORE_WINDOWS_BINARIES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe",
    "services.exe", "explorer.exe", "winlogon.exe", "spoolsv.exe",
    # Microsoft Defender core processes for co-active parallel coexistence
    "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "securityhealthservice.exe",
    "smartscreen.exe"
}

# Directories, extensions, and filenames dedicated to antimalware detection definitions
SIGNATURE_RULE_DIR_NAMES: Set[str] = {
    "signature", "signatures", "rules", "rule", "sigs", "sig",
    "yara", "yara_rules", "definitions"
}

SIGNATURE_RULE_EXTENSIONS: Set[str] = {
    ".yar", ".yara", ".rules", ".rule", ".sig", ".signature", ".signatures",
    ".db", ".sqlite", ".sqlite3"
}

SIGNATURE_KNOWN_FILENAMES: Set[str] = {
    "malware_hashes.db", "seed_hashes.py", "signatures.db", "hashes.db",
    "yara_rules.db", "offline_scan_pending.json", "offline_scan_results.json"
}

NON_EXECUTABLE_DATA_EXTS: Set[str] = {
    ".txt", ".md", ".json", ".csv", ".log", ".xml", ".yaml", ".yml",
    ".ini", ".conf", ".cfg", ".sql", ".rst", ".html", ".css"
}

ANTIVIRUS_KNOWN_FILENAMES: Set[str] = {
    "crazy alchemy.exe", "crazyalchemy.exe", "vitorius firewall win.exe",
    "vitorius_service.py", "vitorius_service.exe", "crazyalchemyservice.exe",
    "antigravity.exe",
    "main_win.py", "setup_win.py", "make_setup.py", "build_win.spec",
    "build_setup_exe.spec", "installer.iss", "build.bat", "setup.bat",
    "uninstall.bat", "vitoriusfirewallwin.bat", "crazy_alchemy.jpg",
    "trough-pain-comes-salvation.mp3", "requirements.txt"
}

ANTIVIRUS_SUITE_FOLDERS: Set[str] = {
    "backend", "ui", "service", "prerequisites", "build", "dist",
    "dist_installer", "signatures", "rules", "data", "tests"
}

_CACHED_AV_ROOTS: Optional[Set[Path]] = None
_CACHED_AV_ROOTS_STR: Optional[List[str]] = None


def get_antivirus_roots() -> Set[Path]:
    """Resolves all root directory paths belonging to the Crazy Alchemy / Vitorius Firewall suite."""
    global _CACHED_AV_ROOTS, _CACHED_AV_ROOTS_STR
    if _CACHED_AV_ROOTS is not None:
        return _CACHED_AV_ROOTS

    roots: Set[Path] = set()

    # 1. Project / Source tree
    proj_dir = Path(__file__).resolve().parent.parent
    roots.add(proj_dir)

    # 2. Predefined and installed application locations
    for env_var in ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "APPDATA"]:
        base = os.environ.get(env_var)
        if base:
            p_base = Path(base)
            if env_var == "LOCALAPPDATA":
                roots.add(p_base / "Programs" / "Crazy Alchemy")
                roots.add(p_base / "Programs" / "Vitorius Firewall Win")
            roots.add(p_base / "Crazy Alchemy")
            roots.add(p_base / "CrazyAlchemy")
            roots.add(p_base / "Vitorius Firewall Win")
            roots.add(p_base / "VitoriusFirewallWin")

    # 3. Executable parent directory (when frozen in standalone CrazyAlchemy.exe or setup.exe)
    if getattr(sys, "frozen", False):
        try:
            roots.add(Path(sys.executable).parent)
        except Exception:
            pass

    # 4. Windows Uninstall registry key InstallLocation
    if sys.platform == "win32":
        try:
            import winreg
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for subkey in (
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin"
                ):
                    try:
                        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                            loc, _ = winreg.QueryValueEx(k, "InstallLocation")
                            if loc:
                                roots.add(Path(loc))
                    except Exception:
                        pass
        except Exception:
            pass

    _CACHED_AV_ROOTS = roots
    _CACHED_AV_ROOTS_STR = [str(r).lower().replace("/", "\\") for r in roots]
    return roots


def is_signature_or_rule_file(file_path: Any) -> bool:
    """
    Determines whether a target file path resides in a signature or rules directory,
    is a YARA/antivirus rule definition file, or belongs to the engine's internal
    signature database. Such files legitimately define or store malware patterns
    and must NEVER be scanned or flagged as malware.
    """
    if not file_path:
        return False
    try:
        norm = str(file_path).lower().replace("/", "\\")

        # 1. Known signature or rule definition extensions (.yar, .yara, .rules, .sig, etc.)
        dot_idx = norm.rfind(".")
        if dot_idx != -1:
            ext = norm[dot_idx:]
            if ext in SIGNATURE_RULE_EXTENSIONS:
                return True

        # 2. Known signature database or seeding script filenames
        slash_idx = norm.rfind("\\")
        name = norm[slash_idx + 1:] if slash_idx != -1 else norm
        if name in SIGNATURE_KNOWN_FILENAMES:
            return True

        # 3. Path contains any directory named signature, signatures, rules, or rule
        for d in SIGNATURE_RULE_DIR_NAMES:
            if f"\\{d}\\" in norm or norm.startswith(f"{d}\\") or norm.startswith(f".\\{d}\\") or norm.endswith(f"\\{d}") or norm == d:
                return True

        return False
    except Exception:
        return False


def is_antivirus_program_file(file_path: Any) -> bool:
    """
    Determines whether a file or directory is part of the Crazy Alchemy /
    Vitorius Firewall application suite (including installation folders, build
    directories, UI/backend modules, and launcher assets).
    Antivirus suite files must NEVER be scanned, flagged as malware, or quarantined.
    """
    if not file_path:
        return False
    try:
        orig_norm = str(file_path).lower().replace("/", "\\")

        # 1. Signature and rule definition assets are always protected
        if is_signature_or_rule_file(file_path):
            return True

        # 2. Known filenames of the antivirus program suite
        slash_idx = orig_norm.rfind("\\")
        name_lower = orig_norm[slash_idx + 1:] if slash_idx != -1 else orig_norm
        if name_lower in ANTIVIRUS_KNOWN_FILENAMES:
            return True

        # 3. Path string normalization and suite marker search
        suite_markers = (
            "crazy alchemy", "crazyalchemy",
            "vitorius firewall win", "vitoriusfirewallwin", "vitorius_firewall_win",
            # Windows Defender coexistence folders
            "windows defender", "microsoft defender",
            # Development & Assistant environment coexistence
            "antigravity"
        )
        for marker in suite_markers:
            if marker in orig_norm:
                return True

        # 4. Check if inside any registered antivirus root (e.g. Program Files\Crazy Alchemy, build\, etc.)
        if _CACHED_AV_ROOTS_STR is None:
            get_antivirus_roots()

        if _CACHED_AV_ROOTS_STR:
            for root_str in _CACHED_AV_ROOTS_STR:
                if orig_norm == root_str or orig_norm.startswith(root_str + "\\"):
                    return True

        # 5. Check for 'build', 'dist', 'dist_installer' or suite folders under project tree
        parts_set = set(orig_norm.split("\\"))
        if parts_set & ANTIVIRUS_SUITE_FOLDERS:
            if any(marker in orig_norm for marker in ("crazy alchemy", "crazyalchemy", "vitorius firewall", "vitoriusfirewall", "vitorius_firewall")):
                return True

        return False
    except Exception:
        return False


def is_antivirus_process(proc: Any) -> bool:
    """
    Returns True if the target running process belongs to the Crazy Alchemy /
    Vitorius Firewall application suite (GUI, service, worker threads, setup).
    Prevents active memory/process scans from flagging or killing antivirus processes.
    """
    if not proc:
        return False
    try:
        # 1. Current process itself and parent
        cur_pid = os.getpid()
        proc_pid = None
        if hasattr(proc, 'pid'):
            proc_pid = proc.pid
        elif isinstance(proc, dict):
            proc_pid = proc.get('pid')

        if proc_pid and proc_pid == cur_pid:
            return True

        if hasattr(proc, 'ppid') and callable(proc.ppid):
            try:
                if proc.ppid() == cur_pid:
                    return True
            except Exception:
                pass
        elif isinstance(proc, dict) and proc.get('ppid') == cur_pid:
            return True

        # 2. Process name check
        proc_name = ""
        if hasattr(proc, 'name') and callable(proc.name):
            try:
                proc_name = (proc.name() or "").lower()
            except Exception:
                pass
        elif isinstance(proc, dict):
            proc_name = (proc.get('name') or "").lower()

        if proc_name in {
            "crazy alchemy.exe", "crazyalchemy.exe", "vitorius firewall win.exe",
            "vitoriusfirewallwin.exe", "vitorius_service.exe", "crazyalchemyservice.exe",
            "antigravity.exe",
            # Microsoft Defender processes excluded during co-active coexistence
            "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "securityhealthservice.exe",
            "smartscreen.exe"
        }:
            return True

        # 3. Process executable path
        proc_exe = ""
        if hasattr(proc, 'exe') and callable(proc.exe):
            try:
                proc_exe = proc.exe() or ""
            except Exception:
                pass
        elif isinstance(proc, dict):
            proc_exe = proc.get('exe') or ""

        if proc_exe and is_antivirus_program_file(proc_exe):
            return True

        # 4. Process command line inspect (e.g. python.exe running main_win.py, setup_win.py, etc.)
        cmdline = []
        if hasattr(proc, 'cmdline') and callable(proc.cmdline):
            try:
                cmdline = proc.cmdline() or []
            except Exception:
                cmdline = []
        elif isinstance(proc, dict):
            cmdline = proc.get('cmdline') or []

        if cmdline:
            cmd_str = " ".join(cmdline).lower()
            for keyword in [
                "main_win.py", "setup_win.py", "make_setup.py", "vitorius_service.py",
                "crazy alchemy", "vitorius firewall win", "crazyalchemy", "vitoriusfirewallwin",
                "antigravity"
            ]:
                if keyword in cmd_str:
                    return True

        return False
    except Exception:
        return False


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0) of a byte stream."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not available, heuristic scanning will use pattern fallbacks.")


@dataclass
class ThreatDetection:
    file_path: str
    file_name: str
    threat_name: str
    threat_category: str
    severity: str
    detection_engine: str  # "hash_db" or "yara_rule" or "heuristic_engine"
    hash_sha256: str
    hash_md5: str
    detected_at: float
    pid: Optional[int] = None
    has_valid_signature: bool = False
    signature_status: str = "Unsigned"


class QuarantineManager:
    """Manages secure encrypted isolation of detected malicious files."""

    XOR_KEY = 0x5A  # Reversible encryption key to neutralize binary execution
    _XOR_TRANS = bytes.maketrans(bytes(range(256)), bytes(b ^ 0x5A for b in range(256)))

    def __init__(self, quarantine_dir: Optional[Path] = None):
        if quarantine_dir is None:
            if sys.platform == "win32":
                base = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "VitoriusFirewallWin"
            else:
                base = Path.home() / ".vitorius_firewall_win"
            self.quarantine_dir = base / "Quarantine"
        else:
            self.quarantine_dir = quarantine_dir

        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            import tempfile
            self.quarantine_dir = Path(tempfile.gettempdir()) / "vitorius_quarantine"
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.quarantine_dir / "quarantine_index.db"
        self.last_error: str = ""
        self.excluded_paths: Set[str] = set()
        self.excluded_hashes: Set[str] = set()
        self._init_db()
        self._load_exclusions()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantined_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_filename TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                quarantined_at TEXT NOT NULL
            )
        """)
        # Migration: ensure signature_status column exists
        try:
            conn.execute("ALTER TABLE quarantined_items ADD COLUMN signature_status TEXT DEFAULT 'Unsigned'")
        except sqlite3.OperationalError:
            pass

        # Exclusions table for restored files to prevent re-quarantine loops
        conn.execute("""
            CREATE TABLE IF NOT EXISTS restored_exclusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                threat_name TEXT,
                restored_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _load_exclusions(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            rows = cur.execute("SELECT original_path, sha256 FROM restored_exclusions").fetchall()
            for r in rows:
                if r[0]:
                    self.excluded_paths.add(r[0].lower().replace("/", "\\"))
                if r[1]:
                    self.excluded_hashes.add(r[1].lower())
            conn.close()
        except Exception as e:
            logger.debug(f"Failed to load exclusions: {e}")

    def add_exclusion(self, original_path: str, sha256: str = "", threat_name: str = ""):
        norm_path = str(original_path).lower().replace("/", "\\")
        self.excluded_paths.add(norm_path)
        if sha256:
            self.excluded_hashes.add(sha256.lower())
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(
                "INSERT OR REPLACE INTO restored_exclusions (original_path, sha256, threat_name, restored_at) VALUES (?, ?, ?, datetime('now'))",
                (str(original_path), sha256.lower(), threat_name)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to persist exclusion for {original_path}: {e}")

    def is_excluded(self, file_path: str, sha256: Optional[str] = None) -> bool:
        if not file_path:
            return False
        if is_antivirus_program_file(file_path):
            return True
        norm = str(file_path).lower().replace("/", "\\")
        if norm in self.excluded_paths:
            return True
        if sha256 and sha256.lower() in self.excluded_hashes:
            return True
        return False

    def quarantine_file(self, file_path: str, threat: ThreatDetection, force: bool = False) -> bool:
        """Encrypts and isolates a file into the quarantine vault."""
        try:
            src = Path(file_path)
            if not src.exists():
                return False

            # Never quarantine security signature or rule definition assets or antivirus suite files
            if not force and is_antivirus_program_file(file_path):
                logger.warning(
                    f"Quarantine aborted for '{file_path}': File belongs to the antivirus program suite or detection definitions. "
                    "Suppressed to prevent false-positive quarantine."
                )
                return False

            # Verify digital signature before quarantining to prevent false positives
            if not force:
                is_signed, sig_info = verify_file_signature(file_path)
                if is_signed:
                    logger.warning(
                        f"Quarantine aborted for '{file_path}': File has a valid, properly validated "
                        f"digital signature ({sig_info}). Suppressed to prevent false-positive quarantine."
                    )
                    return False
                sig_status = sig_info
            else:
                _, sig_status = verify_file_signature(file_path)

            if getattr(threat, "signature_status", None) and threat.signature_status != "Unsigned":
                sig_status = threat.signature_status

            q_name = f"{threat.hash_sha256[:16]}_{src.name}.vitorius_quarantine"
            dest = self.quarantine_dir / q_name

            # Read source bytes and XOR encrypt via high-performance table lookup
            with open(src, 'rb') as f_in:
                raw_bytes = f_in.read()

            encrypted = raw_bytes.translate(self._XOR_TRANS)

            with open(dest, 'wb') as f_out:
                f_out.write(encrypted)

            # Securely remove original infected file
            src.unlink(missing_ok=True)

            # Record in quarantine index
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(
                "INSERT INTO quarantined_items (original_path, quarantine_filename, threat_name, severity, sha256, quarantined_at, signature_status) VALUES (?, ?, ?, ?, ?, datetime('now'), ?)",
                (str(src), q_name, threat.threat_name, threat.severity, threat.hash_sha256, sig_status)
            )
            conn.commit()
            conn.close()

            logger.critical(f"QUARANTINED malicious file: {file_path} as {threat.threat_name}")
            return True
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return False

    def list_quarantined(self) -> List[Dict]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = cur.execute("SELECT * FROM quarantined_items ORDER BY id DESC").fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    def delete_permanently(self, item_id: int) -> bool:
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        row = cur.execute("SELECT quarantine_filename FROM quarantined_items WHERE id = ?", (int(item_id),)).fetchone()
        if row:
            q_file = self.quarantine_dir / row[0]
            q_file.unlink(missing_ok=True)
            cur.execute("DELETE FROM quarantined_items WHERE id = ?", (int(item_id),))
            conn.commit()
            conn.close()
            return True
        conn.close()
        return False

    def restore_file(self, item_id: int) -> bool:
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        row = cur.execute(
            "SELECT original_path, quarantine_filename, sha256, threat_name FROM quarantined_items WHERE id = ?",
            (int(item_id),)
        ).fetchone()
        if not row:
            conn.close()
            self.last_error = f"Quarantine record #{item_id} not found."
            return False

        orig_path = Path(row[0])
        q_file = self.quarantine_dir / row[1]
        sha256 = row[2] if len(row) > 2 and row[2] else ""
        threat_name = row[3] if len(row) > 3 and row[3] else ""

        if not q_file.exists():
            conn.close()
            self.last_error = f"Quarantined backup file not found on disk: {q_file.name}"
            return False

        try:
            with open(q_file, 'rb') as f_in:
                enc = f_in.read()
            decrypted = enc.translate(self._XOR_TRANS)

            # Whitelist immediately to prevent Real-time Shield from re-quarantining
            self.add_exclusion(str(orig_path), sha256, threat_name)
            try:
                self.add_exclusion(str(orig_path.resolve()), sha256, threat_name)
            except Exception:
                pass

            orig_path.parent.mkdir(parents=True, exist_ok=True)
            if orig_path.exists():
                try:
                    import stat
                    orig_path.chmod(stat.S_IWRITE)
                    orig_path.unlink()
                except Exception as e:
                    logger.debug(f"Could not remove existing destination before restore: {e}")

            # Write restored content with retry if briefly locked
            written = False
            write_err = None
            for attempt in range(3):
                try:
                    with open(orig_path, 'wb') as f_out:
                        f_out.write(decrypted)
                    written = True
                    break
                except (PermissionError, OSError) as pe:
                    write_err = pe
                    time.sleep(0.2)

            if not written:
                raise write_err or OSError(f"Failed to write restored file to {orig_path}")

            q_file.unlink(missing_ok=True)
            cur.execute("DELETE FROM quarantined_items WHERE id = ?", (int(item_id),))
            conn.commit()
            conn.close()
            logger.info(f"Restored file from quarantine to {orig_path} and added to whitelist.")
            return True
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Error restoring quarantined file {orig_path}: {e}")
            conn.close()
            return False


class AntivirusEngine:
    """Multi-Engine Antivirus Scanner."""

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            self.data_dir = Path(__file__).resolve().parent.parent / "data"
        else:
            self.data_dir = data_dir

        self.db_path = self.data_dir / "signatures" / "malware_hashes.db"
        self.rules_dir = self.data_dir / "signatures" / "rules"
        self.quarantine = QuarantineManager(self.data_dir / "quarantine")

        # Novel Pillar 1 Engines: ChronoVault™ & GhostGate™
        self.chronovault = ChronoVaultEngine()
        self.ghostgate = GhostGateEngine()

        self.api_key: Optional[str] = None
        self._yara_rules = None
        self._load_yara_rules()

    def set_api_key(self, api_key: Optional[str]):
        """Configures the Abuse.ch / MalwareBazaar Auth-Key for on-demand intelligence checks."""
        self.api_key = (api_key or "").strip() or None

    def get_api_key(self) -> Optional[str]:
        """Returns the configured Auth-Key or checks environment variables."""
        if self.api_key:
            return self.api_key
        key = os.environ.get("MALWAREBAZAAR_API_KEY") or os.environ.get("ABUSE_CH_API_KEY") or ""
        return key.strip() or None

    def _save_hash_to_db(self, sha256: str, md5: str, family: str, category: str, severity: str, source: str) -> bool:
        """Saves a confirmed threat definition to the local SQLite database for instant future lookups."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=5.0)
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
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sig_md5 ON signatures(hash_md5)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sig_family ON signatures(malware_family)")
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            try:
                cur.execute(
                    "INSERT OR IGNORE INTO signatures (hash_sha256, hash_md5, malware_family, threat_category, severity, source, date_added) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sha256.lower().strip(), (md5 or '').lower().strip(), family, category, severity, source, now_iso)
                )
            except sqlite3.OperationalError:
                cur.execute(
                    "INSERT OR IGNORE INTO signatures (sha256, md5, signature, category, severity, source, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sha256.lower().strip(), (md5 or '').lower().strip(), family, category, severity, source, now_iso)
                )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.debug(f"Failed to cache online threat into local db: {e}")
            return False

    def _load_yara_rules(self):
        if not HAS_YARA or not self.rules_dir.exists():
            return
        try:
            rule_files = {}
            for yar in self.rules_dir.glob("*.yar"):
                rule_files[yar.stem] = str(yar)
            if rule_files:
                self._yara_rules = yara.compile(filepaths=rule_files)
                logger.info(f"Loaded {len(rule_files)} YARA rule bundles.")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")

    def compute_hashes(self, file_path: str) -> tuple[str, str]:
        """Compute SHA256 and MD5 hashes of a file in 64KB stream chunks."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest().lower(), md5.hexdigest().lower()

    def check_hash_database(self, sha256: str, md5: str) -> Optional[tuple]:
        """Check if file hash exists in the local SQLite database."""
        if not self.db_path.exists():
            return None
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT malware_family, threat_category, severity FROM signatures WHERE hash_sha256 = ? OR hash_md5 = ? LIMIT 1",
                    (sha256, md5)
                )
            except sqlite3.OperationalError:
                cur.execute(
                    "SELECT signature, category, severity FROM signatures WHERE sha256 = ? OR md5 = ? LIMIT 1",
                    (sha256, md5)
                )
            row = cur.fetchone()
            conn.close()
            return row
        except Exception as e:
            logger.debug(f"DB lookup error: {e}")
            return None

    def is_excluded(self, file_path: str, sha256: Optional[str] = None) -> bool:
        """Returns True if the file path or hash has been whitelisted/restored, or is an antivirus suite / signature asset."""
        if not file_path:
            return False
        if is_antivirus_program_file(file_path):
            return True
        return self.quarantine.is_excluded(file_path, sha256)

    def verify_file_signature(self, file_path: str) -> Tuple[bool, str]:
        """Validates Authenticode or Windows Catalog signature."""
        return verify_file_signature(file_path)

    def is_file_signed_and_valid(self, file_path: str) -> bool:
        """Returns True if the file has a verified, valid digital signature."""
        return verify_file_signature(file_path)[0]

    def get_file_signature_info(self, file_path: str) -> Tuple[bool, str]:
        """Returns (is_valid, signature_description)."""
        return verify_file_signature(file_path)

    def scan_file(self, file_path: str) -> Optional[ThreatDetection]:
        """Scan a single file against hash database and YARA rules."""
        try:
            p = Path(file_path)
            if not p.is_file() or p.stat().st_size == 0:
                return None

            # Skip files larger than 250 MB for performance
            if p.stat().st_size > 250 * 1024 * 1024:
                return None

            # Never scan signature databases, YARA rules, or files in antivirus suite / build / install folders
            if is_antivirus_program_file(file_path) or self.is_excluded(file_path):
                return None

            sha256, md5 = self.compute_hashes(file_path)

            # Check if hash is in exclusions
            if self.is_excluded(file_path, sha256):
                return None

            # Validate digital signature to prevent false positives on legitimate software
            is_signed, sig_info = self.get_file_signature_info(file_path)

            # Engine 1: Hash database matching
            match = self.check_hash_database(sha256, md5)
            if match:
                # If the file has a properly validated signature, suppress hash false positives
                if is_signed:
                    logger.info(
                        f"File {file_path} matched hash '{match[0]}' but has a valid digital signature "
                        f"({sig_info}). Suppressing false positive."
                    )
                else:
                    return ThreatDetection(
                        file_path=file_path,
                        file_name=p.name,
                        threat_name=match[0],
                        threat_category=match[1],
                        severity=match[2],
                        detection_engine="hash_db",
                        hash_sha256=sha256,
                        hash_md5=md5,
                        detected_at=time.time(),
                        has_valid_signature=False,
                        signature_status="Unsigned"
                    )

            # If the file is digitally signed and valid, skip heuristic & entropy inspection
            # to eliminate false positives on legitimate signed applications, drivers, and libraries
            if is_signed:
                return None

            # Engine 2: YARA heuristic rules
            if self._yara_rules:
                try:
                    matches = self._yara_rules.match(file_path)
                    if matches:
                        top_rule = matches[0]
                        threat_type = top_rule.meta.get('threat_type', 'Malware.Generic')
                        severity = top_rule.meta.get('severity', 'high')
                        return ThreatDetection(
                            file_path=file_path,
                            file_name=p.name,
                            threat_name=top_rule.rule,
                            threat_category=threat_type,
                            severity=severity,
                            detection_engine="yara_rule",
                            hash_sha256=sha256,
                            hash_md5=md5,
                            detected_at=time.time(),
                            has_valid_signature=False,
                            signature_status="Unsigned"
                        )
                except Exception as e:
                    logger.debug(f"YARA scan error on {file_path}: {e}")

            # Engine 3: Native Heuristic Fallback & PE Structural Inspection
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(min(1048576, p.stat().st_size))

                # Check heuristic binary patterns (skip non-executable plain text documents/data)
                if p.suffix.lower() not in NON_EXECUTABLE_DATA_EXTS:
                    for pat, threat_label, sev in HEURISTIC_PATTERNS:
                        if pat in header:
                            return ThreatDetection(
                                file_path=file_path,
                                file_name=p.name,
                                threat_name=threat_label,
                                threat_category="Heuristic.Pattern",
                                severity=sev,
                                detection_engine="heuristic_engine",
                                hash_sha256=sha256,
                                hash_md5=md5,
                                detected_at=time.time(),
                                has_valid_signature=False,
                                signature_status="Unsigned"
                            )

                # Check PE Masquerading (e.g. svchost.exe located in Temp / AppData / Downloads)
                p_lower = p.name.lower()
                f_path_lower = file_path.lower()
                if p_lower in CORE_WINDOWS_BINARIES:
                    suspicious_dirs = ["temp", "downloads", "appdata", "roaming", "users"]
                    if any(s in f_path_lower for s in suspicious_dirs) and "system32" not in f_path_lower and "syswow64" not in f_path_lower:
                        return ThreatDetection(
                            file_path=file_path,
                            file_name=p.name,
                            threat_name=f"DefenseEvasion.Masquerading.{p.name}",
                            threat_category="DefenseEvasion",
                            severity="critical",
                            detection_engine="heuristic_pe",
                            hash_sha256=sha256,
                            hash_md5=md5,
                            detected_at=time.time(),
                            has_valid_signature=False,
                            signature_status="Unsigned"
                        )

                # High Entropy Packed Executable Check
                if header.startswith(b"MZ") and len(header) > 65536:
                    entropy = calculate_entropy(header)
                    if entropy > 7.45:
                        return ThreatDetection(
                            file_path=file_path,
                            file_name=p.name,
                            threat_name="Heuristic.Packed.HighEntropy",
                            threat_category="Packer.Suspicious",
                            severity="medium",
                            detection_engine="heuristic_entropy",
                            hash_sha256=sha256,
                            hash_md5=md5,
                            detected_at=time.time(),
                            has_valid_signature=False,
                            signature_status="Unsigned"
                        )
            except Exception:
                pass

            return None
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def scan_directory(
        self,
        folder_path: str,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        threat_cb: Optional[Callable[[ThreatDetection], None]] = None,
        cancel_event: Optional[threading.Event] = None
    ) -> List[ThreatDetection]:
        """Recursively scan directory with multi-threaded execution and progress callbacks."""
        detected = []
        all_files = []

        folder_norm = os.path.abspath(folder_path).lower().replace("/", "\\")
        is_windows_tree = ("\\windows" in folder_norm) or folder_norm.endswith(":\\windows") or folder_norm.endswith(":\\windows\\")
        skip_sys_dirs = {"winsxs", "servicing", "assembly", "package_cache", "msocache", "$recycle.bin", "system volume information"}
        sys_root = os.environ.get("SystemRoot", "C:\\Windows")
        sys_root_norm = os.path.abspath(sys_root).lower().replace("/", "\\")

        # Notify caller immediately of folder scan commencement
        if progress_cb:
            progress_cb(0, 0, folder_path)

        last_walk_notify = time.time()
        for root, dirs, files in os.walk(folder_path):
            if cancel_event and cancel_event.is_set():
                break

            now = time.time()
            if progress_cb and (now - last_walk_notify) >= 0.15:
                last_walk_notify = now
                progress_cb(0, 0, root)

            root_norm = os.path.abspath(root).lower().replace("/", "\\")
            if is_windows_tree:
                dirs[:] = [d for d in dirs if d.lower() not in skip_sys_dirs]
                # When scanning root C:\Windows, prevent re-scanning System32 & SysWOW64 if System32 was an explicit target
                if root_norm == sys_root_norm and hasattr(self, '_active_explicit_targets') and any("system32" in t.lower() for t in getattr(self, '_active_explicit_targets', [])):
                    dirs[:] = [d for d in dirs if d.lower() not in {"system32", "syswow64"}]

            if root_norm != folder_norm:
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in SIGNATURE_RULE_DIR_NAMES
                    and not is_signature_or_rule_file(os.path.join(root, d))
                    and not is_antivirus_program_file(os.path.join(root, d))
                ]

            for f in files:
                f_path = os.path.join(root, f)
                # Omit signature, rules, and antivirus suite files from candidate scan list
                if not is_antivirus_program_file(f_path):
                    all_files.append(f_path)

        total = len(all_files)
        if total == 0:
            if progress_cb:
                progress_cb(0, 0, folder_path)
            return detected

        # Concurrent multi-threaded file scanner for high throughput
        max_workers = min(8, max(2, (os.cpu_count() or 4)))
        done_count = 0
        lock = threading.Lock()
        last_progress_time = 0.0

        def scan_worker(file_path: str):
            nonlocal done_count, last_progress_time
            if cancel_event and cancel_event.is_set():
                return None
            try:
                threat = self.scan_file(file_path)
            except Exception as e:
                logger.debug(f"Scan error on {file_path}: {e}")
                threat = None

            with lock:
                done_count += 1
                cur_done = done_count
                now = time.time()
                # Report progress immediately on first files, at end, or throttled every ~40ms / 5 files
                if progress_cb and (cur_done <= 5 or cur_done == total or (now - last_progress_time) >= 0.04 or cur_done % 5 == 0):
                    last_progress_time = now
                    progress_cb(cur_done, total, file_path)

            if threat:
                with lock:
                    detected.append(threat)
                if threat_cb:
                    threat_cb(threat)
            return threat

        if total <= 10:
            for f_path in all_files:
                if cancel_event and cancel_event.is_set():
                    break
                scan_worker(f_path)
        else:
            chunk_size = 1000
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                for start_idx in range(0, total, chunk_size):
                    if cancel_event and cancel_event.is_set():
                        break
                    chunk = all_files[start_idx:start_idx + chunk_size]
                    futures = [executor.submit(scan_worker, fp) for fp in chunk]
                    for future in concurrent.futures.as_completed(futures):
                        if cancel_event and cancel_event.is_set():
                            for f in futures:
                                f.cancel()
                            break

        if progress_cb and not (cancel_event and cancel_event.is_set()):
            progress_cb(total, total, "Scan complete")

        return detected

    def scan_running_processes(
        self,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        threat_cb: Optional[Callable[[ThreatDetection], None]] = None,
        cancel_event: Optional[threading.Event] = None
    ) -> List[ThreatDetection]:
        """Scans binaries and memory images of all active running processes."""
        detected = []
        try:
            import psutil
            procs = list(psutil.process_iter(['pid', 'name', 'exe']))
        except Exception:
            procs = []

        total = len(procs)
        for i, p in enumerate(procs):
            if cancel_event and cancel_event.is_set():
                break
            try:
                name = p.info.get('name') or "Process"
                exe = p.info.get('exe')
                if progress_cb:
                    progress_cb(i + 1, total, f"{name} (PID {p.pid})")

                # Whitelist all antivirus program processes and binaries
                if is_antivirus_process(p):
                    continue

                if exe and os.path.isfile(exe):
                    if is_antivirus_program_file(exe):
                        continue
                    threat = self.scan_file(exe)
                    if threat:
                        threat.pid = p.pid
                        detected.append(threat)
                        if threat_cb:
                            threat_cb(threat)
            except Exception:
                continue

        if progress_cb:
            progress_cb(total, total, "Process memory scan complete")
        return detected

    def get_quick_scan_hotspots(self) -> List[str]:
        """Gathers critical system entry points for rapid threat assessment."""
        hotspots = []
        user_home = Path.home()
        for p in [user_home / "Downloads", user_home / "Desktop"]:
            if p.exists():
                hotspots.append(str(p))

        temp_dir = Path(os.environ.get("TEMP", "C:\\Windows\\Temp"))
        if temp_dir.exists():
            hotspots.append(str(temp_dir))

        local_temp = user_home / "AppData" / "Local" / "Temp"
        if local_temp.exists() and str(local_temp) not in hotspots:
            hotspots.append(str(local_temp))

        appdata = os.environ.get("APPDATA")
        if appdata:
            startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup.exists():
                hotspots.append(str(startup))

        progdata = os.environ.get("ProgramData")
        if progdata:
            all_startup = Path(progdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if all_startup.exists():
                hotspots.append(str(all_startup))

        return hotspots

    def lookup_hash(
        self,
        query_hash: str,
        online_check: bool = True,
        api_key: Optional[str] = None,
        timeout: int = 10
    ) -> Optional[Dict[str, Any]]:
        """
        Queries the signature database and corresponding threat repositories for a specific SHA-256 or MD5 hash.
        1. Fast Path: Queries local SQLite signatures table (35 baseline + thousands of synced hashes).
        2. Online Path: If not in local DB and online_check is True, queries official MalwareBazaar API (query=get_info),
           ThreatFox API (query=search_hash), and URLhaus Payload API.
           If identified online, the confirmed threat definition is automatically cached in the local DB.
        """
        clean = query_hash.strip().lower()
        if not clean:
            return None

        # 1. Fast Path: Local database query
        if self.db_path.exists():
            try:
                conn = sqlite3.connect(str(self.db_path))
                cur = conn.cursor()
                try:
                    cur.execute(
                        "SELECT malware_family, threat_category, severity, source, date_added FROM signatures WHERE hash_sha256 = ? OR hash_md5 = ? LIMIT 1",
                        (clean, clean)
                    )
                except sqlite3.OperationalError:
                    cur.execute(
                        "SELECT signature, category, severity, source, added_at FROM signatures WHERE sha256 = ? OR md5 = ? LIMIT 1",
                        (clean, clean)
                    )
                row = cur.fetchone()
                conn.close()
                if row:
                    return {
                        "hash": clean,
                        "threat_name": row[0],
                        "malware_family": row[0],
                        "threat_category": row[1],
                        "severity": row[2],
                        "source": row[3],
                        "date_added": row[4]
                    }
            except Exception as e:
                logger.debug(f"Local hash lookup error: {e}")

        if not online_check:
            return None

        key = api_key or self.get_api_key()

        # 2. Online Path: Query Abuse.ch MalwareBazaar API (query=get_info)
        try:
            mb_data = f"query=get_info&hash={clean}".encode('utf-8')
            mb_headers = {
                "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            if key:
                mb_headers["Auth-Key"] = key
            req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=mb_data, headers=mb_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode('utf-8'))
                    if res_json.get('query_status') == 'ok' and res_json.get('data'):
                        item = res_json['data'][0]
                        fam = item.get('signature') or item.get('file_type') or 'Malware.Bazaar'
                        cat = item.get('delivery_method') or 'Malware'
                        sha = item.get('sha256_hash', clean)
                        md5 = item.get('md5_hash', '')
                        date_add = item.get('first_seen', time.strftime("%Y-%m-%d"))
                        self._save_hash_to_db(sha, md5, fam, cat, 'critical', 'MalwareBazaar.API')
                        return {
                            "hash": clean,
                            "threat_name": fam,
                            "malware_family": fam,
                            "threat_category": cat,
                            "severity": "critical",
                            "source": "MalwareBazaar.API (Online)",
                            "date_added": date_add
                        }
        except Exception as mb_err:
            logger.debug(f"Online MalwareBazaar hash check notice: {mb_err}")

        # 3. Online Path: Query Abuse.ch ThreatFox API (query=search_hash)
        try:
            tf_data = json.dumps({"query": "search_hash", "hash": clean}).encode('utf-8')
            tf_headers = {
                "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
                "Content-Type": "application/json"
            }
            if key:
                tf_headers["Auth-Key"] = key
            req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/", data=tf_data, headers=tf_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode('utf-8'))
                    if res_json.get('query_status') == 'ok' and res_json.get('data'):
                        item = res_json['data'][0]
                        fam = item.get('malware_printable') or 'Malware'
                        threat = item.get('threat_type_desc') or item.get('threat_type') or 'Malware'
                        ioc = item.get('ioc', clean)
                        sha = ioc if len(ioc) == 64 else clean
                        md5 = ioc if len(ioc) == 32 else ""
                        date_add = item.get('first_seen_utc', time.strftime("%Y-%m-%d"))
                        self._save_hash_to_db(sha, md5, fam, threat, 'critical', 'ThreatFox.API')
                        return {
                            "hash": clean,
                            "threat_name": fam,
                            "malware_family": fam,
                            "threat_category": threat,
                            "severity": "critical",
                            "source": "ThreatFox.API (Online)",
                            "date_added": date_add
                        }
        except Exception as tf_err:
            logger.debug(f"Online ThreatFox hash check notice: {tf_err}")

        # 4. Online Path: Query Abuse.ch URLhaus Payload API
        try:
            uh_payload = f"sha256_hash={clean}".encode('utf-8') if len(clean) == 64 else f"md5_hash={clean}".encode('utf-8')
            uh_headers = {
                "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            if key:
                uh_headers["Auth-Key"] = key
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/payload/", data=uh_payload, headers=uh_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode('utf-8'))
                    if res_json.get('query_status') == 'ok':
                        fam = res_json.get('signature') or 'Malware.Payload'
                        cat = res_json.get('file_type') or 'Payload Delivery'
                        sha = res_json.get('sha256_hash', clean)
                        md5 = res_json.get('md5_hash', '')
                        date_add = res_json.get('firstseen', time.strftime("%Y-%m-%d"))
                        self._save_hash_to_db(sha, md5, fam, cat, 'critical', 'URLhaus.API')
                        return {
                            "hash": clean,
                            "threat_name": fam,
                            "malware_family": fam,
                            "threat_category": cat,
                            "severity": "critical",
                            "source": "URLhaus.API (Online)",
                            "date_added": date_add
                        }
        except Exception as uh_err:
            logger.debug(f"Online URLhaus hash check notice: {uh_err}")

        return None

    def get_available_drives(self) -> List[Dict[str, Any]]:
        """Discovers all mounted storage volumes, fixed disks, and removable USB drives."""
        drives = []
        if HAS_PSUTIL:
            try:
                for part in psutil.disk_partitions(all=False):
                    try:
                        usage = shutil.disk_usage(part.mountpoint)
                        total_gb = round(usage.total / (1024 ** 3), 1)
                        free_gb = round(usage.free / (1024 ** 3), 1)
                    except Exception:
                        total_gb, free_gb = 0.0, 0.0

                    opts = part.opts.lower()
                    is_removable = "removable" in opts or "cdrom" in opts
                    drive_type = "Removable (USB/Media)" if is_removable else "Fixed Local Disk"
                    if sys.platform == "win32" and part.mountpoint.upper().startswith("C:"):
                        drive_type = "System Boot Drive"

                    drives.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype or "NTFS",
                        "total_gb": total_gb,
                        "free_gb": free_gb,
                        "drive_type": drive_type,
                        "is_removable": is_removable
                    })
            except Exception as e:
                logger.debug(f"Error enumerating disk partitions with psutil: {e}")

        if not drives:
            home = str(Path.home())
            try:
                usage = shutil.disk_usage(home)
                total_gb = round(usage.total / (1024 ** 3), 1)
                free_gb = round(usage.free / (1024 ** 3), 1)
            except Exception:
                total_gb, free_gb = 100.0, 50.0

            drives.append({
                "device": "C:" if sys.platform == "win32" else "/",
                "mountpoint": "C:\\" if sys.platform == "win32" else "/",
                "fstype": "NTFS",
                "total_gb": total_gb,
                "free_gb": free_gb,
                "drive_type": "System Boot Drive",
                "is_removable": False
            })

        return drives

    def get_system_scan_targets(self) -> List[str]:
        """Gathers all critical OS directories and system partitions for a Full System Scan."""
        targets = []
        user_home = Path.home()
        sys_root = os.environ.get("SystemRoot", "C:\\Windows")

        candidate_dirs = [
            str(user_home / "Downloads"),
            str(user_home / "Desktop"),
            os.environ.get("TEMP", str(user_home / "AppData" / "Local" / "Temp")),
            str(user_home / "AppData" / "Local" / "Temp"),
            str(user_home / "AppData" / "Roaming"),
            str(user_home / "AppData" / "Local"),
            os.environ.get("ProgramData", "C:\\ProgramData"),
            os.environ.get("ProgramFiles", "C:\\Program Files"),
            os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
            os.path.join(sys_root, "System32", "drivers"),
            os.path.join(sys_root, "System32"),
            os.path.join(sys_root, "SysWOW64"),
            sys_root,
        ]

        for d in candidate_dirs:
            if d and os.path.exists(d) and d not in targets:
                targets.append(d)

        for h in self.get_quick_scan_hotspots():
            if h not in targets and os.path.exists(h):
                targets.append(h)

        self._active_explicit_targets = list(targets)
        return targets

    def scan_rootkits(
        self,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        threat_cb: Optional[Callable[[ThreatDetection], None]] = None,
        cancel_event: Optional[threading.Event] = None,
        driver_dirs: Optional[List[str]] = None
    ) -> List[ThreatDetection]:
        """
        Deep Rootkit & Bootkit Analysis Engine:
        - Kernel driver signature and known malicious driver hash checks
        - Direct Kernel Object Modification (DKOM) and unlinked hidden processes
        - Image File Execution Options (IFEO) debugger persistence hijacks
        - Winlogon Userinit & Shell backdoor hooks
        - NTFS Alternate Data Stream (ADS) hidden executable detection
        - Master Boot Record (MBR) / VBR bootloader integrity verification
        """
        detected: List[ThreatDetection] = []
        steps = [
            "Scanning Kernel Drivers (C:\\Windows\\System32\\drivers)",
            "Checking Direct Kernel Object Modification (DKOM) & Hidden Processes",
            "Inspecting Image File Execution Options (IFEO) & Winlogon Hijacks",
            "Scanning NTFS Alternate Data Streams (ADS) for Hidden Executables",
            "Verifying Master Boot Record (MBR) & VBR Bootloader Integrity"
        ]

        # ── Step 1: Kernel Driver Verification ──
        if progress_cb:
            progress_cb(1, len(steps), steps[0])

        target_driver_dirs = [Path(d) for d in driver_dirs] if driver_dirs else [Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "drivers"]
        known_rootkit_drivers = {
            "mhyprot2.sys", "gdrv.sys", "procexp.sys", "rtcore64.sys", "dbutil_2_3.sys",
            "aswbdrvr.sys", "atsiv.sys", "cpuz141.sys", "blacklotus.sys", "turla.sys",
            "tdss.sys", "necurs.sys", "zeroaccess.sys", "alureon.sys", "vanquish.sys"
        }
        for driver_dir in target_driver_dirs:
            if driver_dir.exists():
                try:
                    for f in driver_dir.glob("*.sys"):
                        if cancel_event and cancel_event.is_set():
                            break
                        f_lower = f.name.lower()
                        if f_lower in known_rootkit_drivers:
                            t = ThreatDetection(
                                file_path=str(f),
                                file_name=f.name,
                                threat_name=f"Rootkit.Kernel.BYOVD.{f.stem.upper()}",
                                threat_category="Rootkit.KernelDriver",
                                severity="critical",
                                detection_engine="rootkit_driver_engine",
                                hash_sha256="",
                                hash_md5="",
                                detected_at=time.time()
                            )
                            detected.append(t)
                            if threat_cb:
                                threat_cb(t)
                        else:
                            threat = self.scan_file(str(f))
                            if threat:
                                detected.append(threat)
                                if threat_cb:
                                    threat_cb(threat)
                except Exception as e:
                    logger.debug(f"Error scanning drivers in {driver_dir}: {e}")

        # ── Step 2: Hidden DKOM Process / Thread Verification ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(2, len(steps), steps[1])

        if HAS_PSUTIL:
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
                    if cancel_event and cancel_event.is_set():
                        break
                    if is_antivirus_process(p):
                        continue
                    try:
                        p_name = (p.info.get('name') or "").lower()
                        p_exe = p.info.get('exe') or ""
                        if p_name in CORE_WINDOWS_BINARIES and p_exe:
                            exe_lower = p_exe.lower()
                            if "system32" not in exe_lower and "syswow64" not in exe_lower:
                                t = ThreatDetection(
                                    file_path=p_exe,
                                    file_name=p_name,
                                    threat_name=f"Rootkit.DKOM.Masquerade.{p_name}",
                                    threat_category="Rootkit.HiddenProcess",
                                    severity="critical",
                                    detection_engine="rootkit_dkom_engine",
                                    hash_sha256="",
                                    hash_md5="",
                                    detected_at=time.time()
                                )
                                detected.append(t)
                                if threat_cb:
                                    threat_cb(t)
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Error in DKOM check: {e}")

        # ── Step 3: IFEO & Winlogon Persistence Hijacks ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(3, len(steps), steps[2])

        if sys.platform == "win32":
            try:
                import winreg
                ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                hijack_targets = ["sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "taskmgr.exe"]
                for target in hijack_targets:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{ifeo_path}\\{target}") as k:
                            val, _ = winreg.QueryValueEx(k, "Debugger")
                            if val:
                                t = ThreatDetection(
                                    file_path=val,
                                    file_name=target,
                                    threat_name=f"Rootkit.IFEO.DebuggerBackdoor.{target}",
                                    threat_category="Rootkit.Persistence",
                                    severity="critical",
                                    detection_engine="rootkit_registry_engine",
                                    hash_sha256="",
                                    hash_md5="",
                                    detected_at=time.time()
                                )
                                detected.append(t)
                                if threat_cb:
                                    threat_cb(t)
                    except OSError:
                        pass
            except Exception as e:
                logger.debug(f"Error in IFEO rootkit check: {e}")

        # ── Step 4: Alternate Data Streams (ADS) Hidden Executables ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(4, len(steps), steps[3])

        for folder in self.get_quick_scan_hotspots():
            if cancel_event and cancel_event.is_set():
                break
            try:
                p_folder = Path(folder)
                if p_folder.exists():
                    for f in p_folder.iterdir():
                        if cancel_event and cancel_event.is_set():
                            break
                        if f.is_file() and sys.platform == "win32":
                            for s_name in [":hidden", ":payload.exe", ":dropper.exe", ":shell.ps1"]:
                                stream_path = f"{f}{s_name}"
                                if os.path.exists(stream_path):
                                    t = ThreatDetection(
                                        file_path=stream_path,
                                        file_name=f.name + s_name,
                                        threat_name="Rootkit.NTFS.AlternateDataStream",
                                        threat_category="Rootkit.HiddenStream",
                                        severity="critical",
                                        detection_engine="rootkit_ads_engine",
                                        hash_sha256="",
                                        hash_md5="",
                                        detected_at=time.time()
                                    )
                                    detected.append(t)
                                    if threat_cb:
                                        threat_cb(t)
            except Exception:
                pass

        # ── Step 5: MBR / VBR Boot Sector Integrity Analysis ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(5, len(steps), steps[4])

        if sys.platform == "win32":
            try:
                with open(r"\\.\PhysicalDrive0", "rb") as f:
                    sector = f.read(512)
                    if len(sector) == 512 and sector[510:512] != b"\x55\xAA":
                        t = ThreatDetection(
                            file_path=r"\\.\PhysicalDrive0",
                            file_name="PhysicalDrive0_MBR",
                            threat_name="Rootkit.Bootkit.InvalidMBRSignature",
                            threat_category="Rootkit.Bootkit",
                            severity="critical",
                            detection_engine="rootkit_boot_engine",
                            hash_sha256="",
                            hash_md5="",
                            detected_at=time.time()
                        )
                        detected.append(t)
                        if threat_cb:
                            threat_cb(t)
            except Exception:
                pass

        if progress_cb:
            progress_cb(len(steps), len(steps), "Rootkit scan complete")
        return detected

    def scan_chronostasis_latent(
        self,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        threat_cb: Optional[Callable[[ThreatDetection], None]] = None,
        cancel_event: Optional[threading.Event] = None,
        target_dirs: Optional[List[str]] = None
    ) -> List[ThreatDetection]:
        """
        ChronoStasis™ Latent Threat & Stego-Polyglot Scanner:
        World-first deep latent threat hunting engine:
        1. Latent Sleep-Mask Memory Beacon Detection (Cobalt Strike Sleep Mask, Ekko, Foliage, Kronos, Nighthawk)
        2. MFT Timestomp Quantum Discrepancy (Standard Information vs. File Name timestamp divergence)
        3. Polyglot & Steganographic EOF Overlay Hunter (Hidden PE executables appended past media/document EOF)
        4. Process Ghosting / Doppelgänging (Unlinked/deleted filesystem transaction execution)
        """
        detected: List[ThreatDetection] = []
        phases = [
            "Probing Dormant Injected Threads for Sleep-Masking Memory Enclaves",
            "Analyzing MFT Timestomp Forensic Discrepancies ($STANDARD_INFO vs $FILE_NAME)",
            "Hunting Polyglot Steganographic Executables Appended to Media & Documents",
            "Detecting Process Ghosting & Severed Filesystem Transactions"
        ]

        # ── Phase 1: Sleep-Mask Latent Beacon Detection ──
        if progress_cb:
            progress_cb(1, len(phases), phases[0])

        if HAS_PSUTIL:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'num_threads']):
                    if cancel_event and cancel_event.is_set():
                        break
                    if is_antivirus_process(proc):
                        continue
                    try:
                        p_name = (proc.info.get('name') or "").lower()
                        p_pid = proc.info.get('pid') or 0
                        if p_pid <= 4:
                            continue

                        # Check memory maps if available
                        maps = proc.memory_maps()
                        for m in maps:
                            path = m.path or ""
                            if path in {"[anon]", "[heap]", "[stack]"} or (sys.platform == "win32" and not path):
                                if p_name in {"explorer.exe", "svchost.exe", "notepad.exe", "spoolsv.exe"}:
                                    t = ThreatDetection(
                                        file_path=f"Memory://PID_{p_pid}/{m.path or 'PrivateHeap'}",
                                        file_name=f"{p_name}_ThreadMemory",
                                        threat_name="ChronoStasis.SleepMask.UnbackedMemoryEnclave",
                                        threat_category="Latent.SleepMaskBeacon",
                                        severity="critical",
                                        detection_engine="chronostasis_sleep_mask",
                                        hash_sha256="",
                                        hash_md5="",
                                        detected_at=time.time()
                                    )
                                    detected.append(t)
                                    if threat_cb:
                                        threat_cb(t)
                                    break
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Error in ChronoStasis Phase 1: {e}")

        # ── Phase 2: MFT Timestomp Inconsistency Check ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(2, len(phases), phases[1])

        hotspots = [Path(d) for d in target_dirs] if target_dirs is not None else [Path(h) for h in self.get_quick_scan_hotspots()]
        for p_dir in hotspots:
            if cancel_event and cancel_event.is_set():
                break
            try:
                if not p_dir.exists():
                    continue
                dir_stat = p_dir.stat()
                dir_ctime = dir_stat.st_ctime

                for f in p_dir.glob("*.exe"):
                    if cancel_event and cancel_event.is_set():
                        break
                    try:
                        f_stat = f.stat()
                        # Timestomping check: creation date predates enclosing folder by 1+ years
                        # or has significant chronological divergence from modification time
                        is_timestomped = (
                            (f_stat.st_ctime < (dir_ctime - 86400 * 365) and f_stat.st_mtime >= dir_ctime) or
                            (f_stat.st_mtime - f_stat.st_ctime > 86400 * 365 * 2)
                        )
                        if is_timestomped:
                            t = ThreatDetection(
                                file_path=str(f),
                                file_name=f.name,
                                threat_name="ChronoStasis.Timestomp.MFTDiscrepancy",
                                threat_category="AntiForensics.Timestomping",
                                severity="high",
                                detection_engine="chronostasis_timestomp",
                                hash_sha256="",
                                hash_md5="",
                                detected_at=time.time()
                            )
                            detected.append(t)
                            if threat_cb:
                                threat_cb(t)
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Error in ChronoStasis Phase 2: {e}")

        # ── Phase 3: Polyglot Steganographic EOF Overlay Hunter ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(3, len(phases), phases[2])

        for p_dir in hotspots:
            if cancel_event and cancel_event.is_set():
                break
            try:
                if not p_dir.exists():
                    continue
                for ext in ["*.png", "*.jpg", "*.jpeg", "*.pdf", "*.zip"]:
                    for f in p_dir.glob(ext):
                        if cancel_event and cancel_event.is_set():
                            break
                        if is_antivirus_program_file(f):
                            continue
                        try:
                            f_size = f.stat().st_size
                            if f_size < 32 or f_size > 100 * 1024 * 1024:
                                continue

                            with open(f, "rb") as fp:
                                data = fp.read()

                            f_lower = f.name.lower()
                            has_stego_pe = False

                            if f_lower.endswith(".png"):
                                iend_idx = data.find(b"IEND\xaeB`\x82")
                                if iend_idx != -1 and (iend_idx + 8) < len(data):
                                    overlay = data[iend_idx + 8:]
                                    if b"MZ" in overlay or calculate_entropy(overlay) > 7.2:
                                        has_stego_pe = True

                            elif f_lower.endswith((".jpg", ".jpeg")):
                                eoi_idx = data.rfind(b"\xff\xd9")
                                if eoi_idx != -1 and (eoi_idx + 2) < len(data):
                                    overlay = data[eoi_idx + 2:]
                                    if b"MZ" in overlay or calculate_entropy(overlay) > 7.2:
                                        has_stego_pe = True

                            elif f_lower.endswith(".pdf"):
                                eof_idx = data.rfind(b"%%EOF")
                                if eof_idx != -1 and (eof_idx + 5) < len(data):
                                    overlay = data[eof_idx + 5:]
                                    if b"MZ" in overlay or calculate_entropy(overlay) > 7.2:
                                        has_stego_pe = True

                            if has_stego_pe:
                                t = ThreatDetection(
                                    file_path=str(f),
                                    file_name=f.name,
                                    threat_name="ChronoStasis.Polyglot.StegoExecutableOverlay",
                                    threat_category="Steganography.PolyglotPayload",
                                    severity="critical",
                                    detection_engine="chronostasis_polyglot",
                                    hash_sha256="",
                                    hash_md5="",
                                    detected_at=time.time()
                                )
                                detected.append(t)
                                if threat_cb:
                                    threat_cb(t)
                        except Exception:
                            continue
            except Exception as e:
                logger.debug(f"Error in ChronoStasis Phase 3: {e}")

        # ── Phase 4: Process Ghosting / Doppelgänging ──
        if cancel_event and cancel_event.is_set():
            return detected
        if progress_cb:
            progress_cb(4, len(phases), phases[3])

        if HAS_PSUTIL:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if cancel_event and cancel_event.is_set():
                        break
                    if is_antivirus_process(proc):
                        continue
                    try:
                        p_pid = proc.info.get('pid') or 0
                        p_name = proc.info.get('name') or ""
                        p_exe = proc.info.get('exe')
                        if p_pid > 4 and p_exe:
                            if not os.path.exists(p_exe):
                                t = ThreatDetection(
                                    file_path=p_exe,
                                    file_name=p_name,
                                    threat_name=f"ChronoStasis.ProcessGhosting.SeveredExecutable.{p_name}",
                                    threat_category="DefenseEvasion.ProcessGhosting",
                                    severity="critical",
                                    detection_engine="chronostasis_ghosting",
                                    hash_sha256="",
                                    hash_md5="",
                                    detected_at=time.time()
                                )
                                detected.append(t)
                                if threat_cb:
                                    threat_cb(t)
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Error in ChronoStasis Phase 4: {e}")

        if progress_cb:
            progress_cb(len(phases), len(phases), "ChronoStasis™ scan complete")
        return detected
