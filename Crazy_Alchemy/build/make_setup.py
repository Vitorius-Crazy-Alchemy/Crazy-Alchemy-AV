#!/usr/bin/env python3
"""
Vitorius Firewall Win - Setup Executable Builder
Compiles build/setup_win.py into standalone setup.exe using PyInstaller or Inno Setup.
"""

import sys
import os
import shutil
import subprocess
from pathlib import Path

BUILD_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BUILD_DIR.parent
DIST_INSTALLER_DIR = PROJECT_DIR / "dist_installer"


def compile_with_inno_setup() -> bool:
    """Attempts compilation with Inno Setup if ISCC.exe is present."""
    iscc_paths = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe"
    ]
    for p in iscc_paths:
        if os.path.exists(p):
            print(f"[*] Found Inno Setup Compiler: {p}")
            iss_file = BUILD_DIR / "installer.iss"
            try:
                res = subprocess.run([p, str(iss_file)], check=True)
                return res.returncode == 0
            except Exception as e:
                print(f"[!] Inno Setup compilation error: {e}")
                return False
    return False


def compile_with_pyinstaller() -> bool:
    """Compiles setup.exe via PyInstaller using build_setup_exe.spec."""
    print("[*] Building standalone setup.exe with PyInstaller...")
    spec_file = BUILD_DIR / "build_setup_exe.spec"

    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "-y", str(spec_file)]
    try:
        res = subprocess.run(cmd, cwd=str(BUILD_DIR), check=True)
        if res.returncode == 0:
            built_exe = BUILD_DIR / "dist" / "setup.exe"
            if built_exe.exists():
                DIST_INSTALLER_DIR.mkdir(parents=True, exist_ok=True)
                dest_installer = DIST_INSTALLER_DIR / "setup.exe"
                dest_root = PROJECT_DIR / "setup.exe"
                shutil.copy2(built_exe, dest_installer)
                shutil.copy2(built_exe, dest_root)
                print(f"[✓] setup.exe created at: {dest_installer}")
                print(f"[✓] setup.exe created at: {dest_root}")
                return True
    except Exception as e:
        print(f"[!] PyInstaller compilation error: {e}")
    return False


def build_setup_executable() -> bool:
    print("=" * 65)
    print(" Compiling Vitorius Firewall Win setup.exe")
    print("=" * 65)

    # 1. Try Inno Setup first for native Windows C/Pascal PE installer
    if compile_with_inno_setup():
        print("[✓] Native setup.exe compiled with Inno Setup.")
        return True

    # 2. Fall back to PyInstaller standalone executable
    if compile_with_pyinstaller():
        print("[✓] Standalone setup.exe compiled with PyInstaller.")
        return True

    print("[✗] Failed to build setup.exe. Ensure PyInstaller is installed: pip install pyinstaller")
    return False


if __name__ == "__main__":
    success = build_setup_executable()
    sys.exit(0 if success else 1)
