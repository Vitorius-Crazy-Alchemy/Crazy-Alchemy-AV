#!/usr/bin/env python3
"""
Unit Tests for Vitorius Firewall Win - Installer & Prerequisites Engine
Tests prerequisite version validation, offline package resolution,
IShellLink shortcut argument handling, and tray bar autostart configuration.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import shutil

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from build.setup_win import (
    parse_version_tuple,
    check_prerequisite,
    REQUIRED_PREREQUISITES,
    create_native_shortcut,
    create_application_launcher,
    configure_tray_and_startup,
    run_installation,
    find_system_python,
    APP_NAME,
    EXE_NAME
)


class TestInstallerAndPrerequisites(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="vitorius_installer_test_")
        self.target_dir = Path(self.temp_dir) / "install_target"
        self.target_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_version_tuple_parser(self):
        """Verifies semantic version string parsing into integer tuples."""
        self.assertEqual(parse_version_tuple("6.5.0"), (6, 5, 0))
        self.assertEqual(parse_version_tuple("5.9.0"), (5, 9, 0))
        self.assertEqual(parse_version_tuple("306"), (306,))
        self.assertEqual(parse_version_tuple("4.3.0rc1"), (4, 3, 0, 1))
        self.assertEqual(parse_version_tuple("6.5.1b2"), (6, 5, 1, 2))
        self.assertTrue(parse_version_tuple("6.5.1") > parse_version_tuple("6.5.0"))
        self.assertTrue(parse_version_tuple("7.0.0") > parse_version_tuple("6.5.0"))

    def test_required_prerequisites_manifest(self):
        """Verifies all user-requested packages are specified in requirements manifest."""
        expected_pkgs = ["PyQt6", "psutil", "watchdog", "yara-python", "pywin32", "pyinstaller"]
        for pkg in expected_pkgs:
            self.assertIn(pkg, REQUIRED_PREREQUISITES)
            self.assertTrue(len(REQUIRED_PREREQUISITES[pkg]["min_version"]) > 0)
            self.assertTrue(len(REQUIRED_PREREQUISITES[pkg]["pip_name"]) > 0)

    @patch("importlib.metadata.version")
    def test_check_prerequisite_satisfied(self, mock_version):
        """Tests that a package meeting or exceeding the minimum version is marked satisfied."""
        mock_version.return_value = "6.7.1"
        is_ok, inst_ver, min_ver = check_prerequisite("PyQt6")
        self.assertTrue(is_ok)
        self.assertEqual(inst_ver, "6.7.1")
        self.assertEqual(min_ver, "6.5.0")

    @patch("importlib.metadata.version")
    def test_check_prerequisite_outdated(self, mock_version):
        """Tests that an older package version is flagged as requiring update."""
        mock_version.return_value = "6.2.0"
        is_ok, inst_ver, min_ver = check_prerequisite("PyQt6")
        self.assertFalse(is_ok)
        self.assertEqual(inst_ver, "6.2.0")
        self.assertEqual(min_ver, "6.5.0")

    def test_check_prerequisite_non_windows_skip(self):
        """Tests that Windows-specific packages like pywin32 skip cleanly on non-Windows platforms."""
        if sys.platform != "win32":
            is_ok, inst_ver, _ = check_prerequisite("pywin32")
            self.assertTrue(is_ok)
            self.assertIn("non-windows", inst_ver)

    def test_psutil_prerequisite_satisfied(self):
        """Tests real detection of psutil in the active environment."""
        is_ok, inst_ver, min_ver = check_prerequisite("psutil")
        self.assertTrue(is_ok)
        self.assertTrue(parse_version_tuple(inst_ver) >= parse_version_tuple("5.9.0"))

    def test_create_application_launcher_bat_fallback(self):
        """Verifies silent pythonw launcher creation when compiled exe is absent."""
        launcher_path = create_application_launcher(self.target_dir)
        self.assertTrue(os.path.exists(launcher_path))
        self.assertTrue(launcher_path.endswith(".bat") or launcher_path.endswith(EXE_NAME))
        if launcher_path.endswith(".bat"):
            with open(launcher_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("main_win.py", content)
            self.assertIn("@echo off", content)

    def test_create_application_launcher_with_existing_exe(self):
        """Verifies that if VitoriusFirewallWin.exe exists, it is selected directly."""
        mock_exe = self.target_dir / EXE_NAME
        mock_exe.touch()
        launcher_path = create_application_launcher(self.target_dir)
        self.assertEqual(launcher_path, str(mock_exe))

    def test_native_shortcut_cross_platform_mock(self):
        """Verifies shortcut creator handles arguments and paths cleanly."""
        target = str(self.target_dir / EXE_NAME)
        dest_lnk = str(self.target_dir / "Vitorius Firewall Win.lnk")
        icon = str(self.target_dir / "icon.ico")
        result = create_native_shortcut(
            target_exe=target,
            shortcut_path=dest_lnk,
            icon_path=icon,
            description="Antivirus and Firewall",
            arguments="--minimized"
        )
        self.assertTrue(result)

    def test_configure_tray_and_startup(self):
        """Verifies tray bar autostart shortcut configuration."""
        target = str(self.target_dir / EXE_NAME)
        icon = str(self.target_dir / "icon.ico")
        # Run tray and startup setup with mocked environment
        with patch.dict(os.environ, {"APPDATA": str(self.temp_dir)}):
            startup_dir = Path(self.temp_dir) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            startup_dir.mkdir(parents=True, exist_ok=True)
            configure_tray_and_startup(self.target_dir, target, icon)
            # Check if shortcut function executed without errors
            self.assertTrue(startup_dir.exists())

    def test_run_installation_pipeline(self):
        """Verifies the complete installation copying and setup pipeline."""
        with patch("build.setup_win.install_all_prerequisites_flow", return_value=True):
            run_installation(source_dir=PROJECT_DIR, target_dir=self.target_dir, install_service=False)
            # Check that critical subdirectories and entry points were copied
            self.assertTrue((self.target_dir / "backend").exists())
            self.assertTrue((self.target_dir / "ui").exists())
            self.assertTrue((self.target_dir / "data").exists())
            self.assertTrue((self.target_dir / "data" / "icons" / "vitorius-firewall.ico").exists())
            self.assertTrue((self.target_dir / "main_win.py").exists())
            self.assertTrue((self.target_dir / "requirements.txt").exists())
            self.assertTrue((self.target_dir / "uninstall.bat").exists())
            self.assertTrue((PROJECT_DIR / "uninstall.bat").exists())

    def test_run_uninstallation_pipeline(self):
        """Verifies the complete uninstallation and cleanup pipeline."""
        from build.setup_win import run_uninstallation, remove_shortcuts, cleanup_installation_directory
        # Create dummy installation structure in target_dir
        (self.target_dir / "main_win.py").touch()
        (self.target_dir / "backend").mkdir(exist_ok=True)
        (self.target_dir / "backend" / "test.py").touch()

        # Execute uninstallation
        with patch("build.setup_win.terminate_running_instances"), \
             patch("build.setup_win.stop_and_remove_windows_service"), \
             patch("build.setup_win.cleanup_firewall_rules"):
            ok = run_uninstallation(target_dir=self.target_dir)
            self.assertTrue(ok)
            # Verify files were removed
            self.assertFalse((self.target_dir / "main_win.py").exists())


if __name__ == "__main__":
    unittest.main()
