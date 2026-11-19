"""
Unit tests for Crazy Alchemy - Windows Defender Coexistence & Setting Propagation Engine
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from backend.profiles_win import FirewallLogger
from backend.defender_manager import (
    WindowsDefenderManager,
    DEFENDER_MODE_DISABLED,
    DEFENDER_MODE_PASSIVE,
    DEFENDER_MODE_ACTIVE,
    ALLOWED_DEFENDER_MODES,
    is_tamper_protection_enabled,
    open_tamper_protection_settings,
    get_defender_am_running_mode,
    get_live_defender_status,
    get_crazy_alchemy_exclusion_targets
)
from backend.exploit_shield import ExploitShield
from backend.core_win import WindowsFirewallCore
from backend.profiles_win import WindowsProfileManager


class TestDefenderManager(unittest.TestCase):
    def setUp(self):
        self.mock_logger = MagicMock(spec=FirewallLogger)
        self.mgr = WindowsDefenderManager(fw_logger=self.mock_logger)

    def test_allowed_modes(self):
        """Verifies allowed coexistence modes."""
        self.assertIn("disabled", ALLOWED_DEFENDER_MODES)
        self.assertIn("passive_secondary", ALLOWED_DEFENDER_MODES)
        self.assertIn("active_coexist", ALLOWED_DEFENDER_MODES)

    def test_set_defender_mode_disabled(self):
        """Verifies completely disabling Windows Defender Antivirus."""
        ok = self.mgr.set_defender_mode(DEFENDER_MODE_DISABLED)
        self.assertTrue(ok)

        status = self.mgr.get_status()
        self.assertEqual(status["mode"], DEFENDER_MODE_DISABLED)
        self.assertFalse(status["realtime_monitoring"])
        self.assertFalse(status["limited_periodic_scanning"])
        self.assertTrue(status["antispyware_disabled"])
        self.mock_logger.log_event.assert_called()

    def test_set_defender_mode_passive_secondary(self):
        """Verifies configuring Defender as passive background secondary scanner."""
        ok = self.mgr.set_defender_mode(DEFENDER_MODE_PASSIVE)
        self.assertTrue(ok)

        status = self.mgr.get_status()
        self.assertEqual(status["mode"], DEFENDER_MODE_PASSIVE)
        self.assertFalse(status["realtime_monitoring"])  # No duplicate on-access file hooks
        self.assertTrue(status["limited_periodic_scanning"])  # Secondary background scanner
        self.assertTrue(status["passive_mode"])

    def test_set_defender_mode_active_coexist(self):
        """Verifies enabling parallel coexistence."""
        ok = self.mgr.set_defender_mode(DEFENDER_MODE_ACTIVE)
        self.assertTrue(ok)

        status = self.mgr.get_status()
        self.assertEqual(status["mode"], DEFENDER_MODE_ACTIVE)
        self.assertTrue(status["realtime_monitoring"])
        self.assertFalse(status["limited_periodic_scanning"])

    def test_invalid_mode_rejected(self):
        """Verifies invalid modes are safely rejected."""
        self.assertFalse(self.mgr.set_defender_mode("invalid_mode_xyz"))

    def test_propagate_exploit_protection_settings(self):
        """Verifies exploit protection changes immediately propagate to the Windows kernel."""
        mock_exploit = MagicMock(spec=ExploitShield)
        mock_profiles = MagicMock(spec=WindowsProfileManager)
        mock_profiles.get_setting.return_value = "Strict"

        # 1. Enable exploit shield
        self.mgr.propagate_setting("anti_exploit_enabled", True, exploit_shield=mock_exploit, profiles=mock_profiles)
        mock_exploit.apply_hardening_profile.assert_called_with("Strict")
        mock_exploit.start.assert_called_once()

        # 2. Disable exploit shield
        self.mgr.propagate_setting("anti_exploit_enabled", False, exploit_shield=mock_exploit, profiles=mock_profiles)
        mock_exploit.stop.assert_called_once()

        # 3. Change profile
        self.mgr.propagate_setting("anti_exploit_profile", "Recommended", exploit_shield=mock_exploit)
        mock_exploit.apply_hardening_profile.assert_called_with("Recommended")

    def test_propagate_realtime_antivirus_conflict_avoidance(self):
        """Verifies that activating Crazy Alchemy shield synchronizes Defender to eliminate duplicate hooks."""
        mock_profiles = MagicMock(spec=WindowsProfileManager)
        mock_profiles.get_setting.return_value = DEFENDER_MODE_PASSIVE

        # When Realtime Shield is turned ON, Defender is synchronized to passive mode
        self.mgr.propagate_setting("realtime_antivirus", True, profiles=mock_profiles)
        self.assertEqual(self.mgr.get_status()["mode"], DEFENDER_MODE_PASSIVE)

        # When Realtime Shield is turned OFF, Defender is restored if it was passive
        self.mgr.propagate_setting("realtime_antivirus", False, profiles=mock_profiles)
        self.assertEqual(self.mgr.get_status()["mode"], DEFENDER_MODE_ACTIVE)

    def test_propagate_firewall_and_system_settings(self):
        """Verifies firewall ICMP stealth and startup settings propagate to Windows."""
        mock_core = MagicMock(spec=WindowsFirewallCore)
        mock_profiles = MagicMock(spec=WindowsProfileManager)

        self.mgr.propagate_setting("block_icmp", True, fw_core=mock_core)
        mock_core.block_icmp.assert_called_with(True)

        self.mgr.propagate_setting("start_with_system", True, profiles=mock_profiles)
        mock_profiles.set_autostart.assert_called_with(True)

    def test_crazy_alchemy_exclusion_targets(self):
        """Verifies exclusion targets include project paths and executable binaries."""
        paths, procs = get_crazy_alchemy_exclusion_targets()
        self.assertIsInstance(paths, list)
        self.assertIsInstance(procs, list)
        self.assertTrue(len(paths) > 0)
        self.assertIn("crazy alchemy.exe", procs)
        self.assertIn("python.exe", procs)

    def test_tamper_protection_detection(self):
        """Verifies tamper protection check returns boolean without errors."""
        tp = is_tamper_protection_enabled()
        self.assertIsInstance(tp, bool)

    def test_open_tamper_protection_settings(self):
        """Verifies opening threat settings via Windows Security URI."""
        with patch("os.startfile", return_value=True) as mock_start:
            ok = open_tamper_protection_settings()
            self.assertTrue(ok)
            mock_start.assert_called_once_with("windowsdefender://threatsettings")

    def test_get_live_defender_status(self):
        """Verifies live Defender status dictionary schema."""
        status = get_live_defender_status()
        self.assertIsInstance(status, dict)
        self.assertIn("realtime_protection_enabled", status)
        self.assertIn("behavior_monitor_enabled", status)
        self.assertIn("tamper_protection_active", status)
        self.assertIn("am_running_mode", status)

    def test_configure_mutual_exclusions(self):
        """Verifies mutual exclusions configuration execution."""
        ok = self.mgr.configure_mutual_exclusions()
        self.assertIsInstance(ok, bool)
        self.assertTrue(self.mgr.get_status()["mutual_exclusions_configured"])


if __name__ == "__main__":
    unittest.main()
