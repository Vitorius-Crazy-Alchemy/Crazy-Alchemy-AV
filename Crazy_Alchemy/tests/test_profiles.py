"""
Unit tests for Crazy Alchemy Security Profiles & Enforcement Engine.
Validates WindowsProfileManager CRUD, factory profiles, schema validation,
firewall rule translation, service mapping, port ranges, ICMP stealth, and posture switching.
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.profiles_win import (
    WindowsProfileManager,
    BUILTIN_FACTORY_PROFILES,
    backup_rules as module_backup_rules,
    restore_rules as module_restore_rules
)
from backend.core_win import (
    WindowsFirewallCore,
    KNOWN_SECURITY_SERVICES,
    _parse_port_spec,
    RULE_PREFIX
)


class TestWindowsProfileManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "test_config.json"
        self.mgr = WindowsProfileManager(config_file=self.config_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_profiles_loaded(self):
        """Verifies that all 5 factory security profiles are loaded and structured properly."""
        profiles = self.mgr.get_profiles()
        expected = ["Home", "Public", "Corporate", "Gaming", "Maximum Security"]
        for p in expected:
            self.assertIn(p, profiles, f"Factory profile {p} must be present")
            data = profiles[p]
            self.assertIn("tier", data)
            self.assertIn("allowed_services", data)
            self.assertIn("allowed_ports", data)
            self.assertIn("icmp_block", data)
            self.assertIn("block_inbound", data)
            self.assertIn("allow_outbound", data)

    def test_active_profile_getter_setter(self):
        """Tests active profile retrieval, switching, and invalid profile rejection."""
        self.assertEqual(self.mgr.get_active_profile(), "Home")
        self.assertTrue(self.mgr.set_active_profile("Gaming"))
        self.assertEqual(self.mgr.get_active_profile(), "Gaming")

        # Switching to non-existent profile should fail
        self.assertFalse(self.mgr.set_active_profile("NonExistentProfile_XYZ"))
        self.assertEqual(self.mgr.get_active_profile(), "Gaming")

    def test_schema_validation(self):
        """Tests validation of profile schema."""
        # Valid profile
        valid_prof = {
            "description": "Test profile",
            "tier": "custom",
            "icmp_block": True,
            "block_inbound": True,
            "allow_outbound": False,
            "allowed_services": ["DNS", "HTTPS"],
            "allowed_ports": [443, "8080/tcp"],
            "blocked_ports": [21, 23]
        }
        is_valid, msg = self.mgr.validate_profile_schema(valid_prof)
        self.assertTrue(is_valid, msg)

        # Invalid: not a dict
        is_valid, _ = self.mgr.validate_profile_schema("not_a_dict")
        self.assertFalse(is_valid)

        # Invalid: icmp_block not bool
        invalid_prof = dict(valid_prof)
        invalid_prof["icmp_block"] = "not_bool"
        is_valid, _ = self.mgr.validate_profile_schema(invalid_prof)
        self.assertFalse(is_valid)

        # Invalid: allowed_services not list
        invalid_prof2 = dict(valid_prof)
        invalid_prof2["allowed_services"] = "single_string"
        is_valid, _ = self.mgr.validate_profile_schema(invalid_prof2)
        self.assertFalse(is_valid)

    def test_create_and_get_custom_profile(self):
        """Tests creating a valid custom profile and verifying persistence."""
        custom_data = {
            "description": "Lab environment for network testing",
            "tier": "custom",
            "allowed_services": ["CoreNetworking", "SSH"],
            "allowed_ports": ["22/tcp", "8080/tcp"],
            "blocked_ports": ["445/tcp"],
            "icmp_block": True,
            "block_inbound": True,
            "allow_outbound": True
        }
        ok, msg = self.mgr.create_profile("Lab", custom_data)
        self.assertTrue(ok, msg)

        retrieved = self.mgr.get_profile("Lab")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["description"], custom_data["description"])
        self.assertEqual(retrieved["tier"], "custom")
        self.assertIn("SSH", retrieved["allowed_services"])
        self.assertTrue(retrieved["icmp_block"])

        # Duplicate creation must fail
        ok2, msg2 = self.mgr.create_profile("Lab", custom_data)
        self.assertFalse(ok2)
        self.assertIn("already exists", msg2)

    def test_update_profile(self):
        """Tests updating an existing profile and rejecting non-existent profile updates."""
        ok, msg = self.mgr.update_profile("Gaming", {
            "description": "Ultra low-latency gaming posture",
            "icmp_block": True
        })
        self.assertTrue(ok, msg)
        updated = self.mgr.get_profile("Gaming")
        self.assertEqual(updated["description"], "Ultra low-latency gaming posture")
        self.assertTrue(updated["icmp_block"])

        # Update non-existent profile
        ok2, msg2 = self.mgr.update_profile("NonExistentProfile", {"tier": "custom"})
        self.assertFalse(ok2)

    def test_delete_profile(self):
        """Tests deleting custom profiles and protecting active/factory profiles."""
        self.mgr.create_profile("DevProfile", {"description": "Temporary"})

        # Cannot delete factory built-in profile without force
        ok_fact, _ = self.mgr.delete_profile("Home")
        self.assertFalse(ok_fact)
        self.assertIn("Home", self.mgr.get_profiles())

        # Cannot delete active profile
        self.mgr.set_active_profile("DevProfile")
        ok_act, msg_act = self.mgr.delete_profile("DevProfile")
        self.assertFalse(ok_act)
        self.assertIn("currently active", msg_act)

        # Switch away and then delete custom profile
        self.mgr.set_active_profile("Home")
        ok_del, _ = self.mgr.delete_profile("DevProfile")
        self.assertTrue(ok_del)
        self.assertNotIn("DevProfile", self.mgr.get_profiles())

    def test_reset_profiles_to_default(self):
        """Tests resetting all profile configurations back to defaults."""
        self.mgr.create_profile("CustomTemp", {"description": "Temp"})
        self.assertIn("CustomTemp", self.mgr.get_profiles())

        res = self.mgr.reset_profiles_to_default()
        self.assertTrue(res)
        profiles = self.mgr.get_profiles()
        self.assertNotIn("CustomTemp", profiles)
        self.assertIn("Home", profiles)
        self.assertIn("Maximum Security", profiles)

    def test_export_and_import_profile(self):
        """Tests exporting a profile to JSON and importing it back."""
        export_path = Path(self.temp_dir.name) / "exported_corporate.json"
        res_exp = self.mgr.export_profile("Corporate", str(export_path))
        self.assertTrue(res_exp)
        self.assertTrue(export_path.exists())

        with open(export_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data["profile_name"], "Corporate")
        self.assertIn("profile_data", data)

        # Import as a new profile by renaming JSON content
        data["profile_name"] = "Corporate_Imported"
        import_path = Path(self.temp_dir.name) / "import_test.json"
        with open(import_path, 'w', encoding='utf-8') as f:
            json.dump(data, f)

        res_imp, msg, p_name = self.mgr.import_profile(str(import_path))
        self.assertTrue(res_imp, msg)
        self.assertEqual(p_name, "Corporate_Imported")
        self.assertIn("Corporate_Imported", self.mgr.get_profiles())

    def test_backup_and_restore_rules_methods_exist(self):
        """Verifies that backup_rules and restore_rules exist on WindowsProfileManager."""
        self.assertTrue(hasattr(self.mgr, "backup_rules"), "backup_rules must be a method on WindowsProfileManager")
        self.assertTrue(hasattr(self.mgr, "restore_rules"), "restore_rules must be a method on WindowsProfileManager")
        self.assertTrue(callable(self.mgr.backup_rules))
        self.assertTrue(callable(self.mgr.restore_rules))

        # Check module-level aliases
        self.assertTrue(callable(module_backup_rules))
        self.assertTrue(callable(module_restore_rules))


class TestPortParser(unittest.TestCase):
    def test_parse_various_port_formats(self):
        """Tests _parse_port_spec with dict, str, int, and port ranges."""
        # Int
        res1 = _parse_port_spec(80)
        self.assertEqual(res1, ("80", "TCP", "in"))

        # String single port
        res2 = _parse_port_spec("443")
        self.assertEqual(res2, ("443", "TCP", "in"))

        # String port with proto
        res3 = _parse_port_spec("53/udp")
        self.assertEqual(res3, ("53", "UDP", "in"))

        # String port range
        res4 = _parse_port_spec("27015-27030/tcp")
        self.assertEqual(res4, ("27015-27030", "TCP", "in"))

        # Dict format
        res5 = _parse_port_spec({"port": "8080", "protocol": "tcp", "direction": "out"})
        self.assertEqual(res5, ("8080", "TCP", "out"))

        # Dict port range
        res6 = _parse_port_spec({"port": "27000-27100", "protocol": "udp"})
        self.assertEqual(res6, ("27000-27100", "UDP", "in"))

        # Invalid formats
        self.assertIsNone(_parse_port_spec(None))
        self.assertIsNone(_parse_port_spec(""))
        self.assertIsNone(_parse_port_spec({"port": ""}))


class TestCoreProfileRulesEnforcement(unittest.TestCase):
    def setUp(self):
        self.core = WindowsFirewallCore()

    @patch('backend.core_win._run_cmd')
    def test_apply_home_profile(self, mock_cmd):
        """
        Tests Home profile application:
        Must permit FileAndPrinterSharing, mDNS, CoreNetworking, RemoteDesktopLocal.
        Must allow ICMP ping echo (icmp_block: false).
        Must set blockinbound,allowoutbound.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
        home_data = BUILTIN_FACTORY_PROFILES["Home"]
        ok = self.core.apply_profile_rules("Home", home_data)
        self.assertTrue(ok)

        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)

        # Verify services applied
        self.assertIn("Prof_Svc_FileAndPrinterSharing", calls_str)
        self.assertIn("Prof_Svc_mDNS", calls_str)
        self.assertIn("Prof_Svc_CoreNetworking", calls_str)
        self.assertIn("Prof_Svc_RemoteDesktopLocal", calls_str)

        # SMB port 445 and NetBIOS ports
        self.assertIn("445", calls_str)
        self.assertIn("5353", calls_str)  # mDNS port

        # ICMP should be unblocked (delete rule called)
        self.assertIn("Block_ICMPv4_Echo", calls_str)
        self.assertIn("delete", calls_str)

        # Posture: blockinbound,allowoutbound
        self.assertIn("blockinbound,allowoutbound", calls_str)

    @patch('backend.core_win._run_cmd')
    def test_apply_public_profile(self, mock_cmd):
        """
        Tests Public profile application:
        Untrusted network posture: drops ICMP ping, permits only CoreNetworking,
        blocks inbound, allows normal outbound.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
        pub_data = BUILTIN_FACTORY_PROFILES["Public"]
        ok = self.core.apply_profile_rules("Public", pub_data)
        self.assertTrue(ok)

        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)

        # CoreNetworking applied
        self.assertIn("Prof_Svc_CoreNetworking", calls_str)
        # Local sharing NOT allowed
        self.assertNotIn("Prof_Svc_FileAndPrinterSharing", calls_str)
        self.assertNotIn("Prof_Svc_mDNS", calls_str)

        # ICMP Stealth: ping dropped (icmpv4:8,any)
        self.assertIn("protocol=icmpv4:8,any", calls_str)

    @patch('backend.core_win._run_cmd')
    def test_apply_corporate_profile(self, mock_cmd):
        """
        Tests Corporate profile application:
        SOC2 compliant posture: strict outbound whitelisting (allow_outbound: false),
        explicit HTTPS/DNS, ICMP ping blocked.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
        corp_data = BUILTIN_FACTORY_PROFILES["Corporate"]
        ok = self.core.apply_profile_rules("Corporate", corp_data)
        self.assertTrue(ok)

        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)

        # Posture: blockinbound,blockoutbound
        self.assertIn("blockinbound,blockoutbound", calls_str)

        # Essential outbound DNS and HTTPS
        self.assertIn("Prof_Essential_DNS", calls_str)
        self.assertIn("Prof_Essential_HTTPS", calls_str)

        # Allowed ports 443 and 8443
        self.assertIn("localport=443", calls_str)
        self.assertIn("localport=8443", calls_str)

        # ICMP blocked
        self.assertIn("protocol=icmpv4:8,any", calls_str)

    @patch('backend.core_win._run_cmd')
    def test_apply_gaming_profile(self, mock_cmd):
        """
        Tests Gaming profile application:
        SteamClient services and port ranges (27015-27030, 27000-27100, 3478-3480, 4380, 3074).
        ICMP ping allowed for latency diagnostics.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
        gaming_data = BUILTIN_FACTORY_PROFILES["Gaming"]
        ok = self.core.apply_profile_rules("Gaming", gaming_data)
        self.assertTrue(ok)

        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)

        # SteamClient services and port ranges
        self.assertIn("localport=27015-27030", calls_str)
        self.assertIn("localport=27000-27100", calls_str)
        self.assertIn("localport=3478-3480", calls_str)
        self.assertIn("localport=4380", calls_str)
        self.assertIn("localport=3074", calls_str)

        # ICMP ping unblocked
        self.assertIn("Block_ICMPv4_Echo", calls_str)

    @patch('backend.core_win._run_cmd')
    def test_apply_maximum_security_profile(self, mock_cmd):
        """
        Tests Maximum Security profile application:
        HIPAA grade complete fortress lockdown.
        All incoming blocked, all outgoing blocked except whitelisted DNS/HTTPS, ICMP dropped.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
        max_data = BUILTIN_FACTORY_PROFILES["Maximum Security"]
        ok = self.core.apply_profile_rules("Maximum Security", max_data)
        self.assertTrue(ok)

        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)

        # Complete lockdown policy
        self.assertIn("blockinbound,blockoutbound", calls_str)

        # Essential whitelisted ports
        self.assertIn("localport=443", calls_str)
        self.assertIn("localport=53", calls_str)

        # ICMP ping dropped
        self.assertIn("protocol=icmpv4:8,any", calls_str)

    @patch('backend.core_win._run_cmd')
    def test_apply_custom_profile_with_blocked_ports_and_ips(self, mock_cmd):
        """
        Tests applying a custom profile containing blocked ports and blocked IPs.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
        custom_data = {
            "tier": "standard",
            "allowed_ports": ["8080/tcp"],
            "blocked_ports": ["445/tcp", "21/tcp"],
            "blocked_ips": ["198.51.100.99"],
            "icmp_block": True,
            "block_inbound": True,
            "allow_outbound": True
        }
        ok = self.core.apply_profile_rules("CustomSecurity", custom_data)
        self.assertTrue(ok)

        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)

        # Allowed port 8080
        self.assertIn("localport=8080", calls_str)
        self.assertIn("action=allow", calls_str)

        # Blocked ports 445 and 21
        self.assertIn("localport=445", calls_str)
        self.assertIn("localport=21", calls_str)
        self.assertIn("Prof_BlockPort", calls_str)

        # Blocked IP
        self.assertIn("198.51.100.99", calls_str)


class TestAppSwitchProfileIntegration(unittest.TestCase):
    def test_switch_profile_triggers_exploit_shield_and_backup(self):
        """Tests that switch_profile synchronizes exploit hardening and creates pre-switch backup."""
        from ui.app_win import VitoriusFirewallMainWindow

        main_win = MagicMock()
        main_win.profiles = WindowsProfileManager(config_file=Path(tempfile.gettempdir()) / "switch_test.json")
        main_win.profiles.backup_rules = MagicMock(return_value="C:\\fake_backup.wfw")
        main_win.profiles.get_setting = MagicMock(return_value=True)
        main_win.fw_core = MagicMock()
        main_win.fw_logger = MagicMock()
        main_win.exploit_shield = MagicMock()
        main_win.tray = MagicMock()
        main_win._update_status_ui = MagicMock()

        # Call real switch_profile logic
        VitoriusFirewallMainWindow.switch_profile(main_win, "Maximum Security")

        # Verify backup was requested
        main_win.profiles.backup_rules.assert_called_once()

        # Verify profile was set
        self.assertEqual(main_win.profiles.get_active_profile(), "Maximum Security")

        # Verify firewall rules applied
        main_win.fw_core.apply_profile_rules.assert_called_once()
        args = main_win.fw_core.apply_profile_rules.call_args[0]
        self.assertEqual(args[0], "Maximum Security")

        # Verify exploit shield received "Strict" hardening
        main_win.exploit_shield.apply_hardening_profile.assert_called_once_with("Strict")

        # Verify audit log recorded
        main_win.fw_logger.log_event.assert_called()

        # Switch to Gaming profile -> verify exploit shield receives "Audit"
        main_win.exploit_shield.reset_mock()
        VitoriusFirewallMainWindow.switch_profile(main_win, "Gaming")
        main_win.exploit_shield.apply_hardening_profile.assert_called_once_with("Audit")


if __name__ == '__main__':
    unittest.main()
