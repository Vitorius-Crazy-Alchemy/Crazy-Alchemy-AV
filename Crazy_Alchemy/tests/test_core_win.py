"""
Unit tests for Vitorius Firewall Win - Core Firewall Backend
"""

import unittest
from unittest.mock import patch, MagicMock
import subprocess
from backend.core_win import WindowsFirewallCore, RULE_PREFIX


class TestWindowsFirewallCore(unittest.TestCase):
    def setUp(self):
        self.core = WindowsFirewallCore()

    def test_cache_invalidation(self):
        self.core._cache['test_key'] = 123
        self.core._cache_time['test_key'] = 456.0
        self.core.invalidate_cache()
        self.assertEqual(len(self.core._cache), 0)
        self.assertEqual(len(self.core._cache_time), 0)

    @patch('backend.core_win._run_cmd')
    def test_is_running(self, mock_cmd):
        self.core.invalidate_cache()
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout="State ON\nOk.\n", stderr=""
        )
        self.assertTrue(self.core.is_running(force_refresh=True))

    @patch('backend.core_win._run_cmd')
    def test_panic_mode_enable(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout="Ok.\n", stderr=""
        )
        res = self.core.set_panic_mode(True)
        self.assertTrue(res)
        self.assertTrue(self.core._panic_active)

    @patch('backend.core_win._run_cmd')
    def test_panic_mode_disable(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout="Ok.\n", stderr=""
        )
        res = self.core.set_panic_mode(False)
        self.assertTrue(res)
        self.assertFalse(self.core._panic_active)

    @patch('backend.core_win._run_cmd_elevated', return_value=False)
    @patch('backend.core_win._send_service_ipc', return_value=None)
    @patch('backend.core_win._run_cmd')
    def test_panic_mode_elevation_failure_returns_false(self, mock_cmd, mock_ipc, mock_elev):
        # Simulate non-elevated failure (code 1)
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=1, stdout="", stderr="The requested operation requires elevation."
        )
        res = self.core.set_panic_mode(True)
        self.assertFalse(res)

    @patch('backend.core_win._run_cmd')
    def test_panic_mode_detected_via_allprofiles_policy(self, mock_cmd):
        def cmd_side_effect(cmd, **kwargs):
            if 'firewallpolicy' in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Firewall Policy BlockInbound,BlockOutbound\n", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="No rules match.", stderr="")
        mock_cmd.side_effect = cmd_side_effect
        self.assertTrue(self.core.get_panic_mode(force_refresh=True))

    @patch('backend.core_win._run_cmd')
    def test_add_port_rule(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout="Ok.\n", stderr=""
        )
        res = self.core.add_port_rule("443", "TCP", "allow", "in")
        self.assertTrue(res)
        called_args = mock_cmd.call_args[0][0]
        self.assertIn("localport=443", called_args)
        self.assertIn("protocol=TCP", called_args)

    @patch('backend.core_win._run_cmd')
    def test_block_ip(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout="Ok.\n", stderr=""
        )
        res = self.core.block_ip("198.51.100.25")
        self.assertTrue(res)
        self.assertEqual(mock_cmd.call_count, 2) # Inbound + Outbound block rules

    @patch('backend.core_win._run_cmd')
    def test_list_all_rules_parser(self, mock_cmd):
        sample_output = """
----------------------------------------------------------------------
Rule Name:                            VitoriusFW_Port_443_TCP_IN
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            443
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow
Ok.
"""
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout=sample_output, stderr=""
        )
        rules = self.core.list_all_rules(vitorius_only=True)
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(r['name'], "VitoriusFW_Port_443_TCP_IN")
        self.assertEqual(r['direction'], "in")
        self.assertEqual(r['action'], "allow")
        self.assertEqual(r['port'], "443")
        self.assertTrue(r['enabled'])

    @patch('backend.core_win._run_cmd')
    def test_localized_rules_parser(self, mock_cmd):
        # German Windows netsh output sample
        sample_german = """
----------------------------------------------------------------------
Regelname:                            VitoriusFW_Prof_Port_80_TCP
----------------------------------------------------------------------
Aktiviert:                            Ja
Richtung:                             Ein
Aktion:                               Zulassen
Protokoll:                            TCP
Lokaler_Port:                         80
Ok.
"""
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout=sample_german, stderr=""
        )
        rules = self.core.list_all_rules(vitorius_only=True)
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(r['name'], "VitoriusFW_Prof_Port_80_TCP")
        self.assertTrue(r['enabled'])
        self.assertEqual(r['direction'], "in")
        self.assertEqual(r['action'], "allow")

    @patch('backend.core_win._run_cmd')
    def test_apply_profile_rules_dict_format(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args=['netsh'], returncode=0, stdout="Ok.\n", stderr=""
        )
        profile_data = {
            "tier": "premium",
            "allowed_ports": [
                {"port": "443", "protocol": "tcp"},
                {"port": "8443", "protocol": "tcp"}
            ],
            "blocked_ips": ["198.51.100.1"],
            "allow_outbound": True
        }
        res = self.core.apply_profile_rules("Corporate", profile_data)
        self.assertTrue(res)
        # Verify that calls with localport=443 and localport=8443 were issued cleanly without syntax error
        calls_str = " ".join(str(call) for call in mock_cmd.call_args_list)
        self.assertIn("localport=443", calls_str)
        self.assertIn("localport=8443", calls_str)


if __name__ == '__main__':
    unittest.main()
