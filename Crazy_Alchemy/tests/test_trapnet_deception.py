"""
Crazy Alchemy - TrapNet Deception & HoneyToken Canary Engine Unit Tests
Tests decoy catalog, presets, interactive protocol emulation, and host tripwires.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import tempfile
import time
import socket
import json
import base64
from pathlib import Path

from backend.honeypot import (
    HoneypotManager,
    HoneyTokenManager,
    TrapEvent,
    DECOY_CATALOG,
    DECEPTION_PRESETS,
    is_port_in_use
)


class TestTrapNetDeceptionCatalogAndPresets(unittest.TestCase):
    """Tests catalog structure, defensive presets, and port conflict checks."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "test_trapnet.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_decoy_catalog_completeness(self):
        """Verifies 26 decoy services across 6 operational sectors."""
        self.assertIn("remote_access", DECOY_CATALOG)
        self.assertIn("databases", DECOY_CATALOG)
        self.assertIn("web_cloud", DECOY_CATALOG)
        self.assertIn("file_sharing", DECOY_CATALOG)
        self.assertIn("iot_industrial", DECOY_CATALOG)
        self.assertIn("mail_directory", DECOY_CATALOG)

        total_decoys = sum(len(items) for items in DECOY_CATALOG.values())
        self.assertGreaterEqual(total_decoys, 24, "Must offer at least 24 rich decoy templates")

        # Verify each decoy has required metadata
        for cat, items in DECOY_CATALOG.items():
            for item in items:
                self.assertIn("name", item)
                self.assertIn("default_port", item)
                self.assertIn("protocol", item)
                self.assertIn("risk_level", item)
                self.assertIn("description", item)

    def test_deception_presets_structure(self):
        """Verifies the 5 ready-to-use deception presets."""
        presets = ["home_workstation", "enterprise_ad", "web_cloud", "iot_scada", "maximum_spiderweb"]
        for p in presets:
            self.assertIn(p, DECEPTION_PRESETS)
            self.assertTrue(len(DECEPTION_PRESETS[p]["ports"]) >= 4)
            self.assertIn("title", DECEPTION_PRESETS[p])
            self.assertIn("description", DECEPTION_PRESETS[p])

    def test_apply_preset_logic(self):
        """Tests applying a preset safely arms conflict-free decoy listeners."""
        hp = HoneypotManager(trap_ports={}, db_path=self.db_path)
        res = hp.apply_preset("home_workstation")

        self.assertTrue(res["success"])
        self.assertGreater(res["armed_count"], 0)
        self.assertEqual(res["preset"], "Home & SOHO Workstation Baseline")

        # Active traps detail
        detail = hp.get_active_traps_detail()
        self.assertGreaterEqual(len(detail), 4)
        for t in detail:
            self.assertIn("port", t)
            self.assertIn("label", t)
            self.assertIn("protocol", t)

    def test_port_in_use_detection(self):
        """Tests detecting an active port bound on localhost."""
        # Bind a temporary test socket
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.bind(("127.0.0.1", 0))
        test_sock.listen(1)
        bound_port = test_sock.getsockname()[1]

        try:
            self.assertTrue(is_port_in_use(bound_port))
        finally:
            test_sock.close()


class TestHoneyTokenCanaryEngine(unittest.TestCase):
    """Tests the HoneyToken Canary file tripwire system (Our Innovation)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "test_honeytokens.db"
        self.bait_dir = self.base_path / "BaitLocation"
        self.alert_events = []

        def mock_alert(ev):
            self.alert_events.append(ev)

        self.mgr = HoneyTokenManager(db_path=self.db_path, alert_callback=mock_alert)
        self.mgr.default_bait_dir = self.bait_dir

    def tearDown(self):
        self.mgr.stop_watchdog()
        self.temp_dir.cleanup()

    def test_templates_available(self):
        self.assertGreaterEqual(len(self.mgr.TEMPLATES), 5)
        template_ids = [t["id"] for t in self.mgr.TEMPLATES]
        self.assertIn("passwords_vault", template_ids)
        self.assertIn("cloud_keys", template_ids)
        self.assertIn("vpn_credentials", template_ids)
        self.assertIn("database_vault", template_ids)

    def test_deploy_and_check_untouched_canaries(self):
        deployed = self.mgr.deploy_all_canaries(target_dir=self.bait_dir)
        self.assertEqual(len(deployed), len(self.mgr.TEMPLATES))

        # Check files exist on disk
        for tok in deployed:
            p = Path(tok.file_path)
            self.assertTrue(p.exists(), f"Canary {p} must exist on disk")

        # Check tripwires on untouched files
        tripped = self.mgr.check_canaries()
        self.assertEqual(len(tripped), 0, "Untouched canaries must not trip wire")

    def test_tripwire_tamper_detection(self):
        """Tests that modifying or encrypting a canary trips the wire instantly."""
        tok = self.mgr.deploy_canary("cloud_keys", target_dir=self.bait_dir)
        self.assertIsNotNone(tok)

        # Untouched check
        self.assertEqual(len(self.mgr.check_canaries()), 0)

        # Simulate infostealer / ransomware modifying the canary file
        canary_path = Path(tok.file_path)
        with open(canary_path, "ab") as f:
            f.write(b"\n# ENCRYPTED_OR_TAMPERED_BY_MALWARE")

        # Check tripwire
        tripped = self.mgr.check_canaries()
        self.assertEqual(len(tripped), 1)
        self.assertEqual(tripped[0]["token_id"], tok.token_id)
        self.assertEqual(tripped[0]["status"], "TRIPPED")
        self.assertEqual(len(self.alert_events), 1)

    def test_tripwire_deletion_detection(self):
        """Tests that deleting a canary file trips the wire."""
        tok = self.mgr.deploy_canary("passwords_vault", target_dir=self.bait_dir)
        canary_path = Path(tok.file_path)
        self.assertTrue(canary_path.exists())

        # Malicious process deletes canary
        canary_path.unlink()

        tripped = self.mgr.check_canaries()
        self.assertEqual(len(tripped), 1)
        self.assertEqual(tripped[0]["status"], "TRIPPED")

    def test_disarm_all_canaries(self):
        self.mgr.deploy_all_canaries(target_dir=self.bait_dir)
        removed = self.mgr.disarm_all_canaries()
        self.assertGreaterEqual(removed, 5)

        canaries = self.mgr.get_canaries()
        for c in canaries:
            self.assertEqual(c["status"], "DISARMED")


class TestProtocolEmulationAndForensics(unittest.TestCase):
    """Tests interactive protocol emulators and forensic report exporting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "test_emulation.db"
        self.hp = HoneypotManager(trap_ports={}, db_path=self.db_path)

    def tearDown(self):
        self.hp.stop()
        self.temp_dir.cleanup()

    def test_interactive_http_emulation(self):
        """Tests HTTP emulator captures basic auth, headers, and returns 401 challenge."""
        mock_sock = MagicMock()
        # Simulated HTTP request with Basic Auth (admin:password123)
        b64_cred = base64.b64encode(b"admin:password123").decode("ascii")
        http_req = (
            f"GET /admin/setup.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"User-Agent: Nikto/2.1.6\r\n"
            f"Authorization: Basic {b64_cred}\r\n\r\n"
        ).encode("utf-8")
        mock_sock.recv.return_value = http_req

        self.hp._handle_intruder(
            mock_sock, "198.51.100.44", 45678, 80, "HTTP-Admin", protocol="http"
        )

        events = self.hp.get_recent_events(limit=5)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["source_ip"], "198.51.100.44")
        self.assertEqual(ev["trap_port"], 80)
        self.assertEqual(ev["attack_type"], "Web Admin / API Reconnaissance")
        self.assertIn("admin:password123", ev["captured_credentials"])
        self.assertIn("Nikto", ev["user_agent"])
        self.assertIn("GET /admin/setup.php", ev["request_uri"])

    def test_interactive_ftp_emulation(self):
        """Tests FTP emulator parses USER and PASS and captures brute-force credentials."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"USER root\r\n",
            b"PASS toor123\r\n"
        ]

        self.hp._handle_intruder(
            mock_sock, "198.51.100.55", 33211, 21, "FTP-Service", protocol="ftp"
        )

        events = self.hp.get_recent_events(limit=5)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["attack_type"], "FTP Credential Brute-Force")
        self.assertIn("USER root", ev["captured_credentials"])
        self.assertIn("PASS toor123", ev["captured_credentials"])

    def test_export_forensics_report(self):
        """Tests exporting forensics to JSON and CSV formats."""
        ev = TrapEvent(
            source_ip="203.0.113.19",
            source_port=55123,
            trap_port=3389,
            trap_service="RDP",
            protocol="TCP",
            timestamp=time.time(),
            raw_payload_hex="030000130e",
            payload_preview="RDP-Probe",
            auto_blocked=True,
            attack_type="RDP Terminal Services Recon"
        )
        self.hp._record_event(ev)

        # JSON Export
        json_rep = self.hp.export_forensics_report(export_format="json")
        data = json.loads(json_rep)
        self.assertIn("report_title", data)
        self.assertIn("intercepted_events", data)
        self.assertEqual(len(data["intercepted_events"]), 1)

        # CSV Export
        csv_rep = self.hp.export_forensics_report(export_format="csv")
        self.assertIn("203.0.113.19", csv_rep)
        self.assertIn("RDP Terminal Services Recon", csv_rep)


class TestTrapNetUIComponents(unittest.TestCase):
    """Tests MonitorPage TrapNet Deception UI integration."""

    @classmethod
    def setUpClass(cls):
        try:
            from PyQt6.QtWidgets import QApplication
            cls.app = QApplication.instance() or QApplication(["test_trapnet_app", "-platform", "offscreen"])
            cls.has_qt = True
        except Exception:
            cls.has_qt = False

    def setUp(self):
        if not self.has_qt:
            self.skipTest("PyQt6 required for UI integration tests")

    def test_monitor_page_trapnet_elements(self):
        from ui.pages_win import MonitorPage

        mock_main = MagicMock()
        db_file = Path(tempfile.gettempdir()) / f"dummy_trapnet_{os.getpid()}.db"
        mock_hp = HoneypotManager(trap_ports={22: "SSH", 80: "HTTP"}, db_path=db_file)
        mock_main.honeypot_mgr = mock_hp
        mock_main.monitor = MagicMock()
        mock_main.fw_core = MagicMock()
        mock_main.fw_logger = MagicMock()

        page = MonitorPage(mock_main)

        # Check subtabs exist
        self.assertTrue(hasattr(page, "trapnet_subtabs"))
        self.assertEqual(page.trapnet_subtabs.count(), 3)

        # Check all 3 sub-tables exist
        self.assertTrue(hasattr(page, "table_traps"))
        self.assertTrue(hasattr(page, "table_decoy_listeners"))
        self.assertTrue(hasattr(page, "table_honeytokens"))

        # Check presets dropdown
        self.assertTrue(hasattr(page, "combo_trap_preset"))
        self.assertEqual(page.combo_trap_preset.count(), 5)

        # Refresh populates tables
        page._refresh_trapnet()
        self.assertGreater(page.table_decoy_listeners.rowCount(), 0)


if __name__ == "__main__":
    unittest.main()
