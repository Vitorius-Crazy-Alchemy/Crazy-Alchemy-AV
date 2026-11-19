"""
Unit tests for Vitorius Antivirus - Email Client Antivirus Shield
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.antivirus import AntivirusEngine, QuarantineManager, ThreatDetection
from backend.profiles_win import FirewallLogger
from backend.email_shield import EmailClientShield, EmailAttachmentHandler, DANGEROUS_EXTENSIONS


class TestEmailShield(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.quarantine_dir = self.base_path / "Quarantine"
        self.qm = QuarantineManager(quarantine_dir=self.quarantine_dir)

        # Mock or use AntivirusEngine
        self.mock_engine = MagicMock(spec=AntivirusEngine)
        self.mock_engine.quarantine = self.qm
        self.mock_engine.scan_file.return_value = None

        self.mock_logger = MagicMock(spec=FirewallLogger)
        self.alert_calls = []

        def _alert_cb(threat, client, reason):
            self.alert_calls.append((threat, client, reason))

        self.shield = EmailClientShield(
            av_engine=self.mock_engine,
            fw_logger=self.mock_logger,
            alert_callback=_alert_cb,
            enabled_clients=["outlook", "thunderbird"]
        )

    def tearDown(self):
        self.shield.stop()
        self.temp_dir.cleanup()

    def test_supported_clients_metadata(self):
        """Verify supported client definitions and configuration."""
        clients = self.shield.get_supported_clients()
        client_ids = [c["id"] for c in clients]

        self.assertIn("outlook", client_ids)
        self.assertIn("thunderbird", client_ids)
        self.assertIn("winmail", client_ids)
        self.assertIn("emclient", client_ids)
        self.assertIn("mailbird", client_ids)

        # Outlook should be monitored, emclient should not be by default in our setup
        outlook_info = next(c for c in clients if c["id"] == "outlook")
        self.assertTrue(outlook_info["is_monitored"])
        self.assertIn("outlook.exe", outlook_info["process_names"])

        emclient_info = next(c for c in clients if c["id"] == "emclient")
        self.assertFalse(emclient_info["is_monitored"])

    def test_toggle_client_monitoring(self):
        """Verify dynamic enabling and disabling of monitored clients."""
        self.assertNotIn("emclient", self.shield.enabled_clients)
        self.shield.set_client_monitored("emclient", True)
        self.assertIn("emclient", self.shield.enabled_clients)

        self.shield.set_client_monitored("emclient", False)
        self.assertNotIn("emclient", self.shield.enabled_clients)

    def test_clean_attachment_pass_through(self):
        """Verify that benign attachments are not flagged or quarantined."""
        clean_file = self.base_path / "document.pdf"
        clean_file.write_bytes(b"%PDF-1.5 test safe document")

        threat = self.shield.inspect_attachment(str(clean_file), client_name="Microsoft Outlook")
        self.assertIsNone(threat)
        self.assertTrue(clean_file.exists())
        self.assertEqual(len(self.alert_calls), 0)

        stats = self.shield.get_stats()
        self.assertEqual(stats["attachments_scanned"], 1)
        self.assertEqual(stats["threats_intercepted"], 0)

    def test_signature_detected_threat(self):
        """Verify that threats identified by signature DB are quarantined and logged."""
        malicious_file = self.base_path / "payload.bin"
        malicious_file.write_bytes(b"MALWARE_PAYLOAD_HERE")

        known_threat = ThreatDetection(
            file_path=str(malicious_file),
            file_name="payload.bin",
            threat_name="Trojan.Generic.Downloader",
            threat_category="Email.Malware",
            severity="critical",
            detection_engine="hash_db",
            hash_sha256="abc",
            hash_md5="123",
            detected_at=1000.0
        )
        self.mock_engine.scan_file.return_value = known_threat

        detected = self.shield.inspect_attachment(str(malicious_file), client_name="Mozilla Thunderbird")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.threat_name, "Trojan.Generic.Downloader")
        self.assertFalse(malicious_file.exists())  # Must be moved to quarantine

        # Check quarantine registry
        quarantined = self.qm.list_quarantined()
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["threat_name"], "Trojan.Generic.Downloader")

        # Check callback & stats
        self.assertEqual(len(self.alert_calls), 1)
        self.assertEqual(self.alert_calls[0][1], "Mozilla Thunderbird")
        self.mock_logger.log_event.assert_called()

        stats = self.shield.get_stats()
        self.assertEqual(stats["threats_intercepted"], 1)
        self.assertEqual(len(stats["recent_events"]), 1)

    def test_double_extension_spoofing_detection(self):
        """Verify heuristic detection of double extensions (e.g. invoice.pdf.exe)."""
        spoofed_file = self.base_path / "urgent_invoice.pdf.exe"
        spoofed_file.write_bytes(b"Executable masquerading as pdf")

        threat = self.shield.inspect_attachment(str(spoofed_file), client_name="Microsoft Outlook")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.threat_name, "Email.Trojan.DoubleExtension")
        self.assertEqual(threat.severity, "critical")
        self.assertFalse(spoofed_file.exists())

        quarantined = self.qm.list_quarantined()
        self.assertEqual(len(quarantined), 1)
        self.assertIn("urgent_invoice.pdf.exe", quarantined[0]["original_path"])

    def test_dangerous_script_attachment_detection(self):
        """Verify blocking of dangerous script extensions (.vbs, .js, .hta, .scr, etc.)."""
        for ext in [".vbs", ".js", ".hta", ".scr", ".ps1"]:
            script_file = self.base_path / f"dropper{ext}"
            script_file.write_bytes(b"WScript.Echo 'test'")

            threat = self.shield.inspect_attachment(str(script_file), client_name="Windows Mail")
            self.assertIsNotNone(threat)
            self.assertEqual(threat.threat_name, f"Email.HighRiskAttachment{ext.upper()}")
            self.assertFalse(script_file.exists())

    def test_disguised_pe_binary_detection(self):
        """Verify detection of Windows PE executables disguised as benign documents."""
        fake_docx = self.base_path / "resume.docx"
        # Start file with DOS 'MZ' header
        fake_docx.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00PE binary pretending to be docx")

        threat = self.shield.inspect_attachment(str(fake_docx), client_name="eM Client")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.threat_name, "Email.Trojan.DisguisedPE")
        self.assertEqual(threat.severity, "critical")
        self.assertFalse(fake_docx.exists())

    def test_attachment_handler_deduplication(self):
        """Verify EmailAttachmentHandler does not spin redundant threads for same path."""
        handler = EmailAttachmentHandler(self.shield)
        test_file = self.base_path / "test_attachment.pdf"
        test_file.write_bytes(b"content")

        with patch.object(self.shield, "inspect_attachment") as mock_inspect:
            handler.process_path(str(test_file), "Outlook")
            # Immediate second call should be ignored by debounce lock
            handler.process_path(str(test_file), "Outlook")

        self.assertIn(str(test_file), handler._recently_scanned)

    def test_start_stop_lifecycle(self):
        """Verify start and stop methods behave properly."""
        self.assertFalse(self.shield.is_running())
        self.shield.start()
        self.assertTrue(self.shield.is_running())
        self.shield.stop()
        self.assertFalse(self.shield.is_running())


if __name__ == "__main__":
    unittest.main()
