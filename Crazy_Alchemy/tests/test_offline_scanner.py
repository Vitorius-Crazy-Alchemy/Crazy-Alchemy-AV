"""
Unit tests for Microsoft Defender-Style Offline Reboot Scanner & Remediation
"""

import os
import tempfile
import unittest
from pathlib import Path

from backend.offline_scanner import OfflineScanManager, mark_file_for_reboot_deletion, clean_autorun_persistence
from backend.core_win import WindowsFirewallCore
from backend.antivirus import AntivirusEngine, ThreatDetection, QuarantineManager
from backend.profiles_win import FirewallLogger


class TestOfflineScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.data_dir = self.base_path / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.fw_core = WindowsFirewallCore()
        # Point to real project signatures
        project_data = Path(__file__).resolve().parent.parent / "data"
        self.av_engine = AntivirusEngine(data_dir=project_data)
        # Use isolated quarantine in temp directory
        self.quarantine_dir = self.base_path / "quarantine"
        self.av_engine.quarantine = QuarantineManager(quarantine_dir=self.quarantine_dir)

        self.logger = FirewallLogger()
        self.logger.log_file = self.base_path / "offline_events.jsonl"

        self.mgr = OfflineScanManager(
            data_dir=self.data_dir,
            fw_core=self.fw_core,
            av_engine=self.av_engine,
            fw_logger=self.logger
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_schedule_and_cancel_offline_scan(self):
        self.assertFalse(self.mgr.is_pending())

        ok, msg = self.mgr.schedule_scan(reboot_now=False, scan_targets=[str(self.base_path)])
        self.assertTrue(ok)
        self.assertTrue(self.mgr.is_pending())

        details = self.mgr.get_pending_details()
        self.assertIsNotNone(details)
        self.assertEqual(details.get("status"), "pending")
        self.assertFalse(details.get("reboot_requested"))
        self.assertIn(str(self.base_path), details.get("custom_dirs", []))

        # Cancel scheduled scan
        ok_cancel, cancel_msg = self.mgr.cancel_scan()
        self.assertTrue(ok_cancel)
        self.assertFalse(self.mgr.is_pending())

    def test_offline_scan_execution_and_malware_cleaning(self):
        # 1. Create a mock malware payload inside a target directory
        mock_hotspot = self.base_path / "hotspot"
        mock_hotspot.mkdir(parents=True, exist_ok=True)

        infected_file = mock_hotspot / "wannacry_dropper.exe"
        # Write bytes matching WannaCry sha256: ed01ebf83334a193736034b4b96e236ec5b326ac6b677a2822fd3415ee401b95
        # Or mock ThreatDetection
        with open(infected_file, "wb") as f:
            f.write(b"MOCK_MALICIOUS_PAYLOAD_FOR_OFFLINE_CLEANING")

        # 2. Schedule scan with custom hotspot
        self.mgr.schedule_scan(reboot_now=False, scan_targets=[str(mock_hotspot)])
        self.assertTrue(self.mgr.is_pending())

        # Mock scan_directory on the engine to trigger threat on our infected_file
        orig_scan_dir = self.av_engine.scan_directory

        def mock_scan_directory(target_dir, progress_cb=None, threat_cb=None, cancel_event=None):
            if str(target_dir) == str(mock_hotspot):
                threat = ThreatDetection(
                    file_path=str(infected_file),
                    file_name="wannacry_dropper.exe",
                    threat_name="WannaCry.Ransomware",
                    threat_category="Ransomware",
                    severity="critical",
                    detection_engine="heuristic_hash",
                    hash_sha256="ed01ebf83334a193736034b4b96e236ec5b326ac6b677a2822fd3415ee401b95",
                    hash_md5="84c82835a5d21bbcf75a61706d8ab549",
                    detected_at=1000.0
                )
                if progress_cb:
                    progress_cb(1, 1, str(infected_file))
                if threat_cb:
                    threat_cb(threat)
                return [threat]
            return []

        self.av_engine.scan_directory = mock_scan_directory

        # 3. Execute the offline scan
        threats_cleaned = []

        def on_threat(threat, remediation):
            threats_cleaned.append((threat, remediation))

        results = self.mgr.execute_offline_scan(threat_cb=on_threat)

        # 4. Verify results
        self.assertFalse(self.mgr.is_pending())  # Pending marker cleared
        self.assertEqual(results.get("threats_found"), 1)
        self.assertEqual(results.get("threats_cleaned"), 1)
        self.assertEqual(len(results.get("cleaned_items")), 1)

        # Original infected file neutralized and removed from hotspot
        self.assertFalse(infected_file.exists())

        # Check that quarantine database received the file
        quarantined_items = self.av_engine.quarantine.list_quarantined()
        self.assertEqual(len(quarantined_items), 1)
        self.assertEqual(quarantined_items[0]["threat_name"], "WannaCry.Ransomware")

        # 5. Check last results and acknowledgment
        last = self.mgr.get_last_results()
        self.assertIsNotNone(last)
        self.assertEqual(last["threats_cleaned"], 1)

        self.mgr.acknowledge_results()
        self.assertIsNone(self.mgr.get_last_results())

    def test_reboot_file_deletion_helper(self):
        dummy_file = self.base_path / "locked_rootkit.sys"
        with open(dummy_file, "wb") as f:
            f.write(b"TEST_LOCKED_DRIVER")

        # Should execute without throwing on any platform
        ok = mark_file_for_reboot_deletion(str(dummy_file))
        # On Linux, mark_file_for_reboot_deletion removes the file as fallback
        self.assertTrue(ok or not dummy_file.exists())

    def test_autorun_cleanup_helper(self):
        # Should execute safely on any platform
        clean_autorun_persistence(str(self.base_path / "test.exe"))

    def test_offline_scan_built_in_repository_sync(self):
        """Verifies that offline scanner checks and syncs malware database from built-in repositories."""
        # Create an isolated offline manager with an empty data directory
        empty_data = self.base_path / "empty_offline_data"
        empty_data.mkdir()
        isolated_mgr = OfflineScanManager(data_dir=empty_data, fw_core=self.fw_core, fw_logger=self.logger)

        repos = isolated_mgr.find_builtin_repositories()
        self.assertGreater(len(repos), 0, "Should locate project built-in repository")

        repo_res = isolated_mgr.sync_builtin_malware_database()
        self.assertTrue(repo_res.get("synced"))
        self.assertGreaterEqual(repo_res.get("active_signatures", 0), 35)
        self.assertGreaterEqual(repo_res.get("active_yara_rules", 0), 3)

        # Target database file should now exist in isolated data_dir
        target_db = empty_data / "signatures" / "malware_hashes.db"
        self.assertTrue(target_db.exists())
        self.assertGreater(target_db.stat().st_size, 0)

        # Check engine database matching works with synced database
        # WannaCry sha256: ed01ebf83334a193736034b4b96e236ec5b326ac6b677a2822fd3415ee401b95
        match = isolated_mgr.av_engine.check_hash_database(
            "ed01ebf83334a193736034b4b96e236ec5b326ac6b677a2822fd3415ee401b95",
            "84c82835a5d21bbcf75a61706d8ab549"
        )
        self.assertIsNotNone(match, "Engine must successfully detect WannaCry from synced database")
        self.assertEqual(match[0], "WannaCry")

    def test_offline_scan_digital_signature_prevents_false_positive(self):
        """Verifies that clean_threat validates digital signatures and protects legitimate signed software."""
        import sys
        # Legitimate signed executable (python.exe)
        py_exe = sys.executable

        threat = ThreatDetection(
            file_path=py_exe,
            file_name=Path(py_exe).name,
            threat_name="FalsePositive.Heuristic.Test",
            threat_category="Suspicious",
            severity="critical",
            detection_engine="heuristic_pattern",
            hash_sha256="0" * 64,
            hash_md5="0" * 32,
            detected_at=1000.0
        )

        remediation = self.mgr.clean_threat(threat, validate_signatures=True)

        if sys.platform == "win32":
            self.assertTrue(remediation.get("is_false_positive"))
            self.assertEqual(remediation.get("action"), "suppressed_valid_signature")
            self.assertIn("Valid", remediation.get("signature_status", ""))
            # Must remain intact on disk!
            self.assertTrue(Path(py_exe).exists(), "Signed file must NEVER be deleted or quarantined!")
        else:
            # On non-Windows platforms, digital signature check returns unsupported
            self.assertFalse(remediation.get("is_false_positive"))

    def test_offline_scan_execution_with_signed_file_suppression(self):
        """Tests offline scan execution correctly distinguishing unsigned malware from valid signed binaries."""
        import sys
        mock_hotspot = self.base_path / "dual_hotspot"
        mock_hotspot.mkdir(parents=True, exist_ok=True)

        # 1. Unsigned mock malware
        malware_file = mock_hotspot / "actual_threat.bin"
        malware_file.write_bytes(b"MALWARE_STRING_123")

        # 2. Signed executable
        py_exe = sys.executable

        # Schedule with custom hotspot
        self.mgr.schedule_scan(reboot_now=False, scan_targets=[str(mock_hotspot)])

        # Mock scan_directory returning both files as threats for mock_hotspot only
        def mock_scan_dual(target_dir, progress_cb=None, threat_cb=None, cancel_event=None):
            if str(target_dir) == str(mock_hotspot):
                t1 = ThreatDetection(
                    file_path=str(malware_file),
                    file_name="actual_threat.bin",
                    threat_name="Malware.Actual.Test",
                    threat_category="Trojan",
                    severity="critical",
                    detection_engine="test",
                    hash_sha256="1" * 64,
                    hash_md5="1" * 32,
                    detected_at=1000.0
                )
                t2 = ThreatDetection(
                    file_path=py_exe,
                    file_name=Path(py_exe).name,
                    threat_name="FalsePositive.Signed.Test",
                    threat_category="Suspicious",
                    severity="high",
                    detection_engine="test",
                    hash_sha256="2" * 64,
                    hash_md5="2" * 32,
                    detected_at=1000.0
                )
                if threat_cb:
                    threat_cb(t1)
                    threat_cb(t2)
                return [t1, t2]
            return []

        self.av_engine.scan_directory = mock_scan_dual

        results = self.mgr.execute_offline_scan(
            check_builtin_db=True,
            validate_signatures=True
        )

        if sys.platform == "win32":
            self.assertEqual(results.get("threats_cleaned"), 1, "Only unsigned malware should be cleaned")
            self.assertEqual(results.get("false_positives_suppressed"), 1, "Signed file must be suppressed as false positive")
            self.assertFalse(malware_file.exists(), "Malware file must be neutralized")
            self.assertTrue(Path(py_exe).exists(), "Signed binary must remain intact")
        else:
            self.assertEqual(results.get("threats_cleaned"), 2)


if __name__ == '__main__':
    unittest.main()
