"""
Unit tests for Vitorius Firewall Win - Antivirus & Quarantine Subsystems
"""

import os
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import sqlite3

from backend.antivirus import AntivirusEngine, QuarantineManager, ThreatDetection
from backend.antivirus_updater import SignatureUpdater, ALLOWED_UPDATE_INTERVALS


class TestAntivirus(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.quarantine_dir = self.base_path / "Quarantine"
        self.qm = QuarantineManager(quarantine_dir=self.quarantine_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_quarantine_flow(self):
        # Create a test simulated infected file
        test_file = self.base_path / "simulated_threat.bin"
        with open(test_file, "wb") as f:
            f.write(b"VITORIUS_ANTIVIRUS_TEST_SIMULATION_MALWARE_PAYLOAD_SAFE_12345")

        threat = ThreatDetection(
            file_path=str(test_file),
            file_name="simulated_threat.bin",
            threat_name="Simulation.Threat.Test",
            threat_category="Virus.Test",
            severity="critical",
            detection_engine="hash_db",
            hash_sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            hash_md5="44d88612fea8a8f36de82e1278abb02f",
            detected_at=1000.0
        )

        # 1. Quarantine file
        ok = self.qm.quarantine_file(str(test_file), threat)
        self.assertTrue(ok)
        self.assertFalse(test_file.exists()) # Original file neutralized

        # 2. Check quarantine database
        items = self.qm.list_quarantined()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['threat_name'], "Simulation.Threat.Test")

        # 3. Restore file
        restore_ok = self.qm.restore_file(items[0]['id'])
        self.assertTrue(restore_ok)
        self.assertTrue(test_file.exists())

        # Cleaned up from quarantine
        self.assertEqual(len(self.qm.list_quarantined()), 0)

    def test_signature_updater_intervals(self):
        """Verifies supported auto-update intervals: 2, 5, 12, 24 hours."""
        self.assertEqual(ALLOWED_UPDATE_INTERVALS, [2, 5, 12, 24])

        db_path = self.base_path / "signatures.db"
        updater = SignatureUpdater(db_path=db_path, interval_hours=12)
        self.assertEqual(updater.get_interval(), 12)

        # Test valid intervals (2, 5, 12, 24)
        for interval in [2, 5, 12, 24]:
            self.assertTrue(updater.set_interval(interval))
            self.assertEqual(updater.get_interval(), interval)

        # Test invalid intervals are rejected
        for invalid in [1, 3, 6, 8, 10, 48, -5]:
            self.assertFalse(updater.set_interval(invalid))
            # Interval remains unchanged
            self.assertEqual(updater.get_interval(), 24)

    def test_signature_updater_auto_update_thread(self):
        """Verifies background thread startup, interval dynamic changes, and shutdown."""
        db_path = self.base_path / "signatures.db"
        updater = SignatureUpdater(db_path=db_path, interval_hours=5)

        self.assertFalse(updater.is_auto_update_running())
        updater.start_auto_update()
        self.assertTrue(updater.is_auto_update_running())
        self.assertIsNotNone(updater._thread)
        self.assertTrue(updater._thread.is_alive())

        # Change interval while thread is running
        self.assertTrue(updater.set_interval(2))
        self.assertEqual(updater.get_interval(), 2)

        # Stop thread
        updater.stop_auto_update()
        self.assertFalse(updater.is_auto_update_running())

    def test_signature_updater_stats(self):
        """Verifies updater stats dictionary contains interval and auto-update metadata."""
        db_path = self.base_path / "signatures.db"
        updater = SignatureUpdater(db_path=db_path, interval_hours=2)
        stats = updater.get_stats()

        self.assertEqual(stats["interval_hours"], 2)
        self.assertEqual(stats["allowed_intervals"], [2, 5, 12, 24])
        self.assertFalse(stats["auto_update_enabled"])

    @patch("urllib.request.urlopen")
    def test_signature_updater_delta_sync(self, mock_urlopen):
        """Verifies delta signature ingestion into sqlite database."""
        db_path = self.base_path / "signatures.db"
        updater = SignatureUpdater(db_path=db_path)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "md5_hash": "b" * 32,
                    "signature": "Trojan.AgentTesla",
                    "delivery_method": "Email.Attachment"
                },
                {
                    "sha256_hash": "c" * 64,
                    "md5_hash": "d" * 32,
                    "signature": "Ransomware.LockBit",
                    "delivery_method": "Exploit"
                }
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_urlopen.return_value = mock_resp

        ok, msg, count = updater.update_signatures()
        self.assertTrue(ok)
        self.assertEqual(count, 2)

        stats = updater.get_stats()
        self.assertEqual(stats["total_signatures"], 2)
        self.assertNotEqual(stats["last_sync"], "Never")

    def test_signature_updater_full_update(self):
        """Verifies full database update ingests baseline threat catalog even offline."""
        db_path = self.base_path / "full_signatures.db"
        updater = SignatureUpdater(db_path=db_path)

        ok, msg, count = updater.full_update_signatures()
        self.assertTrue(ok)
        self.assertGreater(count, 0)
        self.assertIn("Full Database Update", msg)

        stats = updater.get_stats()
        self.assertGreater(stats["total_signatures"], 15)
        self.assertNotEqual(stats["last_sync"], "Never")

    def test_signature_updater_api_key_configuration(self):
        """Verifies Abuse.ch / MalwareBazaar Auth-Key set and get operations."""
        db_path = self.base_path / "key_test.db"
        updater = SignatureUpdater(db_path=db_path, api_key="initial-test-key")
        self.assertEqual(updater.get_api_key(), "initial-test-key")

        updater.set_api_key("new-auth-key-12345")
        self.assertEqual(updater.get_api_key(), "new-auth-key-12345")

        updater.set_api_key("")
        self.assertIsNone(updater.get_api_key())

    @patch("urllib.request.urlopen")
    def test_signature_updater_401_unauthorized_mirror_fallback(self, mock_urlopen):
        """Verifies that HTTP 401 Unauthorized seamlessly falls back to community mirror."""
        import urllib.error
        db_path = self.base_path / "fallback_signatures.db"
        updater = SignatureUpdater(db_path=db_path)

        # Mock first call (API) raising 401 Unauthorized, second call (mirror) returning hashes
        def side_effect(req, *args, **kwargs):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            if "mb-api.abuse.ch" in url:
                raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)
            else:
                # Mirror response
                m = MagicMock()
                m.status = 206
                dummy_hashes = "\n".join(["1" * 64, "2" * 64, "3" * 64])
                m.read.return_value = dummy_hashes.encode("utf-8")
                m.__enter__.return_value = m
                m.__exit__.return_value = None
                return m

        mock_urlopen.side_effect = side_effect

        ok, msg, count = updater.update_signatures()
        self.assertTrue(ok)
        self.assertEqual(count, 3)
        self.assertIn("MalwareBazaar.Mirror", msg)

    def test_available_drives_enumeration(self):
        """Verifies logical drive discovery and metadata reporting."""
        engine = AntivirusEngine(data_dir=self.base_path)
        drives = engine.get_available_drives()
        self.assertIsInstance(drives, list)
        self.assertGreater(len(drives), 0)

        first = drives[0]
        self.assertIn("mountpoint", first)
        self.assertIn("fstype", first)
        self.assertIn("total_gb", first)
        self.assertIn("free_gb", first)
        self.assertIn("drive_type", first)

    def test_system_scan_targets(self):
        """Verifies full system scan targets resolution."""
        engine = AntivirusEngine(data_dir=self.base_path)
        targets = engine.get_system_scan_targets()
        self.assertIsInstance(targets, list)
        self.assertGreater(len(targets), 0)

    def test_rootkit_scan_detection(self):
        """Verifies deep rootkit detection for known malicious kernel drivers."""
        engine = AntivirusEngine(data_dir=self.base_path)

        driver_dir = self.base_path / "drivers"
        driver_dir.mkdir(parents=True, exist_ok=True)
        bad_driver = driver_dir / "mhyprot2.sys"
        bad_driver.write_bytes(b"Simulated vulnerable rootkit driver payload")

        threats = engine.scan_rootkits(driver_dirs=[str(driver_dir)])
        threat_names = [t.threat_name for t in threats]
        self.assertTrue(any("Rootkit.Kernel.BYOVD" in n for n in threat_names))

    def test_chronostasis_stego_polyglot_detection(self):
        """Verifies ChronoStasis™ hunter detecting hidden executables appended past media EOF."""
        engine = AntivirusEngine(data_dir=self.base_path)

        hotspot = self.base_path / "hotspot"
        hotspot.mkdir(parents=True, exist_ok=True)

        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr_chunk = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
        hidden_payload = b"MZ\x90\x00\x03\x00\x00\x00Hidden Stego Executable Payload Overlay"

        stego_png = hotspot / "wallpaper.png"
        stego_png.write_bytes(png_header + ihdr_chunk + iend_chunk + hidden_payload)

        clean_png = hotspot / "safe.png"
        clean_png.write_bytes(png_header + ihdr_chunk + iend_chunk)

        threats = engine.scan_chronostasis_latent(target_dirs=[str(hotspot)])
        stego_threats = [t for t in threats if "wallpaper.png" in t.file_path]
        self.assertEqual(len(stego_threats), 1)
        self.assertEqual(stego_threats[0].threat_name, "ChronoStasis.Polyglot.StegoExecutableOverlay")
        self.assertEqual(stego_threats[0].severity, "critical")

        clean_threats = [t for t in threats if "safe.png" in t.file_path]
        self.assertEqual(len(clean_threats), 0)

    def test_chronostasis_timestomp_detection(self):
        """Verifies ChronoStasis™ detection of anti-forensic timestomp anomalies."""
        engine = AntivirusEngine(data_dir=self.base_path)

        hotspot = self.base_path / "timestomp_dir"
        hotspot.mkdir(parents=True, exist_ok=True)

        fake_exe = hotspot / "trojan.exe"
        fake_exe.write_bytes(b"Executable with forged timestamps")

        now = time.time()
        past = now - (86400 * 365 * 3)

        orig_os_stat = os.stat
        def mock_stat_fn(p, *args, **kwargs):
            st = orig_os_stat(p, *args, **kwargs)
            if "trojan.exe" in str(p):
                class FakeStat:
                    st_ctime = past
                    st_mtime = now
                    st_size = 1024
                return FakeStat()
            return st

        with patch("os.stat", side_effect=mock_stat_fn):
            threats = engine.scan_chronostasis_latent(target_dirs=[str(hotspot)])
            ts_threats = [t for t in threats if "ChronoStasis.Timestomp" in t.threat_name]
            self.assertGreaterEqual(len(ts_threats), 1)

    def test_antivirus_page_refresh_stats_alias(self):
        """Verifies AntivirusPage has refresh_stats alias and refresh method."""
        from ui.pages_win import AntivirusPage
        self.assertTrue(hasattr(AntivirusPage, 'refresh_stats'))
        self.assertTrue(hasattr(AntivirusPage, 'refresh'))

    def test_digital_signature_verification(self):
        """Verifies Windows Authenticode & Catalog digital signature verification."""
        from backend.antivirus import verify_file_signature
        import sys

        # Python executable and cmd.exe are signed Windows binaries
        py_valid, py_desc = verify_file_signature(sys.executable)
        self.assertTrue(py_valid)
        self.assertIn("Valid", py_desc)

        cmd_path = r"C:\Windows\System32\cmd.exe"
        if os.path.exists(cmd_path):
            cmd_valid, cmd_desc = verify_file_signature(cmd_path)
            self.assertTrue(cmd_valid)
            self.assertIn("Valid", cmd_desc)

        # Unsigned test file
        test_file = self.base_path / "unsigned_test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)
        u_valid, u_desc = verify_file_signature(str(test_file))
        self.assertFalse(u_valid)

        # Non-existent file
        no_file = self.base_path / "does_not_exist.dll"
        ne_valid, ne_desc = verify_file_signature(str(no_file))
        self.assertFalse(ne_valid)

    def test_quarantine_prevents_quarantining_signed_files(self):
        """Ensures that validly signed binaries are protected from false-positive quarantine."""
        import sys
        # Use python.exe or a real signed file
        signed_file = sys.executable

        threat = ThreatDetection(
            file_path=signed_file,
            file_name=Path(signed_file).name,
            threat_name="FalsePositive.Test",
            threat_category="Suspicious",
            severity="critical",
            detection_engine="heuristic_engine",
            hash_sha256="0" * 64,
            hash_md5="0" * 32,
            detected_at=time.time()
        )

        # Quarantine should be blocked because the file has a verified digital signature
        quarantined = self.qm.quarantine_file(signed_file, threat, force=False)
        self.assertFalse(quarantined)
        self.assertTrue(os.path.exists(signed_file))

    def test_scan_file_suppresses_false_positives_on_signed_file(self):
        """Verifies that heuristic patterns and entropy checks do not flag signed binaries."""
        import sys
        engine = AntivirusEngine(data_dir=self.base_path)

        # Python executable contains high-entropy bytecode and strings, but is digitally signed
        detection = engine.scan_file(sys.executable)
        # Should be None (not flagged as a false positive)
        self.assertIsNone(detection)

    def test_restore_whitelists_file_and_prevents_requarantine(self):
        """Verifies that restored files are added to the exclusion whitelist and not re-quarantined."""
        test_file = self.base_path / "app_tool.exe"
        hook_str = b"".join([b"discord.com", b"/api/webhooks/"])
        test_file.write_bytes(b"MZ" + hook_str + b"A" * 500)

        threat = ThreatDetection(
            file_path=str(test_file),
            file_name="app_tool.exe",
            threat_name="Infostealer.DiscordWebhook",
            threat_category="Infostealer",
            severity="high",
            detection_engine="heuristic_engine",
            hash_sha256="abc123def456",
            hash_md5="12345678",
            detected_at=time.time()
        )

        # 1. Quarantine unsigned test file
        ok = self.qm.quarantine_file(str(test_file), threat)
        self.assertTrue(ok)
        self.assertFalse(test_file.exists())

        items = self.qm.list_quarantined()
        self.assertEqual(len(items), 1)
        item_id = items[0]["id"]

        # 2. Restore file
        restore_ok = self.qm.restore_file(item_id)
        self.assertTrue(restore_ok)
        self.assertTrue(test_file.exists())

        # 3. Verify it is whitelisted in QuarantineManager and AntivirusEngine
        self.assertTrue(self.qm.is_excluded(str(test_file)))
        engine = AntivirusEngine(data_dir=self.base_path)
        # Point engine's quarantine to same manager
        engine.quarantine = self.qm
        self.assertTrue(engine.is_excluded(str(test_file)))

        # 4. Calling scan_file on the whitelisted restored file should return None
        rescan = engine.scan_file(str(test_file))
        self.assertIsNone(rescan)

    def test_ui_quarantine_table_checkbox_and_restore(self):
        """Verifies UI checkbox selection next to threat name and batch restoration."""
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from PyQt6.QtCore import Qt
        from ui.pages_win import AntivirusPage

        app = QApplication.instance() or QApplication([])

        mock_main = MagicMock()
        mock_main.av_engine = AntivirusEngine(data_dir=self.base_path)
        mock_main.av_updater = MagicMock()
        mock_main.fw_logger = MagicMock()

        page = AntivirusPage(mock_main)

        # 1. Create and quarantine two test threats
        f1 = self.base_path / "threat1.bin"
        f1.write_bytes(b"payload_1")
        f2 = self.base_path / "threat2.bin"
        f2.write_bytes(b"payload_2")

        t1 = ThreatDetection(
            file_path=str(f1), file_name="threat1.bin", threat_name="Test.Threat.One",
            threat_category="Trojan", severity="critical", detection_engine="heuristic",
            hash_sha256="111111", hash_md5="1111", detected_at=time.time()
        )
        t2 = ThreatDetection(
            file_path=str(f2), file_name="threat2.bin", threat_name="Test.Threat.Two",
            threat_category="Ransomware", severity="high", detection_engine="heuristic",
            hash_sha256="222222", hash_md5="2222", detected_at=time.time()
        )

        mock_main.av_engine.quarantine.quarantine_file(str(f1), t1)
        mock_main.av_engine.quarantine.quarantine_file(str(f2), t2)
        self.assertFalse(f1.exists())
        self.assertFalse(f2.exists())

        # 2. Populate table
        page.refresh_quarantine()
        self.assertEqual(page.table_q.rowCount(), 2)

        # 3. Check both threat checkboxes next to their names
        chk0 = page.table_q.item(0, 0)
        chk1 = page.table_q.item(1, 0)
        self.assertIsNotNone(chk0)
        self.assertIsNotNone(chk1)
        self.assertEqual(chk0.checkState(), Qt.CheckState.Unchecked)

        chk0.setCheckState(Qt.CheckState.Checked)
        chk1.setCheckState(Qt.CheckState.Checked)

        # 4. Mock user dialog confirmation and run restore
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            with patch.object(QMessageBox, "information"):
                page._restore_selected()

        # Both files restored and removed from quarantine
        self.assertTrue(f1.exists())
        self.assertTrue(f2.exists())
        self.assertEqual(page.table_q.rowCount(), 0)
        self.assertTrue(mock_main.av_engine.is_excluded(str(f1)))
        self.assertTrue(mock_main.av_engine.is_excluded(str(f2)))

    def test_signature_and_rules_files_not_flagged(self):
        """Verifies that files in signature and rules folders are never flagged as malware."""
        from backend.antivirus import is_signature_or_rule_file
        engine = AntivirusEngine(data_dir=self.base_path)

        # 1. Test built-in YARA rule files in data/signatures/rules
        project_root = Path(__file__).resolve().parent.parent
        builtin_rules = project_root / "data" / "signatures" / "rules"
        if builtin_rules.exists():
            for rule_file in builtin_rules.glob("*.yar"):
                self.assertTrue(is_signature_or_rule_file(rule_file))
                self.assertTrue(engine.is_excluded(str(rule_file)))
                detection = engine.scan_file(str(rule_file))
                self.assertIsNone(detection, f"Rule file {rule_file.name} was falsely flagged as malware!")

        # 2. Test user signature and rules directories
        user_sig_dir = self.base_path / "signature"
        user_rules_dir = self.base_path / "rules"
        user_sig_dir.mkdir(parents=True, exist_ok=True)
        user_rules_dir.mkdir(parents=True, exist_ok=True)

        miner_str = "".join(["strat", "um+tcp://"])
        shadow_str = "".join(["vssadmin ", "delete shadows"])
        discord_str = "".join(["discord.com", "/api/webhooks/"])
        sig_file = user_sig_dir / "threat_definitions.txt"
        sig_file.write_text(f"{shadow_str}\n{miner_str}\n{discord_str}", encoding="utf-8")

        rule_file = user_rules_dir / "custom_ransomware_detector.yar"
        ransom_str = "".join(["All your files ", "have been encrypted"])
        rule_file.write_text(f'rule RansomCheck {{ strings: $a = "{ransom_str}" condition: $a }}', encoding="utf-8")

        for f in [sig_file, rule_file]:
            self.assertTrue(is_signature_or_rule_file(f))
            self.assertTrue(engine.is_excluded(str(f)))
            self.assertIsNone(engine.scan_file(str(f)), f"{f.name} should not be flagged!")

        # 3. Test quarantine refusal for signature/rule files
        threat = ThreatDetection(
            file_path=str(rule_file),
            file_name=rule_file.name,
            threat_name="FalsePositive.Test",
            threat_category="Ransomware",
            severity="critical",
            detection_engine="test",
            hash_sha256="0" * 64,
            hash_md5="0" * 32,
            detected_at=time.time()
        )
        quarantined = engine.quarantine.quarantine_file(str(rule_file), threat)
        self.assertFalse(quarantined, "QuarantineManager should refuse to quarantine signature/rule files!")
        self.assertTrue(rule_file.exists(), "Rule file must remain intact!")

    def test_scan_directory_skips_signature_and_rules_folders(self):
        """Verifies that scan_directory excludes signature and rules folders from threat detection."""
        engine = AntivirusEngine(data_dir=self.base_path)

        scan_root = self.base_path / "scan_target"
        scan_root.mkdir(parents=True, exist_ok=True)

        sig_dir = scan_root / "signature"
        rules_dir = scan_root / "rules"
        sig_dir.mkdir()
        rules_dir.mkdir()

        dummy_str = "".join(["strat", "um+tcp://"])
        (sig_dir / "hashes.txt").write_text("".join(["wmic ", "shadowcopy delete"]), encoding="utf-8")
        (rules_dir / "detect.yar").write_text(f'rule Dummy {{ strings: $b = "{dummy_str}" condition: $b }}', encoding="utf-8")

        threats = engine.scan_directory(str(scan_root))
        self.assertEqual(len(threats), 0, "No threats should be flagged inside signature and rules folders!")

    def test_verify_file_signature_never_spawns_powershell_window(self):
        """Verifies that verify_file_signature uses native WinTrust in-process and does not spawn subprocesses."""
        import sys
        from backend.antivirus import verify_file_signature, _HAS_WINTRUST

        # 1. Non-executable file (should return immediately without subprocess)
        sample_txt = self.base_path / "notes.txt"
        sample_txt.write_text("plain text file", encoding="utf-8")

        with patch("subprocess.run") as mock_subproc:
            is_valid, desc = verify_file_signature(str(sample_txt))
            self.assertFalse(is_valid)
            self.assertIn("Non-executable format", desc)
            mock_subproc.assert_not_called()

        # 2. Unsigned executable file on Windows with _HAS_WINTRUST
        sample_exe = self.base_path / "unsigned_test.exe"
        sample_exe.write_bytes(b"MZ" + b"\x00" * 512)

        if sys.platform == "win32" and _HAS_WINTRUST:
            with patch("subprocess.run") as mock_subproc:
                is_valid, desc = verify_file_signature(str(sample_exe))
                self.assertFalse(is_valid)
                mock_subproc.assert_not_called()

        # 3. Valid signed executable (python.exe)
        if sys.platform == "win32" and _HAS_WINTRUST:
            with patch("subprocess.run") as mock_subproc:
                is_valid, desc = verify_file_signature(sys.executable)
                self.assertTrue(is_valid)
                self.assertIn("Valid Authenticode Signature", desc)
                mock_subproc.assert_not_called()

    def test_antivirus_program_files_and_directories_never_flagged(self):
        """Verifies that antivirus installation directories, build folders, and suite files are never flagged as malware."""
        from backend.antivirus import is_antivirus_program_file, AntivirusEngine, ThreatDetection

        engine = AntivirusEngine(data_dir=self.base_path)

        user_programs = Path.home() / "AppData" / "Local" / "Programs" / "Crazy Alchemy"
        paths_to_verify = [
            str(user_programs),
            str(user_programs / "Crazy Alchemy.exe"),
            str(user_programs / "backend" / "antivirus.py"),
            r"C:\Program Files\Crazy Alchemy\CrazyAlchemy.exe",
            str(Path(__file__).resolve().parent.parent / "build"),
            str(Path(__file__).resolve().parent.parent / "build" / "setup_win.py"),
            str(Path(__file__).resolve().parent.parent / "build" / "make_setup.py"),
            str(Path(__file__).resolve().parent.parent / "backend" / "antivirus.py"),
            str(Path(__file__).resolve().parent.parent / "main_win.py"),
        ]

        for p in paths_to_verify:
            self.assertTrue(is_antivirus_program_file(p), f"Should recognize {p} as antivirus program file")
            self.assertTrue(engine.is_excluded(p), f"Should exclude {p} from scanning")

        # Scan folder inside build directory (must return 0 threats)
        build_dir = Path(__file__).resolve().parent.parent / "build"
        if build_dir.exists():
            threats = engine.scan_directory(str(build_dir))
            self.assertEqual(len(threats), 0, "Build directory must not contain flagged malware threats!")

        # Quarantine must refuse to quarantine antivirus program files
        dummy_file = self.base_path / "Crazy Alchemy" / "core_module.exe"
        dummy_file.parent.mkdir(parents=True, exist_ok=True)
        dummy_file.write_bytes(b"MZ" + b"\x00" * 500)

        threat = ThreatDetection(
            file_path=str(dummy_file),
            file_name="core_module.exe",
            threat_name="FalsePositive.Miner",
            threat_category="Miner",
            severity="high",
            detection_engine="test",
            hash_sha256="abc123" * 10,
            hash_md5="12345678",
            detected_at=time.time()
        )
        quarantined = engine.quarantine.quarantine_file(str(dummy_file), threat)
        self.assertFalse(quarantined, "QuarantineManager must refuse to quarantine files in Crazy Alchemy directories!")
        self.assertTrue(dummy_file.exists(), "Antivirus program file must remain on disk intact!")

    def test_antivirus_processes_never_flagged(self):
        """Verifies that antivirus running processes and python runners are whitelisted and never flagged."""
        import os
        from backend.antivirus import is_antivirus_process, AntivirusEngine

        engine = AntivirusEngine(data_dir=self.base_path)

        # 1. Self process
        self.assertTrue(is_antivirus_process({"pid": os.getpid()}))

        user_programs = Path.home() / "AppData" / "Local" / "Programs" / "Crazy Alchemy"
        # 2. Process with executable in Crazy Alchemy directory
        self.assertTrue(is_antivirus_process({
            "pid": 54321,
            "exe": str(user_programs / "Crazy Alchemy.exe"),
            "name": "Crazy Alchemy.exe"
        }))

        # 3. Python process executing main_win.py
        self.assertTrue(is_antivirus_process({
            "pid": 65432,
            "exe": sys.executable,
            "name": "python.exe",
            "cmdline": [sys.executable, "main_win.py"]
        }))

        # 4. Process scan should not detect antivirus processes
        threats = engine.scan_running_processes()
        # Verify no detected threat points to an antivirus process or python runner
        for t in threats:
            self.assertNotIn("crazy alchemy", t.file_path.lower())
            self.assertNotIn("main_win.py", t.file_path.lower())

    def test_quarantine_restore_cleans_entry_and_persists_exclusion(self):
        """Verifies that QuarantineManager.restore_file clears the database record, restores file, and persists exclusion."""
        from backend.antivirus import QuarantineManager, ThreatDetection

        qm = QuarantineManager(self.base_path / "test_q_vault")
        target_file = self.base_path / "restore_test" / "document_report.bin"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        orig_content = b"CRITICAL_REPORT_CONTENT_123456789"
        target_file.write_bytes(orig_content)

        threat = ThreatDetection(
            file_path=str(target_file),
            file_name="document_report.bin",
            threat_name="Test.Ransomware.Sample",
            threat_category="Ransomware",
            severity="critical",
            detection_engine="test",
            hash_sha256="ffff1111222233334444555566667777888899990000aaaa"[:64],
            hash_md5="ffff111122223333"[:32],
            detected_at=time.time()
        )

        # Quarantine
        ok = qm.quarantine_file(str(target_file), threat, force=True)
        self.assertTrue(ok)
        self.assertFalse(target_file.exists(), "Original file should be removed during quarantine")

        items = qm.list_quarantined()
        self.assertEqual(len(items), 1)
        item_id = items[0]["id"]

        # Restore
        restored = qm.restore_file(item_id)
        self.assertTrue(restored, f"Restore failed: {qm.last_error}")
        self.assertTrue(target_file.exists(), "Restored file must exist at original path")
        self.assertEqual(target_file.read_bytes(), orig_content, "Restored content must match original bytes")

        # Database record must be deleted
        remaining = qm.list_quarantined()
        self.assertEqual(len(remaining), 0, "Quarantined items table must be empty after restore")

        # Exclusion must be recorded and active
        self.assertTrue(qm.is_excluded(str(target_file)), "Restored file path must be in exclusions")
        self.assertTrue(qm.is_excluded(str(target_file), threat.hash_sha256), "Restored file hash must be in exclusions")


if __name__ == '__main__':
    unittest.main()
