"""
Unit tests for Novel Features:
1. TrapNet Deception Decoy Ports
2. ChainGuard Process Ancestry Validator
3. AppPrint Network DNA Profiling
"""

import time
import tempfile
import unittest
from pathlib import Path
from backend.honeypot import HoneypotManager, TrapEvent
from backend.chainguard import ChainGuardEngine, ProcessChain
from backend.appprint import AppPrintEngine, AppFingerprint, AnomalyAlert


class TestNovelFeatures(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_trapnet_event_recording(self):
        db_file = self.base_path / "test_trapnet.db"
        blocked_ips = []

        def mock_block(ip):
            blocked_ips.append(ip)
            return True

        hp = HoneypotManager(
            trap_ports={2222: "SSH-Test"},
            block_callback=mock_block,
            db_path=db_file
        )

        event = TrapEvent(
            source_ip="198.51.100.99",
            source_port=54321,
            trap_port=22,
            trap_service="SSH",
            protocol="TCP",
            timestamp=time.time(),
            raw_payload_hex="5353482d322e30",
            payload_preview="SSH-2.0",
            auto_blocked=True
        )

        hp._record_event(event)

        stats = hp.get_trap_stats()
        self.assertEqual(stats["total_traps"], 1)
        self.assertEqual(stats["unique_ips"], 1)
        self.assertEqual(stats["auto_blocked_count"], 1)

        events = hp.get_recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source_ip"], "198.51.100.99")

    def test_chainguard_heuristics(self):
        db_file = self.base_path / "test_chainguard.db"
        cg = ChainGuardEngine(db_path=db_file)

        # Suspicious chain simulation: winword.exe -> cmd.exe -> powershell.exe
        chain = ProcessChain(
            pid=9999,
            process_name="powershell.exe",
            exe_path="C:\\Windows\\System32\\powershell.exe",
            parent_pid=8888,
            parent_name="cmd.exe",
            grandparent_name="winword.exe",
            full_chain=["explorer.exe", "winword.exe", "cmd.exe", "powershell.exe"],
            chain_hash="test_hash_1234",
            is_suspicious=True,
            suspicion_reasons=["Document application (winword.exe) spawned script shell (powershell.exe) with network access"],
            remote_endpoints=["185.220.101.5:4444"]
        )

        cg._record_event(chain)

        stats = cg.get_stats()
        self.assertEqual(stats["total_historical_events"], 1)
        self.assertEqual(stats["unique_suspicious_chains"], 1)

        events = cg.get_recent_events(limit=5)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["process_name"], "powershell.exe")
        self.assertIn("winword.exe", events[0]["full_chain"])

    def test_appprint_fingerprint_learning(self):
        db_file = self.base_path / "test_appprint.db"
        ap = AppPrintEngine(db_path=db_file)

        fp = AppFingerprint(
            app_name="chrome.exe",
            exe_path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
            typical_remote_ports={80, 443},
            typical_protocols={"TCP"},
            typical_subnets={"142.250", "172.217"},
            samples_count=50,
            confidence_score=0.8
        )

        ap._save_fingerprint(fp)
        fps = ap.get_fingerprints()
        self.assertEqual(len(fps), 1)
        self.assertEqual(fps[0]["app_name"], "chrome.exe")
        self.assertIn(443, fps[0]["typical_remote_ports"])

        # Test reset fingerprint
        self.assertTrue(ap.reset_fingerprint("chrome.exe"))
        self.assertEqual(len(ap.get_fingerprints()), 0)

        # Test anomaly clearing
        self.assertTrue(ap.clear_anomalies())

    def test_chainguard_whitelist_persistence(self):
        db_file = self.base_path / "test_chainguard_wl.db"
        cg = ChainGuardEngine(db_path=db_file)

        # Test whitelisting
        self.assertTrue(cg.whitelist_chain("hash_abc_123", "User authorized script"))
        self.assertTrue(cg.is_whitelisted("hash_abc_123"))
        self.assertFalse(cg.is_whitelisted("unknown_hash"))

        # Test removing whitelist
        self.assertTrue(cg.remove_whitelist("hash_abc_123"))
        self.assertFalse(cg.is_whitelisted("hash_abc_123"))

    def test_trapnet_dynamic_port_management(self):
        db_file = self.base_path / "test_trapnet_dyn.db"
        hp = HoneypotManager(trap_ports={8080: "HTTP-Trap"}, db_path=db_file)

        self.assertIn(8080, hp.trap_ports)
        self.assertTrue(hp.add_trap_port(8088, "Custom-Trap"))
        self.assertIn(8088, hp.trap_ports)
        self.assertTrue(hp.remove_trap_port(8088))
        self.assertNotIn(8088, hp.trap_ports)

    def test_entropy_and_heuristic_analyzer(self):
        from backend.antivirus import calculate_entropy, AntivirusEngine
        # Low entropy: repeating bytes
        low_data = b"A" * 1000
        self.assertLess(calculate_entropy(low_data), 1.0)

        # High entropy: pseudo-random bytes
        import os
        random_data = os.urandom(1000)
        self.assertGreater(calculate_entropy(random_data), 7.0)

        # Threat hash lookup interface
        project_data = Path(__file__).resolve().parent.parent / "data"
        av = AntivirusEngine(data_dir=project_data)
        lookup = av.lookup_hash("ed01ebf83334a193736034b4b96e236ec5b326ac6b677a2822fd3415ee401b95")  # WannaCry
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup["threat_name"], "WannaCry")

    def test_logger_csv_export_and_clear(self):
        from backend.profiles_win import FirewallLogger
        logger = FirewallLogger()
        logger.log_file = self.base_path / "test_events.jsonl"

        logger.log_event("test_event", "info", "Testing event logging")
        events = logger.get_recent_events()
        self.assertEqual(len(events), 1)

        csv_file = self.base_path / "export_events.csv"
        self.assertTrue(logger.export_logs_csv(str(csv_file)))
        self.assertTrue(csv_file.exists())

        self.assertTrue(logger.clear_logs())
        self.assertEqual(len(logger.get_recent_events()), 0)

    def test_startup_and_tray_settings(self):
        from backend.profiles_win import WindowsProfileManager, set_autostart_registry
        config_path = self.base_path / "test_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            f.write('{"settings": {"start_with_system": true, "start_minimized": true, "close_to_tray": true}}')

        pm = WindowsProfileManager(config_file=config_path)
        self.assertTrue(pm.get_setting("start_with_system"))
        self.assertTrue(pm.get_setting("autostart"))
        self.assertTrue(pm.get_setting("start_minimized"))
        self.assertTrue(pm.get_setting("close_to_tray"))

        # Update autostart
        self.assertTrue(pm.set_autostart(False))
        self.assertFalse(pm.get_setting("start_with_system"))
        self.assertFalse(pm.get_setting("autostart"))

    def test_taskbar_integration_interface(self):
        from ui.taskbar_win import WindowsTaskbarProgress, set_app_user_model_id, TBPF_NORMAL, TBPF_ERROR
        # Test AppUserModelID registration doesn't throw
        set_app_user_model_id()

        # Test WindowsTaskbarProgress methods without crash
        tb = WindowsTaskbarProgress()
        tb.set_hwnd(12345)
        tb.set_progress(50, 100)
        tb.set_state(TBPF_NORMAL)
        tb.set_state(TBPF_ERROR)
        tb.clear()
        self.assertEqual(tb.hwnd, 12345)


if __name__ == '__main__':
    unittest.main()
