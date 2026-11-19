"""
Unit tests for Crazy Alchemy Browser Web Shield & Brave-Style AdBlock Companion.
Tests extension deployment, manifest validation, browser detection (Chrome, Brave, Edge, Firefox, Opera),
companion HTTP API endpoints, malware URL auditing, and ad/tracker blocking.
"""

import os
import sys
import json
import time
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.browser_shield import (
    BrowserDetector,
    ExtensionDeployer,
    BrowserCompanionServer,
    extract_base_domain,
    match_domain_suffix,
    KNOWN_MALWARE_DOMAINS,
    KNOWN_AD_DOMAINS,
    KNOWN_TRACKER_DOMAINS,
    KNOWN_MINER_DOMAINS,
    BRAVE_STYLE_COSMETIC_CSS,
    DEFAULT_COMPANION_PORT
)


class TestDomainUtilities(unittest.TestCase):
    def test_extract_base_domain(self):
        self.assertEqual(extract_base_domain("https://www.example.com/path?arg=1"), "www.example.com")
        self.assertEqual(extract_base_domain("http://phishing.xyz:8080/login"), "phishing.xyz")
        self.assertEqual(extract_base_domain("sub.domain.co.uk/test"), "sub.domain.co.uk")
        self.assertEqual(extract_base_domain("bare-domain.org"), "bare-domain.org")

    def test_match_domain_suffix(self):
        targets = {"doubleclick.net", "malware.top"}
        self.assertTrue(match_domain_suffix("doubleclick.net", targets))
        self.assertTrue(match_domain_suffix("ad.doubleclick.net", targets))
        self.assertTrue(match_domain_suffix("sub.deep.malware.top", targets))
        self.assertFalse(match_domain_suffix("safe-website.org", targets))
        self.assertFalse(match_domain_suffix("nodoubleclick.net.evil.com", targets))


class TestBrowserDetector(unittest.TestCase):
    def test_browser_definitions_cover_all_target_browsers(self):
        """Verifies Chrome, Brave, Edge, Firefox, and Opera are all defined."""
        defs = BrowserDetector.get_browser_definitions()
        for b in ["brave", "edge", "chrome", "firefox", "opera"]:
            self.assertIn(b, defs)
            self.assertIn("name", defs[b])
            self.assertIn("paths", defs[b])
            self.assertIn("extensions_url", defs[b])

    def test_detect_all_returns_structured_records(self):
        """Tests that detect_all returns valid detection records for all 5 browsers."""
        detected = BrowserDetector.detect_all()
        self.assertEqual(len(detected), 5)
        for b_id, record in detected.items():
            self.assertIn("id", record)
            self.assertIn("name", record)
            self.assertIn("installed", record)
            self.assertIsInstance(record["installed"], bool)
            self.assertIn("extensions_url", record)

    @patch('os.path.exists')
    def test_mock_detection(self, mock_exists):
        # Simulate Brave being installed
        mock_exists.side_effect = lambda p: "Brave-Browser" in p
        self.assertTrue(BrowserDetector.is_installed("brave"))
        self.assertIsNotNone(BrowserDetector.get_browser_exe("brave"))


class TestExtensionDeployer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.target_dir = Path(self.temp_dir.name) / "test_extension"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_deploy_extension_creates_valid_manifest_v3(self):
        """Deploys extension and validates Manifest V3 compliance."""
        ext_dir = ExtensionDeployer.deploy_extension_files(self.target_dir)
        self.assertTrue(ext_dir.exists())

        # Check manifest.json
        manifest_path = ext_dir / "manifest.json"
        self.assertTrue(manifest_path.exists())
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        self.assertEqual(manifest.get("manifest_version"), 3)
        self.assertIn("name", manifest)
        self.assertIn("version", manifest)
        self.assertIn("permissions", manifest)
        self.assertIn("declarativeNetRequest", manifest["permissions"])
        self.assertIn("storage", manifest["permissions"])
        self.assertIn("host_permissions", manifest)
        self.assertIn("<all_urls>", manifest["host_permissions"])
        self.assertIn("background", manifest)
        self.assertIn("content_scripts", manifest)
        self.assertIn("action", manifest)

    def test_deploy_extension_creates_all_assets(self):
        """Verifies background.js, content.js, rules.json, blocked.html, popup files, icons exist."""
        ext_dir = ExtensionDeployer.deploy_extension_files(self.target_dir)
        expected_files = [
            "manifest.json", "background.js", "content.js",
            "rules.json", "blocked.html", "popup.html", "popup.js",
            "icon16.png", "icon48.png", "icon128.png"
        ]
        for f in expected_files:
            p = ext_dir / f
            self.assertTrue(p.exists(), f"Asset {f} must exist in deployed extension")
            self.assertGreater(p.stat().st_size, 0, f"Asset {f} must not be empty")

    def test_rules_json_syntax(self):
        """Verifies rules.json is a valid declarativeNetRequest rule list."""
        ext_dir = ExtensionDeployer.deploy_extension_files(self.target_dir)
        rules_path = ext_dir / "rules.json"
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)

        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 10)
        first_rule = rules[0]
        self.assertIn("id", first_rule)
        self.assertIn("action", first_rule)
        self.assertEqual(first_rule["action"]["type"], "block")
        self.assertIn("condition", first_rule)
        self.assertIn("urlFilter", first_rule["condition"])

    def test_install_for_browser(self):
        """Tests install_for_browser returns instructions and clipboard notification for all 5 browsers."""
        for b in ["brave", "edge", "chrome", "firefox", "opera"]:
            ok, msg = ExtensionDeployer.install_for_browser(b)
            self.assertTrue(ok)
            self.assertIn("Developer mode", msg)
            self.assertIn("Load unpacked", msg)


class TestBrowserCompanionServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logger_mock = MagicMock()
        cls.profiles_mock = MagicMock()
        cls.profiles_mock.get_active_profile.return_value = "Corporate"
        cls.profiles_mock.get_setting.side_effect = lambda k, d=None: True

        # Use port 49219 for testing to avoid collisions
        cls.test_port = 49219
        cls.server = BrowserCompanionServer(
            port=cls.test_port,
            fw_logger=cls.logger_mock,
            profiles=cls.profiles_mock
        )
        started = cls.server.start()
        if not started:
            raise RuntimeError("Failed to start test BrowserCompanionServer")
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _get(self, path: str):
        url = f"http://127.0.0.1:{self.test_port}{path}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())

    def _post(self, path: str, payload: dict):
        url = f"http://127.0.0.1:{self.test_port}{path}"
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())

    def test_status_endpoint(self):
        """Tests /api/status reports online state and active profile."""
        data = self._get("/api/status")
        self.assertEqual(data.get("status"), "online")
        self.assertEqual(data.get("active_profile"), "Corporate")
        self.assertIn("threats_blocked", data)
        self.assertIn("ads_blocked", data)

    def test_config_endpoint(self):
        """Tests /api/config retrieval and update."""
        cfg = self._get("/api/config")
        self.assertTrue(cfg.get("browser_protection"))

        # Update
        res = self._post("/api/config", {"browser_adblock": True})
        self.assertTrue(res.get("success"))

    def test_adblock_rules_endpoint(self):
        """Tests /api/adblock_rules returns cosmetic CSS and domain blocklists."""
        data = self._get("/api/adblock_rules")
        self.assertIn("cosmetic_css", data)
        self.assertIn("ad_domains", data)
        self.assertIn("tracker_domains", data)
        self.assertIn("doubleclick.net", data["ad_domains"])
        self.assertIn("google-analytics.com", data["tracker_domains"])

    def test_browsers_endpoint(self):
        """Tests /api/browsers returns detected browsers."""
        browsers = self._get("/api/browsers")
        self.assertIn("brave", browsers)
        self.assertIn("edge", browsers)
        self.assertIn("chrome", browsers)
        self.assertIn("firefox", browsers)
        self.assertIn("opera", browsers)

    def test_check_url_malware_detection(self):
        """Tests /api/check_url flags known malware and phishing domains."""
        # Known malware domain
        res1 = self._post("/api/check_url", {"url": "https://crypto-drainer.click/airdrop"})
        self.assertTrue(res1.get("blocked"))
        self.assertEqual(res1.get("category"), "malware")

        # Heuristic keyword match
        res2 = self._post("/api/check_url", {"url": "http://steamcommuniity.ru/trade"})
        self.assertTrue(res2.get("blocked"))
        self.assertEqual(res2.get("category"), "malware")

        # Clean URL
        res3 = self._post("/api/check_url", {"url": "https://www.google.com/search?q=test"})
        self.assertFalse(res3.get("blocked"))
        self.assertEqual(res3.get("category"), "clean")

    def test_check_url_ad_and_tracker_detection(self):
        """Tests /api/check_url blocks ads and trackers."""
        # DoubleClick ad server
        res_ad = self._post("/api/check_url", {"url": "https://ad.doubleclick.net/pixel"})
        self.assertTrue(res_ad.get("blocked"))
        self.assertEqual(res_ad.get("category"), "ad")

        # Google Analytics tracker
        res_tr = self._post("/api/check_url", {"url": "https://google-analytics.com/analytics.js"})
        self.assertTrue(res_tr.get("blocked"))
        self.assertEqual(res_tr.get("category"), "tracker")

        # Cryptominer
        res_miner = self._post("/api/check_url", {"url": "https://coinhive.com/lib/miner.js"})
        self.assertTrue(res_miner.get("blocked"))
        self.assertEqual(res_miner.get("category"), "cryptominer")

    def test_report_threat_increments_counter_and_logs(self):
        """Tests /api/report_threat increments counter and triggers security audit log."""
        init_threats = self.server.threats_blocked
        payload = {
            "url": "http://phishing-bank-login.xyz/auth",
            "domain": "phishing-bank-login.xyz",
            "threat_type": "phishing",
            "reason": "Deceptive credential harvester"
        }
        res = self._post("/api/report_threat", payload)
        self.assertTrue(res.get("success"))
        self.assertEqual(self.server.threats_blocked, init_threats + 1)
        self.logger_mock.log_event.assert_called()

    def test_report_ad_increments_counter(self):
        """Tests /api/report_ad increments ad block metric."""
        init_ads = self.server.ads_blocked
        res = self._post("/api/report_ad", {"count": 5})
        self.assertTrue(res.get("success"))
        self.assertEqual(self.server.ads_blocked, init_ads + 5)


if __name__ == '__main__':
    unittest.main()
