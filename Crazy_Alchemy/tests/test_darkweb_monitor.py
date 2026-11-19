"""
Unit Tests for Vitorius Firewall Win - DarkWeb Identity & Breach Intelligence Monitor
Validates strict maximum 15 email monitoring limit, live threat feed queries,
duplicate prevention, input validation, and breach database operations.
"""

import unittest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error
import io

from backend.darkweb_monitor import DarkWebMonitor, MAX_MONITORED_EMAILS
from backend.profiles_win import FirewallLogger


class TestDarkWebMonitor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.data_dir = Path(self.temp_dir)
        self.fw_logger = FirewallLogger()
        self.alerts = []
        self.monitor = DarkWebMonitor(
            data_dir=self.data_dir,
            fw_logger=self.fw_logger,
            check_interval_hours=1,
            alert_callback=lambda email, breaches: self.alerts.append((email, breaches))
        )

    def tearDown(self):
        self.monitor.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_database_initialization(self):
        """Verifies database schemas and tables are initialized correctly."""
        self.assertTrue(self.monitor.db_path.exists())
        stats = self.monitor.get_stats()
        self.assertEqual(stats["total_monitored"], 0)
        self.assertEqual(stats["max_allowed"], 15)
        self.assertEqual(stats["compromised_accounts"], 0)
        self.assertEqual(stats["total_breaches_found"], 0)
        self.assertEqual(stats["last_sync"], "Never")

    def test_max_15_emails_limit_enforced(self):
        """
        Verifies that at most 15 emails can be added for dark web monitoring,
        and the 16th email is strictly rejected.
        """
        self.assertEqual(MAX_MONITORED_EMAILS, 15)

        # Add 15 distinct email addresses
        for i in range(1, 16):
            email = f"user{i}@enterprise.com"
            success, msg = self.monitor.add_email(email)
            self.assertTrue(success, f"Failed to add email {i}: {msg}")
            self.assertIn(f"({i}/15)", msg)

        # Confirm 15 emails are tracked
        emails = self.monitor.get_monitored_emails()
        self.assertEqual(len(emails), 15)
        stats = self.monitor.get_stats()
        self.assertEqual(stats["total_monitored"], 15)

        # Attempt to add the 16th email - must fail strictly
        fail_success, fail_msg = self.monitor.add_email("user16@enterprise.com")
        self.assertFalse(fail_success)
        self.assertIn("Maximum limit of 15 monitored emails reached", fail_msg)

        # Confirm count remains 15
        self.assertEqual(len(self.monitor.get_monitored_emails()), 15)

    def test_email_validation_and_normalization(self):
        """Tests email format validation, whitespace trimming, and lowercase conversion."""
        # Invalid email formats
        invalid_emails = ["notanemail", "user@", "@domain.com", "user@domain", "user space@domain.com"]
        for inv in invalid_emails:
            success, msg = self.monitor.add_email(inv)
            self.assertFalse(success, f"Expected invalid email to fail: {inv}")
            self.assertIn("Invalid email address format", msg)

        # Valid with leading/trailing spaces and mixed case
        success, msg = self.monitor.add_email("  SecOps.ADMIN@VitoriusCorp.COM  ")
        self.assertTrue(success)
        emails = self.monitor.get_monitored_emails()
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]["email"], "secops.admin@vitoriuscorp.com")

        # Duplicate email check
        dup_success, dup_msg = self.monitor.add_email("SECOPS.ADMIN@vitoriuscorp.com")
        self.assertFalse(dup_success)
        self.assertIn("already being monitored", dup_msg)

    def test_remove_email_and_cascade(self):
        """Tests email removal and verifies slot frees up for a new email."""
        # Add 15 emails
        for i in range(1, 16):
            self.monitor.add_email(f"worker{i}@domain.org")

        self.assertEqual(len(self.monitor.get_monitored_emails()), 15)

        # Remove worker10@domain.org
        remove_success, remove_msg = self.monitor.remove_email("worker10@domain.org")
        self.assertTrue(remove_success)
        self.assertEqual(len(self.monitor.get_monitored_emails()), 14)

        # Now 15th slot is available again
        new_success, new_msg = self.monitor.add_email("replacement@domain.org")
        self.assertTrue(new_success)
        self.assertEqual(len(self.monitor.get_monitored_emails()), 15)

    @patch("urllib.request.urlopen")
    def test_live_check_clean_email(self, mock_urlopen):
        """Simulates querying live breach feed for an uncompromised email (HTTP 404)."""
        self.monitor.add_email("clean_user@securecorp.com")

        # Mock 404 HTTPError (email is clean)
        fp = io.BytesIO(b'{"status":"clean"}')
        http_err = urllib.error.HTTPError(
            url="https://api.xposedornot.com/v1/check-email/clean_user@securecorp.com",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=fp
        )
        mock_urlopen.side_effect = http_err

        try:
            breaches = self.monitor.check_email_live("clean_user@securecorp.com")
        finally:
            fp.close()
            http_err.close()

        self.assertEqual(len(breaches), 0)

        emails = self.monitor.get_monitored_emails()
        self.assertEqual(len(emails), 1)
        self.assertFalse(emails[0]["is_compromised"])
        self.assertEqual(emails[0]["breach_count"], 0)
        self.assertNotEqual(emails[0]["last_checked"], "Never")

    @patch("urllib.request.urlopen")
    def test_live_check_compromised_email(self, mock_urlopen):
        """Simulates querying live breach feed for a breached email (HTTP 200)."""
        self.monitor.add_email("victim@company.com")

        # Mock API returning breaches
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "breaches": [["LinkedIn-Dump-2023", "Adobe-Exploit-DB"]]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_urlopen.return_value = mock_resp

        breaches = self.monitor.check_email_live("victim@company.com")
        self.assertEqual(len(breaches), 2)
        self.assertEqual(breaches[0]["breach_name"], "LinkedIn-Dump-2023")
        self.assertEqual(breaches[1]["breach_name"], "Adobe-Exploit-DB")

        # Verify database updated
        emails = self.monitor.get_monitored_emails()
        self.assertEqual(len(emails), 1)
        self.assertTrue(emails[0]["is_compromised"])
        self.assertEqual(emails[0]["breach_count"], 2)

        # Verify breach records retrieved
        records = self.monitor.get_breaches_for_email("victim@company.com")
        self.assertEqual(len(records), 2)

        all_records = self.monitor.get_all_breaches()
        self.assertEqual(len(all_records), 2)

        # Verify alert callback fired
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0][0], "victim@company.com")

        # Check stats summary
        stats = self.monitor.get_stats()
        self.assertEqual(stats["total_monitored"], 1)
        self.assertEqual(stats["compromised_accounts"], 1)
        self.assertEqual(stats["total_breaches_found"], 2)

    def test_background_thread_start_stop(self):
        """Verifies safe startup and shutdown of background monitoring thread."""
        self.assertFalse(self.monitor._running)
        self.monitor.start()
        self.assertTrue(self.monitor._running)
        self.assertIsNotNone(self.monitor._thread)
        self.assertTrue(self.monitor._thread.is_alive())

        self.monitor.stop()
        self.assertFalse(self.monitor._running)


if __name__ == '__main__':
    unittest.main()
