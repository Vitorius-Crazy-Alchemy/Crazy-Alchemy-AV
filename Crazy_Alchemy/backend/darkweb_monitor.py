"""
Vitorius Antivirus - Email Dark Web & Data Breach Monitoring Engine
Monitors up to 15 user email addresses against continuously updated dark web threat feeds,
compromised credential dumps, and breach intelligence sources (XposedOrNot, DeHashed/HIBP datasets).
"""

import os
import sys
import re
import json
import time
import logging
import sqlite3
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger('vitorius.win.darkweb')

from backend.profiles_win import DATA_DIR, FirewallLogger

MAX_MONITORED_EMAILS = 15

# Primary live threat intelligence endpoints for dark web credential exposures
XPOSEDORNOT_CHECK_API = "https://api.xposedornot.com/v1/check-email/{email}"
XPOSEDORNOT_BREACHES_API = "https://api.xposedornot.com/v1/breaches"


class DarkWebMonitor:
    """
    Manages dark web exposure monitoring for up to 15 email accounts,
    pulling updates from live breach feeds and logging compromised credentials.
    """

    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        fw_logger: Optional[FirewallLogger] = None,
        check_interval_hours: int = 6,
        alert_callback=None
    ):
        self.data_dir = data_dir or DATA_DIR
        self.db_path = self.data_dir / "darkweb_monitor.db"
        self.fw_logger = fw_logger or FirewallLogger()
        self.check_interval_sec = max(3600, check_interval_hours * 3600)
        self.alert_callback = alert_callback

        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._breach_catalog_cache: Dict[str, Dict[str, Any]] = {}

        self._init_db()

    def _init_db(self):
        """Initializes SQLite database schemas for dark web monitoring."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS monitored_emails (
                    email TEXT PRIMARY KEY,
                    added_at TEXT NOT NULL,
                    last_checked TEXT,
                    breach_count INTEGER DEFAULT 0,
                    is_compromised INTEGER DEFAULT 0
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS breach_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    breach_name TEXT NOT NULL,
                    breach_date TEXT,
                    domain TEXT,
                    leaked_data TEXT,
                    description TEXT,
                    detected_at TEXT NOT NULL,
                    UNIQUE(email, breach_name)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS breach_catalog (
                    breach_name TEXT PRIMARY KEY,
                    domain TEXT,
                    breach_date TEXT,
                    leaked_data TEXT,
                    description TEXT,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialize dark web database: {e}")

    def add_email(self, email: str) -> Tuple[bool, str]:
        """
        Adds an email to dark web monitoring. Enforces strict maximum of 15 emails.
        """
        clean_email = email.strip().lower()
        if not clean_email or not self.EMAIL_REGEX.match(clean_email):
            return False, "Invalid email address format."

        with self._lock:
            current_emails = self.get_monitored_emails()
            if any(e["email"] == clean_email for e in current_emails):
                return False, f"Email '{clean_email}' is already being monitored."

            if len(current_emails) >= MAX_MONITORED_EMAILS:
                return False, f"Maximum limit of {MAX_MONITORED_EMAILS} monitored emails reached. Please remove an email first."

            try:
                conn = sqlite3.connect(str(self.db_path))
                cur = conn.cursor()
                now_iso = datetime.now(timezone.utc).isoformat()
                cur.execute(
                    "INSERT INTO monitored_emails (email, added_at, last_checked, breach_count, is_compromised) VALUES (?, ?, ?, 0, 0)",
                    (clean_email, now_iso, "Never")
                )
                conn.commit()
                conn.close()

                self.fw_logger.log_event(
                    "darkweb_email_added", "info",
                    f"Added email to DarkWeb monitoring: {clean_email} ({len(current_emails) + 1}/{MAX_MONITORED_EMAILS})"
                )
                logger.info(f"Added email for DarkWeb monitoring: {clean_email}")
                return True, f"Email '{clean_email}' successfully added to DarkWeb monitoring ({len(current_emails) + 1}/{MAX_MONITORED_EMAILS})."
            except Exception as e:
                logger.error(f"Failed to add email {clean_email}: {e}")
                return False, f"Database error: {e}"

    def remove_email(self, email: str) -> Tuple[bool, str]:
        """Removes an email and its breach records from dark web monitoring."""
        clean_email = email.strip().lower()
        with self._lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cur = conn.cursor()
                cur.execute("DELETE FROM monitored_emails WHERE email = ?", (clean_email,))
                cur.execute("DELETE FROM breach_records WHERE email = ?", (clean_email,))
                conn.commit()
                conn.close()

                self.fw_logger.log_event("darkweb_email_removed", "info", f"Removed email from DarkWeb monitoring: {clean_email}")
                return True, f"Removed '{clean_email}' from DarkWeb monitoring."
            except Exception as e:
                logger.error(f"Failed to remove email {clean_email}: {e}")
                return False, f"Database error: {e}"

    def get_monitored_emails(self) -> List[Dict[str, Any]]:
        """Returns all monitored emails (at most 15)."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("SELECT email, added_at, last_checked, breach_count, is_compromised FROM monitored_emails ORDER BY added_at DESC")
            rows = cur.fetchall()
            conn.close()

            results = []
            for r in rows:
                results.append({
                    "email": r[0],
                    "added_at": r[1],
                    "last_checked": r[2] or "Never",
                    "breach_count": r[3] or 0,
                    "is_compromised": bool(r[4])
                })
            return results
        except Exception as e:
            logger.error(f"Failed to query monitored emails: {e}")
            return []

    def get_breaches_for_email(self, email: str) -> List[Dict[str, Any]]:
        """Returns all recorded breach instances for a specific email."""
        clean_email = email.strip().lower()
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                SELECT breach_name, breach_date, domain, leaked_data, description, detected_at
                FROM breach_records
                WHERE email = ?
                ORDER BY breach_date DESC
            """, (clean_email,))
            rows = cur.fetchall()
            conn.close()

            results = []
            for r in rows:
                results.append({
                    "breach_name": r[0],
                    "breach_date": r[1] or "Unknown",
                    "domain": r[2] or "Unknown",
                    "leaked_data": r[3] or "Credentials, Passwords",
                    "description": r[4] or "Compromised in verified dark web paste/breach.",
                    "detected_at": r[5]
                })
            return results
        except Exception as e:
            logger.error(f"Failed to query breach records for {clean_email}: {e}")
            return []

    def get_all_breaches(self) -> List[Dict[str, Any]]:
        """Returns all recorded breach instances across all monitored accounts."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                SELECT email, breach_name, breach_date, domain, leaked_data, description, detected_at
                FROM breach_records
                ORDER BY detected_at DESC
            """)
            rows = cur.fetchall()
            conn.close()

            results = []
            for r in rows:
                results.append({
                    "email": r[0],
                    "breach_name": r[1],
                    "breach_date": r[2] or "Unknown",
                    "domain": r[3] or "Unknown",
                    "leaked_data": r[4] or "Credentials",
                    "description": r[5] or "Compromised in dark web dump.",
                    "detected_at": r[6]
                })
            return results
        except Exception as e:
            logger.error(f"Failed to query all breaches: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Returns overview statistics for the dark web monitoring page."""
        emails = self.get_monitored_emails()
        compromised = sum(1 for e in emails if e["is_compromised"])
        total_breaches = sum(e["breach_count"] for e in emails)

        last_sync = "Never"
        checked_dates = [e["last_checked"] for e in emails if e["last_checked"] != "Never"]
        if checked_dates:
            last_sync = max(checked_dates)

        return {
            "total_monitored": len(emails),
            "max_allowed": MAX_MONITORED_EMAILS,
            "compromised_accounts": compromised,
            "total_breaches_found": total_breaches,
            "last_sync": last_sync
        }

    def _sync_breach_catalog(self, timeout: int = 10):
        """Fetches and caches updated breach definitions and leaked data classes."""
        try:
            req = urllib.request.Request(
                XPOSEDORNOT_BREACHES_API,
                headers={"User-Agent": "Vitorius-Firewall-Win-Enterprise/2.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    raw = resp.read().decode('utf-8')
                    data = json.loads(raw)
                    breach_list = data.get("exposedBreaches", [])
                    now_iso = datetime.now(timezone.utc).isoformat()

                    conn = sqlite3.connect(str(self.db_path))
                    cur = conn.cursor()
                    for b in breach_list:
                        name = b.get("breachID", "")
                        if not name:
                            continue
                        domain = b.get("domain", "")
                        b_date = b.get("breachDate", "")
                        exposed = ", ".join(b.get("xposedData", [])) or "Passwords, Emails"
                        desc = b.get("xposureDetails", "")

                        self._breach_catalog_cache[name.lower()] = {
                            "domain": domain,
                            "breach_date": b_date,
                            "leaked_data": exposed,
                            "description": desc
                        }

                        cur.execute("""
                            INSERT OR REPLACE INTO breach_catalog
                            (breach_name, domain, breach_date, leaked_data, description, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (name, domain, b_date, exposed, desc, now_iso))

                    conn.commit()
                    conn.close()
                    logger.info(f"Synchronized {len(breach_list)} updated dark web breach definitions.")
        except Exception as e:
            logger.debug(f"Breach catalog synchronization notice: {e}")

    def check_email_live(self, email: str, timeout: int = 12) -> List[Dict[str, Any]]:
        """
        Queries updated live breach intelligence sources for a specific email address.
        Records discovered breaches and updates compromised status.
        """
        clean_email = email.strip().lower()
        logger.info(f"Checking live dark web feeds for: {clean_email}")

        # Ensure breach definitions are populated
        if not self._breach_catalog_cache:
            self._sync_breach_catalog(timeout=5)

        discovered_breaches = []
        url = XPOSEDORNOT_CHECK_API.format(email=clean_email)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Vitorius-Firewall-Win-Enterprise/2.0 (LudaCris)",
                "Accept": "application/json"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    raw = resp.read().decode('utf-8')
                    result = json.loads(raw)
                    breaches_raw = result.get("breaches", [])
                    if isinstance(breaches_raw, list):
                        # Some endpoints return [["Breach1", "Breach2"]] or ["Breach1", "Breach2"]
                        if breaches_raw and isinstance(breaches_raw[0], list):
                            names = breaches_raw[0]
                        else:
                            names = breaches_raw

                        for b_name in names:
                            if isinstance(b_name, str) and b_name.strip():
                                b_clean = b_name.strip()
                                meta = self._breach_catalog_cache.get(b_clean.lower(), {})
                                discovered_breaches.append({
                                    "breach_name": b_clean,
                                    "domain": meta.get("domain", "Unknown"),
                                    "breach_date": meta.get("breach_date", "Recent"),
                                    "leaked_data": meta.get("leaked_data", "Credentials, Passwords, PII"),
                                    "description": meta.get("description", "Exposed in verified dark web paste/database leak.")
                                })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # 404 means email is clean in database!
                logger.info(f"Email {clean_email} is clean (no exposures found in live feeds).")
            else:
                logger.warning(f"Live breach check HTTP {e.code} for {clean_email}")
        except Exception as e:
            logger.warning(f"Live breach check network error for {clean_email}: {e}")

        # Update database with findings
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()

            new_breaches_count = 0
            for b in discovered_breaches:
                try:
                    cur.execute("""
                        INSERT INTO breach_records
                        (email, breach_name, breach_date, domain, leaked_data, description, detected_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (clean_email, b["breach_name"], b["breach_date"], b["domain"], b["leaked_data"], b["description"], now_iso))
                    new_breaches_count += 1
                except sqlite3.IntegrityError:
                    # Already recorded breach
                    pass

            is_comp = 1 if len(discovered_breaches) > 0 else 0
            cur.execute("""
                UPDATE monitored_emails
                SET last_checked = ?, breach_count = ?, is_compromised = ?
                WHERE email = ?
            """, (now_iso, len(discovered_breaches), is_comp, clean_email))

            conn.commit()
            conn.close()

            if new_breaches_count > 0:
                self.fw_logger.log_event(
                    "darkweb_breach_detected", "critical",
                    f"DarkWeb Alert: {clean_email} found in {new_breaches_count} new breach(es)!",
                    details={"email": clean_email, "breaches": [b["breach_name"] for b in discovered_breaches]}
                )
                if self.alert_callback:
                    self.alert_callback(clean_email, discovered_breaches)

        except Exception as e:
            logger.error(f"Error persisting breach results for {clean_email}: {e}")

        return discovered_breaches

    def check_all_monitored_live(self) -> Dict[str, Any]:
        """
        Synchronizes all monitored emails (up to 15) against live updated sources.
        """
        emails = self.get_monitored_emails()
        logger.info(f"Performing DarkWeb live sync across {len(emails)} monitored accounts...")

        # Update breach catalog first
        self._sync_breach_catalog(timeout=10)

        total_checked = 0
        total_breaches = 0

        for e in emails:
            target = e["email"]
            found = self.check_email_live(target)
            total_checked += 1
            total_breaches += len(found)
            # Polite rate-limiting between API calls
            time.sleep(0.4)

        return {
            "emails_checked": total_checked,
            "total_breaches": total_breaches,
            "synced_at": datetime.now(timezone.utc).isoformat()
        }

    def start(self):
        """Starts background periodic dark web synchronization thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="darkweb-monitor-loop")
            self._thread.start()
        logger.info("DarkWeb Identity Shield & Breach Monitor activated.")

    def stop(self):
        """Stops background dark web synchronization thread."""
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("DarkWeb Identity Shield stopped.")

    def _monitor_loop(self):
        """Continuous background thread periodically querying updated threat feeds."""
        while True:
            with self._lock:
                if not self._running:
                    break

            try:
                self.check_all_monitored_live()
            except Exception as e:
                logger.error(f"Error during scheduled DarkWeb feed sync: {e}")

            # Sleep until next interval (checking running flag periodically)
            steps = int(self.check_interval_sec / 5)
            for _ in range(steps):
                with self._lock:
                    if not self._running:
                        return
                time.sleep(5)
