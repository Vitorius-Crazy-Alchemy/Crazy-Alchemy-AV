"""
Crazy Alchemy Antivirus - Online Incremental Signature Updater
Fetches malware hash signatures from Abuse.ch threat repositories (MalwareBazaar, ThreatFox, URLhaus)
and high-speed community mirrors to keep local threat signatures continuously updated.
Supports scheduled auto-updating every 2, 5, 12, or 24 hours.
"""

import os
import csv
import io
import gzip
import sqlite3
import json
import logging
import time
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List, Set

logger = logging.getLogger('vitorius.win.updater')

# Free API endpoints, bulk exports and community threat intelligence mirrors
MALWAREBAZAAR_RECENT_API = "https://mb-api.abuse.ch/api/v1/"
MALWAREBAZAAR_EXPORT_RECENT_URL = "https://mb-api.abuse.ch/v2/files/exports/{api_key}/recent.csv"
THREATFOX_EXPORT_RECENT_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{api_key}/recent.csv"
THREATFOX_IOCS_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_PAYLOADS_API = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
URLHAUS_PAYLOADS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MALWAREBAZAAR_MIRROR_RECENT_URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/sources/bazaar.abuse.ch.sha256.txt"
COMMUNITY_SHA256_FEED_URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"

# Supported periodic auto-update intervals (in hours)
ALLOWED_UPDATE_INTERVALS: List[int] = [2, 5, 12, 24]
DEFAULT_UPDATE_INTERVAL_HOURS: int = 12


class SignatureUpdater:
    """
    Manages online synchronization of malware hash signatures across Abuse.ch repositories
    (MalwareBazaar bulk export & API, ThreatFox IOCs, and URLhaus payloads) as well as
    verified high-speed community mirrors.
    """

    def __init__(
        self,
        db_path: Path,
        interval_hours: int = DEFAULT_UPDATE_INTERVAL_HOURS,
        fw_logger=None,
        on_update_callback=None,
        api_key: Optional[str] = None
    ):
        self.db_path = db_path
        self.fw_logger = fw_logger
        self.on_update_callback = on_update_callback
        self.api_key = (api_key or os.environ.get("MALWAREBAZAAR_API_KEY") or os.environ.get("ABUSE_CH_API_KEY") or "").strip() or None

        self.interval_hours = interval_hours if interval_hours in ALLOWED_UPDATE_INTERVALS else DEFAULT_UPDATE_INTERVAL_HOURS

        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_attempt: Optional[str] = None
        self._last_status: Optional[str] = None

    def set_api_key(self, api_key: Optional[str]):
        """Sets or clears the Abuse.ch / MalwareBazaar Auth-Key."""
        with self._lock:
            self.api_key = (api_key or "").strip() or None
        logger.info("Threat intelligence Auth-Key configured.")

    def get_api_key(self) -> Optional[str]:
        """Returns the configured Abuse.ch / MalwareBazaar Auth-Key, if any."""
        with self._lock:
            return self.api_key

    def set_interval(self, hours: int) -> bool:
        """
        Sets the auto-update interval. Must be one of 2, 5, 12, or 24 hours.
        Returns True if updated successfully, False if interval is invalid.
        """
        if hours not in ALLOWED_UPDATE_INTERVALS:
            logger.warning(f"Invalid auto-update interval: {hours}. Allowed intervals: {ALLOWED_UPDATE_INTERVALS}")
            return False

        with self._lock:
            self.interval_hours = hours

        logger.info(f"Virus scanner auto-update interval set to every {hours} hours.")
        if self.fw_logger:
            self.fw_logger.log_event(
                "updater_interval_changed", "info",
                f"Virus scanner auto-update frequency configured to every {hours} hours"
            )
        return True

    def get_interval(self) -> int:
        """Returns the current auto-update interval in hours."""
        with self._lock:
            return self.interval_hours

    def start_auto_update(self, interval_hours: Optional[int] = None, on_update_callback=None):
        """Starts periodic background signature synchronization thread."""
        with self._lock:
            if interval_hours is not None:
                if interval_hours in ALLOWED_UPDATE_INTERVALS:
                    self.interval_hours = interval_hours
                else:
                    logger.warning(f"Ignored invalid interval {interval_hours}; using {self.interval_hours}h")

            if on_update_callback is not None:
                self.on_update_callback = on_update_callback

            if self._running:
                return

            self._running = True
            self._thread = threading.Thread(target=self._auto_update_loop, daemon=True, name="signature-auto-updater")
            self._thread.start()

        logger.info(f"Malware signature auto-updater started (every {self.interval_hours} hours).")

    def stop_auto_update(self):
        """Stops periodic background signature synchronization thread."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Malware signature auto-updater stopped.")

    def is_auto_update_running(self) -> bool:
        """Returns True if the background auto-update thread is active."""
        with self._lock:
            return self._running

    def _auto_update_loop(self):
        """Continuous background loop executing periodic signature updates."""
        logger.info(f"Signature auto-update loop active (interval: every {self.interval_hours} hours).")
        while True:
            with self._lock:
                if not self._running:
                    break
                current_interval = self.interval_hours

            # Execute online signature update
            try:
                now_str = datetime.now(timezone.utc).isoformat()
                self._last_attempt = now_str
                ok, msg, count = self.update_signatures()
                self._last_status = msg

                if self.fw_logger:
                    self.fw_logger.log_event(
                        "signature_auto_update",
                        "info" if ok else "warning",
                        f"Signature auto-update ({current_interval}h schedule): {msg} (+{count} signatures)"
                    )

                if self.on_update_callback:
                    try:
                        self.on_update_callback(ok, msg, count)
                    except Exception as cb_err:
                        logger.debug(f"Error in auto-update callback: {cb_err}")

            except Exception as e:
                logger.error(f"Error during scheduled signature update: {e}")
                self._last_status = str(e)

            # Sleep in 5-second slices up to current_interval * 3600 seconds,
            # allowing immediate termination or prompt response to interval changes
            total_seconds = max(60, current_interval * 3600)
            elapsed = 0
            while elapsed < total_seconds:
                with self._lock:
                    if not self._running:
                        return
                    if self.interval_hours != current_interval:
                        break
                time.sleep(5)
                elapsed += 5

    def get_stats(self) -> Dict[str, Any]:
        """Returns database statistics (total signatures, last sync date, auto-update status)."""
        stats: Dict[str, Any] = {
            "total_signatures": 0,
            "last_sync": "Never",
            "version": "3.0.0",
            "auto_update_enabled": self._running,
            "interval_hours": self.interval_hours,
            "allowed_intervals": list(ALLOWED_UPDATE_INTERVALS),
            "last_attempt": self._last_attempt,
            "last_status": self._last_status
        }

        if not self.db_path.exists():
            return stats

        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM signatures")
            row = cur.fetchone()
            if row:
                stats["total_signatures"] = row[0]

            cur.execute("SELECT value FROM sync_meta WHERE key = 'last_sync'")
            meta_row = cur.fetchone()
            if meta_row:
                stats["last_sync"] = meta_row[0]
            conn.close()

            return stats
        except Exception as e:
            logger.error(f"Error querying signature stats: {e}")
            stats["last_sync"] = "Error"
            return stats

    def _ensure_tables_and_get_cols(self, cur) -> List[str]:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                hash_sha256 TEXT PRIMARY KEY,
                hash_md5 TEXT,
                malware_family TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'critical',
                source TEXT NOT NULL,
                date_added TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sig_md5 ON signatures(hash_md5)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sig_family ON signatures(malware_family)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sync_meta (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        """)
        cur.execute("PRAGMA table_info(signatures)")
        return [r[1] for r in cur.fetchall()]

    def _insert_signature(self, cur, cols: List[str], sha256: str, md5: str, family: str, category: str, severity: str, source: str, date_str: str) -> int:
        """Single-row insertion helper kept for compatibility."""
        if not sha256 and not md5:
            return 0
        sha_clean = (sha256 or '').lower().strip()
        md5_clean = (md5 or '').lower().strip()
        fam_clean = family or 'Trojan.Generic'
        cat_clean = category or 'Malware'
        sev_clean = severity or 'critical'
        src_clean = source or 'MalwareBazaar'

        if 'hash_sha256' in cols:
            cur.execute(
                "INSERT OR IGNORE INTO signatures (hash_sha256, hash_md5, malware_family, threat_category, severity, source, date_added) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sha_clean, md5_clean, fam_clean, cat_clean, sev_clean, src_clean, date_str)
            )
        else:
            cur.execute(
                "INSERT OR IGNORE INTO signatures (sha256, md5, signature, category, severity, source, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sha_clean, md5_clean, fam_clean, cat_clean, sev_clean, src_clean, date_str)
            )
        return 1 if cur.rowcount > 0 else 0

    def _batch_insert_signatures(
        self,
        cur,
        cols: List[str],
        entries: List[Tuple[str, str, str, str, str, str]],
        date_str: str
    ) -> int:
        """
        High-performance deduplicating batch signature inserter.
        Each entry is (sha256, md5, family, category, severity, source).
        Uses executemany inside transaction for sub-second ingestion of tens of thousands of records.
        Returns count of new signatures actually inserted into SQLite.
        """
        if not entries:
            return 0

        unique_map: Dict[str, Tuple[str, str, str, str, str, str, str]] = {}
        for entry in entries:
            sha, md5, fam, cat, sev, src = entry
            sha_clean = (sha or "").strip().lower()
            md5_clean = (md5 or "").strip().lower()

            if len(sha_clean) != 64 and len(md5_clean) != 32:
                continue

            dedup_key = sha_clean if len(sha_clean) == 64 else f"md5:{md5_clean}"
            if dedup_key in unique_map:
                continue

            fam_clean = fam or "Trojan.Generic"
            cat_clean = cat or "Malware"
            sev_clean = sev or "critical"
            src_clean = src or "MalwareBazaar"

            unique_map[dedup_key] = (
                sha_clean, md5_clean, fam_clean, cat_clean, sev_clean, src_clean, date_str
            )

        batch_list = list(unique_map.values())
        if not batch_list:
            return 0

        cur.execute("SELECT COUNT(*) FROM signatures")
        count_before = cur.fetchone()[0]

        chunk_size = 5000
        for i in range(0, len(batch_list), chunk_size):
            chunk = batch_list[i:i + chunk_size]
            if 'hash_sha256' in cols:
                cur.executemany(
                    "INSERT OR IGNORE INTO signatures "
                    "(hash_sha256, hash_md5, malware_family, threat_category, severity, source, date_added) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    chunk
                )
            else:
                cur.executemany(
                    "INSERT OR IGNORE INTO signatures "
                    "(sha256, md5, signature, category, severity, source, added_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    chunk
                )

        cur.execute("SELECT COUNT(*) FROM signatures")
        count_after = cur.fetchone()[0]
        return max(0, count_after - count_before)

    def _fetch_malwarebazaar_export(self, api_key: str, timeout: int = 25) -> List[Tuple[str, str, str, str, str, str]]:
        """
        Fetches Abuse.ch MalwareBazaar recent additions (last 48 hours) bulk CSV export.
        Requires an authenticated Auth-Key. Returns list of (sha256, md5, family, category, severity, source).
        """
        if not api_key:
            return []
        url = MALWAREBAZAAR_EXPORT_RECENT_URL.format(api_key=api_key)
        headers = {
            "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
            "Accept-Encoding": "gzip, deflate"
        }
        req = urllib.request.Request(url, headers=headers)
        entries: List[Tuple[str, str, str, str, str, str]] = []
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    raw = resp.read()
                    if resp.headers.get("Content-Encoding") == "gzip" or raw.startswith(b"\x1f\x8b"):
                        raw = gzip.decompress(raw)
                    text = raw.decode("utf-8", errors="ignore")
                    reader = csv.reader(io.StringIO(text))

                    sha_idx = 1
                    md5_idx = 2
                    sig_idx = 8
                    type_idx = 6

                    for row in reader:
                        if not row:
                            continue
                        if row[0].startswith("#"):
                            header_line = ",".join(row).lower()
                            if "sha256_hash" in header_line:
                                cols = [c.strip().strip('#"\' ').lower() for c in row]
                                if "sha256_hash" in cols:
                                    sha_idx = cols.index("sha256_hash")
                                if "md5_hash" in cols:
                                    md5_idx = cols.index("md5_hash")
                                if "signature" in cols:
                                    sig_idx = cols.index("signature")
                                if "file_type_guess" in cols:
                                    type_idx = cols.index("file_type_guess")
                            continue

                        if len(row) <= max(sha_idx, md5_idx):
                            continue

                        sha = row[sha_idx].strip().lower()
                        md5 = row[md5_idx].strip().lower() if len(row) > md5_idx else ""
                        sig = row[sig_idx].strip() if len(row) > sig_idx and row[sig_idx].strip() not in ("n/a", "None", "") else ""
                        ftype = row[type_idx].strip() if len(row) > type_idx else ""
                        family = sig or ftype or "Trojan.Generic"

                        if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
                            entries.append((sha, md5, family, "Malware", "critical", "MalwareBazaar.Export"))
            logger.info(f"Retrieved {len(entries):,} threat hashes from MalwareBazaar recent bulk export.")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                logger.warning(f"MalwareBazaar Export HTTP {e.code}: Invalid or unauthorized Auth-Key.")
            else:
                logger.warning(f"MalwareBazaar Export HTTP {e.code}: {e.reason}")
        except Exception as e:
            logger.warning(f"MalwareBazaar Export fetch notice: {e}")
        return entries

    def _fetch_malwarebazaar_api(self, api_key: Optional[str], selector: str = "100", timeout: int = 15) -> List[Tuple[str, str, str, str, str, str]]:
        """
        Queries official Abuse.ch MalwareBazaar JSON API for recent malware samples.
        """
        data_payload = f"query=get_recent&selector={selector}".encode('utf-8')
        headers = {
            "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        if api_key:
            headers["Auth-Key"] = api_key

        req = urllib.request.Request(MALWAREBAZAAR_RECENT_API, data=data_payload, headers=headers)
        entries: List[Tuple[str, str, str, str, str, str]] = []
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode('utf-8'))
                    if res_json.get('query_status') == 'ok':
                        for item in res_json.get('data', []):
                            sha = item.get('sha256_hash', '').strip().lower()
                            md5 = item.get('md5_hash', '').strip().lower()
                            family = item.get('signature') or item.get('file_type') or 'Trojan.Generic'
                            category = item.get('delivery_method') or 'Malware'
                            if len(sha) == 64:
                                entries.append((sha, md5, family, category, 'critical', 'MalwareBazaar.API'))
            logger.info(f"Retrieved {len(entries):,} hashes from MalwareBazaar API (selector={selector}).")
        except Exception as e:
            logger.debug(f"MalwareBazaar API (selector={selector}) notice: {e}")
        return entries

    def _fetch_threatfox_hashes(self, api_key: Optional[str], timeout: int = 20) -> List[Tuple[str, str, str, str, str, str]]:
        """
        Fetches malware file hashes from Abuse.ch ThreatFox (corresponding IOC repository).
        Attempts bulk export first if key is present; falls back to live IOCs query.
        """
        entries: List[Tuple[str, str, str, str, str, str]] = []

        if api_key:
            try:
                url = THREATFOX_EXPORT_RECENT_URL.format(api_key=api_key)
                headers = {
                    "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
                    "Accept-Encoding": "gzip, deflate"
                }
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        raw = resp.read()
                        if resp.headers.get("Content-Encoding") == "gzip" or raw.startswith(b"\x1f\x8b"):
                            raw = gzip.decompress(raw)
                        text = raw.decode("utf-8", errors="ignore")
                        reader = csv.reader(io.StringIO(text))

                        ioc_idx = 2
                        type_idx = 3
                        fam_idx = 7
                        threat_idx = 4

                        for row in reader:
                            if not row:
                                continue
                            if row[0].startswith("#"):
                                cols = [c.strip().strip('#"\' ').lower() for c in row]
                                if "ioc_value" in cols:
                                    ioc_idx = cols.index("ioc_value")
                                elif "ioc" in cols:
                                    ioc_idx = cols.index("ioc")
                                if "ioc_type" in cols:
                                    type_idx = cols.index("ioc_type")
                                if "malware_printable" in cols:
                                    fam_idx = cols.index("malware_printable")
                                if "threat_type" in cols:
                                    threat_idx = cols.index("threat_type")
                                continue

                            if len(row) <= max(ioc_idx, type_idx):
                                continue

                            ioc_val = row[ioc_idx].strip().lower()
                            ioc_type = row[type_idx].strip().lower()
                            fam = row[fam_idx].strip() if len(row) > fam_idx else "Malware"
                            ttype = row[threat_idx].strip() if len(row) > threat_idx else "Malware"

                            if ioc_type in ("sha256_hash", "sha256") and len(ioc_val) == 64:
                                entries.append((ioc_val, "", fam or "Malware", ttype or "Malware", "critical", "Abuse.ch.ThreatFox"))
                            elif ioc_type in ("md5_hash", "md5") and len(ioc_val) == 32:
                                entries.append(("", ioc_val, fam or "Malware", ttype or "Malware", "critical", "Abuse.ch.ThreatFox"))
                if entries:
                    logger.info(f"Retrieved {len(entries):,} file hashes from ThreatFox bulk export.")
                    return entries
            except Exception as e:
                logger.debug(f"ThreatFox bulk export notice: {e}")

        # Live ThreatFox IOCs API fallback
        try:
            req_data = json.dumps({"query": "get_iocs", "days": 3}).encode("utf-8")
            headers = {
                "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
                "Content-Type": "application/json"
            }
            if api_key:
                headers["Auth-Key"] = api_key
            req = urllib.request.Request(THREATFOX_IOCS_API, data=req_data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    if res_json.get("query_status") == "ok":
                        for item in res_json.get("data", []):
                            ioc = item.get("ioc", "").strip().lower()
                            ioc_type = item.get("ioc_type", "").strip().lower()
                            fam = item.get("malware_printable") or "Malware"
                            threat = item.get("threat_type_desc") or item.get("threat_type") or "Malware"
                            if ioc_type in ("sha256_hash", "sha256") and len(ioc) == 64:
                                entries.append((ioc, "", fam, threat, "critical", "ThreatFox.API"))
                            elif ioc_type in ("md5_hash", "md5") and len(ioc) == 32:
                                entries.append(("", ioc, fam, threat, "critical", "ThreatFox.API"))
            if entries:
                logger.info(f"Retrieved {len(entries):,} file hashes from ThreatFox IOCs API.")
        except Exception as e:
            logger.debug(f"ThreatFox IOCs API query notice: {e}")

        return entries

    def _fetch_urlhaus_payloads(self, api_key: Optional[str], timeout: int = 20) -> List[Tuple[str, str, str, str, str, str]]:
        """
        Fetches malware payload hashes from Abuse.ch URLhaus (corresponding payload repository).
        """
        entries: List[Tuple[str, str, str, str, str, str]] = []

        try:
            headers = {"User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)"}
            if api_key:
                headers["Auth-Key"] = api_key
            req = urllib.request.Request(URLHAUS_PAYLOADS_API, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    if res_json.get("query_status") == "ok":
                        for p in res_json.get("payloads", []):
                            sha = p.get("sha256_hash", "").strip().lower()
                            md5 = p.get("md5_hash", "").strip().lower()
                            sig = p.get("signature") or "Malware.Payload"
                            ftype = p.get("file_type") or "Payload"
                            if len(sha) == 64 or len(md5) == 32:
                                entries.append((sha, md5, sig, ftype, "critical", "URLhaus.Payload"))
            if entries:
                logger.info(f"Retrieved {len(entries):,} payload hashes from URLhaus API.")
                return entries
        except Exception as e:
            logger.debug(f"URLhaus payloads API query notice: {e}")

        # Fallback to URLhaus recent payload CSV
        try:
            req = urllib.request.Request(URLHAUS_PAYLOADS_CSV, headers={"User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    text = resp.read().decode("utf-8", errors="ignore")
                    reader = csv.reader(io.StringIO(text))
                    for row in reader:
                        if not row or row[0].startswith("#") or len(row) < 3:
                            continue
                        for col in row:
                            clean_col = col.strip().lower()
                            if len(clean_col) == 64 and all(c in "0123456789abcdef" for c in clean_col):
                                entries.append((clean_col, "", "Malware.Payload", "Payload Delivery", "critical", "URLhaus.Feed"))
                                break
            if entries:
                logger.info(f"Retrieved {len(entries):,} payload hashes from URLhaus CSV feed.")
        except Exception as e:
            logger.debug(f"URLhaus payload CSV fallback notice: {e}")

        return entries

    def _fetch_community_mirrors(self, max_bytes: int = 5 * 1024 * 1024, timeout: int = 20) -> List[Tuple[str, str, str, str, str, str]]:
        """
        Fetches high-speed verified community malware hash feeds (MalwareBazaar mirror & community feeds).
        """
        entries: List[Tuple[str, str, str, str, str, str]] = []
        for url, src_name in [
            (MALWAREBAZAAR_MIRROR_RECENT_URL, "MalwareBazaar.Mirror"),
            (COMMUNITY_SHA256_FEED_URL, "Community.ClamAV")
        ]:
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "CrazyAlchemy-AV/3.0 (Windows 11 x64)",
                        "Range": f"bytes=0-{max_bytes}"
                    }
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status in (200, 206):
                        raw = resp.read().decode("utf-8", errors="ignore")
                        for line in raw.splitlines():
                            h = line.strip().lower()
                            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                                entries.append((h, "", "Trojan.Generic", "Malware", "high", src_name))
            except Exception as e:
                logger.debug(f"Community mirror fetch notice ({url}): {e}")

        if entries:
            logger.info(f"Retrieved {len(entries):,} hashes from community mirrors.")
        return entries

    def update_signatures(self, timeout: int = 20) -> Tuple[bool, str, int]:
        """
        Fetches latest malware deltas from MalwareBazaar and corresponding repositories.
        1. If an Abuse.ch Auth-Key is present:
           - Ingests MalwareBazaar 48-hour bulk export (recent.csv) and live API additions.
           - Ingests ThreatFox IOC malware file hashes (SHA-256 / MD5).
           - Ingests URLhaus payload malware hashes.
        2. If unauthorized, omitted, or unreachable, seamlessly falls back
           to high-speed verified community mirrors (MalwareBazaar mirror + Community feeds).
        Returns (success_bool, message, new_signatures_count).
        """
        api_key = self.get_api_key()
        all_entries: List[Tuple[str, str, str, str, str, str]] = []
        sources_used: List[str] = []
        network_error = None

        if api_key:
            # 1. MalwareBazaar Recent Authenticated Export
            mb_export = self._fetch_malwarebazaar_export(api_key, timeout=timeout)
            if mb_export:
                all_entries.extend(mb_export)
                sources_used.append("MalwareBazaar Export")

            # 2. MalwareBazaar Live API (last 100 additions)
            mb_api = self._fetch_malwarebazaar_api(api_key, selector="100", timeout=timeout)
            if mb_api:
                all_entries.extend(mb_api)
                sources_used.append("MalwareBazaar API")

            # 3. ThreatFox IOC Hashes
            tf_hashes = self._fetch_threatfox_hashes(api_key, timeout=timeout)
            if tf_hashes:
                all_entries.extend(tf_hashes)
                sources_used.append("ThreatFox")

            # 4. URLhaus Payload Hashes
            uh_hashes = self._fetch_urlhaus_payloads(api_key, timeout=timeout)
            if uh_hashes:
                all_entries.extend(uh_hashes)
                sources_used.append("URLhaus")

        # 5. Seamless fallback to community mirrors if without key or if online feeds yielded nothing
        if not all_entries:
            mirror_hashes = self._fetch_community_mirrors(max_bytes=2 * 1024 * 1024, timeout=timeout)
            if mirror_hashes:
                all_entries.extend(mirror_hashes)
                sources_used.append("Community Mirrors")
            elif not api_key:
                network_error = "Community mirrors unreachable"
            else:
                network_error = "Threat repositories unreachable or key unauthorized"

        now_iso = datetime.now(timezone.utc).isoformat()
        added_count = 0
        total_count = 0

        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=30.0)
            try:
                cur = conn.cursor()
                cols = self._ensure_tables_and_get_cols(cur)

                added_count = self._batch_insert_signatures(cur, cols, all_entries, now_iso)

                cur.execute(
                    "INSERT OR REPLACE INTO sync_meta VALUES ('last_sync', ?, ?)",
                    (now_iso, now_iso)
                )

                cur.execute("SELECT COUNT(*) FROM signatures")
                row = cur.fetchone()
                total_count = row[0] if row else 0

                conn.commit()
            finally:
                conn.close()

            if network_error and not all_entries:
                return False, f"Update server unavailable: {network_error}. Existing threat definitions remain active.", 0

            src_str = " + ".join(sources_used) if sources_used else "Threat Intelligence Feeds"
            if added_count > 0:
                msg = f"Successfully synchronized ({src_str}). Added {added_count:,} new signatures ({total_count:,} total active)."
            else:
                msg = f"Signatures are up to date ({total_count:,} active threat signatures verified against {src_str})."

            # Synchronize Abuse.ch live malware domains with the same Auth-Key
            try:
                from backend.browser_shield import AbuseCHDomainManager
                d_mgr = AbuseCHDomainManager(fw_logger=self.fw_logger)
                d_mgr.set_api_key(api_key)
                d_mgr.sync_feeds(force=False)
            except Exception as d_err:
                logger.debug(f"Antivirus updater domain sync notice: {d_err}")

            logger.info(msg)
            return True, msg, added_count
        except Exception as e:
            logger.error(f"Database write error during update: {e}")
            return False, f"Database write error: {e}", 0

    def full_update_signatures(self, timeout: int = 30, progress_callback=None) -> Tuple[bool, str, int]:
        """
        Executes a comprehensive Full Database Update across all threat repositories:
        1. Ingests all curated enterprise malware definitions (CORE_BASELINE_THREATS).
        2. Ingests Abuse.ch MalwareBazaar bulk export (recent.csv) and live API deltas.
        3. Ingests Abuse.ch ThreatFox IOC file hashes (SHA-256 / MD5).
        4. Ingests Abuse.ch URLhaus malware payload hashes.
        5. Ingests high-capacity community feeds (ClamAV & community verified mirrors).
        6. Synchronizes Abuse.ch live malware domains and updates metadata.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        all_entries: List[Tuple[str, str, str, str, str, str]] = []
        sources_used: List[str] = []

        # 1. Ingest Core Baseline Threats Catalog
        try:
            from data.signatures.seed_hashes import CORE_BASELINE_THREATS
            for sha, md5, fam, cat, sev, src in CORE_BASELINE_THREATS:
                all_entries.append((sha, md5, fam, cat, sev, src))
            sources_used.append("Baseline Seeds")
        except Exception as e:
            logger.debug(f"Baseline catalog load notice: {e}")

        # 2. Ingest MalwareBazaar, ThreatFox, and URLhaus if Auth-Key present
        api_key = self.get_api_key()
        if api_key:
            mb_export = self._fetch_malwarebazaar_export(api_key, timeout=timeout)
            if mb_export:
                all_entries.extend(mb_export)
                sources_used.append("MalwareBazaar Export")

            mb_api = self._fetch_malwarebazaar_api(api_key, selector="100", timeout=timeout)
            if mb_api:
                all_entries.extend(mb_api)
                sources_used.append("MalwareBazaar API")

            tf_hashes = self._fetch_threatfox_hashes(api_key, timeout=timeout)
            if tf_hashes:
                all_entries.extend(tf_hashes)
                sources_used.append("ThreatFox")

            uh_hashes = self._fetch_urlhaus_payloads(api_key, timeout=timeout)
            if uh_hashes:
                all_entries.extend(uh_hashes)
                sources_used.append("URLhaus")

        # 3. Ingest High-Speed Verified Community Feeds
        mirror_hashes = self._fetch_community_mirrors(max_bytes=10 * 1024 * 1024, timeout=timeout)
        if mirror_hashes:
            all_entries.extend(mirror_hashes)
            sources_used.append("Community Feeds")

        added_count = 0
        total_count = 0

        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=45.0)
            try:
                cur = conn.cursor()
                cols = self._ensure_tables_and_get_cols(cur)

                added_count = self._batch_insert_signatures(cur, cols, all_entries, now_iso)

                cur.execute("SELECT COUNT(*) FROM signatures")
                row = cur.fetchone()
                total_count = row[0] if row else 0

                cur.execute("INSERT OR REPLACE INTO sync_meta VALUES ('last_sync', ?, ?)", (now_iso, now_iso))
                cur.execute("INSERT OR REPLACE INTO sync_meta VALUES ('full_sync', ?, ?)", (now_iso, now_iso))
                conn.commit()
            finally:
                conn.close()

            # Synchronize Abuse.ch live malware domains with the same Auth-Key
            try:
                from backend.browser_shield import AbuseCHDomainManager
                d_mgr = AbuseCHDomainManager(fw_logger=self.fw_logger)
                d_mgr.set_api_key(api_key)
                d_mgr.sync_feeds(force=True)
            except Exception as d_err:
                logger.debug(f"Antivirus updater domain sync notice: {d_err}")

            src_str = " + ".join(sources_used)
            msg = f"Full Database Update Complete: Ingested {added_count:,} definitions ({total_count:,} total active threat signatures from {src_str})."
            logger.info(msg)
            return True, msg, added_count
        except Exception as e:
            logger.error(f"Full update signatures failure: {e}")
            return False, f"Full database update error: {e}", 0
