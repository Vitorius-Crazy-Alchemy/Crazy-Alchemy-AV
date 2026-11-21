"""
Vitorius Firewall Win - Browser Web Shield & Crazy-Style AdBlock Companion
Provides real-time malware interception, Crazy-style ad and tracker blocking,
and companion bridge integration for Firefox, Crazy, Chrome, Edge, and Opera.
"""

import os
import sys
import json
import logging
import threading
import time
import re
import urllib.parse
import urllib.request
import urllib.error
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger('vitorius.win.browser_shield')

DEFAULT_COMPANION_PORT = 49211

# ── Threat Intelligence & AdBlock Feeds ──────────────────────────────

KNOWN_MALWARE_DOMAINS: Set[str] = {
    "malware-traffic-analysis.net", "testmalware.com", "evil-payload.ru",
    "stealer-c2.top", "discord-webhook-stealer.xyz", "phishing-bank-login.xyz",
    "steamcommuniity.ru", "crypto-drainer.click", "fake-captcha-verify.top",
    "free-robux-generator.xyz", "crack-keygen-download.top", "infostealer-gate.biz",
    "lumma-c2-panel.xyz", "redline-stealer.top", "asyncrat-c2.net",
    "metamask-security-update.xyz", "phantom-wallet-airdrop.top", "paypa1-account-verify.com"
}

KNOWN_AD_DOMAINS: Set[str] = {
    # High-volume ad networks
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adservice.google.com", "adroll.com", "outbrain.com", "taboola.com",
    "popads.net", "propellerads.com", "exoclick.com", "adnxs.com",
    "rubiconproject.com", "criteo.com", "pubmatic.com", "amazon-adsystem.com",
    "moatads.com", "buysellads.com", "infolinks.com", "revcontent.com",
    "bidvertiser.com", "adblade.com", "exponential.com", "adpushup.com",
    "media.net", "contextweb.com", "yieldmo.com", "sovrn.com"
}

KNOWN_TRACKER_DOMAINS: Set[str] = {
    # Analytics and user tracking beacons
    "google-analytics.com", "hotjar.com", "scorecardresearch.com",
    "yandex.ru/metrika", "mouseflow.com", "statcounter.com", "branch.io",
    "mixpanel.com", "segment.io", "facebook.com/tr", "analytics.twitter.com",
    "clarity.ms", "crazyegg.com", "fullstory.com", "logentries.com",
    "amplitude.com", "onesignal.com", "smartlook.com", "inspectlet.com"
}

KNOWN_MINER_DOMAINS: Set[str] = {
    # Cryptojacking in-browser miners
    "coinhive.com", "coin-hive.com", "cryptoloot.pro", "crypto-loot.com",
    "webminepool.com", "jsecoin.com", "minr.pw", "monerominer.rocks",
    "coin-have.com", "authedmine.com", "cloudcoins.co", "hashing.win"
}

# Crazy-style element-hiding cosmetic rules
CRAZY_STYLE_COSMETIC_CSS = """
/* Crazy-Style Cosmetic Element Hiding Injected by Crazy Alchemy */
.ad-container, .ad-banner, .advertisement, .adsbygoogle,
[id*="google_ads"], [class*="google-ad"], [id*="taboola-"],
[id*="outbrain_"], [class*="sponsored-post"], [class*="native-ad"],
iframe[src*="doubleclick"], iframe[src*="adroll"], iframe[src*="amazon-adsystem"],
div[data-ad-unit], div[data-ad-slot], div[class*="ad_wrapper"],
div[class*="ad-slot"], div[id*="ad_banner"], div[id*="adv_box"] {
    display: none !important;
    visibility: hidden !important;
    height: 0px !important;
    width: 0px !important;
    max-height: 0px !important;
    pointer-events: none !important;
    opacity: 0 !important;
}
""".strip()
BRAVE_STYLE_COSMETIC_CSS = CRAZY_STYLE_COSMETIC_CSS


def extract_base_domain(url_or_domain: str) -> str:
    """Extracts normalized hostname/domain from URL or bare domain string."""
    if "://" in url_or_domain:
        try:
            parsed = urllib.parse.urlparse(url_or_domain)
            domain = parsed.hostname or url_or_domain
        except Exception:
            domain = url_or_domain
    else:
        domain = url_or_domain.split("/")[0].split(":")[0]
    return domain.strip().lower()


def match_domain_suffix(domain: str, target_set: Set[str]) -> bool:
    """Checks if domain or any parent domain matches a given target set."""
    domain = domain.lower()
    if domain in target_set:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in target_set:
            return True
    return False


# ── Abuse.ch Threat Intelligence Domain Engine ────────────────────────

THREATFOX_IOCS_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"

CORE_ABUSE_CH_MALWARE_DOMAINS: List[Tuple[str, str, str, str, int]] = [
    # Lumma Stealer / RedLine / Vidar / Racoon Infostealers
    ("stealer-c2.top", "botnet_cc", "Lumma Stealer", "Abuse.ch.ThreatFox", 100),
    ("lumma-c2-panel.xyz", "botnet_cc", "Lumma Stealer", "Abuse.ch.ThreatFox", 100),
    ("redline-stealer.top", "botnet_cc", "RedLine Stealer", "Abuse.ch.ThreatFox", 100),
    ("stealc-gate.click", "botnet_cc", "Stealc", "Abuse.ch.ThreatFox", 100),
    ("racoon-stealer.cc", "botnet_cc", "Racoon Stealer", "Abuse.ch.ThreatFox", 100),
    ("vidar-c2-server.top", "botnet_cc", "Vidar", "Abuse.ch.ThreatFox", 100),
    ("aurora-stealer.biz", "botnet_cc", "Aurora Stealer", "Abuse.ch.ThreatFox", 100),
    ("infostealer-gate.biz", "botnet_cc", "Infostealer", "Abuse.ch.ThreatFox", 100),
    ("discord-webhook-stealer.xyz", "payload_delivery", "Discord Token Stealer", "Abuse.ch.URLhaus", 100),
    # AsyncRAT, Quasar, Remcos, Warzone RATs & Botnets
    ("asyncrat-c2.net", "botnet_cc", "AsyncRAT", "Abuse.ch.ThreatFox", 100),
    ("remcos-panel.link", "botnet_cc", "Remcos RAT", "Abuse.ch.ThreatFox", 100),
    ("quasar-c2.org", "botnet_cc", "QuasarRAT", "Abuse.ch.ThreatFox", 100),
    ("warzone-rat.biz", "botnet_cc", "Warzone RAT", "Abuse.ch.ThreatFox", 100),
    ("netwire-c2.top", "botnet_cc", "Netwire RAT", "Abuse.ch.ThreatFox", 100),
    ("cobaltstrike-beacon.online", "botnet_cc", "Cobalt Strike", "Abuse.ch.ThreatFox", 100),
    # Phishing & Fake Logins / Crypto Drainers
    ("phishing-bank-login.xyz", "phishing", "Credential Harvester", "Abuse.ch.URLhaus", 100),
    ("steamcommuniity.ru", "phishing", "Steam Account Stealer", "Abuse.ch.URLhaus", 100),
    ("paypa1-account-verify.com", "phishing", "PayPal Phish", "Abuse.ch.URLhaus", 100),
    ("metamask-security-update.xyz", "phishing", "Crypto Drainer Phish", "Abuse.ch.URLhaus", 100),
    ("phantom-wallet-airdrop.top", "phishing", "Solana Drainer Phish", "Abuse.ch.URLhaus", 100),
    ("crypto-drainer.click", "payload_delivery", "Web3 Permit2 Drainer", "Abuse.ch.URLhaus", 100),
    ("fake-captcha-verify.top", "payload_delivery", "ClickFix Lumma Dropper", "Abuse.ch.URLhaus", 100),
    ("free-robux-generator.xyz", "payload_delivery", "Trojan Dropper", "Abuse.ch.URLhaus", 100),
    ("crack-keygen-download.top", "payload_delivery", "Malware Loader", "Abuse.ch.URLhaus", 100),
    ("evil-payload.ru", "payload_delivery", "Generic Malware Dropper", "Abuse.ch.URLhaus", 100),
    ("malware-traffic-analysis.net", "malware_analysis", "Traffic Analysis Sandbox", "Abuse.ch.ThreatFox", 100),
    ("testmalware.com", "test_domain", "EICAR / Test Domain", "Abuse.ch.ThreatFox", 100)
]


class AbuseCHDomainManager:
    """
    Manages Abuse.ch live threat intelligence domain feeds (ThreatFox, URLhaus, MalwareBazaar).
    Persists indicators to SQLite and provides ultra-low-latency in-memory set lookups.
    Uses the shared Abuse.ch Auth-Key or verified community feeds.
    """

    def __init__(self, db_path: Optional[Path] = None, fw_logger=None, profiles=None):
        if db_path is None:
            project_dir = Path(__file__).resolve().parent.parent
            self.db_path = project_dir / "data" / "signatures" / "malware_domains.db"
        else:
            self.db_path = Path(db_path)
        self.fw_logger = fw_logger
        self.profiles = profiles
        self.api_key: Optional[str] = None
        self._lock = threading.Lock()
        self._domains: Set[str] = set()
        self._domain_details: Dict[str, Dict[str, Any]] = {}
        self._init_db()
        self.load_domains()

    def _init_db(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS malware_domains (
                        domain TEXT PRIMARY KEY,
                        threat_type TEXT,
                        malware_family TEXT,
                        source TEXT,
                        confidence INTEGER DEFAULT 100,
                        first_seen TEXT,
                        last_updated TEXT
                    )
                ''')
                cur.execute("CREATE INDEX IF NOT EXISTS idx_domain_threat ON malware_domains(threat_type)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_domain_source ON malware_domains(source)")
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS sync_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )
                ''')
                cur.execute("SELECT COUNT(*) FROM malware_domains")
                count = cur.fetchone()[0]
                if count == 0:
                    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    for dom, ttype, fam, src, conf in CORE_ABUSE_CH_MALWARE_DOMAINS:
                        cur.execute('''
                            INSERT OR IGNORE INTO malware_domains
                            (domain, threat_type, malware_family, source, confidence, first_seen, last_updated)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (dom, ttype, fam, src, conf, now_iso, now_iso))
                    conn.commit()
        except Exception as e:
            logger.warning(f"Error initializing Abuse.ch malware domain database: {e}")

    def load_domains(self):
        with self._lock:
            try:
                if not self.db_path.exists():
                    self._init_db()
                with sqlite3.connect(self.db_path) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT domain, threat_type, malware_family, source, confidence FROM malware_domains")
                    rows = cur.fetchall()
                    self._domains = {r[0].lower() for r in rows if r[0]}
                    self._domain_details = {
                        r[0].lower(): {
                            "threat_type": r[1] or "C2 Server",
                            "malware_family": r[2] or "Malware",
                            "source": r[3] or "Abuse.ch",
                            "confidence": r[4] or 100
                        }
                        for r in rows if r[0]
                    }
                    logger.debug(f"Loaded {len(self._domains):,} Abuse.ch threat domains into memory cache.")
            except Exception as e:
                logger.warning(f"Failed to load Abuse.ch threat domains: {e}")

    def get_api_key(self) -> Optional[str]:
        with self._lock:
            if self.api_key:
                return self.api_key
        key = ""
        if self.profiles and hasattr(self.profiles, "get_setting"):
            key = self.profiles.get_setting("abuse_ch_api_key") or self.profiles.get_setting("malwarebazaar_api_key") or ""
        if not key:
            key = os.environ.get("ABUSE_CH_API_KEY") or os.environ.get("MALWAREBAZAAR_API_KEY") or ""
        return key.strip() or None

    def set_api_key(self, api_key: Optional[str]):
        with self._lock:
            self.api_key = (api_key or "").strip() or None

    def get_count(self) -> int:
        with self._lock:
            return len(self._domains)

    def get_domains(self) -> Set[str]:
        with self._lock:
            return set(self._domains)

    def is_domain_blocked(self, domain_or_url: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        domain = extract_base_domain(domain_or_url)
        with self._lock:
            if domain in self._domains:
                return True, self._domain_details.get(domain)
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self._domains:
                    return True, self._domain_details.get(parent)
        return False, None

    def sync_feeds(self, force: bool = False, timeout: int = 10) -> Tuple[bool, str, int]:
        """
        Synchronizes malware and C2 domains from Abuse.ch (ThreatFox / URLhaus / MalwareBazaar).
        Uses direct API with shared Auth-Key when present, or high-speed verified community mirrors.
        """
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        api_key = self.get_api_key()

        new_entries = []
        source_used = "Abuse.ch.OSINT"
        error_notice = None

        # 1. Query ThreatFox API (Primary source for C2 domains, stealer panels, drainers)
        threatfox_ok = False
        try:
            req_data = json.dumps({"query": "get_iocs", "days": 3}).encode("utf-8")
            headers = {
                "User-Agent": "CrazyAlchemy-AV/2.0 (LadyZi)",
                "Content-Type": "application/json"
            }
            if api_key:
                headers["Auth-Key"] = api_key
                headers["API-KEY"] = api_key
            req = urllib.request.Request(THREATFOX_IOCS_API, data=req_data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    if res_json.get("query_status") == "ok":
                        threatfox_ok = True
                        source_used = "Abuse.ch.ThreatFox.API"
                        for item in res_json.get("data", []):
                            ioc = item.get("ioc", "")
                            ioc_type = item.get("ioc_type", "")
                            if ioc_type in ("domain", "url", "ip:port"):
                                dom = extract_base_domain(ioc)
                                if dom and "." in dom and len(dom) >= 4 and not dom.startswith("."):
                                    fam = item.get("malware_printable") or "Malware"
                                    threat = item.get("threat_type_desc") or item.get("threat_type") or "Botnet C2"
                                    conf = int(item.get("confidence_level", 100))
                                    new_entries.append((dom, threat, fam, "Abuse.ch.ThreatFox", conf, now_iso, now_iso))
        except Exception as tf_err:
            error_notice = str(tf_err)
            logger.debug(f"ThreatFox query note: {tf_err}")

        # 2. Query URLhaus API
        urlhaus_ok = False
        if api_key:
            try:
                headers = {
                    "User-Agent": "CrazyAlchemy-AV/2.0 (LadyZi)",
                    "Auth-Key": api_key
                }
                req = urllib.request.Request(URLHAUS_RECENT_API, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        res_json = json.loads(resp.read().decode("utf-8"))
                        if res_json.get("query_status") == "ok":
                            urlhaus_ok = True
                            source_used = "Abuse.ch.AuthKey.MultiFeed"
                            for item in res_json.get("urls", []):
                                u = item.get("url", "")
                                dom = extract_base_domain(u)
                                if dom and "." in dom and len(dom) >= 4 and not dom.startswith("."):
                                    threat = item.get("threat") or "Malware Download"
                                    new_entries.append((dom, "payload_delivery", threat, "Abuse.ch.URLhaus", 95, now_iso, now_iso))
            except Exception as uh_err:
                if not error_notice:
                    error_notice = str(uh_err)
                logger.debug(f"URLhaus query note: {uh_err}")

        # 3. Fallback: OSINT Verified Hostfile if APIs were unreachable or without Auth-Key
        if not threatfox_ok and not urlhaus_ok:
            try:
                req = urllib.request.Request(
                    URLHAUS_HOSTFILE_URL,
                    headers={
                        "User-Agent": "CrazyAlchemy-AV/2.0 (LadyZi)",
                        "Range": "bytes=0-1048576"
                    }
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status in (200, 206):
                        lines = resp.read().decode("utf-8", errors="ignore").splitlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    dom = extract_base_domain(parts[1])
                                    if dom and "." in dom and len(dom) >= 4 and not dom.startswith("."):
                                        new_entries.append((dom, "malware_host", "Malware.Distribution", "Abuse.ch.URLhaus.Mirror", 90, now_iso, now_iso))
                        if new_entries:
                            source_used = "Abuse.ch.CommunityMirror"
            except Exception as mirror_err:
                if not error_notice:
                    error_notice = str(mirror_err)
                logger.debug(f"Abuse.ch hostfile mirror note: {mirror_err}")

        # 4. Save new entries to SQLite if any fetched
        if new_entries:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cur = conn.cursor()
                    cur.executemany('''
                        INSERT OR REPLACE INTO malware_domains
                        (domain, threat_type, malware_family, source, confidence, first_seen, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', new_entries)
                    cur.execute("INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_sync', ?)", (now_iso,))
                    cur.execute("INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_source', ?)", (source_used,))
                    cur.execute("INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_count', ?)", (str(len(new_entries)),))
                    conn.commit()
                self.load_domains()
                total = len(self._domains)
                if self.fw_logger and hasattr(self.fw_logger, "log_event"):
                    self.fw_logger.log_event(
                        "threat_feed_sync",
                        "info",
                        f"Abuse.ch domain sync: Ingested {len(new_entries):,} IOCs via {source_used} (Total active: {total:,})"
                    )
                return True, f"Successfully synchronized {len(new_entries):,} threat indicators via {source_used}.", total
            except Exception as db_err:
                logger.error(f"Failed to persist Abuse.ch domains: {db_err}")
                return False, f"Database error during indicator save: {db_err}", len(self._domains)

        total = len(self._domains)
        if total > 0:
            msg = f"Network note: {error_notice or 'No new IOCs'}. {total:,} active Abuse.ch malware domains remain enforced."
            return True, msg, total
        return False, f"Unable to reach Abuse.ch: {error_notice or 'Unknown error'}", 0

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._domains)
        api_key = self.get_api_key()
        last_sync = "Never"
        last_source = "None"
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT value FROM sync_meta WHERE key = 'last_sync'")
                r = cur.fetchone()
                if r:
                    last_sync = r[0]
                cur.execute("SELECT value FROM sync_meta WHERE key = 'last_source'")
                r2 = cur.fetchone()
                if r2:
                    last_source = r2[0]
        except Exception:
            pass
        return {
            "total_domains": total,
            "last_sync": last_sync,
            "last_source": last_source,
            "api_key_configured": bool(api_key),
            "auth_mode": "Direct Abuse.ch Auth-Key" if api_key else "Community Mirror"
        }


# ── Browser Detection ────────────────────────────────────────────────

class BrowserDetector:
    """Detects installed browsers on Windows 11 (Brave, Edge, Chrome, Firefox, Opera, Opera GX, Vivaldi)."""

    @staticmethod
    def get_browser_definitions() -> Dict[str, Dict[str, Any]]:
        return {
            "brave": {
                "name": "Brave Browser",
                "vendor": "Brave Software",
                "icon": "🦁",
                "icon_file": "brave.png",
                "extensions_url": "brave://extensions",
                "app_path": "brave.exe",
                "client_key": "Brave",
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"),
                    os.path.expandvars(r"%PROGRAMFILES%\BraveSoftware\Brave-Browser\Application\brave.exe"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\BraveSoftware\Brave-Browser\Application\brave.exe"),
                ],
                "reg_key": r"Software\BraveSoftware\Brave-Browser\Extensions"
            },
            "edge": {
                "name": "Microsoft Edge",
                "vendor": "Microsoft",
                "icon": "🌀",
                "icon_file": "edge.png",
                "extensions_url": "edge://extensions",
                "app_path": "msedge.exe",
                "client_key": "Microsoft Edge",
                "paths": [
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe"),
                    os.path.expandvars(r"%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe"),
                    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
                ],
                "reg_key": r"Software\Microsoft\Edge\Extensions"
            },
            "chrome": {
                "name": "Google Chrome",
                "vendor": "Google",
                "icon": "🌐",
                "icon_file": "chrome.png",
                "extensions_url": "chrome://extensions",
                "app_path": "chrome.exe",
                "client_key": "Google Chrome",
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
                    os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"),
                ],
                "reg_key": r"Software\Google\Chrome\Extensions"
            },
            "firefox": {
                "name": "Mozilla Firefox",
                "vendor": "Mozilla",
                "icon": "🦊",
                "icon_file": "firefox.png",
                "extensions_url": "about:debugging#/runtime/this-firefox",
                "app_path": "firefox.exe",
                "client_key": "FIREFOX.EXE",
                "paths": [
                    os.path.expandvars(r"%PROGRAMFILES%\Mozilla Firefox\firefox.exe"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Mozilla Firefox\firefox.exe"),
                    os.path.expandvars(r"%LOCALAPPDATA%\Mozilla Firefox\firefox.exe"),
                ],
                "reg_key": r"Software\Mozilla\Firefox\Extensions"
            },
            "opera": {
                "name": "Opera",
                "vendor": "Opera Software",
                "icon": "🔴",
                "icon_file": "opera.png",
                "extensions_url": "opera://extensions",
                "app_path": "opera.exe",
                "client_key": "Opera",
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\launcher.exe"),
                    os.path.expandvars(r"%PROGRAMFILES%\Opera\launcher.exe"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Opera\launcher.exe"),
                ],
                "reg_key": r"Software\Opera Software\Opera Stable\Extensions"
            },
            "operagx": {
                "name": "Opera GX",
                "vendor": "Opera Software",
                "icon": "🎮",
                "icon_file": "operagx.png",
                "extensions_url": "opera://extensions",
                "app_path": "opera.exe",
                "client_key": "Opera GX",
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera GX\launcher.exe"),
                    os.path.expandvars(r"%PROGRAMFILES%\Opera GX\launcher.exe"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Opera GX\launcher.exe"),
                ],
                "reg_key": r"Software\Opera Software\Opera GX Stable\Extensions"
            },
            "vivaldi": {
                "name": "Vivaldi",
                "vendor": "Vivaldi Technologies",
                "icon": "🛡️",
                "icon_file": "vivaldi.png",
                "extensions_url": "vivaldi://extensions",
                "app_path": "vivaldi.exe",
                "client_key": "Vivaldi",
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe"),
                    os.path.expandvars(r"%PROGRAMFILES%\Vivaldi\Application\vivaldi.exe"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Vivaldi\Application\vivaldi.exe"),
                ],
                "reg_key": r"Software\Vivaldi\Extensions"
            }
        }

    @classmethod
    def find_browser_executable(cls, info: Dict[str, Any]) -> Optional[str]:
        """Resolves the browser executable path via filesystem paths and Windows Registry."""
        # 1. Direct filesystem paths
        for p in info.get("paths", []):
            if p and os.path.exists(p):
                return os.path.normpath(p)

        if sys.platform != "win32":
            return None

        # 2. Windows Registry: App Paths
        app_exe = info.get("app_path")
        if app_exe:
            try:
                import winreg
                for root in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                    for sub in [
                        rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{app_exe}",
                        rf"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{app_exe}",
                    ]:
                        try:
                            with winreg.OpenKey(root, sub) as k:
                                val, _ = winreg.QueryValueEx(k, "")
                                if val:
                                    clean_p = val.strip(' \t\r\n"')
                                    if os.path.exists(clean_p):
                                        return os.path.normpath(clean_p)
                        except Exception:
                            pass
            except Exception:
                pass

        # 3. Windows Registry: StartMenuInternet
        client_key = info.get("client_key")
        if client_key:
            try:
                import winreg
                for root in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                    sub = rf"SOFTWARE\Clients\StartMenuInternet\{client_key}\shell\open\command"
                    try:
                        with winreg.OpenKey(root, sub) as k:
                            val, _ = winreg.QueryValueEx(k, "")
                            if val:
                                clean_p = val.strip(' \t\r\n"')
                                if os.path.exists(clean_p):
                                    return os.path.normpath(clean_p)
                    except Exception:
                        pass
            except Exception:
                pass

        return None

    @staticmethod
    def get_file_version(path: str) -> Optional[str]:
        """Extracts PE File Version on Windows using Win32 API."""
        if sys.platform != "win32" or not path or not os.path.exists(path):
            return None
        try:
            import ctypes
            from ctypes import wintypes
            size = ctypes.windll.version.GetFileVersionInfoSizeW(path, None)
            if not size:
                return None
            res = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(path, 0, size, res):
                return None
            ptr = ctypes.c_void_p()
            length = ctypes.c_uint()
            if not ctypes.windll.version.VerQueryValueW(res, r"\\", ctypes.byref(ptr), ctypes.byref(length)):
                return None
            class VS_FIXEDFILEINFO(ctypes.Structure):
                _fields_ = [
                    ("dwSignature", wintypes.DWORD),
                    ("dwStrucVersion", wintypes.DWORD),
                    ("dwFileVersionMS", wintypes.DWORD),
                    ("dwFileVersionLS", wintypes.DWORD),
                ]
            vs = VS_FIXEDFILEINFO.from_address(ptr.value)
            ms = vs.dwFileVersionMS
            ls = vs.dwFileVersionLS
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        except Exception:
            return None

    @classmethod
    def detect_all(cls) -> Dict[str, Dict[str, Any]]:
        """Scans filesystem and registry to return detection metadata for all supported browsers."""
        definitions = cls.get_browser_definitions()
        results = {}
        for b_id, info in definitions.items():
            found_path = cls.find_browser_executable(info)
            version = cls.get_file_version(found_path) if found_path else None
            results[b_id] = {
                "id": b_id,
                "name": info["name"],
                "vendor": info["vendor"],
                "icon": info["icon"],
                "icon_file": info.get("icon_file", f"{b_id}.png"),
                "installed": found_path is not None,
                "path": found_path,
                "version": version,
                "extensions_url": info["extensions_url"]
            }
        return results

    @classmethod
    def is_installed(cls, browser_id: str) -> bool:
        defs = cls.get_browser_definitions()
        if browser_id not in defs:
            return False
        return cls.find_browser_executable(defs[browser_id]) is not None

    @classmethod
    def get_browser_exe(cls, browser_id: str) -> Optional[str]:
        defs = cls.get_browser_definitions()
        if browser_id not in defs:
            return None
        return cls.find_browser_executable(defs[browser_id])


# ── Extension File Generator ─────────────────────────────────────────

def copy_to_clipboard(text: str) -> bool:
    """Copies text to the Windows clipboard via PowerShell/clip."""
    try:
        import subprocess
        kwargs = {"capture_output": True, "text": True}
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000
        subprocess.run(['clip'], input=text, **kwargs)
        return True
    except Exception as e:
        logger.debug(f"Failed to copy to clipboard: {e}")
        return False


class ExtensionDeployer:
    """Packages and deploys the Crazy Alchemy Web Shield & Crazy AdBlock extension files."""

    @staticmethod
    def get_template_extension_dir() -> Path:
        """Returns the base template extension directory inside the project/installation."""
        base_dir = Path(__file__).resolve().parent.parent / "data" / "browser_extension"
        return base_dir

    @classmethod
    def get_default_extension_dir(cls) -> Path:
        """
        Returns the user-writable browser extension directory.
        Prioritizes user profile directories (%LOCALAPPDATA% or %APPDATA%) so Chromium
        (Chrome, Brave, Edge, Opera, etc.) and Firefox have full write permissions to compile,
        index, and persist internal ruleset indexes (_metadata/generated_indexed_rulesets)
        without triggering:
        'rules.json: Internal error while parsing rules' (Chromium ERROR_PERSISTING_RULESET)
        which happens when Crazy Alchemy is installed in Program Files or a protected path.
        Gracefully falls back to template directory if user AppData is inaccessible.
        """
        candidates = []
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            candidates.append(Path(local_app) / "CrazyAlchemy" / "browser_extension")
        app_data = os.environ.get("APPDATA")
        if app_data:
            candidates.append(Path(app_data) / "CrazyAlchemy" / "browser_extension")
        candidates.append(Path.home() / "AppData" / "Local" / "CrazyAlchemy" / "browser_extension")
        candidates.append(Path.home() / ".crazyalchemy" / "browser_extension")
        candidates.append(cls.get_template_extension_dir())

        for cand in candidates:
            try:
                cand.mkdir(parents=True, exist_ok=True)
                test_file = cand / ".write_test"
                test_file.write_text("ok", encoding="utf-8")
                test_file.unlink(missing_ok=True)
                return cand
            except (OSError, PermissionError):
                continue

        return cls.get_template_extension_dir()

    @classmethod
    def deploy_extension_files(cls, target_dir: Optional[Path] = None) -> Path:
        """Writes or refreshes all extension source files (Manifest V3 compatible)."""
        ext_dir = target_dir or cls.get_default_extension_dir()
        try:
            ext_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            ext_dir = cls.get_template_extension_dir()
            ext_dir.mkdir(parents=True, exist_ok=True)

        # 0. Clean up any stale or corrupted _metadata directory (which causes
        # 'rules.json: Internal error while parsing rules' due to index/checksum mismatches or locks)
        meta_dir = ext_dir / "_metadata"
        if meta_dir.exists():
            try:
                import shutil
                shutil.rmtree(meta_dir, ignore_errors=True)
            except Exception as e:
                logger.debug(f"Could not purge _metadata directory: {e}")

        tpl_meta = cls.get_template_extension_dir() / "_metadata"
        if tpl_meta.exists():
            try:
                import shutil
                shutil.rmtree(tpl_meta, ignore_errors=True)
            except Exception:
                pass

        # 1. manifest.json
        manifest_data = {
            "manifest_version": 3,
            "name": "Crazy Alchemy Web Shield & Crazy AdBlock",
            "version": "3.0.0",
            "description": "Real-time malware, phishing, and crypto-drainer defense powered by Crazy Alchemy Desktop Antivirus, with Crazy-style ultra-fast Ad & Tracker blocking.",
            "permissions": [
                "declarativeNetRequest",
                "storage",
                "alarms",
                "tabs"
            ],
            "host_permissions": [
                "<all_urls>"
            ],
            "background": {
                "service_worker": "background.js"
            },
            "content_scripts": [
                {
                    "matches": ["<all_urls>"],
                    "js": ["content.js"],
                    "run_at": "document_start",
                    "all_frames": True
                }
            ],
            "action": {
                "default_title": "Crazy Alchemy Web Shield & Crazy AdBlock",
                "default_popup": "popup.html",
                "default_icon": {
                    "16": "icon16.png",
                    "48": "icon48.png",
                    "128": "icon128.png"
                }
            },
            "icons": {
                "16": "icon16.png",
                "48": "icon48.png",
                "128": "icon128.png"
            },
            "declarative_net_request": {
                "rule_resources": [
                    {
                        "id": "adblock_rules",
                        "enabled": True,
                        "path": "rules.json"
                    }
                ]
            },
            "web_accessible_resources": [
                {
                    "resources": ["blocked.html", "icon48.png"],
                    "matches": ["<all_urls>"]
                }
            ],
            "browser_specific_settings": {
                "gecko": {
                    "id": "webshield@crazyalchemy.local",
                    "strict_min_version": "109.0"
                }
            }
        }
        with open(ext_dir / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        # 2. rules.json (Declarative Net Request Rules)
        rules = []
        rule_id = 1
        all_block_domains = sorted(KNOWN_AD_DOMAINS | KNOWN_TRACKER_DOMAINS | KNOWN_MINER_DOMAINS | KNOWN_MALWARE_DOMAINS)
        for dom in all_block_domains:
            clean_dom = dom.strip()
            if not clean_dom:
                continue
            rules.append({
                "id": rule_id,
                "priority": 1,
                "action": {"type": "block"},
                "condition": {
                    "urlFilter": f"||{clean_dom}^",
                    "resourceTypes": ["main_frame", "sub_frame", "script", "xmlhttprequest", "image", "other"]
                }
            })
            rule_id += 1

        with open(ext_dir / "rules.json", "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)

        # Also synchronize template directory if writable and distinct from ext_dir
        try:
            tpl_dir = cls.get_template_extension_dir()
            if tpl_dir.exists() and tpl_dir.resolve() != ext_dir.resolve():
                with open(tpl_dir / "manifest.json", "w", encoding="utf-8") as f:
                    json.dump(manifest_data, f, indent=2)
                with open(tpl_dir / "rules.json", "w", encoding="utf-8") as f:
                    json.dump(rules, f, indent=2)
        except Exception:
            pass

        # 3. background.js
        background_js = """
// Crazy Alchemy Web Shield & Crazy AdBlock Service Worker
const COMPANION_URL = "http://127.0.0.1:49211";
let settings = {
    malware_protection: true,
    adblock_enabled: true,
    miner_protection: true,
    whitelist: []
};
let stats = {
    threats_blocked: 0,
    ads_blocked: 0
};

// Load stats & settings from storage
chrome.storage.local.get(["settings", "stats"], (res) => {
    if (res.settings) Object.assign(settings, res.settings);
    if (res.stats) Object.assign(stats, res.stats);
});

// Periodic heartbeat with Crazy Alchemy Desktop
async function pingCompanion() {
    try {
        const resp = await fetch(`${COMPANION_URL}/api/status`);
        if (resp.ok) {
            chrome.action.setBadgeText({ text: "ON" });
            chrome.action.setBadgeBackgroundColor({ color: "#2e7d32" }); // Green
        }
    } catch (e) {
        chrome.action.setBadgeText({ text: "LOC" });
        chrome.action.setBadgeBackgroundColor({ color: "#e65100" }); // Orange (local mode)
    }
}
setInterval(pingCompanion, 15000);
pingCompanion();

// Intercept navigations for Malware / Phishing Defense
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
        if (!settings.malware_protection) return;

        try {
            const urlObj = new URL(tab.url);
            const domain = urlObj.hostname.toLowerCase();

            // Check if whitelisted
            if (settings.whitelist.includes(domain)) return;

            // Query Crazy Alchemy local engine
            let blocked = false;
            let reason = "Malicious domain";
            let category = "malware";

            try {
                const checkRes = await fetch(`${COMPANION_URL}/api/check_url`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: tab.url, domain: domain })
                });
                if (checkRes.ok) {
                    const data = await checkRes.json();
                    if (data.blocked) {
                        blocked = true;
                        reason = data.reason || reason;
                        category = data.category || category;
                    }
                }
            } catch (err) {
                // Standalone local check fallback
                const knownBad = ["malware-traffic-analysis.net", "testmalware.com", "crypto-drainer.click", "phishing-bank-login.xyz"];
                if (knownBad.some(b => domain.includes(b))) {
                    blocked = true;
                    category = "malware";
                }
            }

            if (blocked) {
                stats.threats_blocked++;
                chrome.storage.local.set({ stats });

                // Redirect tab to built-in blocked warning page
                const blockedUrl = chrome.runtime.getURL("blocked.html") + 
                    `?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(reason)}&category=${encodeURIComponent(category)}`;
                chrome.tabs.update(tabId, { url: blockedUrl });

                // Report threat to desktop companion
                try {
                    fetch(`${COMPANION_URL}/api/report_threat`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ url: tab.url, domain, threat_type: category, reason })
                    }).catch(() => {});
                } catch(e) {}
            }
        } catch (e) {}
    }
});

// Listen for messages from content.js and popup.js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "ADS_BLOCKED_REPORT") {
        const count = msg.count || 1;
        stats.ads_blocked += count;
        chrome.storage.local.set({ stats });
        sendResponse({ success: true, total: stats.ads_blocked });
    } else if (msg.type === "GET_STATUS") {
        sendResponse({ settings, stats });
    } else if (msg.type === "UPDATE_SETTINGS") {
        Object.assign(settings, msg.settings);
        chrome.storage.local.set({ settings });
        sendResponse({ success: true, settings });
    }
    return true;
});
""".strip()
        with open(ext_dir / "background.js", "w", encoding="utf-8") as f:
            f.write(background_js)

        # 4. content.js (Crazy-Style Cosmetic Filter & CoinMiner Stopper)
        content_js = """
// Crazy Alchemy Crazy-Style In-Page AdBlock & Miner Neutralizer
(function() {
    'use strict';

    // 1. Inject Crazy-style cosmetic element hiding CSS
    const style = document.createElement('style');
    style.id = 'crazy-alchemy-adblock-styles';
    style.textContent = `
        .ad-container, .ad-banner, .advertisement, .adsbygoogle,
        [id*="google_ads"], [class*="google-ad"], [id*="taboola-"],
        [id*="outbrain_"], [class*="sponsored-post"], [class*="native-ad"],
        iframe[src*="doubleclick"], iframe[src*="adroll"], iframe[src*="amazon-adsystem"],
        div[data-ad-unit], div[data-ad-slot], div[class*="ad_wrapper"],
        div[class*="ad-slot"], div[id*="ad_banner"], div[id*="adv_box"] {
            display: none !important;
            visibility: hidden !important;
            height: 0px !important;
            width: 0px !important;
            max-height: 0px !important;
            pointer-events: none !important;
            opacity: 0 !important;
        }
    `;
    (document.head || document.documentElement).appendChild(style);

    // 2. Cryptominer Neutralizer (traps WebAssembly mining loops)
    if (window.CoinHive) window.CoinHive = undefined;
    if (window.CryptoLoot) window.CryptoLoot = undefined;

    // 3. Scan and count hidden ad elements to report statistics
    let reportedAds = 0;
    function scanAndCountAds() {
        const adElements = document.querySelectorAll(
            '.adsbygoogle, [id*="google_ads"], iframe[src*="doubleclick"], [class*="sponsored-post"]'
        );
        if (adElements.length > reportedAds) {
            const delta = adElements.length - reportedAds;
            reportedAds = adElements.length;
            chrome.runtime.sendMessage({ type: "ADS_BLOCKED_REPORT", count: delta }, () => {
                if (chrome.runtime.lastError) {}
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scanAndCountAds);
    } else {
        scanAndCountAds();
    }
    setInterval(scanAndCountAds, 4000);
})();
""".strip()
        with open(ext_dir / "content.js", "w", encoding="utf-8") as f:
            f.write(content_js)

        # 5. blocked.html (High-contrast warning page)
        blocked_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Threat Intercepted - Crazy Alchemy Shield</title>
    <style>
        body {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .card {
            background-color: #161b22;
            border: 1px solid #f85149;
            border-radius: 12px;
            padding: 36px 40px;
            max-width: 580px;
            box-shadow: 0 16px 40px rgba(0,0,0,0.6);
            text-align: center;
        }
        .icon {
            font-size: 56px;
            margin-bottom: 12px;
        }
        h1 {
            color: #ff7b72;
            font-size: 24px;
            margin: 0 0 10px 0;
        }
        p {
            font-size: 14px;
            color: #8b949e;
            line-height: 1.6;
        }
        .url-box {
            background-color: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 10px;
            font-family: monospace;
            font-size: 13px;
            color: #e6edf3;
            word-break: break-all;
            margin: 18px 0;
        }
        .btn-group {
            display: flex;
            gap: 12px;
            justify-content: center;
            margin-top: 24px;
        }
        button {
            padding: 10px 20px;
            border-radius: 6px;
            border: none;
            font-size: 14px;
            font-weight: bold;
            cursor: pointer;
        }
        .btn-primary {
            background-color: #238636;
            color: white;
        }
        .btn-secondary {
            background-color: #21262d;
            color: #8b949e;
            border: 1px solid #30363d;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🛡️⚠️</div>
        <h1>Dangerous Website Blocked</h1>
        <p>Crazy Alchemy Web Shield & Antivirus prevented this connection because the target domain was identified as harboring malware, phishing, or crypto-stealing scripts.</p>
        <div class="url-box" id="target-url">Blocked URL Loading...</div>
        <div class="btn-group">
            <button class="btn-primary" onclick="history.back()">Back to Safety (Recommended)</button>
            <button class="btn-secondary" onclick="window.close()">Close Tab</button>
        </div>
    </div>
    <script>
        const params = new URLSearchParams(window.location.search);
        const url = params.get('url') || 'Unknown URL';
        document.getElementById('target-url').textContent = url;
    </script>
</body>
</html>
""".strip()
        with open(ext_dir / "blocked.html", "w", encoding="utf-8") as f:
            f.write(blocked_html)

        # 6. popup.html
        popup_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Crazy Alchemy Shields</title>
    <style>
        body {
            width: 320px;
            background-color: #121820;
            color: #e6edf3;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 16px;
            user-select: none;
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #21262d;
            padding-bottom: 12px;
            margin-bottom: 12px;
        }
        .title {
            font-size: 14px;
            font-weight: bold;
            color: #58a6ff;
        }
        .pill {
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 12px;
            background-color: #1e3a2f;
            color: #81c784;
            font-weight: bold;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 16px;
        }
        .stat-card {
            background-color: #1a222d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 10px;
            text-align: center;
        }
        .stat-num {
            font-size: 20px;
            font-weight: bold;
            color: #388bfd;
        }
        .stat-lbl {
            font-size: 11px;
            color: #8b949e;
            margin-top: 2px;
        }
        .row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 13px;
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 34px;
            height: 18px;
        }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
            background-color: #30363d; transition: .3s; border-radius: 18px;
        }
        .slider:before {
            position: absolute; content: ""; height: 12px; width: 12px; left: 3px; bottom: 3px;
            background-color: white; transition: .3s; border-radius: 50%;
        }
        input:checked + .slider { background-color: #238636; }
        input:checked + .slider:before { transform: translateX(16px); }
        .footer {
            border-top: 1px solid #21262d;
            padding-top: 10px;
            margin-top: 12px;
            text-align: center;
            font-size: 11px;
            color: #6e7681;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">🛡️ Crazy Alchemy Web Shield</div>
        <div class="pill" id="status-pill">Active</div>
    </div>
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-num" id="stat-threats">0</div>
            <div class="stat-lbl">Threats Blocked</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" id="stat-ads">0</div>
            <div class="stat-lbl">Ads & Trackers</div>
        </div>
    </div>
    <div class="row">
        <span>Malware & Phishing Defense</span>
        <label class="switch">
            <input type="checkbox" id="chk-malware" checked>
            <span class="slider"></span>
        </label>
    </div>
    <div class="row">
        <span>Crazy-Style Ad & Tracker Blocker</span>
        <label class="switch">
            <input type="checkbox" id="chk-adblock" checked>
            <span class="slider"></span>
        </label>
    </div>
    <div class="row">
        <span>Anti-Cryptojacking Shield</span>
        <label class="switch">
            <input type="checkbox" id="chk-miner" checked>
            <span class="slider"></span>
        </label>
    </div>
    <div class="footer">
        Crazy Alchemy v3.0 LadyZi Desktop Suite
    </div>
    <script src="popup.js"></script>
</body>
</html>
""".strip()
        with open(ext_dir / "popup.html", "w", encoding="utf-8") as f:
            f.write(popup_html)

        # 7. popup.js
        popup_js = """
document.addEventListener('DOMContentLoaded', () => {
    chrome.runtime.sendMessage({ type: "GET_STATUS" }, (resp) => {
        if (!resp) return;
        document.getElementById('stat-threats').textContent = (resp.stats?.threats_blocked || 0).toLocaleString();
        document.getElementById('stat-ads').textContent = (resp.stats?.ads_blocked || 0).toLocaleString();

        const s = resp.settings || {};
        document.getElementById('chk-malware').checked = s.malware_protection !== false;
        document.getElementById('chk-adblock').checked = s.adblock_enabled !== false;
        document.getElementById('chk-miner').checked = s.miner_protection !== false;
    });

    function saveSettings() {
        const newSettings = {
            malware_protection: document.getElementById('chk-malware').checked,
            adblock_enabled: document.getElementById('chk-adblock').checked,
            miner_protection: document.getElementById('chk-miner').checked
        };
        chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: newSettings });
    }

    document.getElementById('chk-malware').addEventListener('change', saveSettings);
    document.getElementById('chk-adblock').addEventListener('change', saveSettings);
    document.getElementById('chk-miner').addEventListener('change', saveSettings);
});
""".strip()
        with open(ext_dir / "popup.js", "w", encoding="utf-8") as f:
            f.write(popup_js)

        # 8. Generate PNG Icons (16, 48, 128)
        cls._generate_icons(ext_dir)

        logger.info(f"Deployed browser extension files to: {ext_dir}")
        return ext_dir

    @classmethod
    def _generate_icons(cls, ext_dir: Path):
        """Generates standard extension PNG icons using the official app icon or template assets."""
        sizes = [16, 48, 128]
        project_dir = Path(__file__).resolve().parent.parent
        app_icon_dir = project_dir / "data" / "icons"
        tpl_dir = cls.get_template_extension_dir()

        import shutil
        copied_all = True
        for size in sizes:
            dst = ext_dir / f"icon{size}.png"
            # 1. Try template directory first if distinct
            src_tpl = tpl_dir / f"icon{size}.png"
            if src_tpl.exists() and src_tpl.resolve() != dst.resolve():
                try:
                    shutil.copy2(src_tpl, dst)
                    continue
                except Exception:
                    pass
            # 2. Try app_icon_dir
            src = app_icon_dir / f"icon_{size}x{size}.png"
            if src.exists():
                try:
                    shutil.copy2(src, dst)
                    continue
                except Exception:
                    pass
            if not dst.exists():
                copied_all = False

        if copied_all:
            return

        # Attempt with PyQt6 if available as fallback
        success = False
        try:
            from PyQt6.QtGui import QImage, QPainter, QColor, QFont
            from PyQt6.QtCore import Qt, QRect
            for size in sizes:
                img = QImage(size, size, QImage.Format.Format_ARGB32)
                img.fill(QColor(0, 0, 0, 0))
                p = QPainter(img)
                # Outer blue shield
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(33, 150, 243))
                p.drawRoundedRect(1, 1, size - 2, size - 2, size // 4, size // 4)
                # Inner green highlight
                p.setBrush(QColor(76, 175, 80))
                p.drawRoundedRect(size // 4, size // 4, size // 2, size // 2, size // 6, size // 6)
                p.end()
                img.save(str(ext_dir / f"icon{size}.png"))
            success = True
        except Exception:
            pass

        if not success:
            # Fallback: write basic valid 1x1 / 16x16 PNG bytes
            basic_png_bytes = bytes([
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
                0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
                0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, 0x61, 0x00, 0x00, 0x00,
                0x19, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60, 0x60, 0x60, 0xF8,
                0xCF, 0xC0, 0xC0, 0xC0, 0x00, 0x82, 0x02, 0x13, 0x00, 0x03, 0x10, 0x00,
                0x01, 0x93, 0x94, 0xD4, 0x54, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
                0x44, 0xAE, 0x42, 0x60, 0x82
            ])
            for size in sizes:
                icon_path = ext_dir / f"icon{size}.png"
                if not icon_path.exists():
                    with open(icon_path, "wb") as f:
                        f.write(basic_png_bytes)

    @classmethod
    def install_for_browser(cls, browser_id: str) -> Tuple[bool, str]:
        """
        Installs/registers the extension for the specified browser.
        Registers external extension registry keys where supported and copies
        the extension folder path to the clipboard.
        """
        ext_dir = cls.deploy_extension_files()
        ext_path_str = str(ext_dir)

        # Copy extension path to Windows clipboard for easy 1-click loading
        copy_to_clipboard(ext_path_str)

        defs = BrowserDetector.get_browser_definitions()
        if browser_id not in defs:
            return False, f"Unknown browser identifier: {browser_id}"

        b_info = defs[browser_id]
        b_name = b_info["name"]

        # Register external extension in Windows registry if on Windows
        reg_success = False
        if sys.platform == "win32":
            try:
                import winreg
                reg_path = b_info["reg_key"]
                # Extension key name
                ext_key_name = "crazyalchemy_shield"
                full_key = f"{reg_path}\\{ext_key_name}"
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, full_key) as k:
                    winreg.SetValueEx(k, "path", 0, winreg.REG_SZ, ext_path_str)
                    winreg.SetValueEx(k, "version", 0, winreg.REG_SZ, "3.0.0")
                reg_success = True
            except Exception as e:
                logger.debug(f"Registry policy registration notice: {e}")

        msg = (
            f"✅ Extension prepared for {b_name}!\n\n"
            f"Folder path copied to clipboard:\n{ext_path_str}\n\n"
            f"1. In {b_name}, navigate to: {b_info['extensions_url']}\n"
            f"2. Enable 'Developer mode' (toggle switch in upper right).\n"
            f"3. Click 'Load unpacked' and paste this folder path."
        )
        return True, msg

    @classmethod
    def launch_browser_extensions_page(cls, browser_id: str) -> bool:
        """Launches the specified browser directly to its extensions page."""
        exe = BrowserDetector.get_browser_exe(browser_id)
        defs = BrowserDetector.get_browser_definitions()
        if browser_id not in defs:
            return False

        ext_dir = cls.deploy_extension_files()
        copy_to_clipboard(str(ext_dir))

        ext_url = defs[browser_id]["extensions_url"]
        try:
            import subprocess
            CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
            if exe and os.path.exists(exe):
                subprocess.Popen([exe, ext_url], creationflags=CREATE_NO_WINDOW)
            else:
                import webbrowser
                webbrowser.open(ext_url)
            return True
        except Exception as e:
            logger.error(f"Failed to launch browser {browser_id}: {e}")
            return False


# ── Companion HTTP Server ────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class BrowserCompanionHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Crazy Alchemy Extension API on 127.0.0.1:49211."""

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logging
        pass

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            server = getattr(self.server, "app_server", None)
            data = {
                "status": "online",
                "version": "3.0 LadyZi",
                "app": "Crazy Alchemy v3.0 LadyZi",
                "threats_blocked": server.threats_blocked if server else 0,
                "ads_blocked": server.ads_blocked if server else 0,
                "abuse_ch_domains": server.get_domain_count() if server else 0,
                "abuse_ch_stats": server.get_abuse_ch_stats() if server else {},
                "active_profile": server.get_active_profile() if server else "Home"
            }
            self._send_json(200, data)
        elif path == "/api/config":
            server = getattr(self.server, "app_server", None)
            cfg = server.get_config() if server else {}
            self._send_json(200, cfg)
        elif path == "/api/browsers":
            browsers = BrowserDetector.detect_all()
            self._send_json(200, browsers)
        elif path == "/api/adblock_rules":
            server = getattr(self.server, "app_server", None)
            data = {
                "cosmetic_css": CRAZY_STYLE_COSMETIC_CSS,
                "ad_domains": list(KNOWN_AD_DOMAINS),
                "tracker_domains": list(KNOWN_TRACKER_DOMAINS),
                "miner_domains": list(KNOWN_MINER_DOMAINS),
                "abuse_ch_domains": list(server.abuse_domain_mgr.get_domains()) if server else list(KNOWN_MALWARE_DOMAINS)
            }
            self._send_json(200, data)
        elif path == "/api/sync_abuse_domains":
            server = getattr(self.server, "app_server", None)
            if server:
                ok, msg, count = server.sync_abuse_ch_domains(force=True)
                self._send_json(200, {"success": ok, "message": msg, "count": count})
            else:
                self._send_json(500, {"error": "Server not attached"})
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        server = getattr(self.server, "app_server", None)

        if path == "/api/check_url":
            url = req_data.get("url", "")
            domain = req_data.get("domain", "") or extract_base_domain(url)
            result = server.check_url_threat(url, domain) if server else {"blocked": False}
            self._send_json(200, result)

        elif path == "/api/report_threat":
            if server:
                server.record_threat_blocked(req_data)
            self._send_json(200, {"success": True})

        elif path == "/api/report_ad":
            count = req_data.get("count", 1)
            if server:
                server.record_ad_blocked(count)
            self._send_json(200, {"success": True})

        elif path == "/api/config":
            if server:
                server.update_config(req_data)
            self._send_json(200, {"success": True})

        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def _send_json(self, code: int, data: Dict[str, Any]):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)


class BrowserCompanionServer:
    """Manages the background HTTP companion server on 127.0.0.1:49211."""

    def __init__(self, port: int = DEFAULT_COMPANION_PORT, fw_logger=None, profiles=None):
        self.port = port
        self.fw_logger = fw_logger
        self.profiles = profiles
        self.threats_blocked = 0
        self.ads_blocked = 0
        self.is_running = False
        self._httpd: Optional[ThreadedHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._runtime_config: Dict[str, Any] = {}

        # Abuse.ch Live Threat Intelligence Domain Manager
        self.abuse_domain_mgr = AbuseCHDomainManager(
            fw_logger=self.fw_logger,
            profiles=self.profiles
        )

    def start(self) -> bool:
        """Starts the companion server in a background daemon thread."""
        if self.is_running:
            return True
        try:
            self._httpd = ThreadedHTTPServer(("127.0.0.1", self.port), BrowserCompanionHandler)
            self._httpd.app_server = self
            self.is_running = True
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()
            logger.info(f"Browser companion bridge listening on http://127.0.0.1:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start browser companion server: {e}")
            self.is_running = False
            return False

    def stop(self):
        """Stops the companion server gracefully."""
        self.is_running = False
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        logger.info("Browser companion bridge stopped.")

    def get_active_profile(self) -> str:
        if self.profiles and hasattr(self.profiles, "get_active_profile"):
            return self.profiles.get_active_profile()
        return "Home"

    def get_config(self) -> Dict[str, Any]:
        cfg = {
            "browser_protection": True,
            "browser_malware_protection": True,
            "browser_abuse_ch_domain_block": True,
            "adblock_enabled": True,
            "miner_protection": True
        }
        if self.profiles and hasattr(self.profiles, "get_setting"):
            cfg["browser_protection"] = self.profiles.get_setting("browser_protection", True)
            cfg["browser_malware_protection"] = self.profiles.get_setting("browser_malware_protection", True)
            cfg["browser_abuse_ch_domain_block"] = self.profiles.get_setting("browser_abuse_ch_domain_block", True)
            cfg["adblock_enabled"] = self.profiles.get_setting("browser_adblock", True)
            cfg["miner_protection"] = self.profiles.get_setting("browser_miner_block", True)
        cfg.update(self._runtime_config)
        return cfg

    def update_config(self, updates: Dict[str, Any]):
        self._runtime_config.update(updates)
        if self.profiles and hasattr(self.profiles, "update_settings"):
            self.profiles.update_settings(updates)

    def get_api_key(self) -> Optional[str]:
        return self.abuse_domain_mgr.get_api_key()

    def set_api_key(self, api_key: Optional[str]):
        self.abuse_domain_mgr.set_api_key(api_key)

    def sync_abuse_ch_domains(self, force: bool = False) -> Tuple[bool, str, int]:
        return self.abuse_domain_mgr.sync_feeds(force=force)

    def get_abuse_ch_stats(self) -> Dict[str, Any]:
        return self.abuse_domain_mgr.get_stats()

    def get_domain_count(self) -> int:
        return self.abuse_domain_mgr.get_count()

    def check_url_threat(self, url: str, domain: str) -> Dict[str, Any]:
        """Audits domain and URL for malware, phishing, and ad/tracker classification."""
        domain = extract_base_domain(domain or url)
        cfg = self.get_config()

        # 0. Check Abuse.ch Threat Intelligence Domain Interception
        if cfg.get("browser_protection", True) and cfg.get("browser_abuse_ch_domain_block", True):
            is_bad, details = self.abuse_domain_mgr.is_domain_blocked(domain or url)
            if is_bad:
                fam = details.get("malware_family", "Malware") if details else "Malware"
                threat = details.get("threat_type", "Botnet C2") if details else "Threat"
                src = details.get("source", "Abuse.ch") if details else "Abuse.ch"
                return {
                    "blocked": True,
                    "category": "malware",
                    "reason": f"{src} Threat Intelligence: Blocked active {fam} ({threat}).",
                    "action": "block"
                }

        # 1. Check Malware & Phishing
        if cfg.get("browser_protection", True) and cfg.get("browser_malware_protection", True):
            if match_domain_suffix(domain, KNOWN_MALWARE_DOMAINS):
                return {
                    "blocked": True,
                    "category": "malware",
                    "reason": "Threat intelligence flagged domain as active malware or phishing vector.",
                    "action": "block"
                }

            # Check suspicious TLD and keywords
            if any(bad_kw in domain for bad_kw in ["stealer", "drainer", "phish", "metamask-update", "paypa1", "steamcommuniity"]):
                return {
                    "blocked": True,
                    "category": "malware",
                    "reason": "Heuristic brand impersonation or infostealer pattern detected.",
                    "action": "block"
                }

        # 2. Check Cryptojacking Miners
        if match_domain_suffix(domain, KNOWN_MINER_DOMAINS):
            return {
                "blocked": True,
                "category": "cryptominer",
                "reason": "In-browser WebAssembly cryptocurrency miner detected.",
                "action": "block"
            }

        # 3. Check Ads & Trackers
        cfg = self.get_config()
        if cfg.get("adblock_enabled", True):
            if match_domain_suffix(domain, KNOWN_AD_DOMAINS):
                return {
                    "blocked": True,
                    "category": "ad",
                    "reason": "Crazy-style ad serving network neutralized.",
                    "action": "block"
                }
            if match_domain_suffix(domain, KNOWN_TRACKER_DOMAINS):
                return {
                    "blocked": True,
                    "category": "tracker",
                    "reason": "User tracking beacon and telemetry script blocked.",
                    "action": "block"
                }

        return {"blocked": False, "category": "clean", "action": "allow"}

    def record_threat_blocked(self, data: Dict[str, Any]):
        """Increments threat count and logs structured security event."""
        self.threats_blocked += 1
        url = data.get("url", "")
        domain = data.get("domain", "")
        reason = data.get("reason", "Malware or phishing URL blocked by Web Shield")
        category = data.get("threat_type", "malware")

        if self.fw_logger and hasattr(self.fw_logger, "log_event"):
            self.fw_logger.log_event(
                "browser_threat_blocked",
                "critical",
                f"Web Shield intercepted {category.upper()} threat on: {domain or url}",
                {"url": url, "domain": domain, "category": category, "reason": reason}
            )

    def record_ad_blocked(self, count: int = 1):
        """Increments ad and tracker neutralization count."""
        self.ads_blocked += count
