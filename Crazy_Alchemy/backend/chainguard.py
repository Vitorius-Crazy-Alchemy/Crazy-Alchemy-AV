"""
Vitorius Firewall Win - ChainGuard Process Ancestry Validator
Analyzes the hierarchical process lineage of all network-active applications on Windows 11.
Detects advanced evasion techniques, Living-off-the-Land Binaries (LOLBins),
macro weaponization, and malicious parent-child execution chains.
"""

import os
import sys
import time
import hashlib
import sqlite3
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Set, Tuple

logger = logging.getLogger('vitorius.win.chainguard')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available: ChainGuard ancestry validation will run in simulated mode.")


@dataclass
class ProcessChain:
    pid: int
    process_name: str
    exe_path: str
    parent_pid: int
    parent_name: str
    grandparent_name: str
    full_chain: List[str]
    chain_hash: str
    is_suspicious: bool
    suspicion_reasons: List[str] = field(default_factory=list)
    remote_endpoints: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


# Signature patterns for suspicious parent -> child execution
OFFICE_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "acrobat.exe", "acrord32.exe"
}

SCRIPT_SHELLS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "bash.exe", "sh.exe"
}

LOLBINS_NETWORK = {
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
    "msbuild.exe", "installutil.exe", "msxsl.exe", "hh.exe"
}

WHITELISTED_CHAINS = {
    ("explorer.exe", "chrome.exe"),
    ("explorer.exe", "firefox.exe"),
    ("explorer.exe", "msedge.exe"),
    ("explorer.exe", "brave.exe"),
    ("services.exe", "svchost.exe"),
    ("services.exe", "spoolsv.exe")
}


class ChainGuardEngine:
    """
    Monitors all network-communicating processes and validates their parentage trees.
    """

    def __init__(self,
                 alert_callback: Optional[Callable[[ProcessChain], None]] = None,
                 db_path: Optional[Path] = None,
                 scan_interval: float = 3.5):
        self.alert_callback = alert_callback
        self.scan_interval = scan_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._suspicious_active: Dict[int, ProcessChain] = {}
        self._seen_chain_alerts: Set[str] = set()
        self._whitelisted_hashes: Set[str] = set()
        self._lock = threading.Lock()
        self._total_scans = 0

        # Database initialization
        if db_path is None:
            base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~/.local/share"))) / "VitoriusFirewallWin"
            base.mkdir(parents=True, exist_ok=True)
            self.db_path = base / "chainguard_events.db"
        else:
            self.db_path = db_path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()
        self._load_whitelist()

    def _init_db(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ancestry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    exe_path TEXT,
                    parent_name TEXT,
                    grandparent_name TEXT,
                    full_chain TEXT NOT NULL,
                    chain_hash TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    remote_endpoints TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS whitelisted_chains (
                    chain_hash TEXT PRIMARY KEY,
                    description TEXT,
                    added_at REAL NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_chain_hash ON ancestry_events(chain_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_chain_ts ON ancestry_events(timestamp)")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialize ChainGuard database: {e}")

    def _load_whitelist(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            rows = cur.execute("SELECT chain_hash FROM whitelisted_chains").fetchall()
            self._whitelisted_hashes = {r[0] for r in rows}
            conn.close()
        except Exception:
            pass

    def whitelist_chain(self, chain_hash: str, description: str = "User Approved") -> bool:
        """Whitelists an approved process lineage, suppressing future alerts."""
        with self._lock:
            self._whitelisted_hashes.add(chain_hash)
            # Remove from currently active suspicious list if present
            to_remove = [pid for pid, c in self._suspicious_active.items() if c.chain_hash == chain_hash]
            for pid in to_remove:
                self._suspicious_active.pop(pid, None)

        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO whitelisted_chains (chain_hash, description, added_at) VALUES (?, ?, ?)",
                (chain_hash, description, time.time())
            )
            conn.commit()
            conn.close()
            logger.info(f"ChainGuard lineage {chain_hash} whitelisted.")
            return True
        except Exception as e:
            logger.error(f"Failed to whitelist chain {chain_hash}: {e}")
            return False

    def is_whitelisted(self, chain_hash: str) -> bool:
        """Returns True if the chain hash is in the active whitelist."""
        with self._lock:
            return chain_hash in self._whitelisted_hashes

    def remove_whitelist(self, chain_hash: str) -> bool:
        """Removes a chain from the whitelist."""
        with self._lock:
            self._whitelisted_hashes.discard(chain_hash)
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("DELETE FROM whitelisted_chains WHERE chain_hash = ?", (chain_hash,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to un-whitelist chain {chain_hash}: {e}")
            return False

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="chainguard-loop")
            self._thread.start()
        logger.info("ChainGuard Process Ancestry Validator activated.")

    def stop(self):
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("ChainGuard Process Ancestry Validator stopped.")

    def _monitor_loop(self):
        while self._running:
            try:
                self._inspect_active_network_processes()
            except Exception as e:
                logger.debug(f"ChainGuard cycle error: {e}")
            time.sleep(self.scan_interval)

    def _inspect_active_network_processes(self):
        if not HAS_PSUTIL:
            return

        self._total_scans += 1
        active_pids: Dict[int, List[str]] = {}

        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.pid and c.raddr:
                    endpoint = f"{c.raddr.ip}:{c.raddr.port}"
                    active_pids.setdefault(c.pid, []).append(endpoint)
        except Exception as e:
            logger.debug(f"Failed to fetch net_connections: {e}")
            return

        current_suspicious = {}

        for pid, endpoints in active_pids.items():
            chain = self.get_chain_for_pid(pid, endpoints)
            if chain and chain.is_suspicious:
                current_suspicious[pid] = chain

                # Alert if this is a newly discovered chain instance
                dedup_key = f"{chain.chain_hash}:{','.join(sorted(endpoints[:3]))}"
                if dedup_key not in self._seen_chain_alerts:
                    self._seen_chain_alerts.add(dedup_key)
                    self._record_event(chain)
                    logger.critical(
                        f"CHAINGUARD ALERT: Suspicious process tree detected for PID {pid} ({chain.process_name})! "
                        f"Lineage: {' -> '.join(chain.full_chain)} | Reasons: {', '.join(chain.suspicion_reasons)}"
                    )
                    if self.alert_callback:
                        try:
                            self.alert_callback(chain)
                        except Exception as e:
                            logger.error(f"ChainGuard alert callback error: {e}")

        with self._lock:
            self._suspicious_active = current_suspicious

    def get_chain_for_pid(self, pid: int, endpoints: Optional[List[str]] = None) -> Optional[ProcessChain]:
        """Resolves the complete ancestor tree for a target PID and applies heuristics."""
        if not HAS_PSUTIL:
            return None

        try:
            proc = psutil.Process(pid)
            p_name = proc.name().lower()
            try:
                exe_path = proc.exe()
            except Exception:
                exe_path = ""

            # Climb parent hierarchy
            chain_names: List[str] = [p_name]
            pids_in_chain: List[int] = [pid]
            current = proc

            try:
                for _ in range(8):  # Max 8 ancestor levels
                    parent = current.parent()
                    if not parent or parent.pid in pids_in_chain or parent.pid == 0:
                        break
                    chain_names.append(parent.name().lower())
                    pids_in_chain.append(parent.pid)
                    current = parent
            except Exception:
                pass

            # Full chain ordered: Root -> Grandparent -> Parent -> Target Process
            full_chain = list(reversed(chain_names))
            parent_name = full_chain[-2] if len(full_chain) >= 2 else "None"
            grandparent_name = full_chain[-3] if len(full_chain) >= 3 else "None"

            # Compute stable hash of execution lineage
            chain_str = "->".join(full_chain)
            chain_hash = hashlib.sha256(chain_str.encode()).hexdigest()[:16]

            # Run suspicion heuristics
            reasons = []

            # 1. Office or PDF app spawning shell or script engine
            for ancestor in full_chain[:-1]:
                if ancestor in OFFICE_PROCESSES and p_name in SCRIPT_SHELLS:
                    reasons.append(f"Document application ({ancestor}) spawned script shell ({p_name}) with network access")
                if ancestor in OFFICE_PROCESSES and p_name in LOLBINS_NETWORK:
                    reasons.append(f"Document application ({ancestor}) spawned LOLBin proxy ({p_name})")

            # 2. LOLBins making direct network connections
            if p_name in LOLBINS_NETWORK:
                if parent_name not in ("explorer.exe", "devenv.exe", "code.exe"):
                    reasons.append(f"Living-off-the-Land binary ({p_name}) active with socket connections")

            # 3. Script host running as network client
            if p_name in {"wscript.exe", "cscript.exe", "mshta.exe"}:
                reasons.append(f"Windows Script Host engine ({p_name}) making direct outbound connections")

            # 4. svchost.exe parent verification
            if p_name == "svchost.exe" and parent_name not in ("services.exe", "None"):
                reasons.append(f"svchost.exe spawned by illegitimate parent: {parent_name}")

            # 5. Excessive nesting depth
            if len(full_chain) >= 6:
                reasons.append(f"Unusually deep execution tree depth ({len(full_chain)} levels)")

            is_suspicious = len(reasons) > 0 and (chain_hash not in self._whitelisted_hashes)

            return ProcessChain(
                pid=pid,
                process_name=p_name,
                exe_path=exe_path,
                parent_pid=proc.ppid() if hasattr(proc, 'ppid') else 0,
                parent_name=parent_name,
                grandparent_name=grandparent_name,
                full_chain=full_chain,
                chain_hash=chain_hash,
                is_suspicious=is_suspicious,
                suspicion_reasons=reasons,
                remote_endpoints=endpoints or []
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as e:
            logger.debug(f"Error building chain for PID {pid}: {e}")
            return None

    def _record_event(self, chain: ProcessChain):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO ancestry_events
                (pid, process_name, exe_path, parent_name, grandparent_name, full_chain, chain_hash, reasons, remote_endpoints, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chain.pid,
                chain.process_name,
                chain.exe_path,
                chain.parent_name,
                chain.grandparent_name,
                " -> ".join(chain.full_chain),
                chain.chain_hash,
                " | ".join(chain.suspicion_reasons),
                ", ".join(chain.remote_endpoints),
                chain.timestamp
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to store ChainGuard event in DB: {e}")

    def get_suspicious_chains(self) -> List[ProcessChain]:
        """Returns currently active suspicious processes."""
        with self._lock:
            return list(self._suspicious_active.values())

    def get_stats(self) -> Dict:
        """Returns statistical telemetry for dashboard and monitor."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            total_events = cur.execute("SELECT COUNT(*) FROM ancestry_events").fetchone()[0]
            unique_chains = cur.execute("SELECT COUNT(DISTINCT chain_hash) FROM ancestry_events").fetchone()[0]
            day_ago = time.time() - 86400
            events_24h = cur.execute("SELECT COUNT(*) FROM ancestry_events WHERE timestamp >= ?", (day_ago,)).fetchone()[0]
            top_culprits = cur.execute("""
                SELECT process_name, COUNT(*) as cnt FROM ancestry_events GROUP BY process_name ORDER BY cnt DESC LIMIT 5
            """).fetchall()
            conn.close()

            with self._lock:
                active_suspicious_count = len(self._suspicious_active)

            return {
                "active_suspicious_count": active_suspicious_count,
                "total_historical_events": total_events,
                "unique_suspicious_chains": unique_chains,
                "events_24h": events_24h,
                "top_culprits": [{"process": r[0], "count": r[1]} for r in top_culprits]
            }
        except Exception as e:
            logger.error(f"Error querying ChainGuard stats: {e}")
            return {
                "active_suspicious_count": 0,
                "total_historical_events": 0,
                "unique_suspicious_chains": 0,
                "events_24h": 0,
                "top_culprits": []
            }

    def get_recent_events(self, limit: int = 50) -> List[Dict]:
        """Fetches historical anomaly logs."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            rows = cur.execute("SELECT * FROM ancestry_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            events = [dict(r) for r in rows]
            conn.close()
            return events
        except Exception as e:
            logger.error(f"Failed to fetch recent ChainGuard events: {e}")
            return []
