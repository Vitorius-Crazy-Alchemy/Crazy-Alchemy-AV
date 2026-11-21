"""
Vitorius Firewall Win - AppPrint Network DNA Fingerprinting Engine
Learns the baseline behavioral network "DNA" of each desktop application over time.
Detects zero-day anomalies, supply chain compromises, trojanized updates,
crypto-mining communication, and C2 beacons by spotting behavioral deviations.
"""

import os
import sys
import time
import json
import sqlite3
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Set, Tuple, Any

logger = logging.getLogger('vitorius.win.appprint')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available: AppPrint will run in mock mode.")


SUSPICIOUS_OUTBOUND_PORTS: Set[int] = {
    1337, 31337, 4444, 5555, 6667, 7777, 8888, 9001, 9050, 9051, 14444, 3333
}


@dataclass
class AppFingerprint:
    app_name: str
    exe_path: str
    typical_remote_ports: Set[int] = field(default_factory=set)
    typical_protocols: Set[str] = field(default_factory=set)
    typical_subnets: Set[str] = field(default_factory=set) # /16 or /24 prefixes
    avg_conns: float = 1.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    samples_count: int = 1
    confidence_score: float = 0.1 # 0.0 to 1.0 based on observation samples

    def to_dict(self) -> dict:
        return {
            "app_name": self.app_name,
            "exe_path": self.exe_path,
            "typical_remote_ports": sorted(list(self.typical_remote_ports)),
            "typical_protocols": sorted(list(self.typical_protocols)),
            "typical_subnets": sorted(list(self.typical_subnets)),
            "avg_conns": round(self.avg_conns, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "samples_count": self.samples_count,
            "confidence_score": round(self.confidence_score, 2)
        }


@dataclass
class AnomalyAlert:
    app_name: str
    anomaly_type: str  # "new_port", "new_subnet", "new_protocol", "suspicious_port", "connection_spike"
    severity: str      # "low", "medium", "high", "critical"
    details: str
    detected_at: float
    remote_ip: str
    remote_port: int
    protocol: str

    def to_dict(self) -> dict:
        return asdict(self)


class AppPrintEngine:
    """
    Learns per-application network signatures and detects drift or active attacks.
    """

    def __init__(self,
                 alert_callback: Optional[Callable[[AnomalyAlert], None]] = None,
                 db_path: Optional[Path] = None,
                 sample_interval: float = 5.0):
        self.alert_callback = alert_callback
        self.sample_interval = sample_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._fingerprints: Dict[str, AppFingerprint] = {}
        self._lock = threading.Lock()
        self._recent_anomalies: List[AnomalyAlert] = []

        if db_path is None:
            base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~/.local/share"))) / "VitoriusFirewallWin"
            base.mkdir(parents=True, exist_ok=True)
            self.db_path = base / "appprint.db"
        else:
            self.db_path = db_path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()
        self._load_fingerprints()

    def _init_db(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fingerprints (
                    app_name TEXT PRIMARY KEY,
                    exe_path TEXT,
                    typical_ports TEXT,
                    typical_protocols TEXT,
                    typical_subnets TEXT,
                    avg_conns REAL,
                    first_seen REAL,
                    last_seen REAL,
                    samples_count INTEGER,
                    confidence_score REAL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT NOT NULL,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    detected_at REAL NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_anom_ts ON anomalies(detected_at)")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialize AppPrint DB: {e}")

    def _load_fingerprints(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            rows = cur.execute("SELECT * FROM fingerprints").fetchall()
            for r in rows:
                app_name = r[0]
                ports = set(json.loads(r[2])) if r[2] else set()
                protos = set(json.loads(r[3])) if r[3] else set()
                subnets = set(json.loads(r[4])) if r[4] else set()
                self._fingerprints[app_name] = AppFingerprint(
                    app_name=app_name,
                    exe_path=r[1] or "",
                    typical_remote_ports=ports,
                    typical_protocols=protos,
                    typical_subnets=subnets,
                    avg_conns=r[5],
                    first_seen=r[6],
                    last_seen=r[7],
                    samples_count=r[8],
                    confidence_score=r[9]
                )
            conn.close()
            logger.info(f"Loaded {len(self._fingerprints)} learned AppPrint fingerprints.")
        except Exception as e:
            logger.error(f"Failed to load fingerprints: {e}")

    def _save_fingerprint(self, fp: AppFingerprint):
        with self._lock:
            self._fingerprints[fp.app_name] = fp
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO fingerprints
                (app_name, exe_path, typical_ports, typical_protocols, typical_subnets, avg_conns, first_seen, last_seen, samples_count, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                fp.app_name,
                fp.exe_path,
                json.dumps(list(fp.typical_remote_ports)),
                json.dumps(list(fp.typical_protocols)),
                json.dumps(list(fp.typical_subnets)),
                fp.avg_conns,
                fp.first_seen,
                fp.last_seen,
                fp.samples_count,
                fp.confidence_score
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error saving fingerprint for {fp.app_name}: {e}")

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._learning_loop, daemon=True, name="appprint-loop")
            self._thread.start()
        logger.info("AppPrint Network DNA Engine active.")

    def stop(self):
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("AppPrint Network DNA Engine stopped.")

    def _get_subnet_prefix(self, ip: str) -> str:
        parts = ip.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return ip

    def _learning_loop(self):
        while self._running:
            try:
                self._collect_and_evaluate_cycle()
            except Exception as e:
                logger.debug(f"AppPrint cycle exception: {e}")
            time.sleep(self.sample_interval)

    def _collect_and_evaluate_cycle(self):
        if not HAS_PSUTIL:
            return

        pid_name_cache: Dict[int, Tuple[str, str]] = {}
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            return

        # Group by application
        app_activity: Dict[str, Dict[str, Any]] = {}

        for c in conns:
            if not c.pid or not c.raddr:
                continue

            r_ip = c.raddr.ip
            r_port = c.raddr.port
            proto = "TCP" if c.type == 1 else "UDP"

            if r_ip in ("127.0.0.1", "0.0.0.0", "::1"):
                continue

            if c.pid not in pid_name_cache:
                try:
                    p = psutil.Process(c.pid)
                    pid_name_cache[c.pid] = (p.name().lower(), p.exe())
                except Exception:
                    pid_name_cache[c.pid] = ("unknown", "")

            app_name, exe_path = pid_name_cache[c.pid]
            if app_name in ("unknown", "system"):
                continue

            if app_name not in app_activity:
                app_activity[app_name] = {
                    "exe_path": exe_path,
                    "conns": []
                }
            app_activity[app_name]["conns"].append((r_ip, r_port, proto))

        now = time.time()

        for app_name, data in app_activity.items():
            connections = data["conns"]
            exe_path = data["exe_path"]
            conn_count = len(connections)

            with self._lock:
                fp = self._fingerprints.get(app_name)
                if not fp:
                    fp = AppFingerprint(
                        app_name=app_name,
                        exe_path=exe_path,
                        first_seen=now,
                        last_seen=now
                    )
                    self._fingerprints[app_name] = fp

            # Anomaly Evaluation (only active if confidence >= 0.3 or for critical ports)
            for r_ip, r_port, proto in connections:
                subnet = self._get_subnet_prefix(r_ip)

                # Check 1: Known C2 / Trojan / Mining Ports
                if r_port in SUSPICIOUS_OUTBOUND_PORTS and r_port not in fp.typical_remote_ports:
                    self._raise_anomaly(
                        app_name=app_name,
                        anomaly_type="suspicious_port",
                        severity="critical",
                        details=f"Connected to known high-risk/mining port {r_port}",
                        r_ip=r_ip, r_port=r_port, proto=proto
                    )

                # Check 2: Deviating port after learning phase
                if fp.confidence_score >= 0.5 and r_port not in fp.typical_remote_ports:
                    # If app has over 10 samples and uses a completely unseen port
                    if len(fp.typical_remote_ports) > 0 and r_port not in (80, 443):
                        self._raise_anomaly(
                            app_name=app_name,
                            anomaly_type="new_port",
                            severity="medium",
                            details=f"Unusual destination port {r_port} (Baseline: {sorted(list(fp.typical_remote_ports))[:4]})",
                            r_ip=r_ip, r_port=r_port, proto=proto
                        )

                # Check 3: Unusual protocol
                if fp.confidence_score >= 0.6 and proto not in fp.typical_protocols:
                    self._raise_anomaly(
                        app_name=app_name,
                        anomaly_type="new_protocol",
                        severity="low",
                        details=f"App switched protocol to {proto}",
                        r_ip=r_ip, r_port=r_port, proto=proto
                    )

                # Ingest into profile
                fp.typical_remote_ports.add(r_port)
                fp.typical_protocols.add(proto)
                fp.typical_subnets.add(subnet)

            # Update moving averages and confidence
            fp.samples_count += 1
            fp.last_seen = now
            fp.avg_conns = (fp.avg_conns * 0.9) + (conn_count * 0.1)

            # Confidence score grows with samples (capped at 1.0)
            fp.confidence_score = min(1.0, fp.samples_count / 120.0)

            # Periodically persist
            if fp.samples_count % 10 == 0:
                self._save_fingerprint(fp)

    def _raise_anomaly(self, app_name: str, anomaly_type: str, severity: str,
                       details: str, r_ip: str, r_port: int, proto: str):
        alert = AnomalyAlert(
            app_name=app_name,
            anomaly_type=anomaly_type,
            severity=severity,
            details=details,
            detected_at=time.time(),
            remote_ip=r_ip,
            remote_port=r_port,
            protocol=proto
        )

        with self._lock:
            self._recent_anomalies.append(alert)
            if len(self._recent_anomalies) > 200:
                self._recent_anomalies.pop(0)

        # Log to DB
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO anomalies
                (app_name, anomaly_type, severity, details, remote_ip, remote_port, protocol, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.app_name, alert.anomaly_type, alert.severity, alert.details,
                alert.remote_ip, alert.remote_port, alert.protocol, alert.detected_at
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error persisting anomaly: {e}")

        logger.warning(f"APPPRINT ANOMALY: [{severity.upper()}] {app_name} -> {details} ({r_ip}:{r_port} {proto})")

        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error(f"AppPrint alert callback error: {e}")

    def get_fingerprints(self) -> List[Dict]:
        with self._lock:
            return [fp.to_dict() for fp in self._fingerprints.values()]

    def reset_fingerprint(self, app_name: str) -> bool:
        """Resets baseline fingerprint for an application so it relearns."""
        with self._lock:
            self._fingerprints.pop(app_name, None)
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("DELETE FROM fingerprints WHERE app_name = ?", (app_name,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error resetting fingerprint for {app_name}: {e}")
            return False

    def clear_anomalies(self) -> bool:
        """Clears all historical anomaly alerts."""
        with self._lock:
            self._recent_anomalies.clear()
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("DELETE FROM anomalies")
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error clearing anomalies: {e}")
            return False

    def get_anomalies(self, limit: int = 50) -> List[Dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            rows = cur.execute("SELECT * FROM anomalies ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            res = [dict(r) for r in rows]
            conn.close()
            return res
        except Exception as e:
            logger.error(f"Failed to fetch anomalies from DB: {e}")
            with self._lock:
                return [a.to_dict() for a in reversed(self._recent_anomalies[-limit:])]

    def get_stats(self) -> Dict:
        with self._lock:
            total_apps = len(self._fingerprints)
            trained_apps = sum(1 for fp in self._fingerprints.values() if fp.confidence_score >= 0.5)

        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            total_anomalies = cur.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            critical_24h = cur.execute(
                "SELECT COUNT(*) FROM anomalies WHERE severity = 'critical' AND detected_at >= ?",
                (time.time() - 86400,)
            ).fetchone()[0]
            conn.close()
        except Exception:
            total_anomalies = len(self._recent_anomalies)
            critical_24h = 0

        return {
            "total_apps_profiled": total_apps,
            "trained_apps_count": trained_apps,
            "training_in_progress": total_apps - trained_apps,
            "total_anomalies_detected": total_anomalies,
            "critical_anomalies_24h": critical_24h
        }
