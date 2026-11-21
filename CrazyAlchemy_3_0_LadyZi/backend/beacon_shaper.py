"""
Crazy Alchemy - BeaconEntropyShaper™
Fast Fourier Transform (FFT) Inter-Packet Interval Analyzer & Phantom C2 Tarpit.

Provides mathematical detection and neutralization of covert periodic C2 beacons:
1. Tracks connection inter-arrival deltas (Δt) per remote destination host/domain.
2. Fast Fourier Transform (FFT) & Power Spectral Density (PSD) analysis to identify synthetic beacon jitter.
3. Coefficient of Variation (CV) modeling distinguishing human traffic from automated heartbeats.
4. Phantom Tarpit Active Defense: traps hostile C2 communication in zero-window rate-clamps.
"""

import math
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger('crazyalchemy.firewall.beaconshaper')

TRUSTED_BEACON_PROCESSES: Set[str] = {
    "antigravity.exe", "code.exe", "cursor.exe", "python.exe", "pythonw.exe",
    "node.exe", "git.exe", "steam.exe", "steamwebhelper.exe", "discord.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
    "epicgameslauncher.exe", "battle.net.exe", "riotclientservices.exe", "system",
    "svchost.exe", "devenv.exe", "idea64.exe", "pycharm64.exe", "clion64.exe",
    "rider64.exe", "webstorm64.exe", "rust-analyzer.exe"
}


@dataclass
class BeaconTargetTelemetry:
    remote_host: str
    connection_timestamps: List[float] = field(default_factory=list)
    intervals: List[float] = field(default_factory=list)
    dominant_frequency_hz: float = 0.0
    estimated_beacon_interval_sec: float = 0.0
    spectral_peak_power: float = 0.0
    coefficient_of_variation: float = 1.0
    is_beacon_confirmed: bool = False
    is_tarpitted: bool = False
    last_seen: float = 0.0


@dataclass
class BeaconAlert:
    remote_host: str
    process_name: str
    estimated_interval_sec: float
    confidence_score: float
    action_taken: str  # "TARPITTED", "BLOCKED", "ALERT"
    spectral_power: float
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "remote_host": self.remote_host,
            "process_name": self.process_name,
            "estimated_interval_sec": round(self.estimated_interval_sec, 2),
            "confidence_score": round(self.confidence_score, 3),
            "action_taken": self.action_taken,
            "spectral_power": round(self.spectral_power, 3),
            "timestamp": self.timestamp,
            "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        }


class BeaconEntropyShaper:
    """
    Mathematical C2 Beacon Frequency Shaper & Phantom Tarpit Engine.
    Examines packet arrival intervals to unmask covert TLS/HTTPS heartbeats.
    """

    def __init__(self, tarpit_callback: Optional[Any] = None):
        self._lock = threading.RLock()
        self.tarpit_callback = tarpit_callback

        # Host telemetry: "remote_ip:port" -> BeaconTargetTelemetry
        self._targets: Dict[str, BeaconTargetTelemetry] = {}
        self._alerts: List[BeaconAlert] = []
        self._total_beacons_trapped = 0
        self._is_enabled = True

    def is_enabled(self) -> bool:
        return self._is_enabled

    def set_enabled(self, enabled: bool):
        with self._lock:
            self._is_enabled = enabled

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_enabled": self._is_enabled,
                "monitored_endpoints": len(self._targets),
                "total_beacons_trapped": self._total_beacons_trapped,
                "active_tarpits_count": sum(1 for t in self._targets.values() if t.is_tarpitted),
                "recent_alerts_count": len(self._alerts)
            }

    def get_active_beacons(self) -> List[Dict[str, Any]]:
        with self._lock:
            res = []
            for k, v in self._targets.items():
                if v.is_beacon_confirmed:
                    res.append({
                        "endpoint": k,
                        "interval_sec": round(v.estimated_beacon_interval_sec, 2),
                        "spectral_peak": round(v.spectral_peak_power, 3),
                        "cv": round(v.coefficient_of_variation, 3),
                        "is_tarpitted": v.is_tarpitted,
                        "samples_count": len(v.intervals)
                    })
            return res

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:][::-1]]

    def record_connection_event(
        self,
        remote_ip: str,
        remote_port: int,
        process_name: str = "Unknown"
    ) -> Tuple[bool, Optional[BeaconAlert]]:
        """
        Records an outbound socket connection timestamp and re-computes
        interval Discrete Fourier Transform (DFT) to detect periodic C2 check-ins.
        """
        if not self._is_enabled or not remote_ip or remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return False, None

        # Ignore loopback and protected developer/system/browser processes
        proc_clean = (process_name or "").lower()
        if proc_clean in TRUSTED_BEACON_PROCESSES:
            return False, None

        # Ignore private LAN subnets
        if (remote_ip.startswith("10.") or remote_ip.startswith("192.168.") or
            remote_ip.startswith("127.") or remote_ip.startswith("fe80:") or
            (remote_ip.startswith("172.") and any(remote_ip.startswith(f"172.{o}.") for o in range(16, 32)))):
            return False, None

        endpoint_key = f"{remote_ip}:{remote_port}"
        now = time.time()

        with self._lock:
            if endpoint_key not in self._targets:
                self._targets[endpoint_key] = BeaconTargetTelemetry(remote_host=endpoint_key)

            target = self._targets[endpoint_key]
            # If seen recently (e.g. within 1.5s), don't record duplicate timestamp
            if target.connection_timestamps and (now - target.connection_timestamps[-1]) < 1.5:
                return False, None

            target.last_seen = now
            target.connection_timestamps.append(now)

            # Keep window of last 24 timestamps
            if len(target.connection_timestamps) > 24:
                target.connection_timestamps.pop(0)

            # Calculate intervals
            if len(target.connection_timestamps) >= 2:
                ts = target.connection_timestamps
                target.intervals = [ts[i] - ts[i - 1] for i in range(1, len(ts))]

            # Need at least 6 connection interval samples to compute spectral variance
            if len(target.intervals) < 6:
                return False, None

            # Calculate mean and standard deviation
            intervals = target.intervals
            n = len(intervals)
            mean_int = sum(intervals) / n
            if mean_int < 0.5:  # Ignore ultra-rapid connection bursts (e.g. web page asset downloads)
                return False, None

            variance = sum((x - mean_int) ** 2 for x in intervals) / n
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_int if mean_int > 0 else 1.0
            target.coefficient_of_variation = cv

            # Discrete Fourier Transform / Peak Spectral Power calculation
            # Evaluating frequency spectrum from f_min (1/300Hz = 5 min) to f_max (1/2Hz = 2s)
            peak_power, dom_freq = self._compute_spectral_peak(intervals)
            target.spectral_peak_power = peak_power
            target.dominant_frequency_hz = dom_freq

            # Detection Criteria:
            # Low coefficient of variation (CV < 0.35) OR high spectral peak density (power > 0.65)
            # indicates periodic C2 heartbeat with synthetic jitter (e.g. Cobalt Strike 60s ± 20%)
            if (cv < 0.32 or peak_power >= 0.70) and not target.is_beacon_confirmed:
                target.is_beacon_confirmed = True
                target.estimated_beacon_interval_sec = mean_int
                target.is_tarpitted = True
                self._total_beacons_trapped += 1

                alert = BeaconAlert(
                    remote_host=endpoint_key,
                    process_name=process_name,
                    estimated_interval_sec=mean_int,
                    confidence_score=min(0.99, max(0.60, 1.0 - cv + (peak_power * 0.3))),
                    action_taken="TARPITTED",
                    spectral_power=peak_power,
                    timestamp=now
                )
                self._alerts.append(alert)

                logger.critical(
                    f"📡 [BeaconShaper] COVERT C2 BEACON DETECTED! Endpoint '{endpoint_key}' ({process_name}) "
                    f"exhibits periodic check-ins every ~{mean_int:.1f}s (CV={cv:.2f}, SpectralPower={peak_power:.2f}). "
                    f"Engaging Phantom Tarpit Active Defense!"
                )

                if self.tarpit_callback:
                    try:
                        self.tarpit_callback(remote_ip, remote_port, process_name)
                    except Exception as e:
                        logger.error(f"Tarpit callback error: {e}")

                return True, alert

        return False, None

    def _compute_spectral_peak(self, intervals: List[float]) -> Tuple[float, float]:
        """
        Computes Discrete Fourier Transform (DFT) magnitude across test frequencies.
        Returns (normalized_peak_power, dominant_frequency_hz).
        """
        n = len(intervals)
        if n < 4:
            return 0.0, 0.0

        # Test frequencies corresponding to intervals from 2s to 300s
        freqs = [1.0 / t for t in range(2, 300, 2)]
        max_power = 0.0
        dom_f = 0.0

        for f in freqs:
            real_sum = sum(math.cos(2 * math.pi * f * intervals[k]) for k in range(n))
            imag_sum = sum(math.sin(2 * math.pi * f * intervals[k]) for k in range(n))
            power = (real_sum ** 2 + imag_sum ** 2) / (n ** 2)
            if power > max_power:
                max_power = power
                dom_f = f

        return max_power, dom_f
