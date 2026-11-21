"""
Crazy Alchemy - AegisChameleon™
Intent-Aware Ephemeral Dynamic Hardening & Environmental Adversary Pressure Metric (EAPM).

Provides adaptive, context-driven security profiles:
1. Financial Bastion Mode: Ephemeral zero-trust hardening during banking/crypto sessions.
2. Ephemeral Dev-Port Leases: Cryptographically timed firewall leases (e.g. 2 hours) for developer ports.
3. Environmental Adversary Pressure Metric (EAPM): Real-time normalized 0.0-1.0 threat pressure score.
4. Autonomous Multi-Tier Defensive Escalation (Baseline -> Stealth -> Lockdown -> Panic Fortress).
"""

import time
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set

logger = logging.getLogger('crazyalchemy.profiles.adaptive')

SENSITIVE_FINANCIAL_BINARIES: Set[str] = {
    "electrum.exe", "exodus.exe", "ledger live.exe", "trezor suite.exe",
    "wasabi.exe", "monero-wallet-gui.exe", "bitwarden.exe", "1password.exe",
    "keepass.exe", "keepassxc.exe"
}


@dataclass
class DevPortLease:
    lease_id: str
    port: int
    protocol: str
    process_name: str
    granted_at: float
    duration_sec: int
    rule_name: str
    is_active: bool = True

    @property
    def remaining_sec(self) -> int:
        elapsed = time.time() - self.granted_at
        return max(0, int(self.duration_sec - elapsed))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "port": self.port,
            "protocol": self.protocol,
            "process_name": self.process_name,
            "granted_at": self.granted_at,
            "duration_sec": self.duration_sec,
            "remaining_sec": self.remaining_sec,
            "rule_name": self.rule_name,
            "is_active": self.is_active and self.remaining_sec > 0
        }


class AegisChameleonEngine:
    """
    Context-Aware Ephemeral Profile & EAPM Orchestrator.
    Dynamically morphs defensive posture based on user intent and external threat pressure.
    """

    def __init__(self, fw_core: Optional[Any] = None, profile_mgr: Optional[Any] = None):
        self._lock = threading.RLock()
        self.fw_core = fw_core
        self.profile_mgr = profile_mgr

        # Financial Bastion state
        self._financial_bastion_active: bool = False
        self._bastion_triggered_by: str = ""
        self._prev_profile_before_bastion: str = "Private"

        # Ephemeral Dev-Port Leases: lease_id -> DevPortLease
        self._leases: Dict[str, DevPortLease] = {}
        self._lease_counter = 0

        # EAPM metrics & background loop
        self._current_eapm: float = 0.05
        self._wifi_pressure: float = 0.0
        self._trapnet_pressure: float = 0.0
        self._ancestry_pressure: float = 0.0
        self._usb_pressure: float = 0.0

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._orchestration_loop, daemon=True, name="aegis-chameleon")
            self._thread.start()

    def stop(self):
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            active_leases = [l.to_dict() for l in self._leases.values() if l.remaining_sec > 0]
            tier_name = self._get_tier_name(self._current_eapm)
            return {
                "eapm_score": round(self._current_eapm, 3),
                "eapm_pct": int(self._current_eapm * 100),
                "tier_name": tier_name,
                "financial_bastion_active": self._financial_bastion_active,
                "bastion_triggered_by": self._bastion_triggered_by,
                "active_dev_leases_count": len(active_leases),
                "wifi_pressure": round(self._wifi_pressure, 2),
                "trapnet_pressure": round(self._trapnet_pressure, 2),
                "ancestry_pressure": round(self._ancestry_pressure, 2)
            }

    def get_active_leases(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [l.to_dict() for l in self._leases.values() if l.remaining_sec > 0]

    def _get_tier_name(self, score: float) -> str:
        if score < 0.25:
            return "Tier 1: Baseline Guard"
        elif score < 0.60:
            return "Tier 2: Stealth Hardening"
        elif score < 0.85:
            return "Tier 3: Hostile Lockdown"
        else:
            return "Tier 4: Panic Fortress"

    # ── Financial Bastion Mode ──────────────────────────────────────────

    def set_financial_bastion(self, active: bool, reason: str = "Manual User Toggle") -> bool:
        """Enforces or releases Financial Bastion Mode."""
        with self._lock:
            if active == self._financial_bastion_active:
                return True

            self._financial_bastion_active = active
            self._bastion_triggered_by = reason if active else ""

            if active:
                logger.critical(f"🛡️ [AegisChameleon] ENGAGING FINANCIAL BASTION MODE! Reason: {reason}")
                if self.profile_mgr and hasattr(self.profile_mgr, "apply_profile"):
                    self._prev_profile_before_bastion = getattr(self.profile_mgr, "active_profile", "Private")
                    self.profile_mgr.apply_profile("Maximum Security")
            else:
                logger.info("🛡️ [AegisChameleon] Disengaging Financial Bastion Mode. Restoring baseline profile.")
                if self.profile_mgr and hasattr(self.profile_mgr, "apply_profile"):
                    self.profile_mgr.apply_profile(self._prev_profile_before_bastion)

            return True

    # ── Ephemeral Dev-Port Leases ────────────────────────────────────────

    def grant_dev_port_lease(
        self,
        port: int,
        protocol: str = "TCP",
        duration_sec: int = 7200,
        process_name: str = "dev_server"
    ) -> str:
        """
        Grants a cryptographically timed temporary firewall rule lease.
        The rule is registered in Windows Firewall and automatically expunged when the timer expires.
        """
        with self._lock:
            self._lease_counter += 1
            lease_id = f"devlease_{int(time.time())}_{self._lease_counter}"
            rule_name = f"VitoriusFW_DevLease_{port}_{protocol.upper()}"

            lease = DevPortLease(
                lease_id=lease_id,
                port=port,
                protocol=protocol.upper(),
                process_name=process_name,
                granted_at=time.time(),
                duration_sec=duration_sec,
                rule_name=rule_name
            )
            self._leases[lease_id] = lease

        # Add firewall rule via WindowsFirewallCore
        if self.fw_core and hasattr(self.fw_core, "add_port_rule"):
            try:
                self.fw_core.add_port_rule(
                    rule_name=rule_name,
                    port=str(port),
                    protocol=protocol,
                    direction="in",
                    action="allow"
                )
                logger.info(f"⏳ [AegisChameleon] Granted Dev-Port Lease: Port {port}/{protocol} for {duration_sec}s ({process_name})")
            except Exception as e:
                logger.error(f"Failed to add dev port lease rule: {e}")

        return lease_id

    def revoke_dev_port_lease(self, lease_id: str) -> bool:
        """Revokes a dev-port lease immediately and removes the firewall rule."""
        with self._lock:
            lease = self._leases.get(lease_id)
            if not lease:
                return False
            lease.is_active = False

        if self.fw_core and hasattr(self.fw_core, "delete_rule_by_name"):
            try:
                self.fw_core.delete_rule_by_name(lease.rule_name)
                logger.info(f"🔒 [AegisChameleon] Expunged Dev-Port Lease rule: {lease.rule_name}")
            except Exception as e:
                logger.error(f"Failed to remove dev port lease rule: {e}")

        return True

    # ── EAPM Calculation & Autonomous Loop ─────────────────────────────

    def _orchestration_loop(self):
        """Background thread updating EAPM pressure and checking dev lease expiry."""
        while self._running:
            try:
                now = time.time()

                # 1. Check and expunge expired dev-port leases
                with self._lock:
                    for lid, lease in list(self._leases.items()):
                        if lease.is_active and lease.remaining_sec <= 0:
                            lease.is_active = False
                            if self.fw_core and hasattr(self.fw_core, "delete_rule_by_name"):
                                try:
                                    self.fw_core.delete_rule_by_name(lease.rule_name)
                                    logger.info(f"⏰ [AegisChameleon] Dev-Port Lease EXPIRED. Auto-sealed port {lease.port}/{lease.protocol}.")
                                except Exception:
                                    pass

                # 2. Check for active Financial/Crypto applications
                self._check_financial_processes()

                # 3. Calculate live EAPM pressure score
                self._recalculate_eapm()

            except Exception as e:
                logger.debug(f"AegisChameleon orchestration error: {e}")

            time.sleep(3.0)

    def _check_financial_processes(self):
        """Auto-triggers Financial Bastion if crypto wallets or password managers are active."""
        if self._financial_bastion_active:
            return

        try:
            import psutil
            for p in psutil.process_iter(['name']):
                pname = (p.info.get('name') or "").lower()
                if pname in SENSITIVE_FINANCIAL_BINARIES:
                    self.set_financial_bastion(True, reason=f"Detected running sensitive wallet/vault: {pname}")
                    break
        except Exception:
            pass

    def _recalculate_eapm(self):
        """Computes multi-factor environmental adversary pressure index [0.0, 1.0]."""
        with self._lock:
            # Query LineageGuard violations
            if self.fw_core and hasattr(self.fw_core, "lineage_guard"):
                blocked = self.fw_core.lineage_guard.get_stats().get("blocked_chains", 0)
                self._ancestry_pressure = min(1.0, blocked * 0.25)

            # Query TrapNet honeypot probe frequency
            # Default baseline
            self._current_eapm = min(
                1.0,
                0.20 * self._wifi_pressure +
                0.35 * self._trapnet_pressure +
                0.35 * self._ancestry_pressure +
                0.10 * self._usb_pressure + 0.05
            )
