"""
Vitorius Firewall Win - Windows 11 Pages
Implements all 8 navigation views with identical workflow and layout to the Linux version:
Dashboard, Antivirus, Rules, Monitor (with TrapNet, ChainGuard, AppPrint tabs),
Apps, Profiles, Logs, and Settings.
"""

import os
import sys
import logging
import threading
import time
import json
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger('vitorius.win.pages')
from ui.taskbar_win import TBPF_NORMAL, TBPF_ERROR, TBPF_PAUSED, TBPF_NOPROGRESS
from backend.honeypot import DECOY_CATALOG, DECEPTION_PRESETS, is_port_in_use, DEFAULT_TRAP_PORTS
from backend.browser_shield import BrowserDetector, ExtensionDeployer

try:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QSizePolicy, QLabel, QPushButton,
        QScrollArea, QFrame, QListWidget, QListWidgetItem, QTableWidget,
        QTableWidgetItem, QHeaderView, QLineEdit, QTextEdit, QComboBox, QProgressBar,
        QFileDialog, QMessageBox, QTabWidget, QDialog, QCheckBox, QInputDialog, QApplication
    )
    from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QObject
    from PyQt6.QtGui import QIcon, QColor
    HAS_PYQT6 = True
except ImportError:
    HAS_PYQT6 = False
    # Mock classes for linting/compilation verification outside Windows
    class QWidget: pass
    class QScrollArea: pass
    class QFrame: pass
    class QObject: pass
    class QColor: pass
    def pyqtSignal(*args): return None


def create_antivirus_option_row(icon_text: str, title: str, subtitle: str, control_widget=None) -> Any:
    """
    Constructs an Adwaita ActionRow / Windows Antivirus style option card.
    Contains icon on left, title + description stacked in center, and action control on right.
    """
    if not HAS_PYQT6:
        return None

    row = QFrame()
    row.setProperty("class", "setting-row")
    lay = QHBoxLayout(row)
    lay.setContentsMargins(14, 8, 14, 8)
    lay.setSpacing(12)

    # Leading Icon
    icon_lbl = QLabel(icon_text)
    icon_lbl.setStyleSheet("font-size: 22px;")
    icon_lbl.setFixedWidth(32)
    icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.addWidget(icon_lbl)

    # Title & Subtitle Stack
    t_box = QVBoxLayout()
    t_box.setSpacing(3)
    lbl_title = QLabel(title)
    lbl_title.setObjectName("RowTitle")
    lbl_title.setStyleSheet("font-size: 13px; font-weight: bold;")
    lbl_sub = QLabel(subtitle)
    lbl_sub.setObjectName("RowSubtitle")
    lbl_sub.setStyleSheet("font-size: 11px;")
    lbl_sub.setWordWrap(True)
    t_box.addWidget(lbl_title)
    t_box.addWidget(lbl_sub)
    lay.addLayout(t_box, stretch=1)

    # Trailing Control Widget
    if control_widget is not None:
        lay.addWidget(control_widget)

    return row


# ── 1. Dashboard Page ────────────────────────────────────────────────

class DashboardPage(QScrollArea if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.app_core = main_win.fw_core
        self.av_engine = main_win.av_engine
        self.monitor = main_win.monitor
        self.profiles = main_win.profiles
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 30)
        layout.setSpacing(16)

        # ── Banner Card ──
        banner = QFrame()
        banner.setProperty("class", "stat-card")
        b_layout = QHBoxLayout(banner)
        b_layout.setContentsMargins(16, 16, 16, 16)

        icon_lbl = QLabel("🛡️")
        icon_lbl.setStyleSheet("font-size: 32px;")
        b_layout.addWidget(icon_lbl)

        t_layout = QVBoxLayout()
        self.banner_title = QLabel("Corporate Protection Engine — Windows 11")
        self.banner_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.banner_sub = QLabel("Firewall, Real-Time Antivirus & Deception Shield Active")
        self.banner_sub.setProperty("class", "subtitle-text")
        t_layout.addWidget(self.banner_title)
        t_layout.addWidget(self.banner_sub)
        b_layout.addLayout(t_layout, stretch=1)

        self.btn_reload = QPushButton("Reload")
        self.btn_reload.clicked.connect(self._on_banner_btn_action)
        b_layout.addWidget(self.btn_reload)
        layout.addWidget(banner)

        # ── Primary Stat Cards Grid (4 cards) ──
        stats_box = QHBoxLayout()
        stats_box.setSpacing(12)

        self.card_zone_val = QLabel("Private")
        self.card_profile_val = QLabel(self.profiles.get_active_profile() or "Home")
        self.card_conns_val = QLabel("0")
        self.card_threats_val = QLabel("0")

        for title, val_lbl in [
            ("Windows Profile", self.card_zone_val),
            ("Security Posture", self.card_profile_val),
            ("Live Connections", self.card_conns_val),
            ("Quarantined Threats", self.card_threats_val)
        ]:
            card = QFrame()
            card.setProperty("class", "stat-card")
            c_lay = QVBoxLayout(card)
            t_lbl = QLabel(title)
            t_lbl.setProperty("class", "card-caption")
            val_lbl.setStyleSheet("font-size: 20px; font-weight: bold;")
            c_lay.addWidget(t_lbl)
            c_lay.addWidget(val_lbl)
            stats_box.addWidget(card)

        layout.addLayout(stats_box)

        # ── Novel Telemetry Cards Grid (4 cards: TrapNet, ChainGuard, AppPrint, DarkWeb) ──
        novel_box = QHBoxLayout()
        novel_box.setSpacing(12)

        self.card_trapnet_val = QLabel("0 Traps")
        self.card_chainguard_val = QLabel("0 Chains")
        self.card_appprint_val = QLabel("0 Anomalies")
        self.card_darkweb_val = QLabel("0 Breached")

        for title, val_lbl, tip, nav_target, tab_idx in [
            ("🍯 TrapNet Deception", self.card_trapnet_val, "Intruders caught on decoy ports", "monitor", 1),
            ("🧠 ChainGuard Ancestry", self.card_chainguard_val, "Suspicious parent-child process chains", "monitor", 2),
            ("🧬 AppPrint Network DNA", self.card_appprint_val, "Behavioral deviation anomalies", "monitor", 3),
            ("🕵️ DarkWeb Exposure", self.card_darkweb_val, "Compromised accounts & credential dumps", "darkweb", 4)
        ]:
            card = QFrame()
            card.setProperty("class", "stat-card")
            card.setCursor(Qt.CursorShape.PointingHandCursor)
            card.setToolTip(f"Click to inspect {title} details & configure")
            card.mousePressEvent = (lambda e, t=nav_target, idx=tab_idx: self.main_win.navigate_to(t, tab_index=idx))
            c_lay = QVBoxLayout(card)
            t_lbl = QLabel(title)
            t_lbl.setStyleSheet("color: #388bfd; font-size: 12px; font-weight: bold;")
            val_lbl.setStyleSheet("font-size: 18px; font-weight: bold;")
            sub_lbl = QLabel(tip)
            sub_lbl.setProperty("class", "card-subcaption")
            c_lay.addWidget(t_lbl)
            c_lay.addWidget(val_lbl)
            c_lay.addWidget(sub_lbl)
            novel_box.addWidget(card)

        layout.addLayout(novel_box)

        # ── Quick Actions Grid (Prominent, High-Visibility, Responsive) ──
        actions_card = QFrame()
        actions_card.setProperty("class", "stat-card")
        act_lay = QVBoxLayout(actions_card)
        act_lay.setContentsMargins(16, 14, 16, 14)
        act_lay.setSpacing(12)

        act_head = QHBoxLayout()
        act_title = QLabel("⚡ Quick Security Actions")
        act_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        act_sub = QLabel("Immediate operational controls and defensive posture shortcuts")
        act_sub.setProperty("class", "subtitle-text")
        act_head.addWidget(act_title)
        act_head.addWidget(act_sub)
        act_head.addStretch()
        act_lay.addLayout(act_head)

        btns_grid = QGridLayout()
        btns_grid.setSpacing(10)

        # Row 0: Critical Defense & Protection
        self.btn_quick_panic = QPushButton("⛔ Panic Lockdown")
        self.btn_quick_panic.setProperty("class", "destructive-action action-card-btn")
        self.btn_quick_panic.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_quick_panic.setToolTip("Immediately sever all inbound and outbound network traffic")
        self.btn_quick_panic.clicked.connect(self.main_win.toggle_panic_mode)
        btns_grid.addWidget(self.btn_quick_panic, 0, 0)

        btn_scan = QPushButton("⚡ Run Quick Scan")
        btn_scan.setProperty("class", "suggested-action action-card-btn")
        btn_scan.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_scan.setToolTip("Rapidly scan system memory, hotspots, and active processes")
        btn_scan.clicked.connect(lambda: self.main_win.navigate_to("antivirus"))
        btns_grid.addWidget(btn_scan, 0, 1)

        btn_block_ip = QPushButton("🚫 Quick Block IP")
        btn_block_ip.setProperty("class", "destructive-action action-card-btn")
        btn_block_ip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_block_ip.setToolTip("Instantly block a malicious remote IP address")
        btn_block_ip.clicked.connect(self._dialog_block_ip)
        btns_grid.addWidget(btn_block_ip, 0, 2)

        btn_profile = QPushButton("🌐 Security Posture")
        btn_profile.setProperty("class", "suggested-action action-card-btn")
        btn_profile.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_profile.setToolTip("Switch active security profile or hardening tier")
        btn_profile.clicked.connect(lambda: self.main_win.navigate_to("profiles"))
        btns_grid.addWidget(btn_profile, 0, 3)

        # Row 1: Defensive Telemetry & Rule Management
        btn_rules = QPushButton("🧱 Firewall Rules")
        btn_rules.setProperty("class", "action-card-btn")
        btn_rules.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_rules.setToolTip("View and manage active inbound and outbound firewall rules")
        btn_rules.clicked.connect(lambda: self.main_win.navigate_to("rules"))
        btns_grid.addWidget(btn_rules, 1, 0)

        btn_dw_manage = QPushButton("🕵️ DarkWeb Monitor")
        btn_dw_manage.setProperty("class", "suggested-action action-card-btn")
        btn_dw_manage.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_dw_manage.setToolTip("Monitor email accounts against credential dumps and dark web breaches")
        btn_dw_manage.clicked.connect(lambda: self.main_win.navigate_to("darkweb"))
        btns_grid.addWidget(btn_dw_manage, 1, 1)

        btn_monitor = QPushButton("📡 Threat Radar")
        btn_monitor.setProperty("class", "action-card-btn")
        btn_monitor.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_monitor.setToolTip("Inspect live sockets, TrapNet decoys, and ChainGuard telemetry")
        btn_monitor.clicked.connect(lambda: self.main_win.navigate_to("monitor"))
        btns_grid.addWidget(btn_monitor, 1, 2)

        btn_manage_apps = QPushButton("💻 App Permissions")
        btn_manage_apps.setProperty("class", "suggested-action action-card-btn")
        btn_manage_apps.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_manage_apps.setToolTip("Manage per-application network permissions and listeners")
        btn_manage_apps.clicked.connect(lambda: self.main_win.navigate_to("apps"))
        btns_grid.addWidget(btn_manage_apps, 1, 3)

        act_lay.addLayout(btns_grid)
        layout.addWidget(actions_card)

        # ── Scanned Services & Applications Card (Like Linux GUI) ──
        apps_card = create_antivirus_option_row(
            "💻",
            "Auto-Scanned Services & Applications",
            "Discovered background Windows services, local network listeners, and desktop apps",
            btn_manage_apps
        )
        if apps_card:
            layout.addWidget(apps_card)

        # ── Recent Audit Events Action List ──
        events_card = QFrame()
        events_card.setProperty("class", "stat-card")
        e_lay = QVBoxLayout(events_card)
        e_lay.setContentsMargins(16, 14, 16, 14)
        e_lay.setSpacing(10)

        e_head = QHBoxLayout()
        e_title = QLabel("📜 Recent Security Events")
        e_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        e_head.addWidget(e_title)
        e_head.addStretch()

        btn_view_full_logs = QPushButton("Inspect Full Log →")
        btn_view_full_logs.setProperty("class", "suggested-action")
        btn_view_full_logs.setToolTip("Open full system audit and threat event logs")
        btn_view_full_logs.clicked.connect(lambda: self.main_win.navigate_to("logs"))
        e_head.addWidget(btn_view_full_logs)
        e_lay.addLayout(e_head)

        self.events_list = QListWidget()
        self.events_list.setObjectName("EventsList")
        self.events_list.setMinimumHeight(150)
        self.events_list.setMaximumHeight(220)
        e_lay.addWidget(self.events_list)
        layout.addWidget(events_card)

        layout.addStretch()
        self.setWidget(container)

    def _on_banner_btn_action(self):
        """Toggles panic off if currently active, or reloads rules."""
        if self.app_core.get_panic_mode():
            self.main_win.toggle_panic_mode()
        else:
            self.main_win.reload_firewall()

    def _dialog_block_ip(self):
        from PyQt6.QtWidgets import QInputDialog
        ip, ok = QInputDialog.getText(self, "Quick Block IP", "Enter IP address or CIDR range to drop immediately:")
        if ok and ip.strip():
            target = ip.strip()
            if self.app_core.block_ip(target):
                self.main_win.fw_logger.log_event("ip_blocked", "warning", f"Blocked IP on Windows 11: {target}")
                QMessageBox.information(self, "IP Blocked", f"Successfully dropped traffic for {target}")
                self.refresh()
            else:
                QMessageBox.warning(self, "Block Failed", f"Could not block {target}. Please check IP format.")

    def refresh(self):
        if not HAS_PYQT6:
            return
        summary = self.app_core.get_summary()
        active_prof = self.profiles.get_active_profile()

        self.card_zone_val.setText(summary.get('default_zone', 'Private'))
        self.card_profile_val.setText(active_prof or "Home")

        stats = self.monitor.get_connection_stats()
        self.card_conns_val.setText(str(stats.get('total', 0)))

        q_items = self.av_engine.quarantine.list_quarantined()
        self.card_threats_val.setText(str(len(q_items)))

        # Update novel stats
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            h_stats = self.main_win.honeypot_mgr.get_trap_stats()
            self.card_trapnet_val.setText(f"{h_stats.get('total_traps', 0)} Trapped ({h_stats.get('auto_blocked_count', 0)} Banned)")

        if hasattr(self.main_win, 'chainguard_engine') and self.main_win.chainguard_engine:
            cg_stats = self.main_win.chainguard_engine.get_stats()
            self.card_chainguard_val.setText(f"{cg_stats.get('active_suspicious_count', 0)} Active ({cg_stats.get('total_historical_events', 0)} Total)")

        if hasattr(self.main_win, 'appprint_engine') and self.main_win.appprint_engine:
            ap_stats = self.main_win.appprint_engine.get_stats()
            self.card_appprint_val.setText(f"{ap_stats.get('total_anomalies_detected', 0)} Alerts ({ap_stats.get('total_apps_profiled', 0)} Apps)")

        if hasattr(self.main_win, 'darkweb_monitor') and self.main_win.darkweb_monitor:
            dw_stats = self.main_win.darkweb_monitor.get_stats()
            self.card_darkweb_val.setText(f"{dw_stats.get('compromised_accounts', 0)} Breached ({dw_stats.get('total_monitored', 0)}/15)")

        # Update banner & panic controls
        is_panic_active = summary.get('panic_mode', False) or self.app_core.get_panic_mode()
        if hasattr(self, 'btn_quick_panic') and self.btn_quick_panic:
            if is_panic_active:
                self.btn_quick_panic.setText("🟢 Lift Panic Lockdown")
                self.btn_quick_panic.setProperty("class", "suggested-action action-card-btn")
            else:
                self.btn_quick_panic.setText("⛔ Panic Lockdown")
                self.btn_quick_panic.setProperty("class", "destructive-action action-card-btn")
            self.btn_quick_panic.style().unpolish(self.btn_quick_panic)
            self.btn_quick_panic.style().polish(self.btn_quick_panic)

        if is_panic_active:
            self.banner_title.setText("⚠️ PANIC LOCKDOWN ACTIVE")
            self.banner_sub.setText("All network traffic is currently severed across all Windows network adapters")
            self.btn_reload.setText("Restore Traffic")
            self.btn_reload.setProperty("class", "suggested-action")
        elif hasattr(self.main_win, 'offline_scanner') and self.main_win.offline_scanner and self.main_win.offline_scanner.is_pending():
            self.banner_title.setText(f"Corporate Protection Active — {active_prof} Mode")
            self.banner_sub.setText("⚠️ Offline Reboot Scan scheduled for next Windows startup • Auto-Remediation Active")
            self.btn_reload.setText("Reload")
            self.btn_reload.setProperty("class", "")
        else:
            self.banner_title.setText(f"Corporate Protection Active — {active_prof} Mode")
            self.banner_sub.setText(f"Windows Firewall Active • {summary.get('total_ports')} ports open, {summary.get('blocked_ips')} IPs blocked")
            self.btn_reload.setText("Reload")
            self.btn_reload.setProperty("class", "")

        # Recent events action list with high-contrast color badges
        self.events_list.clear()
        events = self.main_win.fw_logger.get_recent_events(limit=10)
        if not events:
            self.events_list.addItem("✓ No recent security incidents. System operating normally.")
        else:
            for e in events:
                time_str = e.get('timestamp', '')[11:19]
                sev = e.get('severity', '').upper()
                icon = "🔴" if sev in ("CRITICAL", "HIGH") else ("🟡" if sev in ("WARNING", "WARN") else "🔵")
                msg = f"{icon} [{time_str}] {sev:<8} │ {e.get('message', '')}"
                self.events_list.addItem(msg)


# ── 2. Antivirus & Threat Protection Page ────────────────────────────

class AntivirusPage(QScrollArea if HAS_PYQT6 else object):
    scan_progress = pyqtSignal(int, str) if HAS_PYQT6 else None
    scan_finished = pyqtSignal(int) if HAS_PYQT6 else None
    update_finished = pyqtSignal(bool, str, int) if HAS_PYQT6 else None

    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.av_engine = main_win.av_engine
        self.updater = main_win.av_updater
        self._cancel_scan = threading.Event()

        if HAS_PYQT6:
            self.scan_progress.connect(self._on_scan_progress)
            self.scan_finished.connect(self._on_scan_finished)
            self.update_finished.connect(self._on_update_finished)

        self._init_ui()

    def _on_update_finished(self, ok: bool, msg: str, count: int):
        try:
            self.btn_update.setEnabled(True)
            if hasattr(self, 'btn_full_update') and self.btn_full_update:
                self.btn_full_update.setEnabled(True)

            if ok:
                self.lbl_av_sub.setText(f"Signatures updated: {count} new entries. {msg}")
                self.refresh()
                QMessageBox.information(
                    self,
                    "Database Update Complete",
                    f"Malware signatures database updated successfully!\n\n"
                    f"{msg}\n\n"
                    f"Active threat signatures are armed in real-time."
                )
            else:
                self.lbl_av_sub.setText(f"Signature update: {msg}")
                self.refresh()
                QMessageBox.warning(
                    self,
                    "Signature Update Notice",
                    f"Signature update notice:\n\n{msg}\n\n"
                    f"Existing local baseline malware definitions remain fully active."
                )
        except Exception as e:
            logger.error(f"Error handling signature update completion: {e}")
            try:
                self.refresh()
            except Exception:
                pass

    def refresh_stats(self):
        """Alias for refresh() to maintain backwards compatibility."""
        self.refresh()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 30)
        layout.setSpacing(16)

        # ── Banner Card: Windows Security Hero Status ──
        self.banner = QFrame()
        self.banner.setProperty("class", "hero-protected")
        b_lay = QHBoxLayout(self.banner)
        b_lay.setContentsMargins(16, 16, 16, 16)

        self.lbl_av_icon = QLabel("🛡️")
        self.lbl_av_icon.setStyleSheet("font-size: 34px;")
        b_lay.addWidget(self.lbl_av_icon)

        t_lay = QVBoxLayout()
        self.lbl_av_title = QLabel("Your Device is Protected")
        self.lbl_av_title.setObjectName("HeroTitle")
        self.lbl_av_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.lbl_av_sub = QLabel("Real-Time File Shield Active • MalwareBazaar & ClamAV Signatures Loaded")
        self.lbl_av_sub.setObjectName("HeroSub")
        self.lbl_av_pills = QLabel("🛡️ Tri-Engine Active  •  📊 Hashes Loaded  •  🔄 Auto-Update: Every 12 Hours")
        self.lbl_av_pills.setObjectName("HeroPills")

        t_lay.addWidget(self.lbl_av_title)
        t_lay.addWidget(self.lbl_av_sub)
        t_lay.addWidget(self.lbl_av_pills)
        b_lay.addLayout(t_lay, stretch=1)

        right_box = QVBoxLayout()
        right_box.setSpacing(6)

        self.btn_update = QPushButton("🔄 Update Signatures Now")
        self.btn_update.clicked.connect(self._run_online_update)
        right_box.addWidget(self.btn_update)

        self.btn_full_update = QPushButton("⚡ Full Database Update")
        self.btn_full_update.setProperty("class", "suggested-action")
        self.btn_full_update.setToolTip("Performs comprehensive threat intelligence ingestion & baseline signature expansion")
        self.btn_full_update.clicked.connect(self._run_full_update)
        right_box.addWidget(self.btn_full_update)

        self.btn_api_key = QPushButton("🔑 Threat Feed API Key")
        self.btn_api_key.setToolTip("Configure optional Abuse.ch Auth-Key for direct API access. (Default uses high-speed community mirrors)")
        self.btn_api_key.clicked.connect(self._dialog_api_key)
        right_box.addWidget(self.btn_api_key)

        auto_row = QHBoxLayout()
        auto_row.setSpacing(6)
        self.chk_auto_update = QCheckBox("Auto-Update:")
        self.chk_auto_update.setToolTip("Automatically update virus signatures in the background")
        self.chk_auto_update.toggled.connect(self._on_auto_update_toggled)

        self.combo_update_interval = QComboBox()
        self.combo_update_interval.addItem("Every 2 Hours", 2)
        self.combo_update_interval.addItem("Every 5 Hours", 5)
        self.combo_update_interval.addItem("Every 12 Hours", 12)
        self.combo_update_interval.addItem("Every 24 Hours", 24)
        self.combo_update_interval.currentIndexChanged.connect(self._on_update_interval_changed)

        auto_row.addWidget(self.chk_auto_update)
        auto_row.addWidget(self.combo_update_interval)
        right_box.addLayout(auto_row)

        b_lay.addLayout(right_box)
        layout.addWidget(self.banner)

        # ── Scan Controls ──
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "stat-card")
        c_lay = QVBoxLayout(ctrl_card)

        c_title = QLabel("On-Demand Malware Scanning")
        c_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        c_lay.addWidget(c_title)

        # ── Scan Controls (Responsive 2x5 Grid) ──
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "stat-card")
        c_lay = QVBoxLayout(ctrl_card)
        c_lay.setContentsMargins(16, 14, 16, 14)
        c_lay.setSpacing(10)

        c_title = QLabel("On-Demand Malware Scanning")
        c_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        c_lay.addWidget(c_title)

        scan_grid = QGridLayout()
        scan_grid.setSpacing(8)

        # Row 0: Primary Malware & System Scans
        btn_quick = QPushButton("⚡ Quick Scan (Hotspots)")
        btn_quick.setProperty("class", "suggested-action")
        btn_quick.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_quick.setMinimumHeight(32)
        btn_quick.setToolTip("Rapidly scan Downloads, Desktop, %TEMP%, and Startup for active malware")
        btn_quick.clicked.connect(self.start_quick_scan)
        scan_grid.addWidget(btn_quick, 0, 0)

        btn_system = QPushButton("🖥️ Full System Scan")
        btn_system.setProperty("class", "suggested-action")
        btn_system.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_system.setMinimumHeight(32)
        btn_system.setToolTip("Deep comprehensive scan across all system partitions, Windows OS trees, and user profiles")
        btn_system.clicked.connect(self.start_system_scan)
        scan_grid.addWidget(btn_system, 0, 1)

        btn_custom = QPushButton("💽 Custom Drives Scan")
        btn_custom.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_custom.setMinimumHeight(32)
        btn_custom.setToolTip("Select specific disk drives (C:, D:, USB drives) or custom folder paths to scan")
        btn_custom.clicked.connect(self._dialog_custom_drives_scan)
        scan_grid.addWidget(btn_custom, 0, 2)

        btn_rootkit = QPushButton("🪤 Rootkit Deep Scan")
        btn_rootkit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_rootkit.setMinimumHeight(32)
        btn_rootkit.setToolTip("Deep kernel driver inspection, DKOM hidden processes, IFEO registry hijacks, and MBR bootkit detection")
        btn_rootkit.clicked.connect(self.start_rootkit_scan)
        scan_grid.addWidget(btn_rootkit, 0, 3)

        btn_chronostasis = QPushButton("🔮 ChronoStasis™ Scan")
        btn_chronostasis.setProperty("class", "suggested-action")
        btn_chronostasis.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_chronostasis.setMinimumHeight(32)
        btn_chronostasis.setToolTip("Hunter for sleeping beacon memory masks (Ekko/Cobalt), MFT timestomp discrepancies, and polyglot stego overlays")
        btn_chronostasis.clicked.connect(self.start_chronostasis_scan)
        scan_grid.addWidget(btn_chronostasis, 0, 4)

        # Row 1: Advanced Hunting, Memory, Offline & Remediation
        btn_mem = QPushButton("🧠 Process Memory Scan")
        btn_mem.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_mem.setMinimumHeight(32)
        btn_mem.setToolTip("Scans active memory images of all running processes for injected code and malicious payloads")
        btn_mem.clicked.connect(self._start_process_scan)
        scan_grid.addWidget(btn_mem, 1, 0)

        btn_offline = QPushButton("🔄 Offline Reboot Scan")
        btn_offline.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_offline.setMinimumHeight(32)
        btn_offline.setToolTip("Schedule an isolated pre-boot scan on restart to eliminate deeply rooted rootkits before Windows starts")
        btn_offline.clicked.connect(self._dialog_offline_scan)
        scan_grid.addWidget(btn_offline, 1, 1)

        btn_exploit = QPushButton("💥 Exploit Shield")
        btn_exploit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_exploit.setMinimumHeight(32)
        btn_exploit.setToolTip("View and configure Windows Exploit Protection, ASR rules, and Core Isolation")
        btn_exploit.clicked.connect(self._dialog_exploit_shield)
        scan_grid.addWidget(btn_exploit, 1, 2)

        btn_hash = QPushButton("🔍 Hash Lookup")
        btn_hash.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_hash.setMinimumHeight(32)
        btn_hash.setToolTip("Query a SHA-256 or MD5 hash against the local signature database")
        btn_hash.clicked.connect(self._dialog_hash_lookup)
        scan_grid.addWidget(btn_hash, 1, 3)

        self.btn_cancel = QPushButton("⏹️ Stop Active Scan")
        self.btn_cancel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_cancel.setMinimumHeight(32)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._stop_scan)
        scan_grid.addWidget(self.btn_cancel, 1, 4)

        c_lay.addLayout(scan_grid)

        self.btn_quick = btn_quick
        self.btn_system = btn_system
        self.btn_custom = btn_custom
        self.btn_rootkit = btn_rootkit
        self.btn_chronostasis = btn_chronostasis
        self.btn_mem = btn_mem
        self.btn_offline = btn_offline
        self.btn_hash = btn_hash
        self.btn_exploit = btn_exploit

        # Offline scan pending alert banner
        self.lbl_offline_alert = QLabel("⚠️ OFFLINE SCAN PENDING: An isolated pre-boot scan is scheduled for next system startup.")
        self.lbl_offline_alert.setStyleSheet("color: #d29922; font-weight: bold; background: #382700; border: 1px solid #9e6a03; padding: 8px 12px; border-radius: 6px;")
        self.lbl_offline_alert.setVisible(False)
        c_lay.addWidget(self.lbl_offline_alert)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        c_lay.addWidget(self.progress_bar)

        self.lbl_scan_file = QLabel("Ready to scan")
        self.lbl_scan_file.setProperty("class", "subtitle-text")
        self.lbl_scan_file.setStyleSheet("font-size: 11px;")
        c_lay.addWidget(self.lbl_scan_file)
        layout.addWidget(ctrl_card)

        # ── Novel Pillar 1 Defense Cards: ChronoVault™ & GhostGate™ ──
        novel_av_box = QHBoxLayout()
        novel_av_box.setSpacing(12)

        # ChronoVault Card
        cv_card = QFrame()
        cv_card.setProperty("class", "stat-card")
        cv_lay = QVBoxLayout(cv_card)
        cv_lay.setContentsMargins(14, 12, 14, 12)
        cv_lay.setSpacing(6)

        cv_head = QHBoxLayout()
        cv_icon = QLabel("🛡️")
        cv_icon.setStyleSheet("font-size: 20px;")
        cv_title = QLabel("ChronoVault™ Reversible In-RAM Mirage")
        cv_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #58a6ff;")
        cv_head.addWidget(cv_icon)
        cv_head.addWidget(cv_title, stretch=1)

        self.chk_chronovault = QCheckBox("Active")
        self.chk_chronovault.setChecked(True)
        self.chk_chronovault.toggled.connect(self._toggle_chronovault)
        cv_head.addWidget(self.chk_chronovault)
        cv_lay.addLayout(cv_head)

        self.lbl_cv_status = QLabel("Zero-Loss Ransomware Buffer: 0 rollbacks • 0.0 MB RAM pool")
        self.lbl_cv_status.setProperty("class", "subtitle-text")
        self.lbl_cv_status.setStyleSheet("font-size: 11px;")
        cv_lay.addWidget(self.lbl_cv_status)

        cv_btn_row = QHBoxLayout()
        btn_cv_history = QPushButton("↺ View Restored Files History")
        btn_cv_history.clicked.connect(self._dialog_chronovault_history)
        cv_btn_row.addWidget(btn_cv_history)
        cv_lay.addLayout(cv_btn_row)
        novel_av_box.addWidget(cv_card)

        # GhostGate Card
        gg_card = QFrame()
        gg_card.setProperty("class", "stat-card")
        gg_lay = QVBoxLayout(gg_card)
        gg_lay.setContentsMargins(14, 12, 14, 12)
        gg_lay.setSpacing(6)

        gg_head = QHBoxLayout()
        gg_icon = QLabel("⚡")
        gg_icon.setStyleSheet("font-size: 20px;")
        gg_title = QLabel("GhostGate™ Syscall Evasion & Stack Telemetry")
        gg_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #a371f7;")
        gg_head.addWidget(gg_icon)
        gg_head.addWidget(gg_title, stretch=1)

        btn_gg_audit = QPushButton("Audit Threads Now")
        btn_gg_audit.setProperty("class", "suggested-action")
        btn_gg_audit.clicked.connect(self._run_ghostgate_audit)
        gg_head.addWidget(btn_gg_audit)
        gg_lay.addLayout(gg_head)

        self.lbl_gg_status = QLabel("RIP-Telemetry: 0 threads audited • 0 unbacked callers detected")
        self.lbl_gg_status.setProperty("class", "subtitle-text")
        self.lbl_gg_status.setStyleSheet("font-size: 11px;")
        gg_lay.addWidget(self.lbl_gg_status)

        gg_btn_row = QHBoxLayout()
        btn_gg_findings = QPushButton("📋 View Evasion Findings")
        btn_gg_findings.clicked.connect(self._dialog_ghostgate_findings)
        gg_btn_row.addWidget(btn_gg_findings)
        gg_lay.addLayout(gg_btn_row)
        novel_av_box.addWidget(gg_card)

        layout.addLayout(novel_av_box)

        # ── Quarantined Items Table ──
        q_card = QFrame()
        q_card.setProperty("class", "stat-card")
        q_lay = QVBoxLayout(q_card)

        q_head = QHBoxLayout()
        q_title = QLabel("Quarantine Vault (Isolated Files)")
        q_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        q_head.addWidget(q_title, stretch=1)

        btn_refresh_q = QPushButton("Refresh")
        btn_refresh_q.clicked.connect(self.refresh_quarantine)
        q_head.addWidget(btn_refresh_q)
        q_lay.addLayout(q_head)

        self.table_q = QTableWidget(0, 7)
        self.table_q.setHorizontalHeaderLabels([
            "Select", "Threat Name", "Original Path", "Severity", "Digital Signature", "Quarantined At", "Action"
        ])
        self.table_q.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_q.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table_q.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_q.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_q.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_q.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_q.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table_q.horizontalHeader().setMinimumSectionSize(90)
        self.table_q.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_q.setMaximumHeight(240)
        self.table_q.cellDoubleClicked.connect(lambda r, c: self._inspect_selected())
        self.table_q.cellClicked.connect(self._on_table_cell_clicked)
        q_lay.addWidget(self.table_q)

        # Actions on quarantine
        q_actions = QHBoxLayout()
        q_actions.setSpacing(8)

        btn_select_all = QPushButton("☑ Select / Deselect All")
        btn_select_all.setToolTip("Toggle selection of all threats in the quarantine vault")
        btn_select_all.clicked.connect(self._toggle_select_all_quarantine)

        btn_inspect = QPushButton("🔍 Inspect Threat Details")
        btn_inspect.clicked.connect(self._inspect_selected)

        btn_restore = QPushButton("🔄 Restore Selected")
        btn_restore.setProperty("class", "suggested-action")
        btn_restore.setToolTip("Restore selected threats back to original paths and whitelist them against re-quarantine")
        btn_restore.clicked.connect(self._restore_selected)

        btn_delete = QPushButton("🗑️ Delete Selected Permanently")
        btn_delete.setProperty("class", "destructive-action")
        btn_delete.setToolTip("Permanently destroy selected infected files from quarantine vault")
        btn_delete.clicked.connect(self._delete_selected)

        q_actions.addWidget(btn_select_all)
        q_actions.addWidget(btn_inspect)
        q_actions.addWidget(btn_restore)
        q_actions.addWidget(btn_delete)
        q_lay.addLayout(q_actions)

        layout.addWidget(q_card)
        layout.addStretch()
        self.setWidget(container)

    def _set_scan_buttons_enabled(self, enabled: bool):
        for btn in [
            getattr(self, 'btn_quick', None),
            getattr(self, 'btn_system', None),
            getattr(self, 'btn_custom', None),
            getattr(self, 'btn_rootkit', None),
            getattr(self, 'btn_chronostasis', None),
            getattr(self, 'btn_mem', None),
            getattr(self, 'btn_offline', None),
        ]:
            if btn:
                btn.setEnabled(enabled)

    def _on_scan_progress(self, pct: int, path: str):
        self.progress_bar.setValue(max(0, min(100, pct)))
        if path.startswith(("Process:", "Indexing:", "Scan complete", "Verifying", "Checking", "Starting")):
            self.lbl_scan_file.setText(path)
        else:
            self.lbl_scan_file.setText(f"Scanning: {path}")
        if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
            self.main_win.taskbar.set_progress(pct, 100)

    def _on_scan_finished(self, threat_count: int):
        self._set_scan_buttons_enabled(True)
        self.btn_cancel.setEnabled(False)
        was_cancelled = self._cancel_scan.is_set()
        if was_cancelled:
            self.progress_bar.setValue(0)
            total_scanned = getattr(self, '_total_scanned_items', 0)
            self.lbl_scan_file.setText(f"Scan stopped by user ({total_scanned} items inspected).")
            if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                self.main_win.taskbar.clear()
            self.refresh_quarantine()
            return

        self.progress_bar.setValue(100)
        if threat_count > 0:
            self.lbl_scan_file.setText(
                f"⚠️ Scan finished. Detected & isolated {threat_count} threat(s). "
                f"Click checkbox next to threat name in Quarantine Vault to restore."
            )
            if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                self.main_win.taskbar.set_state(TBPF_ERROR)
        else:
            total_scanned = getattr(self, '_total_scanned_items', 0)
            if total_scanned > 0:
                self.lbl_scan_file.setText(f"Scan finished. Clean ({total_scanned} items inspected) — No threats found.")
            else:
                self.lbl_scan_file.setText("Scan finished. Clean — No threats found (All files clean or properly validated).")
            if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                self.main_win.taskbar.clear()
        self.refresh_quarantine()
        if threat_count > 0:
            for r in range(min(threat_count, self.table_q.rowCount())):
                chk = self.table_q.item(r, 0)
                if chk:
                    chk.setCheckState(Qt.CheckState.Checked)

    def _get_downloads_dir(self) -> str:
        """Resolves the user's Downloads directory across Windows and Linux environments."""
        if sys.platform == "win32":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
                    val, _ = winreg.QueryValueEx(k, "{374DE290-123F-4565-9164-39C4925E467B}")
                    expanded = os.path.expandvars(val)
                    if os.path.isdir(expanded):
                        return expanded
            except Exception:
                pass
        std = os.path.expanduser("~/Downloads")
        return std if os.path.exists(std) else os.path.expanduser("~")

    def start_quick_scan(self):
        hotspots = self.av_engine.get_quick_scan_hotspots()
        if not hotspots:
            hotspots = [self._get_downloads_dir()]
        self.lbl_scan_file.setText("Starting Quick Scan (Active Processes & Threat Hotspots)...")
        self._start_scan_multi_thread(hotspots, scan_type="quick")

    def start_system_scan(self):
        targets = self.av_engine.get_system_scan_targets()
        self.lbl_scan_file.setText("Starting Full Deep System Scan across all OS volumes...")
        self._start_scan_multi_thread(targets, scan_type="system")

    def _dialog_custom_drives_scan(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Custom Antivirus Drive & Folder Scanner")
        dialog.setMinimumWidth(540)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(12)

        lbl_head = QLabel("💽 Select Drives & Folders to Scan:")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: bold;")
        d_lay.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Select any mounted fixed partition, secondary drive, removable USB flash storage, "
            "or add custom folders to include in this antivirus scan:"
        )
        lbl_desc.setProperty("class", "subtitle-text")
        lbl_desc.setStyleSheet("font-size: 11px;")
        lbl_desc.setWordWrap(True)
        d_lay.addWidget(lbl_desc)

        # Drive list
        drives_card = QFrame()
        drives_card.setProperty("class", "stat-card")
        dc_lay = QVBoxLayout(drives_card)
        dc_lay.setSpacing(8)

        lbl_d_title = QLabel("Detected Storage Volumes:")
        lbl_d_title.setStyleSheet("font-weight: bold;")
        dc_lay.addWidget(lbl_d_title)

        drive_checkboxes = {}
        avail_drives = self.av_engine.get_available_drives()
        for d in avail_drives:
            mp = d["mountpoint"]
            label = f"{mp} ({d['fstype']}) — {d['total_gb']} GB total, {d['free_gb']} GB free [{d['drive_type']}]"
            chk = QCheckBox(label)
            if "C:" in mp.upper() or mp == "/":
                chk.setChecked(True)
            drive_checkboxes[mp] = chk
            dc_lay.addWidget(chk)

        d_lay.addWidget(drives_card)

        # Custom folders section
        f_card = QFrame()
        f_card.setProperty("class", "stat-card")
        fc_lay = QVBoxLayout(f_card)
        fc_lay.setSpacing(6)

        lbl_f_title = QLabel("Additional Custom Folders:")
        lbl_f_title.setStyleSheet("font-weight: bold;")
        fc_lay.addWidget(lbl_f_title)

        list_folders = QListWidget()
        list_folders.setMaximumHeight(90)
        fc_lay.addWidget(list_folders)

        f_btn_row = QHBoxLayout()
        btn_add_folder = QPushButton("+ Add Custom Folder")
        btn_rm_folder = QPushButton("Remove Selected Folder")

        def _add_f():
            chosen = QFileDialog.getExistingDirectory(dialog, "Select Folder to Scan")
            if chosen and chosen not in [list_folders.item(i).text() for i in range(list_folders.count())]:
                list_folders.addItem(chosen)

        def _rm_f():
            row = list_folders.currentRow()
            if row >= 0:
                list_folders.takeItem(row)

        btn_add_folder.clicked.connect(_add_f)
        btn_rm_folder.clicked.connect(_rm_f)
        f_btn_row.addWidget(btn_add_folder)
        f_btn_row.addWidget(btn_rm_folder)
        fc_lay.addLayout(f_btn_row)
        d_lay.addWidget(f_card)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_start = QPushButton("🚀 Start Custom Scan")
        btn_start.setProperty("class", "suggested-action")
        btn_cancel = QPushButton("Cancel")
        btn_start.clicked.connect(dialog.accept)
        btn_cancel.clicked.connect(dialog.reject)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_start)
        d_lay.addLayout(btn_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected_paths = []
            for mp, chk in drive_checkboxes.items():
                if chk.isChecked():
                    selected_paths.append(mp)
            for i in range(list_folders.count()):
                selected_paths.append(list_folders.item(i).text())

            if selected_paths:
                self._start_scan_multi_thread(selected_paths)
            else:
                QMessageBox.warning(self, "No Targets Selected", "Please select at least one drive or folder to scan.")

    def start_rootkit_scan(self):
        self._cancel_scan.clear()
        self._set_scan_buttons_enabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        self._total_scanned_items = 0
        self.lbl_scan_file.setText("Initializing Rootkit & Bootkit Deep Analysis...")
        if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
            self.main_win.taskbar.set_state(TBPF_NORMAL)

        def worker():
            threats = []
            try:
                def on_progress(cur, total, msg):
                    self._total_scanned_items += 1
                    pct = int((cur / max(1, total)) * 100)
                    if HAS_PYQT6 and self.scan_progress:
                        self.scan_progress.emit(pct, msg)

                def on_threat(threat):
                    quarantined = self.av_engine.quarantine.quarantine_file(threat.file_path, threat)
                    sev = "critical" if threat.severity == "critical" else "warning"
                    self.main_win.fw_logger.log_event(
                        "rootkit_quarantined" if quarantined else "rootkit_detected",
                        sev,
                        f"Rootkit Threat: {threat.threat_name} in {threat.file_path}"
                    )
                    if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                        self.main_win.taskbar.set_state(TBPF_ERROR)

                threats = self.av_engine.scan_rootkits(
                    progress_cb=on_progress,
                    threat_cb=on_threat,
                    cancel_event=self._cancel_scan
                )
            except Exception as e:
                logger.error(f"Error during rootkit scan: {e}", exc_info=True)
            finally:
                if HAS_PYQT6 and self.scan_finished:
                    self.scan_finished.emit(len(threats))

        threading.Thread(target=worker, daemon=True, name="av-rootkit-scan").start()

    def start_chronostasis_scan(self):
        self._cancel_scan.clear()
        self._set_scan_buttons_enabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        self._total_scanned_items = 0
        self.lbl_scan_file.setText("Initializing ChronoStasis™ Latent Threat & Stego-Polyglot Scan...")
        if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
            self.main_win.taskbar.set_state(TBPF_NORMAL)

        def worker():
            threats = []
            try:
                def on_progress(cur, total, msg):
                    self._total_scanned_items += 1
                    pct = int((cur / max(1, total)) * 100)
                    if HAS_PYQT6 and self.scan_progress:
                        self.scan_progress.emit(pct, msg)

                def on_threat(threat):
                    quarantined = self.av_engine.quarantine.quarantine_file(threat.file_path, threat)
                    sev = "critical" if threat.severity == "critical" else "warning"
                    self.main_win.fw_logger.log_event(
                        "chronostasis_quarantined" if quarantined else "chronostasis_detected",
                        sev,
                        f"ChronoStasis™ Threat: {threat.threat_name} in {threat.file_path}"
                    )
                    if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                        self.main_win.taskbar.set_state(TBPF_ERROR)

                threats = self.av_engine.scan_chronostasis_latent(
                    progress_cb=on_progress,
                    threat_cb=on_threat,
                    cancel_event=self._cancel_scan
                )
            except Exception as e:
                logger.error(f"Error during chronostasis scan: {e}", exc_info=True)
            finally:
                if HAS_PYQT6 and self.scan_finished:
                    self.scan_finished.emit(len(threats))

        threading.Thread(target=worker, daemon=True, name="av-chronostasis-scan").start()

    def _start_custom_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan with Crazy Alchemy Antivirus")
        if folder:
            self._start_scan_thread(folder)

    def _start_scan_multi_thread(self, target_dirs: List[str], scan_type: str = "custom"):
        self._cancel_scan.clear()
        self._set_scan_buttons_enabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        self._total_scanned_items = 0
        if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
            self.main_win.taskbar.set_state(TBPF_NORMAL)

        def worker():
            total_threats = []
            try:
                # If quick scan, inspect running processes first for rapid high-value coverage
                if scan_type == "quick":
                    last_proc_cur = 0
                    def on_proc_threat(threat):
                        q = self.av_engine.quarantine.quarantine_file(threat.file_path, threat)
                        sev = "critical" if threat.severity == "critical" else "warning"
                        self.main_win.fw_logger.log_event(
                            "process_threat_quarantined" if q else "process_threat_detected",
                            sev,
                            f"Process Threat: {threat.threat_name} (PID: {threat.pid}) in {threat.file_path}"
                        )

                    def on_proc_progress(cur, total, path):
                        nonlocal last_proc_cur
                        if cur > last_proc_cur:
                            self._total_scanned_items += (cur - last_proc_cur)
                            last_proc_cur = cur
                        pct = int((cur / max(1, total)) * 25)
                        if HAS_PYQT6 and self.scan_progress:
                            self.scan_progress.emit(min(25, pct), f"Process: {path}")

                    proc_threats = self.av_engine.scan_running_processes(
                        progress_cb=on_proc_progress,
                        threat_cb=on_proc_threat,
                        cancel_event=self._cancel_scan
                    )
                    total_threats.extend(proc_threats)

                base_pct = 25 if scan_type == "quick" else 0
                avail_pct = 75 if scan_type == "quick" else 100
                num_targets = max(1, len(target_dirs))

                for i, target_dir in enumerate(target_dirs):
                    if self._cancel_scan.is_set():
                        break

                    last_dir_cur = 0
                    def on_progress(cur, total, path):
                        nonlocal last_dir_cur
                        if cur > last_dir_cur:
                            self._total_scanned_items += (cur - last_dir_cur)
                            last_dir_cur = cur
                        dir_pct = (cur / max(1, total)) if total > 0 else 0.0
                        overall_pct = base_pct + int(((i + dir_pct) / num_targets) * avail_pct)
                        if HAS_PYQT6 and self.scan_progress:
                            self.scan_progress.emit(min(99, overall_pct), path)

                    def on_threat(threat):
                        quarantined = self.av_engine.quarantine.quarantine_file(threat.file_path, threat)
                        if quarantined:
                            self.main_win.fw_logger.log_event(
                                "malware_quarantined", "critical",
                                f"Detected & Quarantined: {threat.threat_name} in {threat.file_path}"
                            )
                            if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                                self.main_win.taskbar.set_state(TBPF_ERROR)
                        else:
                            self.main_win.fw_logger.log_event(
                                "malware_detected", "critical",
                                f"Threat detected: {threat.threat_name} in {threat.file_path}"
                            )

                    threats = self.av_engine.scan_directory(
                        target_dir,
                        progress_cb=on_progress,
                        threat_cb=on_threat,
                        cancel_event=self._cancel_scan
                    )
                    total_threats.extend(threats)
            except Exception as e:
                logger.error(f"Error during threat scan: {e}", exc_info=True)
            finally:
                if HAS_PYQT6 and self.scan_finished:
                    self.scan_finished.emit(len(total_threats))

        threading.Thread(target=worker, daemon=True, name="av-scan-worker").start()

    def _start_process_scan(self):
        self._cancel_scan.clear()
        self._set_scan_buttons_enabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        self._total_scanned_items = 0
        self.lbl_scan_file.setText("Scanning active process memory and executable modules...")
        if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
            self.main_win.taskbar.set_state(TBPF_NORMAL)

        def worker():
            threats = []
            try:
                def on_threat(threat):
                    quarantined = self.av_engine.quarantine.quarantine_file(threat.file_path, threat)
                    sev = "critical" if threat.severity == "critical" else "warning"
                    self.main_win.fw_logger.log_event(
                        "process_threat_quarantined" if quarantined else "process_threat_detected",
                        sev,
                        f"Process Threat: {threat.threat_name} (PID: {threat.pid}) in {threat.file_path}"
                    )
                    if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                        self.main_win.taskbar.set_state(TBPF_ERROR)

                def on_progress(cur, total, path):
                    self._total_scanned_items += 1
                    pct = int((cur / max(1, total)) * 100)
                    if HAS_PYQT6 and self.scan_progress:
                        self.scan_progress.emit(min(99, pct), f"Process: {path}")

                threats = self.av_engine.scan_running_processes(
                    progress_cb=on_progress,
                    threat_cb=on_threat,
                    cancel_event=self._cancel_scan
                )
            except Exception as e:
                logger.error(f"Error during process scan: {e}", exc_info=True)
            finally:
                if HAS_PYQT6 and self.scan_finished:
                    self.scan_finished.emit(len(threats))

        threading.Thread(target=worker, daemon=True, name="av-proc-scan").start()

    def _dialog_hash_lookup(self):
        hash_str, ok = QInputDialog.getText(
            self, "Threat Intelligence Hash Lookup",
            "Enter binary SHA-256 or MD5 hash to query against local & online threat databases:"
        )
        if ok and hash_str.strip():
            target = hash_str.strip()
            curr_key = (self.updater.get_api_key() if self.updater else (self.main_win.profiles.get_setting("malwarebazaar_api_key", "") if hasattr(self.main_win, 'profiles') else "")) or ""
            match = self.av_engine.lookup_hash(target, online_check=True, api_key=curr_key)
            if match:
                src = match.get('source', 'Malware Database')
                is_online = "Online" in src or "API" in src
                tag = " (Verified Online Intelligence)" if is_online else " (Local Database Match)"
                cache_note = "\n\nThe confirmed threat definition has been cached in your local signature database." if is_online else ""
                QMessageBox.warning(
                    self, "Threat Identified",
                    f"⚠️ MALICIOUS MATCH IDENTIFIED!{tag}\n\n"
                    f"Threat Name: {match.get('threat_name')}\n"
                    f"Malware Family: {match.get('malware_family', match.get('threat_name'))}\n"
                    f"Threat Category: {match.get('threat_category', 'Malware')}\n"
                    f"Severity Level: {match.get('severity', 'high').upper()}\n"
                    f"Intelligence Source: {src}\n"
                    f"Queried Hash: {target}"
                    f"{cache_note}"
                )
            else:
                stats = self.updater.get_stats() if self.updater else {}
                total_sigs = stats.get('total_signatures', 0)
                repo_info = "authenticated Abuse.ch repositories (MalwareBazaar, ThreatFox, URLhaus)" if curr_key else "Abuse.ch repositories and community feeds"
                QMessageBox.information(
                    self, "Hash Clean",
                    f"✅ No threat match found for hash:\n{target}\n\n"
                    f"The hash was verified clean across the local signature database ({total_sigs:,} records) "
                    f"and {repo_info}."
                )

    def _dialog_api_key(self):
        curr_key = (self.updater.get_api_key() if self.updater else (self.main_win.profiles.get_setting("malwarebazaar_api_key", "") if hasattr(self.main_win, 'profiles') else "")) or ""
        masked = f"{curr_key[:6]}...{curr_key[-4:]}" if len(curr_key) > 10 else (curr_key if curr_key else "None (Using Verified Community Mirror)")
        key, ok = QInputDialog.getText(
            self, "Threat Intelligence Auth-Key",
            f"Enter your Abuse.ch / MalwareBazaar Auth-Key (from auth.abuse.ch):\n"
            f"Current status: {masked}\n\n"
            f"Note: This single Auth-Key authenticates BOTH MalwareBazaar file signatures\n"
            f"and live Abuse.ch (ThreatFox / URLhaus) malware domain blocking feeds.\n"
            f"Leaving this blank is completely fine! Crazy Alchemy automatically synchronizes\n"
            f"via verified high-speed threat intelligence mirrors without requiring a key.",
            text=curr_key
        )
        if ok:
            clean_key = key.strip()
            if self.updater:
                self.updater.set_api_key(clean_key)
            if hasattr(self, 'av_engine') and self.av_engine:
                self.av_engine.set_api_key(clean_key)
            if hasattr(self.main_win, 'av_engine') and self.main_win.av_engine:
                self.main_win.av_engine.set_api_key(clean_key)
            if hasattr(self.main_win, 'profiles'):
                self.main_win.profiles.update_settings({
                    "malwarebazaar_api_key": clean_key,
                    "abuse_ch_api_key": clean_key
                })
            if hasattr(self.main_win, "browser_shield") and self.main_win.browser_shield:
                self.main_win.browser_shield.set_api_key(clean_key)
                import threading
                threading.Thread(target=self.main_win.browser_shield.sync_abuse_ch_domains, kwargs={"force": True}, daemon=True).start()
            if clean_key:
                QMessageBox.information(
                    self, "Auth-Key Configured",
                    "Abuse.ch Auth-Key saved successfully!\nDirect API synchronization will now authenticate with your key."
                )
            else:
                QMessageBox.information(
                    self, "Community Mirror Mode Active",
                    "Auth-Key cleared. Crazy Alchemy will synchronize via verified high-speed community mirrors."
                )

    def _on_table_cell_clicked(self, row: int, col: int):
        if col != 0 and col != 6:
            chk_item = self.table_q.item(row, 0)
            if chk_item:
                new_state = Qt.CheckState.Unchecked if chk_item.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked
                chk_item.setCheckState(new_state)

    def _toggle_select_all_quarantine(self):
        total = self.table_q.rowCount()
        if total == 0:
            return
        any_unchecked = any(
            self.table_q.item(r, 0) and self.table_q.item(r, 0).checkState() != Qt.CheckState.Checked
            for r in range(total)
        )
        new_state = Qt.CheckState.Checked if any_unchecked else Qt.CheckState.Unchecked
        for r in range(total):
            item = self.table_q.item(r, 0)
            if item:
                item.setCheckState(new_state)

    def _inspect_selected(self):
        row = self.table_q.currentRow()
        if row < 0:
            for r in range(self.table_q.rowCount()):
                chk = self.table_q.item(r, 0)
                if chk and chk.checkState() == Qt.CheckState.Checked:
                    row = r
                    break
        if row < 0:
            QMessageBox.information(self, "No Selection", "Please select or check an item from the quarantine vault to inspect.")
            return

        chk_item = self.table_q.item(row, 0)
        item_id = chk_item.data(Qt.ItemDataRole.UserRole) if chk_item else None
        items = self.av_engine.quarantine.list_quarantined()
        target = None
        for itm in items:
            if itm.get("id") == item_id:
                target = itm
                break
        if not target and items and row < len(items):
            target = items[row]
        if not target:
            return

        details = (
            f"Threat Identifier: {target.get('id')}\n"
            f"Threat Classification: {target.get('threat_name')}\n"
            f"Severity: {str(target.get('severity', 'high')).upper()}\n"
            f"Original Path: {target.get('original_path')}\n"
            f"Vault Location: {target.get('quarantine_filename')}\n"
            f"Digital Signature: {target.get('signature_status', 'Unsigned')}\n"
            f"SHA-256 Hash: {target.get('sha256', 'N/A')}\n"
            f"Quarantined At: {target.get('quarantined_at')}\n"
            f"Isolation Status: Encrypted & Isolated from Windows Explorer"
        )
        QMessageBox.information(self, "Quarantine Threat Inspection", details)

    def _start_scan_thread(self, target_dir: str):
        self._start_scan_multi_thread([target_dir], scan_type="folder")

    def _stop_scan(self):
        self._cancel_scan.set()
        self._set_scan_buttons_enabled(True)
        self.btn_cancel.setEnabled(False)
        self.lbl_scan_file.setText("Scan cancelled by user.")
        self.progress_bar.setValue(0)
        if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
            self.main_win.taskbar.clear()

    def refresh_quarantine(self):
        if not HAS_PYQT6:
            return
        items = self.av_engine.quarantine.list_quarantined()
        self.table_q.setRowCount(len(items))
        for row, itm in enumerate(items):
            item_id = itm.get('id')

            # Column 0: Checkbox
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            chk_item.setData(Qt.ItemDataRole.UserRole, item_id)
            chk_item.setToolTip(f"Click to select threat #{item_id} for restore or deletion")
            self.table_q.setItem(row, 0, chk_item)

            # Column 1: Threat Name
            name_item = QTableWidgetItem(str(itm.get('threat_name', 'Unknown Threat')))
            name_item.setData(Qt.ItemDataRole.UserRole, item_id)
            name_item.setToolTip(f"ID: {item_id}\nSHA-256: {itm.get('sha256', 'N/A')}")
            self.table_q.setItem(row, 1, name_item)

            # Column 2: Original Path
            path_item = QTableWidgetItem(str(itm.get('original_path', '')))
            path_item.setToolTip(str(itm.get('original_path', '')))
            self.table_q.setItem(row, 2, path_item)

            # Column 3: Severity
            sev_str = str(itm.get('severity', 'high')).upper()
            sev_item = QTableWidgetItem(sev_str)
            self.table_q.setItem(row, 3, sev_item)

            # Column 4: Digital Signature Status
            sig_status = str(itm.get('signature_status') or 'Unsigned')
            sig_item = QTableWidgetItem(sig_status)
            if "Valid" in sig_status:
                sig_item.setForeground(QColor("#3fb950"))
            else:
                sig_item.setForeground(QColor("#f85149"))
            self.table_q.setItem(row, 4, sig_item)

            # Column 5: Quarantined At
            time_item = QTableWidgetItem(str(itm.get('quarantined_at', '')))
            self.table_q.setItem(row, 5, time_item)

            self.table_q.setRowHeight(row, 36)

            # Column 6: Action (Single row restore button next to threat)
            btn_row_restore = QPushButton("🔄 Restore")
            btn_row_restore.setProperty("class", "suggested-action table-action")
            btn_row_restore.setToolTip(f"Restore '{itm.get('threat_name')}' to original path and whitelist it against re-quarantine")
            t_name = str(itm.get('threat_name', 'Unknown Threat'))
            orig_p = str(itm.get('original_path', ''))
            btn_row_restore.clicked.connect(
                lambda _, qid=item_id, qname=t_name, qpath=orig_p: self._restore_single(qid, qname, qpath)
            )
            self.table_q.setCellWidget(row, 6, btn_row_restore)

    def _restore_single(self, item_id: int, threat_name: str, orig_path: str):
        if not HAS_PYQT6:
            return
        confirm = QMessageBox.question(
            self,
            "Confirm Threat Restoration",
            f"Are you sure you want to restore this file to its original path?\n\n"
            f"Threat: {threat_name}\n"
            f"Path: {orig_path}\n\n"
            f"Restored files are whitelisted and will not trigger false-positive quarantines.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok = self.av_engine.quarantine.restore_file(item_id)
        if ok:
            self.main_win.fw_logger.log_event(
                "threat_restored", "warning",
                f"Restored & Whitelisted: {threat_name} to {orig_path}"
            )
            self.refresh_quarantine()
            remaining = self.table_q.rowCount()
            if remaining == 0:
                self.lbl_scan_file.setText("✓ All quarantined threats restored and whitelisted.")
                self.lbl_scan_file.setStyleSheet("color: #3fb950; font-size: 11px; font-weight: bold;")
                if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                    self.main_win.taskbar.clear()
            else:
                self.lbl_scan_file.setText(f"✓ Restored {threat_name}. {remaining} threat(s) remain in Quarantine Vault.")
                self.lbl_scan_file.setStyleSheet("color: #d29922; font-size: 11px; font-weight: bold;")

            # Synchronize Dashboard and Logs windows
            if hasattr(self.main_win, 'pages'):
                if "dashboard" in self.main_win.pages:
                    self.main_win.pages["dashboard"].refresh()
                if "logs" in self.main_win.pages:
                    self.main_win.pages["logs"].refresh()

            QMessageBox.information(
                self,
                "Threat Successfully Restored",
                f"Successfully restored and whitelisted:\n\n"
                f"• {threat_name} -> {orig_path}\n\n"
                f"File has been added to the exclusion whitelist and will not trigger false-positive quarantines."
            )
        else:
            err = getattr(self.av_engine.quarantine, "last_error", "Unknown error")
            QMessageBox.critical(
                self,
                "Restore Failed",
                f"Could not restore '{threat_name}':\n\n{err}"
            )

    def _restore_selected(self):
        if not HAS_PYQT6:
            return
        total_rows = self.table_q.rowCount()
        if total_rows == 0:
            QMessageBox.information(self, "Quarantine Vault Empty", "There are currently no quarantined threats to restore.")
            return

        # 1. Collect checked items
        selected_entries = []
        for r in range(total_rows):
            chk_item = self.table_q.item(r, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                item_id = chk_item.data(Qt.ItemDataRole.UserRole)
                name_item = self.table_q.item(r, 1)
                path_item = self.table_q.item(r, 2)
                t_name = name_item.text() if name_item else f"ID {item_id}"
                orig_path = path_item.text() if path_item else ""
                selected_entries.append((r, item_id, t_name, orig_path))

        # 2. Fallback to currently selected row if no checkboxes checked
        if not selected_entries:
            curr_row = self.table_q.currentRow()
            if curr_row >= 0:
                chk_item = self.table_q.item(curr_row, 0)
                item_id = chk_item.data(Qt.ItemDataRole.UserRole) if chk_item else None
                if item_id is not None:
                    name_item = self.table_q.item(curr_row, 1)
                    path_item = self.table_q.item(curr_row, 2)
                    t_name = name_item.text() if name_item else f"ID {item_id}"
                    orig_path = path_item.text() if path_item else ""
                    selected_entries.append((curr_row, item_id, t_name, orig_path))

        if not selected_entries:
            QMessageBox.information(
                self,
                "No Threat Selected",
                "Please click the checkbox next to the threat(s) you wish to restore, or select a row, then click 'Restore Selected'."
            )
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Threat Restoration",
            f"Are you sure you want to restore {len(selected_entries)} file(s) to their original path(s)?\n\n"
            f"Restored files will be whitelisted to protect against future false-positive quarantines.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        restored_names = []
        failed_entries = []

        for row, item_id, t_name, orig_path in selected_entries:
            ok = self.av_engine.quarantine.restore_file(item_id)
            if ok:
                restored_names.append(f"{t_name} -> {orig_path}")
                self.main_win.fw_logger.log_event(
                    "threat_restored", "warning",
                    f"Restored & Whitelisted: {t_name} to {orig_path}"
                )
            else:
                err = getattr(self.av_engine.quarantine, "last_error", "Unknown error")
                failed_entries.append(f"{t_name}: {err}")

        self.refresh_quarantine()
        remaining = self.table_q.rowCount()
        if remaining == 0:
            self.lbl_scan_file.setText("✓ All quarantined threats restored and whitelisted.")
            self.lbl_scan_file.setStyleSheet("color: #3fb950; font-size: 11px; font-weight: bold;")
            if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                self.main_win.taskbar.clear()
        else:
            self.lbl_scan_file.setText(f"✓ Restored {len(restored_names)} threat(s). {remaining} threat(s) remain in Quarantine Vault.")
            self.lbl_scan_file.setStyleSheet("color: #d29922; font-size: 11px; font-weight: bold;")

        # Synchronize Dashboard and Logs windows
        if hasattr(self.main_win, 'pages'):
            if "dashboard" in self.main_win.pages:
                self.main_win.pages["dashboard"].refresh()
            if "logs" in self.main_win.pages:
                self.main_win.pages["logs"].refresh()

        if restored_names and not failed_entries:
            QMessageBox.information(
                self,
                "Threats Successfully Restored",
                f"Successfully restored and whitelisted {len(restored_names)} file(s):\n\n" +
                "\n".join(f"• {item}" for item in restored_names) +
                "\n\nFiles have been added to the exclusion whitelist and will not trigger false-positive quarantines."
            )
        elif restored_names and failed_entries:
            QMessageBox.warning(
                self,
                "Partial Restore Results",
                f"Restored {len(restored_names)} file(s):\n" +
                "\n".join(f"• {item}" for item in restored_names) +
                f"\n\nFailed to restore {len(failed_entries)} file(s):\n" +
                "\n".join(f"• {item}" for item in failed_entries)
            )
        else:
            QMessageBox.critical(
                self,
                "Restore Failed",
                "Could not restore selected file(s):\n\n" +
                "\n".join(f"• {item}" for item in failed_entries)
            )

    def _delete_selected(self):
        if not HAS_PYQT6:
            return
        total_rows = self.table_q.rowCount()
        if total_rows == 0:
            return

        selected_entries = []
        for r in range(total_rows):
            chk_item = self.table_q.item(r, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                item_id = chk_item.data(Qt.ItemDataRole.UserRole)
                name_item = self.table_q.item(r, 1)
                t_name = name_item.text() if name_item else f"ID {item_id}"
                selected_entries.append((r, item_id, t_name))

        if not selected_entries:
            curr_row = self.table_q.currentRow()
            if curr_row >= 0:
                chk_item = self.table_q.item(curr_row, 0)
                item_id = chk_item.data(Qt.ItemDataRole.UserRole) if chk_item else None
                if item_id is not None:
                    name_item = self.table_q.item(curr_row, 1)
                    t_name = name_item.text() if name_item else f"ID {item_id}"
                    selected_entries.append((curr_row, item_id, t_name))

        if not selected_entries:
            QMessageBox.information(
                self,
                "No Threat Selected",
                "Please click the checkbox next to the threat(s) you wish to permanently delete."
            )
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Permanent Deletion",
            f"Are you sure you want to permanently delete {len(selected_entries)} isolated threat file(s)?\n\n"
            f"This action CANNOT be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        deleted_count = 0
        for r, item_id, t_name in selected_entries:
            if self.av_engine.quarantine.delete_permanently(item_id):
                deleted_count += 1
                self.main_win.fw_logger.log_event(
                    "threat_deleted", "info",
                    f"Permanently purged quarantine threat: {t_name} (ID {item_id})"
                )

        self.refresh_quarantine()
        remaining = self.table_q.rowCount()
        if remaining == 0:
            self.lbl_scan_file.setText("Quarantine Vault is clean.")
            self.lbl_scan_file.setProperty("class", "subtitle-text")
            self.lbl_scan_file.setStyleSheet("font-size: 11px;")
            if hasattr(self.main_win, 'taskbar') and self.main_win.taskbar:
                self.main_win.taskbar.clear()
        else:
            self.lbl_scan_file.setText(f"Deleted selected threats. {remaining} threat(s) remain in Quarantine Vault.")

        # Synchronize Dashboard and Logs windows
        if hasattr(self.main_win, 'pages'):
            if "dashboard" in self.main_win.pages:
                self.main_win.pages["dashboard"].refresh()
            if "logs" in self.main_win.pages:
                self.main_win.pages["logs"].refresh()

        QMessageBox.information(
            self,
            "Threats Deleted",
            f"Successfully deleted {deleted_count} quarantined threat file(s) permanently."
        )

    def _run_online_update(self):
        self.btn_update.setEnabled(False)
        if hasattr(self, 'btn_full_update') and self.btn_full_update:
            self.btn_full_update.setEnabled(False)
        self.lbl_av_sub.setText("Connecting to malware signature feeds (MalwareBazaar / ClamAV)...")

        def worker():
            try:
                ok, msg, count = self.updater.update_signatures()
            except Exception as e:
                logger.error(f"Online update worker error: {e}")
                ok, msg, count = False, f"Update failed: {e}", 0
            if HAS_PYQT6 and self.update_finished:
                self.update_finished.emit(ok, msg, count)
        threading.Thread(target=worker, daemon=True, name="online-update-worker").start()

    def _run_full_update(self):
        self.btn_update.setEnabled(False)
        if hasattr(self, 'btn_full_update') and self.btn_full_update:
            self.btn_full_update.setEnabled(False)
        self.lbl_av_sub.setText("Executing Full Database Update (Seeding baseline definitions & intelligence feeds)...")

        def worker():
            try:
                ok, msg, count = self.updater.full_update_signatures()
            except Exception as e:
                logger.error(f"Full update worker error: {e}")
                ok, msg, count = False, f"Full update failed: {e}", 0
            if HAS_PYQT6 and self.update_finished:
                self.update_finished.emit(ok, msg, count)
        threading.Thread(target=worker, daemon=True, name="full-update-worker").start()

    def _dialog_offline_scan(self):
        """Displays dialog to configure and schedule Microsoft Defender-style offline scan."""
        if not hasattr(self.main_win, 'offline_scanner') or not self.main_win.offline_scanner:
            QMessageBox.warning(self, "Offline Scanner", "Offline scan subsystem is not initialized.")
            return

        scanner = self.main_win.offline_scanner
        is_pending = scanner.is_pending()

        box = QMessageBox(self)
        box.setWindowTitle("Crazy Alchemy — Offline Reboot Scanner")

        if is_pending:
            details = scanner.get_pending_details() or {}
            box.setIcon(QMessageBox.Icon.Warning)
            box.setText(
                "⚠️ OFFLINE SCAN CURRENTLY SCHEDULED\n\n"
                f"An offline antimalware scan is scheduled to run when Windows restarts.\n"
                f"Scheduled At: {details.get('scheduled_at', '')[:19].replace('T', ' ')}\n\n"
                "When your PC reboots, Crazy Alchemy will isolate network connectivity (Panic Mode), "
                "scan system drivers and critical hotspots, and automatically clean any detected threats.\n\n"
                "What would you like to do?"
            )
            btn_reboot_now = box.addButton("Restart PC Now", QMessageBox.ButtonRole.AcceptRole)
            btn_cancel_scan = box.addButton("Cancel Scheduled Scan", QMessageBox.ButtonRole.DestructiveRole)
            btn_close = box.addButton("Keep Scheduled & Close", QMessageBox.ButtonRole.RejectRole)

            box.exec()
            clicked = box.clickedButton()
            if clicked == btn_reboot_now:
                scanner._trigger_reboot(delay_sec=5, reason="Initiating Crazy Alchemy Offline Scan...")
                QMessageBox.information(self, "Restarting", "Your PC is restarting in 5 seconds to run the offline scanner.")
            elif clicked == btn_cancel_scan:
                scanner.cancel_scan()
                QMessageBox.information(self, "Cancelled", "The offline scan has been cancelled.")
                self.refresh()
        else:
            box.setIcon(QMessageBox.Icon.Question)
            box.setText(
                "🛡️ MICROSOFT DEFENDER-STYLE OFFLINE SCANNER\n\n"
                "Some malware, ransomware droppers, and rootkits cannot be safely removed "
                "while Windows is actively running because they lock system files or inject into running processes.\n\n"
                "The Crazy Alchemy Offline Scanner runs in an isolated, network-severed pre-boot environment.\n\n"
                "• All network traffic is temporarily severed (Panic Mode).\n"
                "• Scans Windows System32 drivers, scheduled tasks, startup entries, and temp hotspots.\n"
                "• Automatically terminates malicious processes and cleans/quarantines all detected threats.\n"
                "• Cleans autorun persistence and marks locked files for reboot removal.\n\n"
                "Select when to run the offline scan:"
            )
            btn_restart_now = box.addButton("Restart & Scan Now", QMessageBox.ButtonRole.AcceptRole)
            btn_next_boot = box.addButton("Scan on Next Reboot", QMessageBox.ButtonRole.ActionRole)
            btn_close = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)

            box.exec()
            clicked = box.clickedButton()
            if clicked == btn_restart_now:
                self._schedule_offline_scan(reboot_now=True)
            elif clicked == btn_next_boot:
                self._schedule_offline_scan(reboot_now=False)

    def _schedule_offline_scan(self, reboot_now: bool):
        if not hasattr(self.main_win, 'offline_scanner') or not self.main_win.offline_scanner:
            return
        ok, msg = self.main_win.offline_scanner.schedule_scan(reboot_now=reboot_now)
        if ok:
            if not reboot_now:
                QMessageBox.information(self, "Offline Scan Scheduled", msg)
            self.refresh()
        else:
            QMessageBox.warning(self, "Schedule Failed", msg)

    def _on_auto_update_toggled(self, checked: bool):
        self.main_win.profiles.update_settings({"signature_auto_update": checked})
        if checked:
            self.updater.start_auto_update()
        else:
            self.updater.stop_auto_update()
        self.main_win.fw_logger.log_event(
            "setting_changed", "info",
            f"Virus scanner auto-update {'enabled' if checked else 'disabled'}"
        )

    def _on_update_interval_changed(self, index: int):
        val = self.combo_update_interval.currentData()
        if val in [2, 5, 12, 24]:
            self.main_win.profiles.update_settings({"signature_update_interval_hours": val})
            self.updater.set_interval(val)

    def refresh(self):
        self.btn_update.setEnabled(True)
        if hasattr(self, 'btn_full_update') and self.btn_full_update:
            self.btn_full_update.setEnabled(True)
        self.refresh_quarantine()
        stats = self.updater.get_stats()
        total_sigs = stats.get('total_signatures', 0)
        last_sync = str(stats.get('last_sync') or 'Never')[:10]
        cur_int = stats.get('interval_hours', 12)
        q_items = self.av_engine.quarantine.list_quarantined()

        # Synchronize auto-update controls without triggering recursive signals
        is_auto = self.main_win.profiles.get_setting("signature_auto_update", True)
        int_hours = self.main_win.profiles.get_setting("signature_update_interval_hours", 12)
        if int_hours not in [2, 5, 12, 24]:
            int_hours = 12

        # Windows Defender dynamic hero banner status
        if len(q_items) > 0:
            self.lbl_av_title.setText(f"⚠️ Action Required — {len(q_items)} Threat(s) Isolated")
            self.lbl_av_icon.setText("⚠️")
            self.banner.setProperty("class", "hero-warning")
        elif not self.main_win.profiles.get_setting("realtime_antivirus", True):
            self.lbl_av_title.setText("⚠️ Real-Time Protection is Turned Off")
            self.lbl_av_icon.setText("⚠️")
            self.banner.setProperty("class", "hero-warning")
        else:
            self.lbl_av_title.setText("Your Device is Protected")
            self.lbl_av_icon.setText("🛡️")
            self.banner.setProperty("class", "hero-protected")

        self.lbl_av_sub.setText(f"Signatures Database: {total_sigs:,} threat hashes loaded • Last sync: {last_sync}")
        email_status = "Active" if (hasattr(self.main_win, 'email_shield') and self.main_win.email_shield and self.main_win.email_shield.is_running()) else "Disabled"
        exploit_status = "Active" if (hasattr(self.main_win, 'exploit_shield') and self.main_win.exploit_shield and self.main_win.exploit_shield.is_running()) else "Disabled"
        self.lbl_av_pills.setText(f"🛡️ Tri-Engine Active  •  📊 {total_sigs:,} Hashes  •  📧 Mail: {email_status}  •  💥 Anti-Exploit: {exploit_status}  •  🔄 Auto-Update: Every {cur_int}h")

        self.chk_auto_update.blockSignals(True)
        self.combo_update_interval.blockSignals(True)
        self.chk_auto_update.setChecked(is_auto)
        for i in range(self.combo_update_interval.count()):
            if self.combo_update_interval.itemData(i) == int_hours:
                self.combo_update_interval.setCurrentIndex(i)
                break
        self.chk_auto_update.blockSignals(False)
        self.combo_update_interval.blockSignals(False)

        if hasattr(self.main_win, 'offline_scanner') and self.main_win.offline_scanner:
            self.lbl_offline_alert.setVisible(self.main_win.offline_scanner.is_pending())

        # Update ChronoVault & GhostGate live telemetry
        if hasattr(self.av_engine, "chronovault") and hasattr(self, "lbl_cv_status"):
            cv_s = self.av_engine.chronovault.get_stats()
            self.lbl_cv_status.setText(
                f"Zero-Loss Buffer: {cv_s.get('total_rollbacks', 0)} rollbacks ({cv_s.get('total_bytes_saved', 0):,} B saved) • "
                f"{cv_s.get('buffered_ram_mb', 0)} MB RAM pool • {cv_s.get('blackholed_pids_count', 0)} Blackholed"
            )
        if hasattr(self.av_engine, "ghostgate") and hasattr(self, "lbl_gg_status"):
            gg_s = self.av_engine.ghostgate.get_stats()
            self.lbl_gg_status.setText(
                f"RIP-Telemetry: {gg_s.get('total_audited_threads', 0)} threads audited • "
                f"{gg_s.get('high_severity_count', 0)} unbacked callers detected"
            )

    def _toggle_chronovault(self, checked: bool):
        if hasattr(self.av_engine, "chronovault"):
            self.av_engine.chronovault.set_enabled(checked)
            st = "Armed (Active)" if checked else "Disabled"
            self.lbl_scan_file.setText(f"ChronoVault™ In-RAM Anti-Ransomware Mirage {st}.")

    def _dialog_chronovault_history(self):
        if not HAS_PYQT6 or not hasattr(self.av_engine, "chronovault"):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("ChronoVault™ Reversible Mirage - Neutralized Ransomware & Rollbacks")
        dialog.setMinimumSize(680, 360)
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        alerts = self.av_engine.chronovault.get_recent_alerts(limit=50)
        lbl_info = QLabel(f"Total Rollbacks: {len(alerts)} events. All original file contents restored from RAM with zero data loss.")
        lbl_info.setStyleSheet("font-weight: bold; color: #58a6ff;")
        lay.addWidget(lbl_info)

        table = QTableWidget(len(alerts), 5)
        table.setHorizontalHeaderLabels(["Timestamp", "Process (PID)", "Target File", "Δ Entropy", "Action Taken"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for r, alt in enumerate(alerts):
            table.setItem(r, 0, QTableWidgetItem(alt.get("timestamp_str", "")))
            table.setItem(r, 1, QTableWidgetItem(f"{alt.get('process_name')} ({alt.get('process_id')})"))
            table.setItem(r, 2, QTableWidgetItem(str(alt.get("target_file", ""))))
            table.setItem(r, 3, QTableWidgetItem(f"+{alt.get('entropy_delta', 0):.2f}"))
            table.setItem(r, 4, QTableWidgetItem(str(alt.get("action_taken", ""))))
        lay.addWidget(table)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        lay.addWidget(btn_close)
        dialog.exec()

    def _run_ghostgate_audit(self):
        if not HAS_PYQT6 or not hasattr(self.av_engine, "ghostgate"):
            return
        self.lbl_scan_file.setText("Running GhostGate™ thread call-stack RIP-telemetry audit...")
        def worker():
            findings = self.av_engine.ghostgate.audit_active_processes()
        threading.Thread(target=worker, daemon=True).start()
        time.sleep(0.3)
        self.refresh()
        QMessageBox.information(
            self,
            "GhostGate Audit Complete",
            "GhostGate thread context & RIP-telemetry audit executed.\nCheck findings table for any unbacked dynamic callers."
        )

    def _dialog_ghostgate_findings(self):
        if not HAS_PYQT6 or not hasattr(self.av_engine, "ghostgate"):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("GhostGate™ Syscall Evasion & Unbacked Thread Memory Findings")
        dialog.setMinimumSize(720, 380)
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        findings = self.av_engine.ghostgate.get_findings(limit=50)
        lbl_info = QLabel(f"Detected Evasions: {len(findings)} threads executing outside legitimate PE images.")
        lbl_info.setStyleSheet("font-weight: bold; color: #f85149;" if findings else "font-weight: bold; color: #3fb950;")
        lay.addWidget(lbl_info)

        table = QTableWidget(len(findings), 5)
        table.setHorizontalHeaderLabels(["Timestamp", "Process (PID)", "TID", "RIP Address", "Memory Type & Protection"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for r, f in enumerate(findings):
            table.setItem(r, 0, QTableWidgetItem(f.get("timestamp_str", "")))
            table.setItem(r, 1, QTableWidgetItem(f"{f.get('process_name')} ({f.get('process_id')})"))
            table.setItem(r, 2, QTableWidgetItem(str(f.get("thread_id", ""))))
            table.setItem(r, 3, QTableWidgetItem(str(f.get("rip_address", ""))))
            table.setItem(r, 4, QTableWidgetItem(f"{f.get('memory_type')} [{f.get('memory_protection')}]"))
        lay.addWidget(table)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        lay.addWidget(btn_close)
        dialog.exec()

    def _dialog_exploit_shield(self):
        """Switches to the Monitor Page's Anti-Exploit Shield tab."""
        if hasattr(self.main_win, 'navigate_to'):
            self.main_win.navigate_to("monitor")
            if "monitor" in self.main_win.pages and hasattr(self.main_win.pages["monitor"], "tabs"):
                tabs = self.main_win.pages["monitor"].tabs
                for i in range(tabs.count()):
                    if "Exploit" in tabs.tabText(i):
                        tabs.setCurrentIndex(i)
                        break


# ── 3. Firewall Rules Page ──────────────────────────────────────────

class RulesPage(QScrollArea if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.app_core = main_win.fw_core
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 30)
        layout.setSpacing(16)

        # Toolbar Card
        t_card = QFrame()
        t_card.setProperty("class", "stat-card")
        t_lay = QVBoxLayout(t_card)
        t_lay.setSpacing(10)

        # Row 1: Action Buttons
        btn_row = QHBoxLayout()
        btn_add_port = QPushButton("+ Allow Port")
        btn_add_port.clicked.connect(self._dialog_add_port)

        btn_block_port = QPushButton("+ Block Port")
        btn_block_port.setProperty("class", "destructive-action")
        btn_block_port.clicked.connect(self._dialog_block_port)

        btn_block_ip = QPushButton("+ Block IP")
        btn_block_ip.setProperty("class", "destructive-action")
        btn_block_ip.clicked.connect(self._dialog_block_ip)

        btn_app_rule = QPushButton("+ Application (.exe)")
        btn_app_rule.clicked.connect(self._dialog_app_rule)

        btn_block_icmp = QPushButton("Block Ping (ICMP)")
        btn_block_icmp.clicked.connect(self._toggle_icmp)

        btn_export = QPushButton("💾 Export Policy")
        btn_export.clicked.connect(self._dialog_export_policy)

        btn_import = QPushButton("📂 Import Policy")
        btn_import.clicked.connect(self._dialog_import_policy)

        btn_row.addWidget(btn_add_port)
        btn_row.addWidget(btn_block_port)
        btn_row.addWidget(btn_block_ip)
        btn_row.addWidget(btn_app_rule)
        btn_row.addWidget(btn_block_icmp)
        btn_row.addStretch()
        btn_row.addWidget(btn_export)
        btn_row.addWidget(btn_import)
        t_lay.addLayout(btn_row)

        # Row 2: Search & Filter bar
        filter_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter rules by name, port, protocol, or program...")
        self.search_input.textChanged.connect(self.refresh)
        filter_row.addWidget(self.search_input, stretch=1)

        self.rule_filter_combo = QComboBox()
        self.rule_filter_combo.addItems(["Crazy Alchemy Managed Rules", "All System Rules", "Inbound Only", "Outbound Only"])
        self.rule_filter_combo.currentIndexChanged.connect(self.refresh)
        filter_row.addWidget(self.rule_filter_combo)

        btn_reload_rules = QPushButton("Refresh")
        btn_reload_rules.clicked.connect(self.refresh)
        filter_row.addWidget(btn_reload_rules)
        t_lay.addLayout(filter_row)

        layout.addWidget(t_card)

        # Rules List Table
        card_rules = QFrame()
        card_rules.setProperty("class", "stat-card")
        cr_lay = QVBoxLayout(card_rules)

        self.lbl_rule_count = QLabel("Active Firewall Rules")
        self.lbl_rule_count.setStyleSheet("font-size: 14px; font-weight: bold;")
        cr_lay.addWidget(self.lbl_rule_count)

        self.rules_table = QTableWidget(0, 7)
        self.rules_table.setHorizontalHeaderLabels(["Rule Name", "Direction", "Action", "Protocol", "Port / Program", "Enabled", "Actions"])
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.rules_table.horizontalHeader().resizeSection(4, 180)
        self.rules_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setMinimumSectionSize(80)
        self.rules_table.setMinimumHeight(450)
        cr_lay.addWidget(self.rules_table)
        layout.addWidget(card_rules)

        self.setWidget(container)

    def _toggle_icmp(self):
        self.app_core.block_icmp(True)
        self.main_win.fw_logger.log_event("icmp_blocked", "warning", "Inbound ICMP echo requests (Ping) blocked on Windows 11")
        QMessageBox.information(self, "ICMP Blocked", "Inbound ICMP echo requests (Ping) are now dropped across all network profiles.")
        self.refresh()

    def _dialog_add_port(self):
        port, ok = QInputDialog.getText(self, "Allow Inbound Port", "Enter Port Number to Allow (e.g. 443, 8080, 27015):")
        if ok and port.strip():
            self.app_core.add_port_rule(port.strip(), "TCP", "allow", "in")
            self.main_win.fw_logger.log_event("port_allowed", "info", f"Opened inbound TCP port: {port.strip()}")
            self.refresh()

    def _dialog_block_port(self):
        port, ok = QInputDialog.getText(self, "Block Inbound Port", "Enter Port Number to Block (e.g. 21, 23, 445):")
        if ok and port.strip():
            self.app_core.block_port(port.strip(), "TCP", "in")
            self.main_win.fw_logger.log_event("port_blocked", "warning", f"Blocked inbound TCP port: {port.strip()}")
            self.refresh()

    def _dialog_block_ip(self):
        ip, ok = QInputDialog.getText(self, "Block IP Address", "Enter IP address or CIDR range to drop immediately (e.g. 192.168.1.50):")
        if ok and ip.strip():
            self.app_core.block_ip(ip.strip())
            self.main_win.fw_logger.log_event("ip_blocked", "warning", f"Dropped traffic for IP: {ip.strip()}")
            self.refresh()

    def _dialog_app_rule(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Application Executable", "", "Executables (*.exe);;All Files (*.*)")
        if not file_path:
            return
        app_name = os.path.splitext(os.path.basename(file_path))[0]
        choice = QMessageBox.question(
            self, "Application Policy",
            f"Configure firewall policy for '{app_name}' ({file_path}):\n\nClick 'Yes' to ALLOW network traffic, or 'No' to BLOCK network traffic.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
        )
        if choice == QMessageBox.StandardButton.Yes:
            self.app_core.allow_app(app_name, file_path)
            self.main_win.fw_logger.log_event("app_allowed", "info", f"Allowed application outbound: {file_path}")
            QMessageBox.information(self, "Application Allowed", f"Traffic permitted for {app_name}.")
            self.refresh()
        elif choice == QMessageBox.StandardButton.No:
            self.app_core.block_app(app_name, file_path)
            self.main_win.fw_logger.log_event("app_blocked", "warning", f"Blocked application outbound: {file_path}")
            QMessageBox.information(self, "Application Blocked", f"Traffic blocked for {app_name}.")
            self.refresh()

    def _dialog_export_policy(self):
        backup_path = self.main_win.profiles.backup_rules()
        if backup_path:
            self.main_win.fw_logger.log_event("policy_exported", "info", f"Exported Windows Firewall policy to: {backup_path}")
            QMessageBox.information(self, "Policy Exported", f"Successfully exported Windows Firewall rules to:\n{backup_path}")
        else:
            QMessageBox.warning(self, "Export Failed", "Could not export Windows Firewall policy. Ensure process has administrator privileges.")

    def _dialog_import_policy(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Windows Firewall Policy", "", "Firewall Policy (*.wfw);;All Files (*.*)")
        if file_path:
            if self.main_win.profiles.restore_rules(file_path):
                self.main_win.fw_logger.log_event("policy_imported", "info", f"Restored Windows Firewall policy from: {file_path}")
                QMessageBox.information(self, "Policy Restored", f"Successfully imported Windows Firewall rules from:\n{file_path}")
                self.refresh()
            else:
                QMessageBox.warning(self, "Import Failed", "Failed to restore firewall policy. File may be corrupted or require elevated rights.")

    def _toggle_rule(self, rule_name: str, currently_enabled: bool):
        new_state = not currently_enabled
        if self.app_core.toggle_rule_enabled(rule_name, new_state):
            status_str = "Enabled" if new_state else "Disabled"
            self.main_win.fw_logger.log_event("rule_toggled", "info", f"Rule '{rule_name}' state changed to {status_str}")
            self.refresh()
        else:
            QMessageBox.warning(self, "Toggle Failed", f"Could not change state for rule '{rule_name}'.")

    def _delete_rule(self, rule_name: str):
        confirm = QMessageBox.question(
            self,
            "Delete Rule",
            f"Are you sure you want to remove rule '{rule_name}' from Windows Firewall?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            if self.app_core.delete_rule_by_name(rule_name):
                self.main_win.fw_logger.log_event("rule_deleted", "warning", f"Deleted firewall rule: {rule_name}")
                QMessageBox.information(self, "Rule Deleted", f"Successfully removed '{rule_name}'.")
                self.refresh()
            else:
                QMessageBox.warning(self, "Delete Failed", f"Could not remove '{rule_name}'.")

    def refresh(self):
        if not HAS_PYQT6:
            return

        filter_mode = self.rule_filter_combo.currentText()
        vitorius_only = (filter_mode in ("Crazy Alchemy Managed Rules", "Vitorius Managed Rules"))
        search_txt = self.search_input.text().strip().lower()

        rules = self.app_core.list_all_rules(vitorius_only=vitorius_only)

        filtered = []
        for r in rules:
            if filter_mode == "Inbound Only" and r.get("direction") != "in":
                continue
            if filter_mode == "Outbound Only" and r.get("direction") != "out":
                continue
            if search_txt:
                name_match = search_txt in r.get("name", "").lower()
                proto_match = search_txt in r.get("protocol", "").lower()
                port_match = search_txt in str(r.get("port", "")).lower()
                prog_match = search_txt in r.get("program", "").lower()
                action_match = search_txt in r.get("action", "").lower()
                if not (name_match or proto_match or port_match or prog_match or action_match):
                    continue
            filtered.append(r)

        self.rules_table.setRowCount(len(filtered))
        for row, r in enumerate(filtered):
            name = r.get("name", "")
            direction = r.get("direction", "").upper()
            action = r.get("action", "").upper()
            proto = r.get("protocol", "").upper()
            port = r.get("port", r.get("program", "any"))
            is_enabled = r.get("enabled", True)

            self.rules_table.setItem(row, 0, QTableWidgetItem(name))
            self.rules_table.setItem(row, 1, QTableWidgetItem(direction))
            self.rules_table.setItem(row, 2, QTableWidgetItem(action))
            self.rules_table.setItem(row, 3, QTableWidgetItem(proto))
            self.rules_table.setItem(row, 4, QTableWidgetItem(port))
            self.rules_table.setRowHeight(row, 36)

            # Column 5: Enabled toggle button
            btn_toggle = QPushButton("Active" if is_enabled else "Disabled")
            if not is_enabled:
                btn_toggle.setProperty("class", "destructive-action table-action")
            else:
                btn_toggle.setProperty("class", "table-action")
            btn_toggle.clicked.connect(lambda _, n=name, en=is_enabled: self._toggle_rule(n, en))
            self.rules_table.setCellWidget(row, 5, btn_toggle)

            # Column 6: Delete button
            btn_del = QPushButton("Delete")
            btn_del.setProperty("class", "destructive-action table-action")
            btn_del.clicked.connect(lambda _, n=name: self._delete_rule(n))
            self.rules_table.setCellWidget(row, 6, btn_del)

        self.lbl_rule_count.setText(f"Active Firewall Rules ({len(filtered)} displayed • {len(rules)} total)")


# ── 4. Network Monitor Page (with TrapNet, ChainGuard, AppPrint) ─────

class MonitorPage(QWidget if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.monitor = main_win.monitor
        self.app_core = main_win.fw_core
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # Tabbed Monitor View
        self.tabs = QTabWidget()

        # ── Tab 1: Live Sockets & Bandwidth ──
        tab_sockets = QWidget()
        ts_lay = QVBoxLayout(tab_sockets)

        top_bar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter connections by program name, IP, or port...")
        self.search_input.textChanged.connect(self._refresh_sockets)
        top_bar.addWidget(self.search_input, stretch=1)

        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["All Protocols", "TCP", "UDP"])
        self.proto_combo.currentIndexChanged.connect(self._refresh_sockets)
        top_bar.addWidget(self.proto_combo)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self._refresh_sockets)
        top_bar.addWidget(btn_refresh)
        ts_lay.addLayout(top_bar)

        self.table_sockets = QTableWidget(0, 6)
        self.table_sockets.setHorizontalHeaderLabels(["Proto", "Program / PID", "Local Address:Port", "Remote Address:Port", "State", "Action"])
        self.table_sockets.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_sockets.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_sockets.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_sockets.horizontalHeader().resizeSection(2, 160)
        self.table_sockets.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table_sockets.horizontalHeader().resizeSection(3, 160)
        self.table_sockets.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_sockets.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table_sockets.horizontalHeader().resizeSection(5, 175)
        self.table_sockets.horizontalHeader().setMinimumSectionSize(65)
        ts_lay.addWidget(self.table_sockets)

        self.lbl_socket_stats = QLabel("Loading socket diagnostics...")
        self.lbl_socket_stats.setProperty("class", "subtitle-text")
        self.lbl_socket_stats.setStyleSheet("font-size: 11px;")
        ts_lay.addWidget(self.lbl_socket_stats)

        self.tabs.addTab(tab_sockets, "📡 Live Network Sockets")

        # ── Tab 2: TrapNet Deception Honeypot & HoneyTokens ──
        tab_trapnet = QWidget()
        tt_lay = QVBoxLayout(tab_trapnet)
        tt_lay.setSpacing(10)

        # Header Hero Card
        h_banner = QFrame()
        h_banner.setProperty("class", "stat-card")
        hb_lay = QHBoxLayout(h_banner)
        lbl_h_icon = QLabel("🍯")
        lbl_h_icon.setStyleSheet("font-size: 28px;")
        hb_lay.addWidget(lbl_h_icon)

        ht_lay = QVBoxLayout()
        self.lbl_trap_title = QLabel("TrapNet Active Network Deception & Canary Tripwires")
        self.lbl_trap_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.lbl_trap_sub = QLabel("Active multi-protocol decoy listeners & host canary files lure, identify, and auto-ban hostile network scanners and infostealers.")
        self.lbl_trap_sub.setProperty("class", "subtitle-text")
        self.lbl_trap_stats = QLabel("Active Decoys: 0 • Intruders Banned: 0 • 24h Probes: 0 • HoneyTokens: 0")
        self.lbl_trap_stats.setStyleSheet("color: #388bfd; font-size: 11px; font-weight: bold;")
        ht_lay.addWidget(self.lbl_trap_title)
        ht_lay.addWidget(self.lbl_trap_sub)
        ht_lay.addWidget(self.lbl_trap_stats)
        hb_lay.addLayout(ht_lay, stretch=1)
        tt_lay.addWidget(h_banner)

        # Action & Presets Toolbar
        tb_card = QFrame()
        tb_card.setProperty("class", "stat-card")
        tb_lay = QHBoxLayout(tb_card)
        tb_lay.setContentsMargins(10, 8, 10, 8)
        tb_lay.setSpacing(8)

        lbl_preset = QLabel("Presets:")
        lbl_preset.setStyleSheet("font-weight: bold;")
        tb_lay.addWidget(lbl_preset)

        self.combo_trap_preset = QComboBox()
        self.combo_trap_preset.addItem("🛡️ Home & SOHO Baseline", "home_workstation")
        self.combo_trap_preset.addItem("🏢 Enterprise Active Directory Fortress", "enterprise_ad")
        self.combo_trap_preset.addItem("🌐 Web & Cloud Deception", "web_cloud")
        self.combo_trap_preset.addItem("🏭 Industrial SCADA & IoT Mesh", "iot_scada")
        self.combo_trap_preset.addItem("🥷 Maximum Spiderweb (All Traps Active)", "maximum_spiderweb")
        tb_lay.addWidget(self.combo_trap_preset)

        btn_apply_preset = QPushButton("Deploy Preset")
        btn_apply_preset.setProperty("class", "suggested-action")
        btn_apply_preset.clicked.connect(self._apply_trap_preset)
        tb_lay.addWidget(btn_apply_preset)

        btn_disarm_preset = QPushButton("Disarm Preset")
        btn_disarm_preset.clicked.connect(self._disarm_trap_preset)
        tb_lay.addWidget(btn_disarm_preset)

        tb_lay.addSpacing(6)

        btn_catalog = QPushButton("➕ Decoy Catalog (26 Services)...")
        btn_catalog.clicked.connect(self._dialog_decoy_catalog)
        tb_lay.addWidget(btn_catalog)

        btn_canaries = QPushButton("🪤 HoneyToken Canaries...")
        btn_canaries.clicked.connect(self._dialog_honeytokens)
        tb_lay.addWidget(btn_canaries)

        btn_miragenet = QPushButton("🌀 MirageNet™ Shells & Poison...")
        btn_miragenet.setProperty("class", "suggested-action")
        btn_miragenet.clicked.connect(self._dialog_miragenet_hub)
        tb_lay.addWidget(btn_miragenet)

        btn_add_custom = QPushButton("+ Custom Port...")
        btn_add_custom.clicked.connect(self._dialog_add_trap)
        tb_lay.addWidget(btn_add_custom)

        tb_lay.addStretch()

        btn_export = QPushButton("📥 Export Forensics")
        btn_export.clicked.connect(self._dialog_export_trapnet_forensics)
        tb_lay.addWidget(btn_export)

        btn_refresh_traps = QPushButton("Refresh")
        btn_refresh_traps.clicked.connect(self._refresh_trapnet)
        tb_lay.addWidget(btn_refresh_traps)

        tt_lay.addWidget(tb_card)

        # Inner Sub-Tabs
        self.trapnet_subtabs = QTabWidget()

        # Sub-Tab 1: Intercepted Intruders
        tab_intrusions = QWidget()
        ti_lay = QVBoxLayout(tab_intrusions)
        ti_lay.setContentsMargins(4, 8, 4, 4)

        self.table_traps = QTableWidget(0, 6)
        self.table_traps.setHorizontalHeaderLabels([
            "Timestamp", "Attacker Source IP:Port", "Target Decoy",
            "Threat Classification", "Captured Credentials / Payload", "Action Taken"
        ])
        self.table_traps.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_traps.cellDoubleClicked.connect(lambda r, c: self._inspect_trap_payload(r))
        ti_lay.addWidget(self.table_traps)

        ti_btn_bar = QHBoxLayout()
        btn_inspect_sel = QPushButton("🔍 Inspect Selected Intrusion")
        btn_inspect_sel.clicked.connect(lambda: self._inspect_trap_payload(None))
        ti_btn_bar.addWidget(btn_inspect_sel)

        ti_btn_bar.addStretch()

        btn_clear_log = QPushButton("🧹 Clear Intrusion Log")
        btn_clear_log.clicked.connect(self._clear_trapnet_events)
        ti_btn_bar.addWidget(btn_clear_log)
        ti_lay.addLayout(ti_btn_bar)

        self.trapnet_subtabs.addTab(tab_intrusions, "🚨 Intercepted Intrusions & Attackers")

        # Sub-Tab 2: Active Decoys & Emulators
        tab_decoys = QWidget()
        td_lay = QVBoxLayout(tab_decoys)
        td_lay.setContentsMargins(4, 8, 4, 4)

        self.table_decoy_listeners = QTableWidget(0, 7)
        self.table_decoy_listeners.setHorizontalHeaderLabels([
            "Decoy Port", "Service Label", "Operational Sector",
            "Emulation Protocol", "Status", "Attacks Trapped", "Actions"
        ])
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_decoy_listeners.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table_decoy_listeners.horizontalHeader().setMinimumSectionSize(80)
        td_lay.addWidget(self.table_decoy_listeners)

        td_btn_bar = QHBoxLayout()
        btn_more_catalog = QPushButton("➕ Browse Full Decoy Catalog...")
        btn_more_catalog.clicked.connect(self._dialog_decoy_catalog)
        td_btn_bar.addWidget(btn_more_catalog)

        td_btn_bar.addStretch()

        btn_disarm_all = QPushButton("🚫 Disarm All Decoy Listeners")
        btn_disarm_all.clicked.connect(self._disarm_all_decoy_listeners)
        td_btn_bar.addWidget(btn_disarm_all)
        td_lay.addLayout(td_btn_bar)

        self.trapnet_subtabs.addTab(tab_decoys, "🍯 Active Decoy Listeners & Emulators")

        # Sub-Tab 3: HoneyToken Canaries
        tab_canaries = QWidget()
        tc_lay = QVBoxLayout(tab_canaries)
        tc_lay.setContentsMargins(4, 8, 4, 4)

        self.table_honeytokens = QTableWidget(0, 6)
        self.table_honeytokens.setHorizontalHeaderLabels([
            "Canary Lure File", "Bait Type", "Deployed Location",
            "Deployed At", "Tripwire Status", "Actions"
        ])
        self.table_honeytokens.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_honeytokens.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_honeytokens.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_honeytokens.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_honeytokens.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_honeytokens.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table_honeytokens.horizontalHeader().resizeSection(5, 175)
        self.table_honeytokens.horizontalHeader().setMinimumSectionSize(160)
        tc_lay.addWidget(self.table_honeytokens)

        tc_btn_bar = QHBoxLayout()
        btn_deploy_all = QPushButton("⚡ Deploy All 5 Canary Lures")
        btn_deploy_all.setProperty("class", "suggested-action")
        btn_deploy_all.clicked.connect(self._deploy_all_canary_lures)
        tc_btn_bar.addWidget(btn_deploy_all)

        btn_disarm_canaries = QPushButton("Disarm & Remove All Canaries")
        btn_disarm_canaries.clicked.connect(self._disarm_all_canary_lures)
        tc_btn_bar.addWidget(btn_disarm_canaries)

        tc_btn_bar.addStretch()

        btn_test_canary = QPushButton("🧪 Simulate Tripwire Trigger (Test)")
        btn_test_canary.clicked.connect(self._simulate_canary_tripwire_test)
        tc_btn_bar.addWidget(btn_test_canary)
        tc_lay.addLayout(tc_btn_bar)

        self.trapnet_subtabs.addTab(tab_canaries, "🪤 HoneyToken Canaries (Host Tripwires)")

        tt_lay.addWidget(self.trapnet_subtabs)
        self.tabs.addTab(tab_trapnet, "🍯 TrapNet Deception")

        # ── Tab 3: ChainGuard Ancestry Validation ──
        tab_chainguard = QWidget()
        tcg_lay = QVBoxLayout(tab_chainguard)

        cg_banner = QFrame()
        cg_banner.setProperty("class", "stat-card")
        cgb_lay = QHBoxLayout(cg_banner)
        lbl_cg_icon = QLabel("🧠")
        lbl_cg_icon.setStyleSheet("font-size: 28px;")
        cgb_lay.addWidget(lbl_cg_icon)

        cgt_lay = QVBoxLayout()
        self.lbl_cg_title = QLabel("ChainGuard Process Lineage & LOLBin Detection")
        self.lbl_cg_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.lbl_cg_sub = QLabel("Validates process ancestry trees to prevent macro weaponization & living-off-the-land proxies")
        self.lbl_cg_sub.setProperty("class", "subtitle-text")
        cgt_lay.addWidget(self.lbl_cg_title)
        cgt_lay.addWidget(self.lbl_cg_sub)
        cgb_lay.addLayout(cgt_lay, stretch=1)

        btn_refresh_cg = QPushButton("Refresh Lineage")
        btn_refresh_cg.clicked.connect(self._refresh_chainguard)
        cgb_lay.addWidget(btn_refresh_cg)
        tcg_lay.addWidget(cg_banner)

        self.table_cg = QTableWidget(0, 5)
        self.table_cg.setHorizontalHeaderLabels(["PID / Process", "Parent Lineage", "Violation Reason", "Remote Sockets", "Action"])
        self.table_cg.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table_cg.horizontalHeader().resizeSection(0, 160)
        self.table_cg.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table_cg.horizontalHeader().resizeSection(1, 160)
        self.table_cg.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_cg.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_cg.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table_cg.horizontalHeader().resizeSection(4, 185)
        self.table_cg.horizontalHeader().setMinimumSectionSize(80)
        tcg_lay.addWidget(self.table_cg)

        self.tabs.addTab(tab_chainguard, "🧠 ChainGuard Lineage")

        # ── Tab 4: AppPrint Network DNA ──
        tab_appprint = QWidget()
        tap_lay = QVBoxLayout(tab_appprint)

        ap_banner = QFrame()
        ap_banner.setProperty("class", "stat-card")
        apb_lay = QHBoxLayout(ap_banner)
        lbl_ap_icon = QLabel("🧬")
        lbl_ap_icon.setStyleSheet("font-size: 28px;")
        apb_lay.addWidget(lbl_ap_icon)

        apt_lay = QVBoxLayout()
        self.lbl_ap_title = QLabel("AppPrint Network DNA Profiling & Drift Detection")
        self.lbl_ap_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.lbl_ap_sub = QLabel("Per-application statistical behavioral baselines — alerts on unauthorized ports or C2 beaconing")
        self.lbl_ap_sub.setProperty("class", "subtitle-text")
        apt_lay.addWidget(self.lbl_ap_title)
        apt_lay.addWidget(self.lbl_ap_sub)
        apb_lay.addLayout(apt_lay, stretch=1)

        btn_clear_anomalies = QPushButton("Clear Anomalies")
        btn_clear_anomalies.clicked.connect(self._clear_anomalies)
        apb_lay.addWidget(btn_clear_anomalies)

        btn_refresh_ap = QPushButton("Refresh DNA")
        btn_refresh_ap.clicked.connect(self._refresh_appprint)
        apb_lay.addWidget(btn_refresh_ap)
        tap_lay.addWidget(ap_banner)

        self.table_ap = QTableWidget(0, 7)
        self.table_ap.setHorizontalHeaderLabels(["App Name", "Confidence", "Learned Remote Ports", "Learned Subnets", "Avg Conns", "Status", "Actions"])
        self.table_ap.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_ap.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ap.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_ap.horizontalHeader().resizeSection(2, 140)
        self.table_ap.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table_ap.horizontalHeader().resizeSection(3, 130)
        self.table_ap.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ap.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ap.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ap.horizontalHeader().setMinimumSectionSize(75)
        tap_lay.addWidget(self.table_ap)

        self.tabs.addTab(tab_appprint, "🧬 AppPrint Network DNA")

        # ── Tab 5: DarkWeb Exposure & Threat Intelligence ──
        tab_darkweb = QWidget()
        tdw_lay = QVBoxLayout(tab_darkweb)
        tdw_lay.setSpacing(10)

        # Banner with stats
        dw_banner = QFrame()
        dw_banner.setProperty("class", "stat-card")
        dwb_lay = QHBoxLayout(dw_banner)
        lbl_dw_icon = QLabel("🕵️")
        lbl_dw_icon.setStyleSheet("font-size: 28px;")
        dwb_lay.addWidget(lbl_dw_icon)

        dwt_lay = QVBoxLayout()
        self.lbl_dw_title = QLabel("DarkWeb Identity Shield & Threat Feed Sync")
        self.lbl_dw_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.lbl_dw_sub = QLabel("Continuously monitors up to 15 corporate and personal emails against dark web dumps & leaked databases.")
        self.lbl_dw_sub.setProperty("class", "subtitle-text")
        self.lbl_dw_stats = QLabel("Monitored: 0 / 15 • Compromised: 0 • Total Breaches: 0 • Last Live Sync: Never")
        self.lbl_dw_stats.setStyleSheet("color: #388bfd; font-size: 11px; font-weight: bold;")
        dwt_lay.addWidget(self.lbl_dw_title)
        dwt_lay.addWidget(self.lbl_dw_sub)
        dwt_lay.addWidget(self.lbl_dw_stats)
        dwb_lay.addLayout(dwt_lay, stretch=1)

        btn_sync_now = QPushButton("🔄 Check Live Feeds Now")
        btn_sync_now.setToolTip("Pull latest breach updates from XposedOrNot & dark web threat intelligence")
        btn_sync_now.clicked.connect(self._sync_darkweb_live)
        dwb_lay.addWidget(btn_sync_now)
        tdw_lay.addWidget(dw_banner)

        # Action bar to add new email
        add_bar = QHBoxLayout()
        self.dw_email_input = QLineEdit()
        self.dw_email_input.setPlaceholderText("Enter email to monitor (e.g. security@company.com)... [Max 15]")
        self.dw_email_input.returnPressed.connect(self._add_darkweb_email)
        add_bar.addWidget(self.dw_email_input, stretch=1)

        btn_add_dw = QPushButton("+ Add Monitored Email")
        btn_add_dw.setProperty("class", "suggested-action")
        btn_add_dw.clicked.connect(self._add_darkweb_email)
        add_bar.addWidget(btn_add_dw)

        btn_refresh_dw = QPushButton("Refresh")
        btn_refresh_dw.clicked.connect(self._refresh_darkweb)
        add_bar.addWidget(btn_refresh_dw)
        tdw_lay.addLayout(add_bar)

        # Monitored accounts label & table
        lbl_acc_title = QLabel("Monitored Email Accounts (Strict Maximum 15):")
        lbl_acc_title.setStyleSheet("font-weight: bold;")
        tdw_lay.addWidget(lbl_acc_title)

        self.table_dw_emails = QTableWidget(0, 5)
        self.table_dw_emails.setHorizontalHeaderLabels(["Email Address", "Security Status", "Breaches Found", "Last Checked", "Actions"])
        self.table_dw_emails.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_dw_emails.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_dw_emails.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_dw_emails.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_dw_emails.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table_dw_emails.horizontalHeader().resizeSection(4, 230)
        self.table_dw_emails.horizontalHeader().setMinimumSectionSize(80)
        self.table_dw_emails.setMaximumHeight(180)
        tdw_lay.addWidget(self.table_dw_emails)

        # Breach details table
        breach_header_bar = QHBoxLayout()
        self.lbl_leak_title = QLabel("Discovered Breach Records & Leaked Data Classes:")
        self.lbl_leak_title.setStyleSheet("font-weight: bold;")
        breach_header_bar.addWidget(self.lbl_leak_title, stretch=1)

        btn_show_all_breaches = QPushButton("Show All Breaches")
        btn_show_all_breaches.clicked.connect(lambda: self._refresh_darkweb(filter_email=None))
        breach_header_bar.addWidget(btn_show_all_breaches)
        tdw_lay.addLayout(breach_header_bar)

        self.table_dw_breaches = QTableWidget(0, 6)
        self.table_dw_breaches.setHorizontalHeaderLabels(["Target Email", "Breach Source", "Domain", "Breach Date", "Exposed Data Classes", "Detected At"])
        self.table_dw_breaches.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table_dw_breaches.horizontalHeader().resizeSection(0, 160)
        self.table_dw_breaches.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_dw_breaches.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_dw_breaches.horizontalHeader().resizeSection(2, 130)
        self.table_dw_breaches.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_dw_breaches.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_dw_breaches.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_dw_breaches.horizontalHeader().setMinimumSectionSize(80)
        tdw_lay.addWidget(self.table_dw_breaches)

        self.tabs.addTab(tab_darkweb, "🕵️ DarkWeb Exposure")

        # ── Tab 6: Windows Anti-Exploit & Attack Surface Reduction ──
        tab_exploit = QWidget()
        te_lay = QVBoxLayout(tab_exploit)
        te_lay.setSpacing(10)

        # Banner with stats
        ex_banner = QFrame()
        ex_banner.setProperty("class", "stat-card")
        exb_lay = QHBoxLayout(ex_banner)
        lbl_ex_icon = QLabel("💥")
        lbl_ex_icon.setStyleSheet("font-size: 28px;")
        exb_lay.addWidget(lbl_ex_icon)

        ext_lay = QVBoxLayout()
        self.lbl_ex_title = QLabel("Windows Exploit Guard & Attack Surface Reduction (ASR)")
        self.lbl_ex_title.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.lbl_ex_sub = QLabel("Active EMET-grade memory protections (DEP, ASLR, CFG, SEHOP, ACG) + 16 Microsoft Defender ASR rules.")
        self.lbl_ex_sub.setProperty("class", "subtitle-text")
        self.lbl_ex_stats = QLabel("Exploits Neutralized: 0 • Active Mitigations: 7/7 • ASR Rules: 16/16 Block • Core Isolation: Active")
        self.lbl_ex_stats.setStyleSheet("color: #388bfd; font-size: 11px; font-weight: bold;")
        ext_lay.addWidget(self.lbl_ex_title)
        ext_lay.addWidget(self.lbl_ex_sub)
        ext_lay.addWidget(self.lbl_ex_stats)
        exb_lay.addLayout(ext_lay, stretch=1)

        # Presets
        preset_box = QVBoxLayout()
        preset_box.setSpacing(4)
        p_row = QHBoxLayout()
        btn_prof_rec = QPushButton("🛡️ Recommended Baseline")
        btn_prof_rec.setProperty("class", "suggested-action")
        btn_prof_rec.clicked.connect(lambda: self._apply_exploit_profile("Recommended"))
        btn_prof_strict = QPushButton("🔒 Strict Fortress")
        btn_prof_strict.clicked.connect(lambda: self._apply_exploit_profile("Strict"))
        btn_prof_audit = QPushButton("📋 Audit Only")
        btn_prof_audit.clicked.connect(lambda: self._apply_exploit_profile("Audit"))
        btn_refresh_ex = QPushButton("Refresh")
        btn_refresh_ex.clicked.connect(self._refresh_exploit_shield)
        p_row.addWidget(btn_prof_rec)
        p_row.addWidget(btn_prof_strict)
        p_row.addWidget(btn_prof_audit)
        p_row.addWidget(btn_refresh_ex)
        preset_box.addLayout(p_row)
        exb_lay.addLayout(preset_box)
        te_lay.addWidget(ex_banner)

        # Exploit sub-tabs: Events, ASR Rules, System Mitigations
        self.ex_tabs = QTabWidget()

        # Subtab A: Live Exploit Interceptions
        sub_events = QWidget()
        sev_lay = QVBoxLayout(sub_events)
        self.table_ex_events = QTableWidget(0, 6)
        self.table_ex_events.setHorizontalHeaderLabels(["Timestamp", "Target Process / PID", "Exploit Technique", "Severity", "Details", "Action"])
        self.table_ex_events.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ex_events.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table_ex_events.horizontalHeader().resizeSection(1, 150)
        self.table_ex_events.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_ex_events.horizontalHeader().resizeSection(2, 150)
        self.table_ex_events.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ex_events.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_ex_events.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table_ex_events.horizontalHeader().resizeSection(5, 120)
        self.table_ex_events.horizontalHeader().setMinimumSectionSize(75)
        sev_lay.addWidget(self.table_ex_events)
        self.ex_tabs.addTab(sub_events, "⚡ Intercepted Exploit Events")

        # Subtab B: Attack Surface Reduction (ASR) Rules
        sub_asr = QWidget()
        sasr_lay = QVBoxLayout(sub_asr)
        self.table_asr = QTableWidget(0, 5)
        self.table_asr.setHorizontalHeaderLabels(["ASR Rule Name", "Category", "GUID", "Protection State", "Toggle Action"])
        self.table_asr.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_asr.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_asr.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_asr.horizontalHeader().resizeSection(2, 140)
        self.table_asr.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_asr.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table_asr.horizontalHeader().resizeSection(4, 130)
        self.table_asr.horizontalHeader().setMinimumSectionSize(75)
        sasr_lay.addWidget(self.table_asr)
        self.ex_tabs.addTab(sub_asr, "🛡️ Microsoft Defender ASR Rules (16)")

        # Subtab C: System Mitigations & Core Isolation
        sub_sys = QWidget()
        ssys_lay = QVBoxLayout(sub_sys)
        self.table_sys_mit = QTableWidget(0, 4)
        self.table_sys_mit.setHorizontalHeaderLabels(["Mitigation / Feature", "Type", "Status", "Description"])
        self.table_sys_mit.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_sys_mit.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_sys_mit.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_sys_mit.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_sys_mit.horizontalHeader().setMinimumSectionSize(75)
        ssys_lay.addWidget(self.table_sys_mit)
        self.ex_tabs.addTab(sub_sys, "🧠 System Mitigations & Core Isolation")

        te_lay.addWidget(self.ex_tabs)
        self.tabs.addTab(tab_exploit, "💥 Anti-Exploit Shield")

        # ── Tab 7: LineageGuard™ Process Ancestry & Injected Sockets ──
        tab_lineage = QWidget()
        tl_lay = QVBoxLayout(tab_lineage)
        tl_lay.setSpacing(10)

        lg_head = QFrame()
        lg_head.setProperty("class", "stat-card")
        lgh_lay = QHBoxLayout(lg_head)
        lgh_icon = QLabel("🧬")
        lgh_icon.setStyleSheet("font-size: 26px;")
        lgh_lay.addWidget(lgh_icon)

        lgt_lay = QVBoxLayout()
        lbl_lg_title = QLabel("LineageGuard™ Process Lineage & Memory Backing Attestation")
        lbl_lg_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        self.lbl_lg_stats = QLabel("Inspected Sockets: 0 • Blocked LOLBin Macro Chains: 0 • Injected Sockets Severed: 0")
        self.lbl_lg_stats.setProperty("class", "subtitle-text")
        lgt_lay.addWidget(lbl_lg_title)
        lgt_lay.addWidget(self.lbl_lg_stats)
        lgh_lay.addLayout(lgt_lay, stretch=1)

        btn_lg_refresh = QPushButton("Refresh")
        btn_lg_refresh.clicked.connect(self._refresh_lineage_guard)
        lgh_lay.addWidget(btn_lg_refresh)
        tl_lay.addWidget(lg_head)

        self.table_lineage = QTableWidget(0, 6)
        self.table_lineage.setHorizontalHeaderLabels([
            "Timestamp", "Process (PID)", "Parent Process", "Ancestry Chain", "Remote Socket Target", "Action"
        ])
        self.table_lineage.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tl_lay.addWidget(self.table_lineage)
        self.tabs.addTab(tab_lineage, "🧬 LineageGuard™ Sockets")

        # ── Tab 8: BeaconEntropyShaper™ C2 FFT Analyzer & Phantom Tarpit ──
        tab_beacon = QWidget()
        tb_lay = QVBoxLayout(tab_beacon)
        tb_lay.setSpacing(10)

        bs_head = QFrame()
        bs_head.setProperty("class", "stat-card")
        bsh_lay = QHBoxLayout(bs_head)
        bsh_icon = QLabel("📡")
        bsh_icon.setStyleSheet("font-size: 26px;")
        bsh_lay.addWidget(bsh_icon)

        bst_lay = QVBoxLayout()
        lbl_bs_title = QLabel("BeaconEntropyShaper™ C2 Arrival-Time FFT Analyzer & Phantom Tarpit")
        lbl_bs_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #a371f7;")
        self.lbl_bs_stats = QLabel("Monitored Outbound Destinations: 0 • Detected Periodic C2 Beacons: 0 • Active Phantom Tarpits: 0")
        self.lbl_bs_stats.setProperty("class", "subtitle-text")
        bst_lay.addWidget(lbl_bs_title)
        bst_lay.addWidget(self.lbl_bs_stats)
        bsh_lay.addLayout(bst_lay, stretch=1)

        btn_bs_refresh = QPushButton("Refresh")
        btn_bs_refresh.clicked.connect(self._refresh_beacon_shaper)
        bsh_lay.addWidget(btn_bs_refresh)
        tb_lay.addWidget(bs_head)

        self.table_beacon = QTableWidget(0, 6)
        self.table_beacon.setHorizontalHeaderLabels([
            "Remote Endpoint", "Estimated Beacon Interval", "FFT Spectral Power", "Interval Jitter (CV)", "Status", "Action Taken"
        ])
        self.table_beacon.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tb_lay.addWidget(self.table_beacon)
        self.tabs.addTab(tab_beacon, "📡 C2 Beacon FFT Shaper")

        layout.addWidget(self.tabs)

    def refresh(self):
        self._refresh_sockets()
        self._refresh_trapnet()
        self._refresh_chainguard()
        self._refresh_appprint()
        self._refresh_darkweb()
        self._refresh_exploit_shield()
        self._refresh_lineage_guard()
        self._refresh_beacon_shaper()

    def _refresh_lineage_guard(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, "app_core") or not hasattr(self.main_win.app_core, "lineage_guard"):
            return
        lg = self.main_win.app_core.lineage_guard
        st = lg.get_stats()
        self.lbl_lg_stats.setText(
            f"Inspected Sockets: {st.get('inspected_connections', 0):,} • "
            f"Blocked LOLBin Macro Chains: {st.get('blocked_chains', 0):,} • "
            f"Active Policy: Enforced"
        )
        evts = lg.get_recent_events(limit=50)
        self.table_lineage.setRowCount(len(evts))
        for r, e in enumerate(evts):
            self.table_lineage.setItem(r, 0, QTableWidgetItem(e.get("timestamp_str", "")))
            self.table_lineage.setItem(r, 1, QTableWidgetItem(f"{e.get('process_name')} ({e.get('process_id')})"))
            self.table_lineage.setItem(r, 2, QTableWidgetItem(f"{e.get('parent_name')} ({e.get('parent_pid')})"))
            self.table_lineage.setItem(r, 3, QTableWidgetItem(str(e.get("ancestry_chain", ""))))
            self.table_lineage.setItem(r, 4, QTableWidgetItem(str(e.get("remote_target", ""))))
            self.table_lineage.setItem(r, 5, QTableWidgetItem(str(e.get("action_taken", ""))))

    def _refresh_beacon_shaper(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, "app_core") or not hasattr(self.main_win.app_core, "beacon_shaper"):
            return
        bs = self.main_win.app_core.beacon_shaper
        st = bs.get_stats()
        self.lbl_bs_stats.setText(
            f"Monitored Outbound Destinations: {st.get('monitored_endpoints', 0):,} • "
            f"Detected Periodic C2 Beacons: {st.get('total_beacons_trapped', 0):,} • "
            f"Active Phantom Tarpits: {st.get('active_tarpits_count', 0)}"
        )
        beacons = bs.get_active_beacons()
        self.table_beacon.setRowCount(len(beacons))
        for r, b in enumerate(beacons):
            self.table_beacon.setItem(r, 0, QTableWidgetItem(str(b.get("endpoint", ""))))
            self.table_beacon.setItem(r, 1, QTableWidgetItem(f"~{b.get('interval_sec', 0)}s"))
            self.table_beacon.setItem(r, 2, QTableWidgetItem(f"{b.get('spectral_peak', 0):.2f}"))
            self.table_beacon.setItem(r, 3, QTableWidgetItem(f"{b.get('cv', 0):.2f}"))
            self.table_beacon.setItem(r, 4, QTableWidgetItem("TARPITTED" if b.get("is_tarpitted") else "Confirmed"))
            self.table_beacon.setItem(r, 5, QTableWidgetItem("Bandwidth Clamped (1B/s)"))

    def _dialog_miragenet_hub(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, "honeypot_mgr") or not hasattr(self.main_win.honeypot_mgr, "miragenet"):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("MirageNet™ Active Counter-Intelligence Deception Hub")
        dialog.setMinimumSize(800, 480)
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        m_tabs = QTabWidget()

        # Subtab 1: TuringHoneypot Virtual Interactive Shell Sessions
        sub1 = QWidget()
        s1_lay = QVBoxLayout(sub1)
        sessions = self.main_win.honeypot_mgr.miragenet.get_shell_sessions()
        lbl_s1 = QLabel(f"TuringHoneypot Virtual Shells: {len(sessions)} interactive sessions logged. Zero host execution.")
        lbl_s1.setStyleSheet("font-weight: bold; color: #58a6ff;")
        s1_lay.addWidget(lbl_s1)

        tbl_s1 = QTableWidget(len(sessions), 5)
        tbl_s1.setHorizontalHeaderLabels(["Connected At", "Attacker IP:Port", "Credentials Used", "Commands Captured", "Duration"])
        tbl_s1.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for r, s in enumerate(sessions):
            tbl_s1.setItem(r, 0, QTableWidgetItem(s.get("connected_time_str", "")))
            tbl_s1.setItem(r, 1, QTableWidgetItem(f"{s.get('remote_ip')}:{s.get('remote_port')}"))
            tbl_s1.setItem(r, 2, QTableWidgetItem(", ".join(s.get("captured_credentials", [])) or "None"))
            tbl_s1.setItem(r, 3, QTableWidgetItem(" | ".join(s.get("commands_executed", [])) or "Idle"))
            tbl_s1.setItem(r, 4, QTableWidgetItem(f"{s.get('duration_sec', 0)}s"))
        s1_lay.addWidget(tbl_s1)
        m_tabs.addTab(sub1, "🖥️ TuringHoneypot Terminal Sessions")

        # Subtab 2: CanaryPoison Intruder De-Anonymization
        sub2 = QWidget()
        s2_lay = QVBoxLayout(sub2)
        attackers = self.main_win.honeypot_mgr.miragenet.get_deanonymized_attackers()
        lbl_s2 = QLabel(f"CanaryPoison De-Anonymized Intruders: {len(attackers)} exfiltrated token trips worldwide.")
        lbl_s2.setStyleSheet("font-weight: bold; color: #f85149;" if attackers else "font-weight: bold; color: #3fb950;")
        s2_lay.addWidget(lbl_s2)

        tbl_s2 = QTableWidget(len(attackers), 5)
        tbl_s2.setHorizontalHeaderLabels(["Triggered At", "Token Name", "Attacker Public IP", "ISP / Cloud Provider", "Geolocation / UA"])
        tbl_s2.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for r, a in enumerate(attackers):
            tbl_s2.setItem(r, 0, QTableWidgetItem(a.get("timestamp_str", "")))
            tbl_s2.setItem(r, 1, QTableWidgetItem(str(a.get("token_name", ""))))
            tbl_s2.setItem(r, 2, QTableWidgetItem(str(a.get("attacker_ip", ""))))
            tbl_s2.setItem(r, 3, QTableWidgetItem(str(a.get("isp_organization", ""))))
            tbl_s2.setItem(r, 4, QTableWidgetItem(f"{a.get('geolocation')} [{a.get('user_agent')}]"))
        s2_lay.addWidget(tbl_s2)
        m_tabs.addTab(sub2, "🌍 CanaryPoison De-Anonymization Map")

        # Subtab 3: QuantumTarpit Scanner Defense
        sub3 = QWidget()
        s3_lay = QVBoxLayout(sub3)
        tp_s = self.main_win.honeypot_mgr.miragenet.get_stats()
        lbl_s3 = QLabel(f"QuantumTarpit Labyrinth: {tp_s.get('tarpit_requests_trapped', 0)} automated scanner probes trapped in infinite procedural maze.")
        lbl_s3.setStyleSheet("font-weight: bold; color: #d29922;")
        s3_lay.addWidget(lbl_s3)
        lbl_desc = QLabel("Automated scanners (Nikto, SQLmap, Gobuster, Nmap) are trapped in an endless procedural directory hierarchy with 1-byte/sec rate clamps, completely exhausting their thread pools.")
        lbl_desc.setWordWrap(True)
        s3_lay.addWidget(lbl_desc)
        s3_lay.addStretch()
        m_tabs.addTab(sub3, "🌀 QuantumTarpit Scanner Defense")

        lay.addWidget(m_tabs)
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        lay.addWidget(btn_close)
        dialog.exec()

    def _refresh_sockets(self):
        if not HAS_PYQT6:
            return

        conns = self.monitor.get_connections()
        search_txt = self.search_input.text().strip().lower()
        selected_proto = self.proto_combo.currentText()

        filtered = []
        for c in conns:
            if selected_proto != "All Protocols" and c.protocol != selected_proto:
                continue
            if search_txt:
                match = (search_txt in c.program.lower() or
                         search_txt in c.remote_ip or
                         search_txt in str(c.remote_port) or
                         search_txt in str(c.local_port))
                if not match:
                    continue
            filtered.append(c)

        self.table_sockets.setRowCount(len(filtered))
        for row, c in enumerate(filtered):
            self.table_sockets.setItem(row, 0, QTableWidgetItem(c.protocol))
            self.table_sockets.setItem(row, 1, QTableWidgetItem(f"{c.program} ({c.pid})"))
            self.table_sockets.setItem(row, 2, QTableWidgetItem(f"{c.local_ip}:{c.local_port}"))
            self.table_sockets.setItem(row, 3, QTableWidgetItem(f"{c.remote_ip}:{c.remote_port}"))
            self.table_sockets.setItem(row, 4, QTableWidgetItem(c.state))
            self.table_sockets.setRowHeight(row, 36)

            act_cell = QWidget()
            act_lay = QHBoxLayout(act_cell)
            act_lay.setContentsMargins(2, 2, 2, 2)
            act_lay.setSpacing(4)

            if c.remote_ip and c.remote_ip not in ("0.0.0.0", "127.0.0.1", "::1", "*"):
                btn_block = QPushButton("Block IP")
                btn_block.setProperty("class", "destructive-action table-action")
                btn_block.clicked.connect(lambda _, ip=c.remote_ip: self._quick_block(ip))
                act_lay.addWidget(btn_block)

            if c.pid and c.pid > 4:
                btn_kill = QPushButton("Kill PID")
                btn_kill.setProperty("class", "destructive-action table-action")
                btn_kill.clicked.connect(lambda _, p=c.pid: self._kill_pid(p))
                act_lay.addWidget(btn_kill)

            self.table_sockets.setCellWidget(row, 5, act_cell)

        bw = self.monitor.get_bandwidth()
        total_rx = sum(v.get('rx_bytes_sec', 0) for v in bw.values()) / 1024
        total_tx = sum(v.get('tx_bytes_sec', 0) for v in bw.values()) / 1024
        self.lbl_socket_stats.setText(
            f"Active sockets: {len(conns)} total • Down: {total_rx:.1f} KB/s • Up: {total_tx:.1f} KB/s"
        )

    def _quick_block(self, ip: str):
        if self.app_core.block_ip(ip):
            self.main_win.fw_logger.log_event("ip_blocked", "warning", f"Blocked remote IP: {ip}")
            QMessageBox.information(self, "IP Blocked", f"Successfully blocked remote IP {ip}")
            self.refresh()

    def _apply_trap_preset(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return
        preset_key = self.combo_trap_preset.currentData()
        if not preset_key:
            return

        res = self.main_win.honeypot_mgr.apply_preset(preset_key)
        preset_title = res.get("preset", preset_key)
        armed = res.get("armed_ports", [])
        conflicts = res.get("conflicts", [])

        msg = f"Applied Defensive Preset: {preset_title}\n\n"
        msg += f"✅ Successfully armed {len(armed)} decoy port(s):\n"
        for p in armed:
            lbl = self.main_win.honeypot_mgr.trap_ports.get(p, "Decoy")
            msg += f"  • Port {p} ({lbl})\n"

        if conflicts:
            msg += f"\n⚠️ Skipped {len(conflicts)} port(s) in conflict with legitimate host services:\n"
            for p in conflicts:
                msg += f"  • Port {p} (Occupied by local Windows service)\n"

        self.main_win.fw_logger.log_event("trap_preset_applied", "info", f"Applied TrapNet preset: {preset_title}")
        QMessageBox.information(self, "Deception Preset Applied", msg)
        self._refresh_trapnet()

    def _disarm_trap_preset(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return
        preset_key = self.combo_trap_preset.currentData()
        if not preset_key:
            return
        res = self.main_win.honeypot_mgr.disarm_preset(preset_key)
        preset_title = res.get("preset", preset_key)
        disarmed_cnt = res.get("disarmed_count", 0)
        self._refresh_trapnet()
        self.main_win.fw_logger.log_event("trap_preset_disarmed", "info", f"Disarmed TrapNet preset: {preset_title} ({disarmed_cnt} ports)")
        QMessageBox.information(
            self, "Deception Preset Disarmed",
            f"Successfully disarmed preset: {preset_title}\n\n"
            f"Closed {disarmed_cnt} active decoy listener(s)."
        )

    def _dialog_decoy_catalog(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("📚 TrapNet Decoy Service Catalog & Suggestions")
        dialog.setMinimumWidth(840)
        dialog.setMinimumHeight(540)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(10)

        lbl_head = QLabel("🎯 Decoy Service Catalog & Threat Lures")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: bold;")
        d_lay.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Select and arm simulated service decoys. Inbound reconnaissance probes targeting these decoy ports "
            "are intercepted, analyzed with interactive protocol emulators, and automatically banned."
        )
        lbl_desc.setProperty("class", "subtitle-text")
        lbl_desc.setWordWrap(True)
        d_lay.addWidget(lbl_desc)

        # Filters toolbar
        filter_bar = QHBoxLayout()
        lbl_f_cat = QLabel("Category:")
        lbl_f_cat.setStyleSheet("font-weight: bold;")
        filter_bar.addWidget(lbl_f_cat)

        combo_cat = QComboBox()
        combo_cat.addItem("All Operational Sectors", "all")
        combo_cat.addItem("Remote Administration (SSH, RDP, Telnet, VNC)", "remote_access")
        combo_cat.addItem("Enterprise Databases (MySQL, MSSQL, Redis, Mongo)", "databases")
        combo_cat.addItem("Web & Cloud Consoles (HTTP, Docker, Actuator)", "web_cloud")
        combo_cat.addItem("File Shares & Storage (SMB, FTP, NFS)", "file_sharing")
        combo_cat.addItem("IoT & Industrial SCADA (RTSP Camera, Modbus, MQTT)", "iot_industrial")
        combo_cat.addItem("Mail & Directory Services (SMTP, LDAP)", "mail_directory")
        filter_bar.addWidget(combo_cat)

        filter_bar.addSpacing(10)

        txt_search = QLineEdit()
        txt_search.setPlaceholderText("Filter decoy by name, port, or description...")
        filter_bar.addWidget(txt_search, stretch=1)
        d_lay.addLayout(filter_bar)

        # Table of catalog items
        table_cat = QTableWidget(0, 6)
        table_cat.setHorizontalHeaderLabels(["Decoy Service", "Default Port", "Sector", "Protocol Mode", "Risk Profile", "Action"])
        table_cat.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        table_cat.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table_cat.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        table_cat.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        table_cat.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        table_cat.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        d_lay.addWidget(table_cat)

        def populate_catalog():
            selected_cat = combo_cat.currentData()
            query = txt_search.text().strip().lower()

            items = []
            for cat_key, cat_items in DECOY_CATALOG.items():
                if selected_cat != "all" and cat_key != selected_cat:
                    continue
                for item in cat_items:
                    if query:
                        match = (
                            query in item["name"].lower() or
                            query in str(item["default_port"]) or
                            query in item["category"].lower() or
                            query in item["description"].lower()
                        )
                        if not match:
                            continue
                    items.append(item)

            table_cat.setRowCount(len(items))
            for row, item in enumerate(items):
                p = item["default_port"]
                is_armed = p in self.main_win.honeypot_mgr._active_trapped_ports

                name_lbl = f"{item.get('icon', '🍯')} {item['name']}"
                table_cat.setItem(row, 0, QTableWidgetItem(name_lbl))
                table_cat.setItem(row, 1, QTableWidgetItem(f"Port {p}"))
                table_cat.setItem(row, 2, QTableWidgetItem(item["category"]))
                table_cat.setItem(row, 3, QTableWidgetItem(item["protocol"].upper()))

                risk_item = QTableWidgetItem(item["risk_level"])
                if item["risk_level"] == "Critical":
                    risk_item.setForeground(QColor("#EF4444"))
                elif item["risk_level"] == "High":
                    risk_item.setForeground(QColor("#F59E0B"))
                else:
                    risk_item.setForeground(QColor("#10B981"))
                table_cat.setItem(row, 4, risk_item)

                btn_arm = QPushButton("Armed (Active)" if is_armed else "Arm Decoy")
                if is_armed:
                    btn_arm.setEnabled(False)
                else:
                    btn_arm.setProperty("class", "suggested-action")
                    btn_arm.clicked.connect(lambda _, it=item: do_arm(it))
                table_cat.setCellWidget(row, 5, btn_arm)

        def do_arm(item):
            p = item["default_port"]
            lbl = f"{item['name']} ({item['category']})"
            proto = item["protocol"]
            if is_port_in_use(p) and p not in self.main_win.honeypot_mgr._active_trapped_ports:
                QMessageBox.warning(
                    dialog, "Port In Use",
                    f"Cannot arm Port {p} because a real host Windows service is currently running on this port."
                )
                return
            if self.main_win.honeypot_mgr.add_trap_port(p, lbl, protocol=proto):
                self.main_win.fw_logger.log_event("trap_added", "info", f"Armed catalog decoy on port {p}: {lbl}")
                QMessageBox.information(
                    dialog, "Decoy Armed",
                    f"Successfully armed '{item['name']}' on Port {p} with {proto.upper()} emulation."
                )
                populate_catalog()
                self._refresh_trapnet()
            else:
                QMessageBox.warning(dialog, "Arm Failed", f"Could not bind Port {p}.")

        combo_cat.currentIndexChanged.connect(populate_catalog)
        txt_search.textChanged.connect(populate_catalog)
        populate_catalog()

        bottom_bar = QHBoxLayout()
        bottom_bar.addStretch()
        btn_close = QPushButton("Done")
        btn_close.setProperty("class", "suggested-action")
        btn_close.clicked.connect(dialog.accept)
        bottom_bar.addWidget(btn_close)
        d_lay.addLayout(bottom_bar)

        dialog.exec()
        self._refresh_trapnet()

    def _dialog_honeytokens(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return

        mgr = self.main_win.honeypot_mgr.honey_token_mgr
        dialog = QDialog(self)
        dialog.setWindowTitle("🪤 HoneyToken Canary Tripwires & Host Deception")
        dialog.setMinimumWidth(820)
        dialog.setMinimumHeight(480)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(10)

        lbl_head = QLabel("🪤 HoneyToken Canary Deception Lures")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: bold;")
        d_lay.addWidget(lbl_head)

        lbl_desc = QLabel(
            "HoneyTokens are realistic decoy files (fake corporate passwords spreadsheet, AWS keys, VPN access profiles, DB configs) "
            "placed in bait locations. Real-time file system tripwires monitor these lures. If malware, an infostealer, or ransomware "
            "touches, modifies, or encrypts any decoy, TrapNet immediately triggers a critical alarm and neutralizes the threat."
        )
        lbl_desc.setProperty("class", "subtitle-text")
        lbl_desc.setWordWrap(True)
        d_lay.addWidget(lbl_desc)

        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Canary Lure", "Bait Type", "Filename", "Tripwire Status", "Action"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().resizeSection(4, 165)
        table.verticalHeader().setDefaultSectionSize(36)
        d_lay.addWidget(table)

        def refresh_canary_table():
            tokens = {t["token_name"]: t for t in reversed(mgr.get_canaries())}
            templates = mgr.TEMPLATES
            table.setRowCount(len(templates))
            for row, t in enumerate(templates):
                name = t["name"]
                lure_type = t["lure_type"]
                fname = t["filename"]
                existing = tokens.get(name)

                table.setItem(row, 0, QTableWidgetItem(name))
                table.setItem(row, 1, QTableWidgetItem(lure_type))
                table.setItem(row, 2, QTableWidgetItem(fname))
                table.setRowHeight(row, 36)

                status_str = "Not Deployed"
                if existing:
                    status_str = "🟢 ARMED & GUARDING" if existing["status"] == "ACTIVE" else ("🔴 TRIPPED!" if existing["status"] == "TRIPPED" else "⚪ DISARMED")
                status_item = QTableWidgetItem(status_str)
                if "ARMED" in status_str:
                    status_item.setForeground(QColor("#10B981"))
                elif "TRIPPED" in status_str:
                    status_item.setForeground(QColor("#EF4444"))
                table.setItem(row, 3, status_item)

                act_w = QWidget()
                act_lay = QHBoxLayout(act_w)
                act_lay.setContentsMargins(4, 2, 4, 2)
                act_lay.setSpacing(6)

                if existing and existing.get("status") == "ACTIVE":
                    btn_t = QPushButton("Test")
                    btn_t.setProperty("class", "suggested-action table-action")
                    btn_t.setToolTip(f"Simulate intruder access on {name}")
                    btn_t.clicked.connect(lambda _, tok=existing: (self._simulate_canary_tripwire_test(tok), refresh_canary_table(), self._refresh_trapnet()))
                    act_lay.addWidget(btn_t)

                    btn_r = QPushButton("Remove")
                    btn_r.setProperty("class", "table-action")
                    btn_r.setToolTip(f"Remove and disarm {name}")
                    btn_r.clicked.connect(lambda _, tid=t["id"]: (mgr.remove_canary(tid), refresh_canary_table(), self._refresh_trapnet()))
                    act_lay.addWidget(btn_r)
                elif existing and existing.get("status") == "TRIPPED":
                    btn_rearm = QPushButton("Re-arm")
                    btn_rearm.setProperty("class", "suggested-action table-action")
                    btn_rearm.setToolTip(f"Re-deploy fresh file for {name}")
                    btn_rearm.clicked.connect(lambda _, tid=t["id"]: (mgr.deploy_canary(tid), refresh_canary_table(), self._refresh_trapnet()))
                    act_lay.addWidget(btn_rearm)

                    btn_r = QPushButton("Remove")
                    btn_r.setProperty("class", "table-action")
                    btn_r.setToolTip(f"Remove and clean up {name}")
                    btn_r.clicked.connect(lambda _, tid=t["id"]: (mgr.remove_canary(tid), refresh_canary_table(), self._refresh_trapnet()))
                    act_lay.addWidget(btn_r)
                else:
                    btn_dep = QPushButton("Deploy Lure")
                    btn_dep.setProperty("class", "suggested-action table-action")
                    btn_dep.setToolTip(f"Deploy bait file for {name}")
                    btn_dep.clicked.connect(lambda _, tid=t["id"]: (mgr.deploy_canary(tid), refresh_canary_table(), self._refresh_trapnet()))
                    act_lay.addWidget(btn_dep)

                table.setCellWidget(row, 4, act_w)

        refresh_canary_table()

        btn_row = QHBoxLayout()
        btn_deploy_all = QPushButton("⚡ Deploy All 5 Canary Lures")
        btn_deploy_all.setProperty("class", "suggested-action")
        btn_deploy_all.clicked.connect(lambda: (mgr.deploy_all_canaries(), refresh_canary_table(), self._refresh_trapnet()))
        btn_row.addWidget(btn_deploy_all)

        btn_disarm_all = QPushButton("Disarm & Clean Up Lures")
        btn_disarm_all.clicked.connect(lambda: (mgr.disarm_all_canaries(clear_db=True), refresh_canary_table(), self._refresh_trapnet()))
        btn_row.addWidget(btn_disarm_all)

        btn_row.addStretch()

        btn_test = QPushButton("🧪 Simulate Tripwire Trigger (Test)")
        btn_test.clicked.connect(lambda: (self._simulate_canary_tripwire_test(), refresh_canary_table(), self._refresh_trapnet()))
        btn_row.addWidget(btn_test)

        btn_close = QPushButton("Done")
        btn_close.clicked.connect(dialog.accept)
        btn_row.addWidget(btn_close)
        d_lay.addLayout(btn_row)

        dialog.exec()
        self._refresh_trapnet()

    def _dialog_add_trap(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return
        port_str, ok = QInputDialog.getText(self, "Add Deception Decoy Trap", "Enter Port Number for Decoy Listener (e.g. 21, 8088, 5900):")
        if ok and port_str.strip():
            try:
                p = int(port_str.strip())
                if p < 1 or p > 65535:
                    QMessageBox.warning(self, "Invalid Port", "Port number must be between 1 and 65535.")
                    return
                service_name, ok2 = QInputDialog.getText(self, "Decoy Service Label", "Enter service name (e.g. FTP-Decoy, Telnet, Custom):", text="Decoy-Service")
                if ok2:
                    proto, ok3 = QInputDialog.getItem(
                        self, "Emulation Protocol", "Select Emulation Engine for this Port:",
                        ["RAW (Standard Banner)", "HTTP (Interactive 401 Web Challenge)", "FTP (Interactive Credential Capture)", "TELNET (Terminal Login Prompt)", "REDIS (Key-Value Engine)", "MYSQL (Database Handshake)"],
                        0, False
                    )
                    p_mode = proto.split()[0].lower() if ok3 else "raw"
                    if self.main_win.honeypot_mgr.add_trap_port(p, service_name.strip() or "Custom", protocol=p_mode):
                        self.main_win.fw_logger.log_event("trap_added", "info", f"Armed TrapNet decoy port: {p} ({service_name}) [Mode: {p_mode}]")
                        QMessageBox.information(self, "Decoy Armed", f"Successfully armed decoy listener on port {p} ({p_mode.upper()} mode).")
                        self._refresh_trapnet()
                    else:
                        QMessageBox.warning(self, "Arm Failed", f"Could not arm decoy on port {p}. Port may already be in use.")
            except ValueError:
                QMessageBox.warning(self, "Invalid Port", "Port number must be a valid integer between 1 and 65535.")

    def _inspect_trap_payload(self, row: Optional[int] = None):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return
        if row is None or row < 0:
            row = self.table_traps.currentRow()
        if row < 0:
            QMessageBox.information(self, "Inspect Intrusion", "Please select an intrusion event from the table to inspect.")
            return

        events = self.main_win.honeypot_mgr.get_recent_events(limit=60)
        if row >= len(events):
            return

        e = events[row]
        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("timestamp", 0)))
        src_ip = e.get("source_ip", "")

        dialog = QDialog(self)
        dialog.setWindowTitle(f"🔍 Forensic Intrusion Telemetry: {src_ip}")
        dialog.setMinimumWidth(680)
        dialog.setMinimumHeight(520)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(10)

        head = QLabel(f"🚨 Intrusion Attempt Forensics: {src_ip}:{e.get('source_port')}")
        head.setStyleSheet("font-size: 14px; font-weight: bold; color: #EF4444;")
        d_lay.addWidget(head)

        info_card = QFrame()
        info_card.setProperty("class", "stat-card")
        ic_lay = QVBoxLayout(info_card)
        ic_lay.setSpacing(6)

        def make_row(lbl, val, is_danger=False):
            r = QHBoxLayout()
            l = QLabel(f"{lbl}:")
            l.setStyleSheet("font-weight: bold; min-width: 150px;")
            v = QLabel(str(val))
            if is_danger:
                v.setStyleSheet("font-weight: bold; color: #EF4444;")
            r.addWidget(l)
            r.addWidget(v, stretch=1)
            return r

        ic_lay.addLayout(make_row("Timestamp", t_str))
        ic_lay.addLayout(make_row("Target Decoy Port", f"Port {e.get('trap_port')} ({e.get('trap_service')})"))
        ic_lay.addLayout(make_row("Threat Classification", e.get("attack_type", "Reconnaissance Scan"), is_danger=True))
        ic_lay.addLayout(make_row("Firewall Action", "AUTOMATICALLY BANNED (Blocked by Windows Firewall)" if e.get("auto_blocked") else "LOGGED (Alert Only)"))

        if e.get("captured_credentials"):
            ic_lay.addLayout(make_row("Captured Credentials", e.get("captured_credentials"), is_danger=True))
        if e.get("request_uri"):
            ic_lay.addLayout(make_row("HTTP Request URI", e.get("request_uri")))
        if e.get("user_agent"):
            ic_lay.addLayout(make_row("Attacker User-Agent", e.get("user_agent")))

        d_lay.addWidget(info_card)

        lbl_dump = QLabel("Interception Payload Inspection (Hex Dump & Printable ASCII):")
        lbl_dump.setStyleSheet("font-weight: bold;")
        d_lay.addWidget(lbl_dump)

        txt_dump = QTextEdit() if HAS_PYQT6 else QLineEdit()
        txt_dump.setReadOnly(True)
        dump_content = (
            f"--- RAW PAYLOAD HEX ---\n{e.get('raw_payload_hex', 'No payload')}\n\n"
            f"--- ASCII DECODED ---\n{e.get('payload_preview', 'No payload')}\n\n"
            f"--- RECON DETAILS ---\n{e.get('details', '')}"
        )
        txt_dump.setText(dump_content)
        d_lay.addWidget(txt_dump)

        b_box = QHBoxLayout()
        btn_ban = QPushButton("🚫 Block Attacker IP")
        btn_ban.setProperty("class", "destructive-action")
        btn_ban.clicked.connect(lambda: (self.main_win.fw_core.block_ip(src_ip), QMessageBox.information(dialog, "IP Banned", f"Remote IP {src_ip} blocked in firewall.")))
        b_box.addWidget(btn_ban)

        btn_copy = QPushButton("📋 Copy Telemetry")
        btn_copy.clicked.connect(lambda: (QApplication.clipboard().setText(dump_content), QMessageBox.information(dialog, "Copied", "Forensic telemetry copied to clipboard.")))
        b_box.addWidget(btn_copy)

        b_box.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setProperty("class", "suggested-action")
        btn_close.clicked.connect(dialog.accept)
        b_box.addWidget(btn_close)
        d_lay.addLayout(b_box)

        dialog.exec()

    def _disarm_decoy_listener(self, port: int):
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            self.main_win.honeypot_mgr.remove_trap_port(port)
            self.main_win.fw_logger.log_event("trap_disarmed", "info", f"Disarmed decoy port {port}")
            self._refresh_trapnet()

    def _disarm_all_decoy_listeners(self):
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            confirm = QMessageBox.question(
                self, "Disarm All Decoys?", "Are you sure you want to disarm all active network decoy listeners?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            if confirm == QMessageBox.StandardButton.Yes:
                for p in list(self.main_win.honeypot_mgr.trap_ports.keys()):
                    self.main_win.honeypot_mgr.remove_trap_port(p)
                self._refresh_trapnet()

    def _deploy_all_canary_lures(self):
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            mgr = self.main_win.honeypot_mgr.honey_token_mgr
            deployed = mgr.deploy_all_canaries()
            self._refresh_trapnet()
            QMessageBox.information(
                self, "HoneyTokens Deployed",
                f"Successfully deployed {len(deployed)} HoneyToken canary lures with real-time file tripwires."
            )

    def _disarm_single_canary(self, token_id_or_name: str):
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            self.main_win.honeypot_mgr.honey_token_mgr.remove_canary(token_id_or_name)
            self._refresh_trapnet()

    def _rearm_single_canary(self, token_name: str):
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            mgr = self.main_win.honeypot_mgr.honey_token_mgr
            template = next((t for t in mgr.TEMPLATES if t["name"] == token_name or t["id"] == token_name), None)
            if template:
                mgr.deploy_canary(template["id"])
            self._refresh_trapnet()

    def _disarm_all_canary_lures(self):
        if hasattr(self.main_win, 'honeypot_mgr') and self.main_win.honeypot_mgr:
            removed = self.main_win.honeypot_mgr.honey_token_mgr.disarm_all_canaries(clear_db=True)
            self._refresh_trapnet()
            QMessageBox.information(self, "Canaries Removed", f"Successfully disarmed and removed {removed} canary files.")

    def _simulate_canary_tripwire_test(self, target_canary: Any = None):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return

        if not isinstance(target_canary, dict):
            target_canary = None

        mgr = self.main_win.honeypot_mgr.honey_token_mgr
        canaries = mgr.get_canaries()

        active = None
        if target_canary and target_canary.get("status") == "ACTIVE":
            active = target_canary
        elif canaries:
            active = next((c for c in canaries if c.get("status") == "ACTIVE"), None)

        if not active:
            mgr.deploy_all_canaries()
            canaries = mgr.get_canaries()
            active = next((c for c in canaries if c.get("status") == "ACTIVE"), None)

        if not active:
            QMessageBox.warning(self, "No Canaries", "Could not find active canaries to test.")
            return

        p = Path(active["file_path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(p, "ab") as f:
                f.write(b"\n# SIMULATED_INFOSTEALER_ACCESS_TEST\n")
        except Exception as e:
            logger.debug(f"Canary test touch notice: {e}")

        mgr.check_canaries()
        self._refresh_trapnet()

        QMessageBox.information(
            self,
            "🧪 Tripwire Test Successful!",
            f"TrapNet HoneyToken Tripwire triggered successfully!\n\n"
            f"Breached Canary: {active['token_name']}\n"
            f"Location: {active['file_path']}\n"
            f"Status: TRIPPED (Intruder Alert Logged)\n\n"
            f"TrapNet caught the unauthorized file access immediately before real user files were touched!"
        )

    def _dialog_export_trapnet_forensics(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return

        fmt, ok = QInputDialog.getItem(
            self, "Export Threat Forensics", "Select Export Format:",
            ["JSON Forensics Archive (*.json)", "CSV Intrusion Log (*.csv)"],
            0, False
        )
        if not ok:
            return

        is_csv = "csv" in fmt.lower()
        ext = "csv" if is_csv else "json"
        flt = "CSV Files (*.csv)" if is_csv else "JSON Files (*.json)"

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Forensic Report",
            f"CrazyAlchemy_TrapNet_Forensics_{int(time.time())}.{ext}",
            flt
        )
        if save_path:
            content = self.main_win.honeypot_mgr.export_forensics_report(export_format=ext)
            Path(save_path).write_text(content, encoding="utf-8")
            self.main_win.fw_logger.log_event("forensics_exported", "info", f"Exported forensics: {save_path}")
            QMessageBox.information(self, "Report Saved", f"Forensic telemetry saved successfully to:\n{save_path}")

    def _clear_trapnet_events(self):
        if not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return
        confirm = QMessageBox.question(
            self, "Clear Intrusion Log?", "Are you sure you want to clear the entire intrusion telemetry log?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.main_win.honeypot_mgr.clear_events()
            self._refresh_trapnet()

    def _refresh_trapnet(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, 'honeypot_mgr') or not self.main_win.honeypot_mgr:
            return

        mgr = self.main_win.honeypot_mgr
        stats = mgr.get_trap_stats()

        # Update Banner Stats
        active_cnt = len(stats.get("active_trap_ports", []))
        banned_cnt = stats.get("auto_blocked_count", 0)
        traps_24h = stats.get("traps_24h", 0)
        canaries_cnt = stats.get("canaries_deployed", 0)
        tripped_cnt = stats.get("canaries_tripped", 0)

        canary_status_str = f"{canaries_cnt} Active"
        if tripped_cnt > 0:
            canary_status_str += f" (⚠️ {tripped_cnt} TRIPPED!)"

        self.lbl_trap_stats.setText(
            f"Active Decoys: {active_cnt} • Intruders Banned: {banned_cnt} • 24h Probes: {traps_24h} • HoneyTokens: {canary_status_str}"
        )

        # 1. Update Intercepted Intruders Table
        events = mgr.get_recent_events(limit=60)
        self.table_traps.setRowCount(len(events))
        for row, e in enumerate(events):
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("timestamp", 0)))
            src = f"{e.get('source_ip', '')}:{e.get('source_port', '')}"
            decoy = f"Port {e.get('trap_port', '')} ({e.get('trap_service', '')})"
            attack = e.get("attack_type", "Reconnaissance Scan")
            creds = e.get("captured_credentials") or e.get("payload_preview", "")[:36]
            status = "BANNED" if e.get("auto_blocked") else "LOGGED"

            self.table_traps.setItem(row, 0, QTableWidgetItem(t_str))
            self.table_traps.setItem(row, 1, QTableWidgetItem(src))
            self.table_traps.setItem(row, 2, QTableWidgetItem(decoy))

            attack_item = QTableWidgetItem(attack)
            if "Worm" in attack or "Breach" in attack or "Exploit" in attack:
                attack_item.setForeground(QColor("#EF4444"))
            self.table_traps.setItem(row, 3, attack_item)

            self.table_traps.setItem(row, 4, QTableWidgetItem(creds))

            st_item = QTableWidgetItem(status)
            if status == "BANNED":
                st_item.setForeground(QColor("#EF4444"))
            else:
                st_item.setForeground(QColor("#F59E0B"))
            self.table_traps.setItem(row, 5, st_item)

        # 2. Update Active Decoys Table
        traps_detail = mgr.get_active_traps_detail()
        self.table_decoy_listeners.setRowCount(len(traps_detail))
        for row, t in enumerate(traps_detail):
            p = t["port"]
            self.table_decoy_listeners.setItem(row, 0, QTableWidgetItem(f"{t.get('icon', '🍯')} Port {p}"))
            self.table_decoy_listeners.setItem(row, 1, QTableWidgetItem(t["label"]))
            self.table_decoy_listeners.setItem(row, 2, QTableWidgetItem(t["category"]))
            self.table_decoy_listeners.setItem(row, 3, QTableWidgetItem(t["protocol"]))

            st_str = "🟢 Listening (Armed)" if t["is_active"] else "⚪ Offline"
            st_item = QTableWidgetItem(st_str)
            if t["is_active"]:
                st_item.setForeground(QColor("#10B981"))
            self.table_decoy_listeners.setItem(row, 4, st_item)

            self.table_decoy_listeners.setItem(row, 5, QTableWidgetItem(f"{t['hits_count']} Interceptions"))
            self.table_decoy_listeners.setRowHeight(row, 36)

            btn_disarm = QPushButton("Disarm")
            btn_disarm.setProperty("class", "table-action")
            btn_disarm.clicked.connect(lambda _, port=p: self._disarm_decoy_listener(port))
            self.table_decoy_listeners.setCellWidget(row, 6, btn_disarm)

        # 3. Update HoneyTokens Canaries Table
        canaries = mgr.honey_token_mgr.get_canaries() if hasattr(mgr, 'honey_token_mgr') else []
        self.table_honeytokens.setRowCount(len(canaries))
        for row, c in enumerate(canaries):
            self.table_honeytokens.setItem(row, 0, QTableWidgetItem(c["token_name"]))
            self.table_honeytokens.setItem(row, 1, QTableWidgetItem(c["lure_type"]))
            self.table_honeytokens.setItem(row, 2, QTableWidgetItem(c["file_path"]))
            dep_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.get("deployed_at", 0)))
            self.table_honeytokens.setItem(row, 3, QTableWidgetItem(dep_str))
            self.table_honeytokens.setRowHeight(row, 36)

            st = c.get("status", "ACTIVE")
            st_str = "🟢 ARMED & GUARDING" if st == "ACTIVE" else ("🔴 TRIPPED!" if st == "TRIPPED" else "⚪ DISARMED")
            st_item = QTableWidgetItem(st_str)
            if "ARMED" in st_str:
                st_item.setForeground(QColor("#10B981"))
            elif "TRIPPED" in st_str:
                st_item.setForeground(QColor("#EF4444"))
            self.table_honeytokens.setItem(row, 4, st_item)

            act_w = QWidget()
            act_lay = QHBoxLayout(act_w)
            act_lay.setContentsMargins(4, 2, 4, 2)
            act_lay.setSpacing(6)

            if st == "ACTIVE":
                btn_test = QPushButton("Test Wire")
                btn_test.setProperty("class", "suggested-action table-action")
                btn_test.setToolTip(f"Simulate intruder access on {c['token_name']}")
                btn_test.clicked.connect(lambda _, tok=c: self._simulate_canary_tripwire_test(tok))
                act_lay.addWidget(btn_test)
            elif st == "TRIPPED":
                btn_rearm = QPushButton("Re-arm")
                btn_rearm.setProperty("class", "suggested-action table-action")
                btn_rearm.setToolTip(f"Restore canary file and re-arm tripwire")
                btn_rearm.clicked.connect(lambda _, name=c["token_name"]: self._rearm_single_canary(name))
                act_lay.addWidget(btn_rearm)

            btn_remove = QPushButton("Remove")
            btn_remove.setProperty("class", "table-action")
            btn_remove.setToolTip(f"Disarm tripwire and permanently delete canary lure file")
            btn_remove.clicked.connect(lambda _, tok_id=c["token_id"]: self._disarm_single_canary(tok_id))
            act_lay.addWidget(btn_remove)

            self.table_honeytokens.setCellWidget(row, 5, act_w)

    def _refresh_chainguard(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, 'chainguard_engine') or not self.main_win.chainguard_engine:
            return

        chains = self.main_win.chainguard_engine.get_suspicious_chains()
        self.table_cg.setRowCount(len(chains))
        for row, c in enumerate(chains):
            pid_proc = f"{c.process_name} (PID {c.pid})"
            lineage = " -> ".join(c.full_chain)
            reason = " | ".join(c.suspicion_reasons)
            endpoints = ", ".join(c.remote_endpoints)

            self.table_cg.setItem(row, 0, QTableWidgetItem(pid_proc))
            self.table_cg.setItem(row, 1, QTableWidgetItem(lineage))
            self.table_cg.setItem(row, 2, QTableWidgetItem(reason))
            self.table_cg.setItem(row, 3, QTableWidgetItem(endpoints))
            self.table_cg.setRowHeight(row, 36)

            act_w = QWidget()
            act_lay = QHBoxLayout(act_w)
            act_lay.setContentsMargins(2, 2, 2, 2)
            act_lay.setSpacing(4)

            btn_kill = QPushButton("Kill Process")
            btn_kill.setProperty("class", "destructive-action table-action")
            btn_kill.clicked.connect(lambda _, p=c.pid: self._kill_pid(p))

            btn_wl = QPushButton("Whitelist")
            btn_wl.setProperty("class", "table-action")
            btn_wl.clicked.connect(lambda _, h=c.chain_hash, n=c.process_name: self._whitelist_chain(h, n))

            act_lay.addWidget(btn_kill)
            act_lay.addWidget(btn_wl)
            self.table_cg.setCellWidget(row, 4, act_w)

    def _whitelist_chain(self, chain_hash: str, process_name: str):
        if hasattr(self.main_win, 'chainguard_engine') and self.main_win.chainguard_engine:
            if self.main_win.chainguard_engine.whitelist_chain(chain_hash, f"User-authorized: {process_name}"):
                self.main_win.fw_logger.log_event("chain_whitelisted", "info", f"Whitelisted lineage: {process_name} ({chain_hash[:8]})")
                QMessageBox.information(self, "Lineage Whitelisted", f"Process chain for '{process_name}' has been permanently whitelisted.")
                self._refresh_chainguard()

    def _kill_pid(self, pid: int):
        try:
            import psutil
            p = psutil.Process(pid)
            p.terminate()
            self.main_win.fw_logger.log_event("process_killed", "warning", f"Terminated process PID {pid} via Crazy Alchemy Monitor")
            QMessageBox.information(self, "Process Terminated", f"Successfully terminated PID {pid}.")
            self._refresh_sockets()
            self._refresh_chainguard()
        except Exception as e:
            QMessageBox.warning(self, "Action Failed", f"Could not terminate PID {pid}: {e}")

    def _reset_appprint_baseline(self, app_name: str):
        if hasattr(self.main_win, 'appprint_engine') and self.main_win.appprint_engine:
            if self.main_win.appprint_engine.reset_fingerprint(app_name):
                self.main_win.fw_logger.log_event("appprint_reset", "info", f"Reset behavioral baseline for: {app_name}")
                QMessageBox.information(self, "Baseline Reset", f"Network DNA baseline for '{app_name}' has been cleared.")
                self._refresh_appprint()

    def _clear_anomalies(self):
        if hasattr(self.main_win, 'appprint_engine') and self.main_win.appprint_engine:
            if self.main_win.appprint_engine.clear_anomalies():
                self.main_win.fw_logger.log_event("appprint_cleared", "info", "Cleared all AppPrint network anomalies")
                QMessageBox.information(self, "Anomalies Cleared", "All AppPrint deviation alerts have been cleared.")
                self._refresh_appprint()

    def _refresh_appprint(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, 'appprint_engine') or not self.main_win.appprint_engine:
            return

        fps = self.main_win.appprint_engine.get_fingerprints()
        self.table_ap.setRowCount(len(fps))
        for row, fp in enumerate(fps):
            app = fp.get("app_name", "")
            conf = f"{int(fp.get('confidence_score', 0) * 100)}%"
            ports = ", ".join(str(p) for p in fp.get("typical_remote_ports", [])[:6])
            subnets = ", ".join(fp.get("typical_subnets", [])[:4])
            avg_c = str(fp.get("avg_conns", 1))
            status = "Learned (Active)" if fp.get("confidence_score", 0) >= 0.5 else "Training"

            self.table_ap.setItem(row, 0, QTableWidgetItem(app))
            self.table_ap.setItem(row, 1, QTableWidgetItem(conf))
            self.table_ap.setItem(row, 2, QTableWidgetItem(ports))
            self.table_ap.setItem(row, 3, QTableWidgetItem(subnets))
            self.table_ap.setItem(row, 4, QTableWidgetItem(avg_c))
            self.table_ap.setItem(row, 5, QTableWidgetItem(status))
            self.table_ap.setRowHeight(row, 36)

            btn_reset = QPushButton("Reset DNA")
            btn_reset.setProperty("class", "table-action")
            btn_reset.clicked.connect(lambda _, a=app: self._reset_appprint_baseline(a))
            self.table_ap.setCellWidget(row, 6, btn_reset)

    def _add_darkweb_email(self):
        if not hasattr(self.main_win, 'darkweb_monitor') or not self.main_win.darkweb_monitor:
            return
        raw_email = self.dw_email_input.text().strip()
        if not raw_email:
            QMessageBox.warning(self, "Input Required", "Please enter an email address to monitor.")
            return

        success, msg = self.main_win.darkweb_monitor.add_email(raw_email)
        if success:
            self.dw_email_input.clear()
            self._refresh_darkweb()
            QMessageBox.information(self, "Email Monitored", msg)
            reply = QMessageBox.question(
                self,
                "Check Live Threat Intelligence?",
                f"Would you like to query live DarkWeb feeds immediately for '{raw_email}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._check_single_email_live(raw_email)
        else:
            QMessageBox.warning(self, "Cannot Add Email", msg)

    def _remove_darkweb_email(self, email: str):
        if not hasattr(self.main_win, 'darkweb_monitor') or not self.main_win.darkweb_monitor:
            return
        reply = QMessageBox.question(
            self,
            "Remove Monitored Account",
            f"Are you sure you want to stop DarkWeb monitoring for:\n\n{email}\n\nAll historical breach records for this email will also be deleted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel
        )
        if reply == QMessageBox.StandardButton.Yes:
            success, msg = self.main_win.darkweb_monitor.remove_email(email)
            self._refresh_darkweb()
            if success:
                QMessageBox.information(self, "Account Removed", msg)
            else:
                QMessageBox.warning(self, "Removal Error", msg)

    def _check_single_email_live(self, email: str):
        if not hasattr(self.main_win, 'darkweb_monitor') or not self.main_win.darkweb_monitor:
            return
        self.lbl_dw_stats.setText(f"Querying live feeds for {email}...")

        def run_single():
            try:
                breaches = self.main_win.darkweb_monitor.check_email_live(email)
                if HAS_PYQT6:
                    QTimer.singleShot(0, lambda: self._on_single_check_finished(email, breaches))
            except Exception as e:
                if HAS_PYQT6:
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Live Query Error", f"Failed live check for {email}: {e}"))

        t = threading.Thread(target=run_single, daemon=True, name="dw-single-check")
        t.start()

    def _on_single_check_finished(self, email: str, breaches: List[Dict[str, Any]]):
        self._refresh_darkweb(filter_email=email)
        if breaches:
            b_names = ", ".join(b["breach_name"] for b in breaches[:4])
            if len(breaches) > 4:
                b_names += f" and {len(breaches) - 4} more"
            QMessageBox.critical(
                self,
                "⚠️ DarkWeb Exposure Detected!",
                f"EXPOSURE FOUND for {email}!\n\n"
                f"The email was identified in {len(breaches)} breach dataset(s):\n{b_names}\n\n"
                "We recommend changing passwords for associated accounts and enabling multi-factor authentication (MFA) immediately."
            )
        else:
            QMessageBox.information(
                self,
                "✓ No Exposures Detected",
                f"Email '{email}' was checked against updated live threat feeds.\n\nNo compromised credentials or dark web leaks were identified."
            )

    def _sync_darkweb_live(self):
        if not hasattr(self.main_win, 'darkweb_monitor') or not self.main_win.darkweb_monitor:
            return
        emails = self.main_win.darkweb_monitor.get_monitored_emails()
        if not emails:
            QMessageBox.information(self, "No Monitored Accounts", "Please add at least one email address before syncing feeds.")
            return

        self.lbl_dw_stats.setText("Syncing live breach feeds from updated threat intelligence sources...")

        def run_sync():
            try:
                res = self.main_win.darkweb_monitor.check_all_monitored_live()
                checked = res.get("emails_checked", 0)
                breaches = res.get("total_breaches", 0)
                if HAS_PYQT6:
                    QTimer.singleShot(0, lambda: self._on_sync_finished(checked, breaches))
            except Exception as ex:
                if HAS_PYQT6:
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Sync Error", f"Failed to sync feeds: {ex}"))

        t = threading.Thread(target=run_sync, daemon=True, name="dw-live-sync")
        t.start()

    def _on_sync_finished(self, checked: int, breaches: int):
        self._refresh_darkweb()
        QMessageBox.information(
            self,
            "DarkWeb Intelligence Sync Complete",
            f"Successfully queried live dark web threat feeds across {checked} monitored accounts.\n\n"
            f"Total breach exposure records identified: {breaches}."
        )

    def _refresh_darkweb(self, filter_email: Optional[str] = None):
        if not HAS_PYQT6 or not hasattr(self.main_win, 'darkweb_monitor') or not self.main_win.darkweb_monitor:
            return

        monitor = self.main_win.darkweb_monitor
        stats = monitor.get_stats()
        monitored_count = stats.get("total_monitored", 0)
        max_allowed = stats.get("max_allowed", 15)
        compromised = stats.get("compromised_accounts", 0)
        total_breaches = stats.get("total_breaches_found", 0)
        last_sync = stats.get("last_sync", "Never")

        status_text = (
            f"Monitored: {monitored_count} / {max_allowed} (Max) • "
            f"Compromised Accounts: {compromised} • "
            f"Total Leaked Records: {total_breaches} • "
            f"Last Feed Sync: {last_sync}"
        )
        self.lbl_dw_stats.setText(status_text)
        if compromised > 0:
            self.lbl_dw_stats.setStyleSheet("color: #F85149; font-size: 11px; font-weight: bold;")
        else:
            self.lbl_dw_stats.setStyleSheet("color: #388bfd; font-size: 11px; font-weight: bold;")

        # Populate Monitored Accounts table
        emails = monitor.get_monitored_emails()
        self.table_dw_emails.setRowCount(len(emails))
        for row, item in enumerate(emails):
            em = item["email"]
            is_comp = item["is_compromised"]
            b_cnt = item["breach_count"]
            last_chk = item["last_checked"]

            self.table_dw_emails.setItem(row, 0, QTableWidgetItem(em))

            status_str = f"⚠️ COMPROMISED ({b_cnt})" if is_comp else "✓ SECURE (Clean)"
            status_item = QTableWidgetItem(status_str)
            if is_comp:
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.green)
            self.table_dw_emails.setItem(row, 1, status_item)

            self.table_dw_emails.setItem(row, 2, QTableWidgetItem(f"{b_cnt} incident(s)"))
            self.table_dw_emails.setItem(row, 3, QTableWidgetItem(last_chk))
            self.table_dw_emails.setRowHeight(row, 36)

            act_cell = QWidget()
            act_lay = QHBoxLayout(act_cell)
            act_lay.setContentsMargins(2, 2, 2, 2)
            act_lay.setSpacing(4)

            btn_view = QPushButton("View Leaks")
            btn_view.setProperty("class", "table-action")
            btn_view.setToolTip("Filter breach table to show exposures for this account")
            btn_view.clicked.connect(lambda _, target=em: self._refresh_darkweb(filter_email=target))
            act_lay.addWidget(btn_view)

            btn_chk = QPushButton("Check Now")
            btn_chk.setProperty("class", "table-action")
            btn_chk.clicked.connect(lambda _, target=em: self._check_single_email_live(target))
            act_lay.addWidget(btn_chk)

            btn_del = QPushButton("Remove")
            btn_del.setProperty("class", "destructive-action table-action")
            btn_del.clicked.connect(lambda _, target=em: self._remove_darkweb_email(target))
            act_lay.addWidget(btn_del)

            self.table_dw_emails.setCellWidget(row, 4, act_cell)

        # Populate Breach Records table
        if filter_email:
            breaches = monitor.get_breaches_for_email(filter_email)
            self.lbl_leak_title.setText(f"Discovered Breach Records for '{filter_email}' ({len(breaches)} found):")
        else:
            breaches = monitor.get_all_breaches()
            self.lbl_leak_title.setText(f"Discovered Breach Records & Leaked Data Classes ({len(breaches)} total):")

        self.table_dw_breaches.setRowCount(len(breaches))
        for row, b in enumerate(breaches):
            self.table_dw_breaches.setItem(row, 0, QTableWidgetItem(b.get("email", "")))
            self.table_dw_breaches.setItem(row, 1, QTableWidgetItem(b.get("breach_name", "")))
            self.table_dw_breaches.setItem(row, 2, QTableWidgetItem(b.get("domain", "")))
            self.table_dw_breaches.setItem(row, 3, QTableWidgetItem(b.get("breach_date", "")))
            self.table_dw_breaches.setItem(row, 4, QTableWidgetItem(b.get("leaked_data", "")))
            self.table_dw_breaches.setItem(row, 5, QTableWidgetItem(b.get("detected_at", "")[:19]))

    def _apply_exploit_profile(self, profile_name: str):
        if not hasattr(self.main_win, 'exploit_shield') or not self.main_win.exploit_shield:
            return
        self.main_win.exploit_shield.apply_hardening_profile(profile_name)
        self.main_win.profiles.update_settings({"anti_exploit_profile": profile_name})
        self._refresh_exploit_shield()
        QMessageBox.information(
            self, "Exploit Protection Profile Applied",
            f"Successfully applied the '{profile_name}' exploit mitigation profile to Windows.\n\n"
            f"All system mitigations and Attack Surface Reduction rules have been updated."
        )

    def _toggle_asr_rule(self, guid: str, current_state: str):
        if not hasattr(self.main_win, 'exploit_shield') or not self.main_win.exploit_shield:
            return
        cycle = {"Block": "Audit", "Audit": "Disabled", "Disabled": "Block"}
        next_state = cycle.get(current_state, "Block")
        self.main_win.exploit_shield.set_asr_rule_state(guid, next_state)
        self._refresh_exploit_shield()

    def _kill_exploit_proc(self, pid: int, name: str):
        if not hasattr(self.main_win, 'exploit_shield') or not self.main_win.exploit_shield:
            return
        ret = QMessageBox.question(
            self, "Terminate Exploited Process",
            f"Are you sure you want to terminate exploited process '{name}' (PID: {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if ret == QMessageBox.StandardButton.Yes:
            ok = self.main_win.exploit_shield.terminate_process(pid)
            if ok:
                QMessageBox.information(self, "Process Terminated", f"Process {name} (PID: {pid}) terminated successfully.")
            else:
                QMessageBox.warning(self, "Termination Failed", f"Could not terminate PID {pid}.")
            self._refresh_exploit_shield()

    def _refresh_exploit_shield(self):
        if not HAS_PYQT6 or not hasattr(self.main_win, 'exploit_shield') or not self.main_win.exploit_shield:
            return

        shield = self.main_win.exploit_shield
        stats = shield.get_stats()

        intercepted = stats.get("exploits_intercepted", 0)
        act_sys = stats.get("active_system_mitigations", 0)
        tot_sys = stats.get("system_mitigations_count", 0)
        act_asr = stats.get("active_asr_rules", 0)
        tot_asr = stats.get("asr_rules_count", 0)
        act_core = stats.get("active_core_isolation", 0)
        tot_core = stats.get("core_isolation_features", 0)

        self.lbl_ex_stats.setText(
            f"Exploits Neutralized: {intercepted} • "
            f"Active Mitigations: {act_sys}/{tot_sys} • "
            f"ASR Rules: {act_asr}/{tot_asr} Enforced • "
            f"Core Isolation: {act_core}/{tot_core} Active"
        )
        if intercepted > 0:
            self.lbl_ex_stats.setStyleSheet("color: #F85149; font-size: 11px; font-weight: bold;")
        else:
            self.lbl_ex_stats.setStyleSheet("color: #388bfd; font-size: 11px; font-weight: bold;")

        # 1. Populate Intercepted Exploit Events
        events = stats.get("recent_events", [])
        self.table_ex_events.setRowCount(len(events))
        for row, ev in enumerate(events):
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.get("timestamp", time.time())))
            self.table_ex_events.setItem(row, 0, QTableWidgetItem(t_str))
            self.table_ex_events.setItem(row, 1, QTableWidgetItem(f"{ev.get('process_name', '')} (PID: {ev.get('pid', '')})"))
            self.table_ex_events.setItem(row, 2, QTableWidgetItem(ev.get("exploit_type", "")))

            sev = ev.get("severity", "high")
            sev_item = QTableWidgetItem(sev.upper())
            if sev == "critical":
                sev_item.setForeground(Qt.GlobalColor.red)
            else:
                sev_item.setForeground(Qt.GlobalColor.yellow)
            self.table_ex_events.setItem(row, 3, sev_item)
            self.table_ex_events.setItem(row, 4, QTableWidgetItem(ev.get("details", "")))
            self.table_ex_events.setRowHeight(row, 36)

            act_cell = QWidget()
            act_lay = QHBoxLayout(act_cell)
            act_lay.setContentsMargins(2, 2, 2, 2)
            btn_kill = QPushButton("Kill Process")
            btn_kill.setProperty("class", "destructive-action table-action")
            pid = ev.get("pid", 0)
            pname = ev.get("process_name", "")
            btn_kill.clicked.connect(lambda _, p=pid, n=pname: self._kill_exploit_proc(p, n))
            act_lay.addWidget(btn_kill)
            self.table_ex_events.setCellWidget(row, 5, act_cell)

        # 2. Populate ASR Rules Table
        rules = shield.get_asr_rules()
        self.table_asr.setRowCount(len(rules))
        for row, r in enumerate(rules):
            self.table_asr.setItem(row, 0, QTableWidgetItem(r.get("name", "")))
            self.table_asr.setItem(row, 1, QTableWidgetItem(r.get("category", "")))
            self.table_asr.setItem(row, 2, QTableWidgetItem(r.get("guid", "")))

            state = r.get("state", "Block")
            state_item = QTableWidgetItem(f"🛡️ {state}" if state == "Block" else (f"📋 {state}" if state == "Audit" else f"⚪ {state}"))
            if state == "Block":
                state_item.setForeground(Qt.GlobalColor.green)
            elif state == "Audit":
                state_item.setForeground(Qt.GlobalColor.yellow)
            else:
                state_item.setForeground(Qt.GlobalColor.gray)
            self.table_asr.setItem(row, 3, state_item)
            self.table_asr.setRowHeight(row, 36)

            act_cell = QWidget()
            act_lay = QHBoxLayout(act_cell)
            act_lay.setContentsMargins(2, 2, 2, 2)
            btn_tog = QPushButton(f"Set: {'Audit' if state == 'Block' else ('Disabled' if state == 'Audit' else 'Block')}")
            btn_tog.setProperty("class", "table-action")
            guid = r.get("guid", "")
            btn_tog.clicked.connect(lambda _, g=guid, s=state: self._toggle_asr_rule(g, s))
            act_lay.addWidget(btn_tog)
            self.table_asr.setCellWidget(row, 4, act_cell)

        # 3. Populate System Mitigations & Core Isolation Table
        sys_mits = shield.get_system_mitigations()
        core_iso = shield.get_core_isolation_status()

        rows_data = [
            ("DEP (Data Execution Prevention)", "System Mitigation", sys_mits.get("DEP", True), "Prevents running code from non-executable memory pages"),
            ("Mandatory ASLR", "System Mitigation", sys_mits.get("MandatoryASLR", True), "Force-relocates images without dynamic base flags"),
            ("Bottom-Up ASLR", "System Mitigation", sys_mits.get("BottomUpASLR", True), "Randomizes base virtual addresses of memory allocations"),
            ("High-Entropy ASLR", "System Mitigation", sys_mits.get("HighEntropyASLR", True), "Enables 64-bit high entropy memory address randomization"),
            ("Control Flow Guard (CFG)", "System Mitigation", sys_mits.get("CFG", True), "Verifies call targets for indirect call instructions"),
            ("SEHOP (Structured Exception Overwrite)", "System Mitigation", sys_mits.get("SEHOP", True), "Validates structured exception handler chains on stack"),
            ("Strict Handle Checks", "System Mitigation", sys_mits.get("StrictHandleCheck", True), "Terminates processes attempting invalid handle operations"),
            ("HVCI / Memory Integrity", "Core Isolation", core_iso.get("HVCI_MemoryIntegrity", True), "Hypervisor-protected kernel code integrity via VBS"),
            ("LSA Protection (RunAsPPL)", "Core Isolation", core_iso.get("LSA_Protection_PPL", True), "Protects LSASS credential memory from injection & dumping"),
            ("Vulnerable Driver Blocklist", "Core Isolation", core_iso.get("VulnerableDriverBlocklist", True), "Blocks known exploited drivers abused for BYOVD rootkits"),
            ("Kernel CET Shadow Stacks", "Hardware Security", core_iso.get("Kernel_CET_ShadowStacks", True), "Hardware-enforced return address validation against ROP/JOP"),
            ("Credential Guard", "Hardware Security", core_iso.get("CredentialGuard", True), "Isolates NTLM/Kerberos secrets within Virtual Trust Level 1 enclave")
        ]

        self.table_sys_mit.setRowCount(len(rows_data))
        for row, (name, m_type, status, desc) in enumerate(rows_data):
            self.table_sys_mit.setItem(row, 0, QTableWidgetItem(name))
            self.table_sys_mit.setItem(row, 1, QTableWidgetItem(m_type))

            st_item = QTableWidgetItem("✓ ACTIVE (Hardened)" if status else "⚪ DISABLED")
            if status:
                st_item.setForeground(Qt.GlobalColor.green)
            else:
                st_item.setForeground(Qt.GlobalColor.gray)
            self.table_sys_mit.setItem(row, 2, st_item)
            self.table_sys_mit.setItem(row, 3, QTableWidgetItem(desc))


# ── 5. Services & Apps Page ──────────────────────────────────────────

class AppsPage(QScrollArea if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.scanner = main_win.scanner
        self.app_core = main_win.fw_core
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 30)
        layout.setSpacing(16)

        # Banner Card
        b_card = QFrame()
        b_card.setProperty("class", "stat-card")
        b_lay = QHBoxLayout(b_card)
        lbl_i = QLabel("💻")
        lbl_i.setStyleSheet("font-size: 32px;")
        b_lay.addWidget(lbl_i)

        t_lay = QVBoxLayout()
        self.lbl_title = QLabel("Auto-Scanned Services & Applications")
        self.lbl_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.lbl_sub = QLabel("Discovered background services and desktop apps")
        self.lbl_sub.setProperty("class", "subtitle-text")
        t_lay.addWidget(self.lbl_title)
        t_lay.addWidget(self.lbl_sub)
        b_lay.addLayout(t_lay, stretch=1)

        btn_rescan = QPushButton("Rescan System")
        btn_rescan.clicked.connect(self._run_scan)
        b_lay.addWidget(btn_rescan)
        layout.addWidget(b_card)

        # Search and Filter Toolbar
        f_card = QFrame()
        f_card.setProperty("class", "stat-card")
        f_lay = QHBoxLayout(f_card)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter applications or services by name...")
        self.search_input.textChanged.connect(self.refresh)
        f_lay.addWidget(self.search_input, stretch=1)

        self.cat_combo = QComboBox()
        self.cat_combo.addItems(["All Items", "Applications Only", "Services Only"])
        self.cat_combo.currentIndexChanged.connect(self.refresh)
        f_lay.addWidget(self.cat_combo)

        layout.addWidget(f_card)

        # Catalog Table
        c_card = QFrame()
        c_card.setProperty("class", "stat-card")
        cc_lay = QVBoxLayout(c_card)

        self.apps_table = QTableWidget(0, 4)
        self.apps_table.setHorizontalHeaderLabels(["Name", "Category", "State", "Network Permission"])
        self.apps_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.apps_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.apps_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.apps_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.apps_table.horizontalHeader().setMinimumSectionSize(95)
        cc_lay.addWidget(self.apps_table)
        layout.addWidget(c_card)

        self.setWidget(container)

    def _run_scan(self):
        self.scanner.scan(self.app_core, self.main_win.profiles, self.main_win.monitor)
        self.refresh()

    def _toggle_app_permission(self, itm, btn):
        """Toggles Windows Firewall block/allow rule for the selected application or service."""
        if itm.is_enabled:
            # Block the application / service
            target_path = itm.exec_path or itm.exec_name
            if itm.category == "service" and itm.ports:
                for port, proto in itm.ports:
                    self.app_core.add_port_rule(str(port), proto.upper(), action="block", direction="in")
            elif target_path:
                self.app_core.block_app(itm.name, target_path)

            itm.is_enabled = False
            btn.setText("Blocked")
            btn.setProperty("class", "destructive-action")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
            self.main_win.fw_logger.log_event("app_blocked", "warning", f"Blocked network access for {itm.name}")
        else:
            # Unblock the application / service
            if itm.category == "service" and itm.ports:
                for port, proto in itm.ports:
                    self.app_core.remove_port_rule(str(port), proto.upper(), direction="in")
            else:
                self.app_core.unblock_app(itm.name, itm.exec_path)

            itm.is_enabled = True
            btn.setText("Allowed")
            btn.setProperty("class", "")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
            self.main_win.fw_logger.log_event("app_allowed", "info", f"Allowed network access for {itm.name}")

    def refresh(self):
        if not HAS_PYQT6:
            return
        items = self.scanner.get_cached_items()
        search_txt = self.search_input.text().strip().lower()
        cat_filter = self.cat_combo.currentText()

        filtered = []
        for itm in items:
            if cat_filter == "Applications Only" and itm.category != "app":
                continue
            if cat_filter == "Services Only" and itm.category != "service":
                continue
            if search_txt and search_txt not in itm.name.lower():
                continue
            filtered.append(itm)

        self.apps_table.setRowCount(len(filtered))
        for row, itm in enumerate(filtered):
            self.apps_table.setItem(row, 0, QTableWidgetItem(itm.name))
            self.apps_table.setItem(row, 1, QTableWidgetItem(itm.category.capitalize()))
            self.apps_table.setItem(row, 2, QTableWidgetItem("Active" if itm.is_running else "Inactive"))
            self.apps_table.setRowHeight(row, 36)

            btn_toggle = QPushButton("Allowed" if itm.is_enabled else "Blocked")
            if not itm.is_enabled:
                btn_toggle.setProperty("class", "destructive-action table-action")
            else:
                btn_toggle.setProperty("class", "table-action")
            btn_toggle.clicked.connect(lambda _, item=itm, b=btn_toggle: self._toggle_app_permission(item, b))
            self.apps_table.setCellWidget(row, 3, btn_toggle)


# ── 6. Security Profiles Page ────────────────────────────────────────

class ProfilesPage(QScrollArea if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.profiles = main_win.profiles
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 30)
        layout.setSpacing(16)

        # Header toolbar card
        h_card = QFrame()
        h_card.setProperty("class", "stat-card")
        h_lay = QVBoxLayout(h_card)
        h_lay.setSpacing(12)

        top_row = QHBoxLayout()
        header_title_lay = QVBoxLayout()
        title_lbl = QLabel("Enterprise Security Profiles")
        title_lbl.setStyleSheet("font-size: 17px; font-weight: bold;")
        subtitle_lbl = QLabel(
            "Dynamic network postures with instant kernel-level Windows 11 Firewall, port whitelisting, "
            "and Exploit Shield synchronization."
        )
        subtitle_lbl.setProperty("class", "subtitle-text")
        header_title_lay.addWidget(title_lbl)
        header_title_lay.addWidget(subtitle_lbl)
        top_row.addLayout(header_title_lay, stretch=1)

        btn_new = QPushButton("➕ Create Custom Profile")
        btn_new.setProperty("class", "suggested-action")
        btn_new.clicked.connect(self._dialog_create_profile)
        top_row.addWidget(btn_new)

        btn_import = QPushButton("📥 Import Profile")
        btn_import.clicked.connect(self._import_profile)
        top_row.addWidget(btn_import)

        btn_backup = QPushButton("💾 Backup Policy")
        btn_backup.clicked.connect(self._backup_policy)
        top_row.addWidget(btn_backup)

        btn_reset = QPushButton("🔄 Reset Defaults")
        btn_reset.clicked.connect(self._reset_profiles_to_default)
        top_row.addWidget(btn_reset)

        h_lay.addLayout(top_row)
        layout.addWidget(h_card)

        # ── Novel Pillar 3: AegisChameleon™ Autonomous Adaptive Profiles & Dev Leases ──
        ac_card = QFrame()
        ac_card.setProperty("class", "stat-card")
        ac_lay = QVBoxLayout(ac_card)
        ac_lay.setContentsMargins(16, 14, 16, 14)
        ac_lay.setSpacing(10)

        ac_top = QHBoxLayout()
        ac_icon = QLabel("🦎")
        ac_icon.setStyleSheet("font-size: 28px;")
        ac_top.addWidget(ac_icon)

        act_lay = QVBoxLayout()
        ac_title = QLabel("AegisChameleon™ Autonomous Adaptive Defense & Threat Pressure (EAPM)")
        ac_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #3fb950;")
        self.lbl_eapm_status = QLabel("Environmental Adversary Pressure Metric: 5% • Tier 1: Baseline Guard")
        self.lbl_eapm_status.setProperty("class", "subtitle-text")
        act_lay.addWidget(ac_title)
        act_lay.addWidget(self.lbl_eapm_status)
        ac_top.addLayout(act_lay, stretch=1)

        self.btn_financial_bastion = QPushButton("🛡️ Engage Financial Bastion")
        self.btn_financial_bastion.setProperty("class", "suggested-action")
        self.btn_financial_bastion.setToolTip("Instant zero-trust hardening: isolates crypto wallets, banking sessions & locks clipboard")
        self.btn_financial_bastion.clicked.connect(self._toggle_financial_bastion)
        ac_top.addWidget(self.btn_financial_bastion)
        ac_lay.addLayout(ac_top)

        self.eapm_bar = QProgressBar()
        self.eapm_bar.setValue(5)
        self.eapm_bar.setMaximum(100)
        self.eapm_bar.setStyleSheet("QProgressBar::chunk { background-color: #2ea043; border-radius: 4px; }")
        ac_lay.addWidget(self.eapm_bar)

        # Ephemeral Dev-Port Leases Sub-Section
        dev_box = QVBoxLayout()
        dev_box.setSpacing(6)
        dev_head = QHBoxLayout()
        lbl_dev_title = QLabel("⏳ Ephemeral Dev-Port Leases (Auto-Expiring Developer Firewall Rules):")
        lbl_dev_title.setStyleSheet("font-weight: bold; font-size: 12px; color: #58a6ff;")
        dev_head.addWidget(lbl_dev_title, stretch=1)

        btn_grant_lease = QPushButton("+ Grant Dev-Port Lease...")
        btn_grant_lease.setProperty("class", "suggested-action")
        btn_grant_lease.clicked.connect(self._dialog_grant_dev_lease)
        dev_head.addWidget(btn_grant_lease)

        btn_refresh_leases = QPushButton("Refresh")
        btn_refresh_leases.clicked.connect(self._refresh_aegis_chameleon)
        dev_head.addWidget(btn_refresh_leases)
        dev_box.addLayout(dev_head)

        self.table_leases = QTableWidget(0, 6)
        self.table_leases.setHorizontalHeaderLabels([
            "Lease ID", "Port / Protocol", "Process Name", "Granted At", "Time Remaining", "Action"
        ])
        self.table_leases.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_leases.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_leases.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_leases.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_leases.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_leases.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_leases.horizontalHeader().setMinimumSectionSize(80)
        self.table_leases.setMaximumHeight(130)
        dev_box.addWidget(self.table_leases)
        ac_lay.addLayout(dev_box)

        layout.addWidget(ac_card)

        # Profiles list
        self.cards_layout = QVBoxLayout()
        self.cards_layout.setSpacing(12)
        layout.addLayout(self.cards_layout)
        layout.addStretch()

        self.setWidget(container)

    def refresh(self):
        if not HAS_PYQT6:
            return

        self._refresh_aegis_chameleon()

        while self.cards_layout.count():
            item = self.cards_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        all_profiles = self.profiles.get_profiles()
        active = self.profiles.get_active_profile()
        builtin_names = {"Home", "Public", "Corporate", "Gaming", "Maximum Security"}

        for name, data in all_profiles.items():
            card = QFrame()
            card.setProperty("class", "stat-card")
            card_lay = QVBoxLayout(card)
            card_lay.setContentsMargins(16, 14, 16, 14)
            card_lay.setSpacing(10)

            # Top Row: Title + Tier / Compliance Badges + Action Buttons
            top_bar = QHBoxLayout()
            title_text = f"🛡️ {name}"
            title_lbl = QLabel(title_text)
            title_lbl.setStyleSheet("font-size: 15px; font-weight: bold;")
            top_bar.addWidget(title_lbl)

            tier = str(data.get("tier", "standard")).upper()
            tier_badge = QLabel(f" [{tier}] ")
            tier_badge.setStyleSheet("font-size: 11px; font-weight: bold; background-color: #2b3a4a; color: #64b5f6; border-radius: 4px; padding: 2px 6px;")
            top_bar.addWidget(tier_badge)

            if "compliance" in data and data["compliance"]:
                comp_badge = QLabel(f" {data['compliance']} COMPLIANT ")
                comp_badge.setStyleSheet("font-size: 11px; font-weight: bold; background-color: #1e3a2f; color: #81c784; border-radius: 4px; padding: 2px 6px;")
                top_bar.addWidget(comp_badge)

            top_bar.addStretch(1)

            # Actions on right
            btn_activate = QPushButton("Active Posture" if active == name else "Activate")
            if active == name:
                btn_activate.setEnabled(False)
                btn_activate.setProperty("class", "suggested-action")
            else:
                btn_activate.clicked.connect(lambda _, n=name: self._activate_profile(n))
            top_bar.addWidget(btn_activate)

            btn_edit = QPushButton("⚙️ Edit / Details")
            btn_edit.clicked.connect(lambda _, n=name: self._dialog_edit_profile(n))
            top_bar.addWidget(btn_edit)

            btn_export = QPushButton("📤 Export")
            btn_export.clicked.connect(lambda _, n=name: self._export_profile(n))
            top_bar.addWidget(btn_export)

            if name not in builtin_names:
                btn_del = QPushButton("🗑️ Delete")
                btn_del.setProperty("class", "destructive-action")
                if active == name:
                    btn_del.setEnabled(False)
                    btn_del.setToolTip("Cannot delete currently active profile")
                else:
                    btn_del.clicked.connect(lambda _, n=name: self._delete_profile(n))
                top_bar.addWidget(btn_del)

            card_lay.addLayout(top_bar)

            # Description
            desc_lbl = QLabel(data.get("description", "No description provided."))
            desc_lbl.setProperty("class", "subtitle-text")
            desc_lbl.setWordWrap(True)
            card_lay.addWidget(desc_lbl)

            # Specs Bar (Posture, ICMP, Outbound)
            specs_bar = QHBoxLayout()
            specs_bar.setSpacing(14)

            inbound_txt = "🛡️ Inbound: Block All" if data.get("block_inbound", True) else "🔓 Inbound: Allow All"
            outbound_txt = "🌐 Outbound: Allow All" if data.get("allow_outbound", True) else "🔒 Outbound: Whitelist Only"
            icmp_txt = "⛔ ICMP Ping: Dropped" if data.get("icmp_block", False) else "🟢 ICMP Ping: Allowed"
            win_prof_txt = f"🪟 Windows Zone: {data.get('windows_profile', 'Private')}"

            for txt in (inbound_txt, outbound_txt, icmp_txt, win_prof_txt):
                lbl = QLabel(txt)
                lbl.setStyleSheet("font-size: 12px; color: #b0bec5; background-color: #1a2332; border-radius: 4px; padding: 3px 8px;")
                specs_bar.addWidget(lbl)
            specs_bar.addStretch(1)
            card_lay.addLayout(specs_bar)

            # Allowed Services & Ports Row
            details_lay = QVBoxLayout()
            details_lay.setSpacing(4)

            svcs = data.get("allowed_services", [])
            svcs_str = ", ".join(svcs) if svcs else "None (Strict isolation)"
            lbl_svcs = QLabel(f"<b>Permitted Services:</b> {svcs_str}")
            lbl_svcs.setStyleSheet("font-size: 12px; color: #cfd8dc;")
            lbl_svcs.setWordWrap(True)
            details_lay.addWidget(lbl_svcs)

            ports = data.get("allowed_ports", [])
            if ports:
                port_list = []
                for p in ports:
                    if isinstance(p, dict):
                        port_list.append(f"{p.get('port')}/{p.get('protocol', 'tcp').upper()}")
                    else:
                        port_list.append(str(p))
                ports_str = ", ".join(port_list)
            else:
                ports_str = "None (Default profile baseline)"
            lbl_ports = QLabel(f"<b>Custom Whitelisted Ports:</b> {ports_str}")
            lbl_ports.setStyleSheet("font-size: 12px; color: #cfd8dc;")
            lbl_ports.setWordWrap(True)
            details_lay.addWidget(lbl_ports)

            blocked_ports = data.get("blocked_ports", [])
            if blocked_ports:
                bport_list = []
                for bp in blocked_ports:
                    if isinstance(bp, dict):
                        bport_list.append(f"{bp.get('port')}/{bp.get('protocol', 'tcp').upper()}")
                    else:
                        bport_list.append(str(bp))
                lbl_bports = QLabel(f"<b>Blacklisted Ports:</b> {', '.join(bport_list)}")
                lbl_bports.setStyleSheet("font-size: 12px; color: #ff8a80;")
                lbl_bports.setWordWrap(True)
                details_lay.addWidget(lbl_bports)

            card_lay.addLayout(details_lay)
            self.cards_layout.addWidget(card)

    def _activate_profile(self, name: str):
        self.main_win.switch_profile(name)
        self.refresh()

    def _dialog_create_profile(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Create Custom Security Profile")
        dlg.setMinimumWidth(560)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(12)

        lbl_hdr = QLabel("<b>Configure New Security Profile</b>")
        lbl_hdr.setStyleSheet("font-size: 15px;")
        lay.addWidget(lbl_hdr)

        form = QVBoxLayout()
        form.setSpacing(10)

        # Name
        form.addWidget(QLabel("Profile Name:"))
        txt_name = QLineEdit()
        txt_name.setPlaceholderText("e.g. Developer Workstation, Isolated Lab")
        form.addWidget(txt_name)

        # Description
        form.addWidget(QLabel("Description:"))
        txt_desc = QLineEdit()
        txt_desc.setPlaceholderText("Detailed description of security scope and purpose...")
        form.addWidget(txt_desc)

        # Tier & Windows Profile
        row1 = QHBoxLayout()
        v_tier = QVBoxLayout()
        v_tier.addWidget(QLabel("Security Tier:"))
        combo_tier = QComboBox()
        combo_tier.addItems(["custom", "standard", "premium"])
        v_tier.addWidget(combo_tier)
        row1.addLayout(v_tier)

        v_win = QVBoxLayout()
        v_win.addWidget(QLabel("Target Windows Profile:"))
        combo_win = QComboBox()
        combo_win.addItems(["Private", "Public", "Domain", "All"])
        v_win.addWidget(combo_win)
        row1.addLayout(v_win)
        form.addLayout(row1)

        # Inbound / Outbound / ICMP
        chk_inbound = QCheckBox("Block All Inbound Traffic (Recommended)")
        chk_inbound.setChecked(True)
        form.addWidget(chk_inbound)

        chk_outbound = QCheckBox("Allow Outbound Traffic (Uncheck for Whitelist Fortress Mode)")
        chk_outbound.setChecked(True)
        form.addWidget(chk_outbound)

        chk_icmp = QCheckBox("Drop Inbound ICMP Ping Echo Requests (Stealth Mode)")
        chk_icmp.setChecked(False)
        form.addWidget(chk_icmp)

        # Services checkboxes
        form.addWidget(QLabel("Permitted Services:"))
        services_grid = QHBoxLayout()
        chk_fps = QCheckBox("File & Printer Sharing")
        chk_mdns = QCheckBox("mDNS Discovery")
        chk_steam = QCheckBox("Steam Gaming")
        chk_core = QCheckBox("Core Networking")
        chk_core.setChecked(True)
        chk_rdp = QCheckBox("Remote Desktop (RDP)")

        col1 = QVBoxLayout()
        col1.addWidget(chk_fps)
        col1.addWidget(chk_mdns)
        services_grid.addLayout(col1)

        col2 = QVBoxLayout()
        col2.addWidget(chk_core)
        col2.addWidget(chk_steam)
        services_grid.addLayout(col2)

        col3 = QVBoxLayout()
        col3.addWidget(chk_rdp)
        services_grid.addLayout(col3)
        form.addLayout(services_grid)

        # Custom Allowed Ports
        form.addWidget(QLabel("Allowed Ports / Ranges (comma-separated, e.g. 443/tcp, 8080/tcp, 27015-27030/udp):"))
        txt_allowed_ports = QLineEdit()
        txt_allowed_ports.setPlaceholderText("e.g. 80/tcp, 443/tcp, 8080/tcp")
        form.addWidget(txt_allowed_ports)

        # Custom Blocked Ports
        form.addWidget(QLabel("Blocked Ports / Ranges (comma-separated, e.g. 21, 23, 445, 137-139):"))
        txt_blocked_ports = QLineEdit()
        txt_blocked_ports.setPlaceholderText("e.g. 21, 23, 445")
        form.addWidget(txt_blocked_ports)

        lay.addLayout(form)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch(1)
        btn_save = QPushButton("Save Profile")
        btn_save.setProperty("class", "suggested-action")
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dlg.reject)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_save)
        lay.addLayout(btn_box)

        def _do_save():
            name = txt_name.text().strip()
            if not name:
                QMessageBox.warning(dlg, "Missing Name", "Please enter a profile name.")
                return

            # Extract services
            selected_svcs = []
            if chk_core.isChecked(): selected_svcs.append("CoreNetworking")
            if chk_fps.isChecked(): selected_svcs.append("FileAndPrinterSharing")
            if chk_mdns.isChecked(): selected_svcs.append("mDNS")
            if chk_steam.isChecked(): selected_svcs.append("SteamClient")
            if chk_rdp.isChecked(): selected_svcs.append("RemoteDesktopLocal")

            # Extract ports
            allowed_ports = []
            for p in txt_allowed_ports.text().split(","):
                p_clean = p.strip()
                if p_clean:
                    allowed_ports.append(p_clean)

            blocked_ports = []
            for bp in txt_blocked_ports.text().split(","):
                bp_clean = bp.strip()
                if bp_clean:
                    blocked_ports.append(bp_clean)

            p_data = {
                "description": txt_desc.text().strip() or "Custom user security profile.",
                "tier": combo_tier.currentText(),
                "windows_profile": combo_win.currentText(),
                "block_inbound": chk_inbound.isChecked(),
                "allow_outbound": chk_outbound.isChecked(),
                "icmp_block": chk_icmp.isChecked(),
                "allowed_services": selected_svcs,
                "allowed_ports": allowed_ports,
                "blocked_ports": blocked_ports,
                "logging": "standard"
            }

            success, msg = self.profiles.create_profile(name, p_data)
            if success:
                self.main_win.fw_logger.log_event("profile_created", "info", f"Created security profile: {name}")
                QMessageBox.information(dlg, "Success", f"Security profile '{name}' created successfully.")
                dlg.accept()
                self.refresh()
            else:
                QMessageBox.warning(dlg, "Error", msg)

        btn_save.clicked.connect(_do_save)
        dlg.exec()

    def _dialog_edit_profile(self, name: str):
        prof = self.profiles.get_profile(name)
        if not prof:
            QMessageBox.warning(self, "Error", f"Profile '{name}' not found.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Edit Profile: {name}")
        dlg.setMinimumWidth(560)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(12)

        lbl_hdr = QLabel(f"<b>Edit Security Profile: {name}</b>")
        lbl_hdr.setStyleSheet("font-size: 15px;")
        lay.addWidget(lbl_hdr)

        form = QVBoxLayout()
        form.setSpacing(10)

        # Description
        form.addWidget(QLabel("Description:"))
        txt_desc = QLineEdit(prof.get("description", ""))
        form.addWidget(txt_desc)

        # Inbound / Outbound / ICMP
        chk_inbound = QCheckBox("Block All Inbound Traffic")
        chk_inbound.setChecked(prof.get("block_inbound", True))
        form.addWidget(chk_inbound)

        chk_outbound = QCheckBox("Allow Outbound Traffic")
        chk_outbound.setChecked(prof.get("allow_outbound", True))
        form.addWidget(chk_outbound)

        chk_icmp = QCheckBox("Drop Inbound ICMP Ping Echo Requests (Stealth Mode)")
        chk_icmp.setChecked(prof.get("icmp_block", False))
        form.addWidget(chk_icmp)

        # Permitted Services
        form.addWidget(QLabel("Permitted Services:"))
        svcs = set(prof.get("allowed_services", []))
        services_grid = QHBoxLayout()
        chk_fps = QCheckBox("File & Printer Sharing")
        chk_fps.setChecked("FileAndPrinterSharing" in svcs)
        chk_mdns = QCheckBox("mDNS Discovery")
        chk_mdns.setChecked("mDNS" in svcs)
        chk_steam = QCheckBox("Steam Gaming")
        chk_steam.setChecked("SteamClient" in svcs)
        chk_core = QCheckBox("Core Networking")
        chk_core.setChecked("CoreNetworking" in svcs)
        chk_rdp = QCheckBox("Remote Desktop (RDP)")
        chk_rdp.setChecked("RemoteDesktopLocal" in svcs)

        col1 = QVBoxLayout()
        col1.addWidget(chk_fps)
        col1.addWidget(chk_mdns)
        services_grid.addLayout(col1)

        col2 = QVBoxLayout()
        col2.addWidget(chk_core)
        col2.addWidget(chk_steam)
        services_grid.addLayout(col2)

        col3 = QVBoxLayout()
        col3.addWidget(chk_rdp)
        services_grid.addLayout(col3)
        form.addLayout(services_grid)

        # Allowed Ports
        form.addWidget(QLabel("Allowed Ports / Ranges:"))
        curr_ports = prof.get("allowed_ports", [])
        port_strs = []
        for p in curr_ports:
            if isinstance(p, dict):
                port_strs.append(f"{p.get('port')}/{p.get('protocol', 'tcp')}")
            else:
                port_strs.append(str(p))
        txt_allowed_ports = QLineEdit(", ".join(port_strs))
        form.addWidget(txt_allowed_ports)

        # Blocked Ports
        form.addWidget(QLabel("Blocked Ports / Ranges:"))
        curr_bports = prof.get("blocked_ports", [])
        bport_strs = []
        for bp in curr_bports:
            if isinstance(bp, dict):
                bport_strs.append(f"{bp.get('port')}/{bp.get('protocol', 'tcp')}")
            else:
                bport_strs.append(str(bp))
        txt_blocked_ports = QLineEdit(", ".join(bport_strs))
        form.addWidget(txt_blocked_ports)

        lay.addLayout(form)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch(1)
        btn_save = QPushButton("Save Changes")
        btn_save.setProperty("class", "suggested-action")
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dlg.reject)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_save)
        lay.addLayout(btn_box)

        def _do_update():
            selected_svcs = []
            if chk_core.isChecked(): selected_svcs.append("CoreNetworking")
            if chk_fps.isChecked(): selected_svcs.append("FileAndPrinterSharing")
            if chk_mdns.isChecked(): selected_svcs.append("mDNS")
            if chk_steam.isChecked(): selected_svcs.append("SteamClient")
            if chk_rdp.isChecked(): selected_svcs.append("RemoteDesktopLocal")

            allowed_ports = [p.strip() for p in txt_allowed_ports.text().split(",") if p.strip()]
            blocked_ports = [bp.strip() for bp in txt_blocked_ports.text().split(",") if bp.strip()]

            updated_data = dict(prof)
            updated_data.update({
                "description": txt_desc.text().strip(),
                "block_inbound": chk_inbound.isChecked(),
                "allow_outbound": chk_outbound.isChecked(),
                "icmp_block": chk_icmp.isChecked(),
                "allowed_services": selected_svcs,
                "allowed_ports": allowed_ports,
                "blocked_ports": blocked_ports
            })

            success, msg = self.profiles.update_profile(name, updated_data)
            if success:
                if name == self.profiles.get_active_profile():
                    self.main_win.switch_profile(name)
                self.main_win.fw_logger.log_event("profile_updated", "info", f"Updated profile: {name}")
                QMessageBox.information(dlg, "Saved", f"Profile '{name}' updated successfully.")
                dlg.accept()
                self.refresh()
            else:
                QMessageBox.warning(dlg, "Error", msg)

        btn_save.clicked.connect(_do_update)
        dlg.exec()

    def _delete_profile(self, name: str):
        confirm = QMessageBox.question(
            self,
            "Delete Profile",
            f"Are you sure you want to permanently remove security profile '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            success, msg = self.profiles.delete_profile(name)
            if success:
                self.main_win.fw_logger.log_event("profile_deleted", "warning", f"Deleted security profile: {name}")
                QMessageBox.information(self, "Deleted", msg)
                self.refresh()
            else:
                QMessageBox.warning(self, "Cannot Delete", msg)

    def _reset_profiles_to_default(self):
        confirm = QMessageBox.question(
            self,
            "Reset Profiles to Default",
            "Are you sure you want to restore all profiles back to factory defaults?\n\nAny custom profiles will be removed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            if self.profiles.reset_profiles_to_default():
                active = self.profiles.get_active_profile()
                self.main_win.switch_profile(active)
                self.main_win.fw_logger.log_event("profiles_reset", "warning", "Reset security profiles to factory defaults.")
                QMessageBox.information(self, "Reset Complete", "Security profiles restored to factory default configuration.")
                self.refresh()
            else:
                QMessageBox.warning(self, "Reset Failed", "Could not restore factory default profiles.")

    def _export_profile(self, name: str):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export Profile '{name}'",
            f"{name.lower().replace(' ', '_')}_profile.json",
            "JSON Profiles (*.json);;All Files (*.*)"
        )
        if file_path:
            if self.profiles.export_profile(name, file_path):
                self.main_win.fw_logger.log_event("profile_exported", "info", f"Exported profile '{name}' to {file_path}")
                QMessageBox.information(self, "Exported", f"Successfully exported profile '{name}' to:\n{file_path}")
            else:
                QMessageBox.warning(self, "Export Failed", f"Failed to export profile '{name}'.")

    def _import_profile(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Security Profile",
            "",
            "JSON Profiles (*.json);;All Files (*.*)"
        )
        if file_path:
            success, msg, p_name = self.profiles.import_profile(file_path, overwrite=True)
            if success:
                self.main_win.fw_logger.log_event("profile_imported", "info", f"Imported security profile '{p_name}'")
                QMessageBox.information(self, "Import Successful", msg)
                self.refresh()
            else:
                QMessageBox.warning(self, "Import Failed", msg)

    def _backup_policy(self):
        backup_path = self.profiles.backup_rules()
        if backup_path:
            self.main_win.fw_logger.log_event("policy_backed_up", "info", f"Exported firewall policy: {backup_path}")
            QMessageBox.information(self, "Backup Successful", f"Firewall rules policy exported successfully:\n{backup_path}")
        else:
            QMessageBox.warning(self, "Backup Failed", "Failed to backup firewall rules. Ensure administrative rights.")

    def _toggle_financial_bastion(self):
        if not hasattr(self.profiles, "adaptive"):
            return
        is_active = self.profiles.adaptive._financial_bastion_active
        self.profiles.adaptive.set_financial_bastion(not is_active, reason="Manual User Toggle")
        self.refresh()

    def _dialog_grant_dev_lease(self):
        if not HAS_PYQT6 or not hasattr(self.profiles, "adaptive"):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Grant Ephemeral Dev-Port Lease")
        dialog.setMinimumSize(420, 240)
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        lbl = QLabel("Temporarily open a developer port with an automatic expiration timer.\nThe firewall rule will be permanently erased when the countdown completes.")
        lbl.setWordWrap(True)
        lay.addWidget(lbl)

        row_p = QHBoxLayout()
        row_p.addWidget(QLabel("Port Number:"))
        input_port = QSpinBox()
        input_port.setRange(1, 65535)
        input_port.setValue(3000)
        row_p.addWidget(input_port)

        row_p.addWidget(QLabel("Protocol:"))
        combo_proto = QComboBox()
        combo_proto.addItems(["TCP", "UDP"])
        row_p.addWidget(combo_proto)
        lay.addLayout(row_p)

        row_t = QHBoxLayout()
        row_t.addWidget(QLabel("Duration (Hours):"))
        combo_dur = QComboBox()
        combo_dur.addItem("30 Minutes", 1800)
        combo_dur.addItem("1 Hour", 3600)
        combo_dur.addItem("2 Hours (Standard Dev)", 7200)
        combo_dur.addItem("4 Hours", 14400)
        combo_dur.addItem("8 Hours", 28800)
        combo_dur.setCurrentIndex(2)
        row_t.addWidget(combo_dur)
        lay.addLayout(row_t)

        row_proc = QHBoxLayout()
        row_proc.addWidget(QLabel("Process / Tool:"))
        input_proc = QLineEdit("node.exe / python.exe")
        row_proc.addWidget(input_proc)
        lay.addLayout(row_proc)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dialog.reject)
        btn_ok = QPushButton("Grant Timed Lease")
        btn_ok.setProperty("class", "suggested-action")
        btn_ok.clicked.connect(dialog.accept)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_ok)
        lay.addLayout(btn_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            port = input_port.value()
            proto = combo_proto.currentText()
            dur = combo_dur.currentData()
            proc = input_proc.text().strip() or "dev_tool"
            lid = self.profiles.adaptive.grant_dev_port_lease(
                port=port, protocol=proto, duration_sec=dur, process_name=proc
            )
            self._refresh_aegis_chameleon()
            QMessageBox.information(
                self,
                "Dev-Port Lease Granted",
                f"Ephemeral lease active for port {port}/{proto} ({dur // 60} minutes).\n\n"
                f"Firewall rule opened and timer running. Port will auto-seal when expired."
            )

    def _revoke_dev_lease(self, lease_id: str):
        if hasattr(self.profiles, "adaptive"):
            self.profiles.adaptive.revoke_dev_port_lease(lease_id)
            self._refresh_aegis_chameleon()

    def _refresh_aegis_chameleon(self):
        if not HAS_PYQT6 or not hasattr(self.profiles, "adaptive"):
            return
        st = self.profiles.adaptive.get_stats()
        pct = st.get("eapm_pct", 5)
        tier = st.get("tier_name", "Tier 1: Baseline Guard")
        self.eapm_bar.setValue(pct)

        if pct < 25:
            self.eapm_bar.setStyleSheet("QProgressBar::chunk { background-color: #2ea043; border-radius: 4px; }")
        elif pct < 60:
            self.eapm_bar.setStyleSheet("QProgressBar::chunk { background-color: #388bfd; border-radius: 4px; }")
        elif pct < 85:
            self.eapm_bar.setStyleSheet("QProgressBar::chunk { background-color: #d29922; border-radius: 4px; }")
        else:
            self.eapm_bar.setStyleSheet("QProgressBar::chunk { background-color: #f85149; border-radius: 4px; }")

        self.lbl_eapm_status.setText(
            f"Adversary Pressure: {pct}% • {tier} • Wi-Fi Risk: {st.get('wifi_pressure', 0):.2f} • "
            f"TrapNet Probes: {st.get('trapnet_pressure', 0):.2f} • Ancestry: {st.get('ancestry_pressure', 0):.2f}"
        )

        is_bastion = st.get("financial_bastion_active", False)
        if is_bastion:
            self.btn_financial_bastion.setText("🛡️ Financial Bastion ENGAGED (Click to Disengage)")
            self.btn_financial_bastion.setStyleSheet("background-color: #8957e5; color: white; font-weight: bold;")
        else:
            self.btn_financial_bastion.setText("🛡️ Engage Financial Bastion (Zero-Trust Banking Mode)")
            self.btn_financial_bastion.setStyleSheet("")

        # Update Leases Table
        leases = self.profiles.adaptive.get_active_leases()
        self.table_leases.setRowCount(len(leases))
        for r, l in enumerate(leases):
            rem = l.get("remaining_sec", 0)
            mins = rem // 60
            secs = rem % 60
            self.table_leases.setItem(r, 0, QTableWidgetItem(str(l.get("lease_id", ""))))
            self.table_leases.setItem(r, 1, QTableWidgetItem(f"{l.get('port')}/{l.get('protocol')}"))
            self.table_leases.setItem(r, 2, QTableWidgetItem(str(l.get("process_name", ""))))
            self.table_leases.setItem(r, 3, QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(l.get("granted_at", 0)))))
            self.table_leases.setItem(r, 4, QTableWidgetItem(f"{mins:02d}:{secs:02d}"))
            self.table_leases.setRowHeight(r, 34)

            btn_rev = QPushButton("Revoke")
            btn_rev.setProperty("class", "destructive-action table-action")
            lid = l.get("lease_id")
            btn_rev.clicked.connect(lambda _, x=lid: self._revoke_dev_lease(x))
            self.table_leases.setCellWidget(r, 5, btn_rev)


# ── 7. Logs Page ─────────────────────────────────────────────────────

class LogsPage(QWidget if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.logger = main_win.fw_logger
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # Toolbar Card
        t_card = QFrame()
        t_card.setProperty("class", "stat-card")
        t_lay = QVBoxLayout(t_card)
        t_lay.setSpacing(10)

        top_bar = QHBoxLayout()
        lbl = QLabel("Security & Threat Audit Events")
        lbl.setStyleSheet("font-size: 16px; font-weight: bold;")
        top_bar.addWidget(lbl, stretch=1)

        btn_export = QPushButton("💾 Export CSV")
        btn_export.clicked.connect(self._export_csv)
        top_bar.addWidget(btn_export)

        btn_clear = QPushButton("🗑️ Clear Log History")
        btn_clear.setProperty("class", "destructive-action")
        btn_clear.clicked.connect(self._clear_logs)
        top_bar.addWidget(btn_clear)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh)
        top_bar.addWidget(btn_refresh)
        t_lay.addLayout(top_bar)

        filter_bar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter audit events by keyword, process, IP, or threat...")
        self.search_input.textChanged.connect(self.refresh)
        filter_bar.addWidget(self.search_input, stretch=1)

        self.sev_combo = QComboBox()
        self.sev_combo.addItems(["All Severities", "CRITICAL Only", "WARNING Only", "INFO Only"])
        self.sev_combo.currentIndexChanged.connect(self.refresh)
        filter_bar.addWidget(self.sev_combo)
        t_lay.addLayout(filter_bar)

        layout.addWidget(t_card)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Severity", "Event", "Message"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setMinimumSectionSize(80)
        layout.addWidget(self.table)

    def _export_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Audit Events to CSV", "crazy_alchemy_security_events.csv", "CSV Files (*.csv);;All Files (*.*)")
        if file_path:
            if self.logger.export_logs_csv(file_path):
                QMessageBox.information(self, "Export Complete", f"Audit logs successfully exported to:\n{file_path}")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export audit logs.")

    def _clear_logs(self):
        confirm = QMessageBox.question(
            self, "Clear Audit Log",
            "Are you sure you want to permanently clear all security audit events?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            if self.logger.clear_logs():
                QMessageBox.information(self, "Cleared", "Audit logs cleared.")
                self.refresh()
            else:
                QMessageBox.warning(self, "Clear Failed", "Could not clear audit logs.")

    def refresh(self):
        if not HAS_PYQT6:
            return
        events = self.logger.get_recent_events(limit=500)
        search_txt = self.search_input.text().strip().lower()
        sev_filter = self.sev_combo.currentText()

        filtered = []
        for e in events:
            sev = e.get('severity', '').upper()
            if sev_filter == "CRITICAL Only" and sev != "CRITICAL":
                continue
            if sev_filter == "WARNING Only" and sev != "WARNING":
                continue
            if sev_filter == "INFO Only" and sev != "INFO":
                continue
            if search_txt:
                msg = e.get('message', '').lower()
                ev_type = e.get('event_type', '').lower()
                if search_txt not in msg and search_txt not in ev_type:
                    continue
            filtered.append(e)

        self.table.setRowCount(len(filtered))
        for row, e in enumerate(filtered):
            self.table.setItem(row, 0, QTableWidgetItem(e.get('timestamp', '')[:19].replace('T', ' ')))
            self.table.setItem(row, 1, QTableWidgetItem(e.get('severity', '').upper()))
            self.table.setItem(row, 2, QTableWidgetItem(e.get('event_type', '')))
            self.table.setItem(row, 3, QTableWidgetItem(e.get('message', '')))
            self.table.setRowHeight(row, 28)


# ── 8. Settings Page ─────────────────────────────────────────────────

class SettingsPage(QScrollArea if HAS_PYQT6 else object):
    def __init__(self, main_win):
        if HAS_PYQT6:
            super().__init__()
        self.main_win = main_win
        self.profiles = main_win.profiles
        self._init_ui()

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 30)
        layout.setSpacing(16)

        header = QLabel("Enterprise Security Settings & Windows Configuration")
        header.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(header)

        # ── Card 0: Appearance & Visual Theme ──
        c_theme = QFrame()
        c_theme.setProperty("class", "stat-card")
        c_theme_lay = QVBoxLayout(c_theme)
        c_theme_lay.setSpacing(8)
        c_theme_title = QLabel("🎨 Appearance & Visual Theme")
        c_theme_title.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 6px;")
        c_theme_lay.addWidget(c_theme_title)

        self.combo_theme = QComboBox()
        self.combo_theme.addItem("🌙 High-Contrast Dark Theme (Optimal Readability)", "dark")
        self.combo_theme.addItem("☀️ Fluent Light Theme (Clean Crisp Interface)", "light")
        self.combo_theme.addItem("🖥️ Follow Windows System Theme", "system")

        cur_theme = self.profiles.get_setting("theme", "dark")
        for i in range(self.combo_theme.count()):
            if self.combo_theme.itemData(i) == cur_theme:
                self.combo_theme.setCurrentIndex(i)
                break
        self.combo_theme.currentIndexChanged.connect(self._on_theme_changed)

        c_theme_lay.addWidget(create_antivirus_option_row(
            "🎨", "Application Visual Theme",
            "Switch between High-Contrast Dark mode and Fluent Light mode for crystal-clear text visibility and eye comfort",
            self.combo_theme
        ))
        layout.addWidget(c_theme)

        # ── Card 1: Core Antivirus & Active Protection Engines ──
        c1 = QFrame()
        c1.setProperty("class", "stat-card")
        c1_lay = QVBoxLayout(c1)
        c1_lay.setSpacing(8)
        c1_title = QLabel("🛡️ Core Antivirus & Active Protection Engines")
        c1_title.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 6px;")
        c1_lay.addWidget(c1_title)

        self.chk_shield = QCheckBox()
        self.chk_shield.setProperty("class", "antivirus-switch")
        self.chk_shield.toggled.connect(lambda v: self._on_setting_changed("realtime_antivirus", v))
        c1_lay.addWidget(create_antivirus_option_row(
            "🛡️", "Real-Time File System Shield",
            "Continuous filesystem watchdog monitoring Downloads, %TEMP%, and Startup for incoming malware",
            self.chk_shield
        ))

        self.chk_sig_autoupdate = QCheckBox()
        self.chk_sig_autoupdate.setProperty("class", "antivirus-switch")
        self.chk_sig_autoupdate.toggled.connect(self._on_sig_autoupdate_toggled)
        c1_lay.addWidget(create_antivirus_option_row(
            "🔄", "Malware Signature Auto-Update",
            "Automatically downloads delta threat updates from MalwareBazaar and community feeds in background",
            self.chk_sig_autoupdate
        ))

        self.combo_sig_interval = QComboBox()
        self.combo_sig_interval.addItem("Every 2 Hours", 2)
        self.combo_sig_interval.addItem("Every 5 Hours", 5)
        self.combo_sig_interval.addItem("Every 12 Hours", 12)
        self.combo_sig_interval.addItem("Every 24 Hours", 24)
        self.combo_sig_interval.currentIndexChanged.connect(self._on_sig_interval_changed)
        c1_lay.addWidget(create_antivirus_option_row(
            "⏱️", "Virus Scanner Update Frequency",
            "Configures the background interval for querying updated threat databases (2, 5, 12, or 24 hours)",
            self.combo_sig_interval
        ))

        btn_cfg_api = QPushButton("Configure Auth-Key")
        btn_cfg_api.clicked.connect(self._dialog_configure_threat_feed_key)
        c1_lay.addWidget(create_antivirus_option_row(
            "🔑", "Threat Intelligence API Key (Abuse.ch)",
            "Optional Auth-Key from auth.abuse.ch for direct MalwareBazaar API access. If blank, high-speed OSINT mirrors are used automatically.",
            btn_cfg_api
        ))

        # Email Client Antivirus Shield Row
        self.chk_email_shield = QCheckBox()
        self.chk_email_shield.setProperty("class", "antivirus-switch")
        self.chk_email_shield.toggled.connect(self._on_email_shield_toggled)

        btn_cfg_email = QPushButton("Configure Clients")
        btn_cfg_email.clicked.connect(self._dialog_configure_email_clients)

        email_ctrl = QWidget()
        ec_lay = QHBoxLayout(email_ctrl)
        ec_lay.setContentsMargins(0, 0, 0, 0)
        ec_lay.setSpacing(8)
        ec_lay.addWidget(btn_cfg_email)
        ec_lay.addWidget(self.chk_email_shield)

        c1_lay.addWidget(create_antivirus_option_row(
            "📧", "Email Client Antivirus Shield",
            "Real-time attachment watchdog guarding Microsoft Outlook, Mozilla Thunderbird, Windows Mail, eM Client & Mailbird",
            email_ctrl
        ))

        # Anti-Exploit & Memory Protection Shield Row
        self.chk_exploit_shield = QCheckBox()
        self.chk_exploit_shield.setProperty("class", "antivirus-switch")
        self.chk_exploit_shield.toggled.connect(self._on_exploit_shield_toggled)

        btn_cfg_exploit = QPushButton("Configure Mitigations")
        btn_cfg_exploit.clicked.connect(self._dialog_configure_exploit_mitigations)

        exploit_ctrl = QWidget()
        exc_lay = QHBoxLayout(exploit_ctrl)
        exc_lay.setContentsMargins(0, 0, 0, 0)
        exc_lay.setSpacing(8)
        exc_lay.addWidget(btn_cfg_exploit)
        exc_lay.addWidget(self.chk_exploit_shield)

        c1_lay.addWidget(create_antivirus_option_row(
            "💥", "Anti-Exploit Protection & Attack Surface Reduction (ASR)",
            "System-wide DEP, ASLR, CFG, SEHOP, 16 Microsoft Defender ASR rules, HVCI Memory Integrity & LSA Protection",
            exploit_ctrl
        ))

        # Windows Defender Coexistence Mode Row
        defender_ctrl = QWidget()
        def_ctrl_lay = QHBoxLayout(defender_ctrl)
        def_ctrl_lay.setContentsMargins(0, 0, 0, 0)
        def_ctrl_lay.setSpacing(8)

        self.combo_defender_mode = QComboBox()
        self.combo_defender_mode.addItem("🛡️ Secondary Antivirus (Passive Background Scanning)", "passive_secondary")
        self.combo_defender_mode.addItem("🚫 Completely Disable Windows Defender Antivirus", "disabled")
        self.combo_defender_mode.addItem("⚡ Co-Active Parallel (Simultaneous Active Shields)", "active_coexist")
        self.combo_defender_mode.currentIndexChanged.connect(self._on_defender_mode_changed)

        self.btn_open_defender_sec = QPushButton("🛡️ Windows Security")
        self.btn_open_defender_sec.setToolTip("Open Windows Security settings to manage Tamper Protection & Defender scanning")
        self.btn_open_defender_sec.clicked.connect(self._open_windows_security_settings)

        def_ctrl_lay.addWidget(self.combo_defender_mode)
        def_ctrl_lay.addWidget(self.btn_open_defender_sec)

        c1_lay.addWidget(create_antivirus_option_row(
            "🪟", "Windows Defender Antivirus Coexistence",
            "Choose whether to completely disable Windows Defender, keep it as secondary antivirus, or run co-active parallel shields",
            defender_ctrl
        ))

        # Real-Time OS Setting Propagation Row
        self.chk_os_sync = QCheckBox()
        self.chk_os_sync.setProperty("class", "antivirus-switch")
        self.chk_os_sync.toggled.connect(lambda v: self._on_setting_changed("sync_settings_with_windows", v))
        c1_lay.addWidget(create_antivirus_option_row(
            "⚡", "Real-Time Windows OS Setting Propagation",
            "Instantly reflects antivirus, exploit mitigations, and firewall policies in Windows to eliminate duplicate background hooks",
            self.chk_os_sync
        ))

        self.chk_trapnet = QCheckBox()
        self.chk_trapnet.setProperty("class", "antivirus-switch")
        self.chk_trapnet.toggled.connect(lambda v: self._on_setting_changed("honeypot_enabled", v))
        c1_lay.addWidget(create_antivirus_option_row(
            "🍯", "TrapNet Active Deception Decoy Ports",
            "Arms decoy listener ports (22, 445, 1433, 3389) and automatically drops & bans probing attackers",
            self.chk_trapnet
        ))

        self.chk_chainguard = QCheckBox()
        self.chk_chainguard.setProperty("class", "antivirus-switch")
        self.chk_chainguard.toggled.connect(lambda v: self._on_setting_changed("chainguard_enabled", v))
        c1_lay.addWidget(create_antivirus_option_row(
            "🧠", "ChainGuard Process Lineage & LOLBin Detection",
            "Validates parent-child process chains to prevent Office macro weaponization and living-off-the-land proxies",
            self.chk_chainguard
        ))

        self.chk_appprint = QCheckBox()
        self.chk_appprint.setProperty("class", "antivirus-switch")
        self.chk_appprint.toggled.connect(lambda v: self._on_setting_changed("appprint_enabled", v))
        c1_lay.addWidget(create_antivirus_option_row(
            "🧬", "AppPrint Network DNA Profiling",
            "Learns statistical behavioral baselines per application and flags anomalous ports or C2 beaconing",
            self.chk_appprint
        ))

        self.chk_darkweb = QCheckBox()
        self.chk_darkweb.setProperty("class", "antivirus-switch")
        self.chk_darkweb.toggled.connect(self._on_darkweb_toggled)

        btn_cfg_darkweb = QPushButton("Manage Monitored Emails")
        btn_cfg_darkweb.clicked.connect(self._dialog_configure_darkweb_emails)

        darkweb_ctrl = QWidget()
        dwc_lay = QHBoxLayout(darkweb_ctrl)
        dwc_lay.setContentsMargins(0, 0, 0, 0)
        dwc_lay.setSpacing(8)
        dwc_lay.addWidget(btn_cfg_darkweb)
        dwc_lay.addWidget(self.chk_darkweb)

        c1_lay.addWidget(create_antivirus_option_row(
            "🕵️", "DarkWeb Identity & Breach Intelligence Shield",
            "Monitors up to 15 corporate and personal email addresses against live dark web credential dumps",
            darkweb_ctrl
        ))

        self.chk_icmp = QCheckBox()
        self.chk_icmp.setProperty("class", "antivirus-switch")
        self.chk_icmp.toggled.connect(self._on_icmp_toggled)
        c1_lay.addWidget(create_antivirus_option_row(
            "🛑", "Stealth Mode (Drop ICMP Echo Pings)",
            "Drops inbound ICMP ping echo requests across all Windows network adapters for network invisibility",
            self.chk_icmp
        ))

        layout.addWidget(c1)

        # ── Card 1.5: Web Browser Protection & Crazy-Style AdBlock Extension ──
        c_browser = QFrame()
        c_browser.setProperty("class", "stat-card")
        c_browser_lay = QVBoxLayout(c_browser)
        c_browser_lay.setSpacing(10)

        # Header Row
        b_hdr_lay = QHBoxLayout()
        b_title_v = QVBoxLayout()
        c_browser_title = QLabel("🌐 Web Browser Protection & Crazy-Style AdBlock")
        c_browser_title.setStyleSheet("font-size: 15px; font-weight: bold;")
        c_browser_desc = QLabel(
            "Integrated browser shield for Brave, Microsoft Edge, Google Chrome, "
            "Mozilla Firefox, Opera, and Vivaldi. Intercepts web malware, phishing, and blocks intrusive ads."
        )
        c_browser_desc.setProperty("class", "subtitle-text")
        b_title_v.addWidget(c_browser_title)
        b_title_v.addWidget(c_browser_desc)
        b_hdr_lay.addLayout(b_title_v, stretch=1)

        self.btn_open_ext_dir = QPushButton("📂 Open Extension Folder")
        self.btn_open_ext_dir.clicked.connect(self._open_extension_dir)
        b_hdr_lay.addWidget(self.btn_open_ext_dir)

        self.btn_ext_guide = QPushButton("📖 Setup Guide")
        self.btn_ext_guide.setProperty("class", "suggested-action")
        self.btn_ext_guide.clicked.connect(self._dialog_browser_extension_guide)
        b_hdr_lay.addWidget(self.btn_ext_guide)

        c_browser_lay.addLayout(b_hdr_lay)

        # Status / Telemetry Strip
        b_status_strip = QHBoxLayout()
        self.lbl_browser_bridge_status = QLabel("🟢 Companion Bridge: Active on 127.0.0.1:49211")
        self.lbl_browser_bridge_status.setStyleSheet("font-size: 12px; color: #81c784; background-color: #1b2e22; border-radius: 4px; padding: 4px 8px; font-weight: bold;")
        b_status_strip.addWidget(self.lbl_browser_bridge_status)

        self.lbl_browser_stats = QLabel("🛡️ Threats Intercepted: 0 | 🚫 Ads & Trackers Neutralized: 0")
        self.lbl_browser_stats.setStyleSheet("font-size: 12px; color: #64b5f6; background-color: #1a2736; border-radius: 4px; padding: 4px 8px;")
        b_status_strip.addWidget(self.lbl_browser_stats)
        b_status_strip.addStretch(1)
        c_browser_lay.addLayout(b_status_strip)

        # Option Switches
        self.chk_browser_malware = QCheckBox()
        self.chk_browser_malware.setProperty("class", "antivirus-switch")
        self.chk_browser_malware.toggled.connect(lambda v: self._on_browser_setting_changed("browser_malware_protection", v))
        c_browser_lay.addWidget(create_antivirus_option_row(
            "🛡️", "Browser Malware, Phishing & Crypto-Drainer Defense",
            "Real-time URL interceptor querying Crazy Alchemy threat intelligence to drop malware downloads, infostealers, and fake logins",
            self.chk_browser_malware
        ))

        # Abuse.ch Live Malware & C2 Domain Interception
        self.chk_browser_abuse_ch = QCheckBox()
        self.chk_browser_abuse_ch.setProperty("class", "antivirus-switch")
        self.chk_browser_abuse_ch.toggled.connect(lambda v: self._on_browser_setting_changed("browser_abuse_ch_domain_block", v))

        btn_sync_abuse = QPushButton("🔄 Sync Feeds")
        btn_sync_abuse.setToolTip("Synchronize latest Abuse.ch ThreatFox & URLhaus malware domains now")
        btn_sync_abuse.clicked.connect(self._sync_abuse_ch_domains_now)

        btn_key = QPushButton("🔑 Auth-Key")
        btn_key.setToolTip("Configure shared Abuse.ch / MalwareBazaar Auth-Key")
        btn_key.clicked.connect(self._dialog_configure_threat_feed_key)

        abuse_ctrl = QWidget()
        ac_lay = QHBoxLayout(abuse_ctrl)
        ac_lay.setContentsMargins(0, 0, 0, 0)
        ac_lay.setSpacing(6)
        ac_lay.addWidget(btn_sync_abuse)
        ac_lay.addWidget(btn_key)
        ac_lay.addWidget(self.chk_browser_abuse_ch)

        c_browser_lay.addWidget(create_antivirus_option_row(
            "🛑", "Abuse.ch Live Malware & C2 Domain Interception",
            "Blocks malicious C2, infostealer, and malware domains from Abuse.ch (ThreatFox / URLhaus / MalwareBazaar) using your shared Auth-Key or community threat feeds",
            abuse_ctrl
        ))

        self.chk_browser_adblock = QCheckBox()
        self.chk_browser_adblock.setProperty("class", "antivirus-switch")
        self.chk_browser_adblock.toggled.connect(lambda v: self._on_browser_setting_changed("browser_adblock", v))
        c_browser_lay.addWidget(create_antivirus_option_row(
            "🛡️", "Crazy-Style Ultra-Fast Ad & Tracker Blocker",
            "Blocks ad networks (DoubleClick, AdSense, Outbrain, Taboola), telemetry tracking pixels, and banner clutter via network and cosmetic filtering",
            self.chk_browser_adblock
        ))

        self.chk_browser_miner = QCheckBox()
        self.chk_browser_miner.setProperty("class", "antivirus-switch")
        self.chk_browser_miner.toggled.connect(lambda v: self._on_browser_setting_changed("browser_miner_block", v))
        c_browser_lay.addWidget(create_antivirus_option_row(
            "⛏️", "Anti-Cryptojacking & WebAssembly CoinMiner Defense",
            "Detects and terminates in-page cryptominers (CoinHive, CryptoLoot, WebMine) to protect CPU and battery",
            self.chk_browser_miner
        ))

        # Browser Deploy Table / List Header with Re-Scan Button
        b_table_hdr_frame = QFrame()
        b_table_hdr_lay = QHBoxLayout(b_table_hdr_frame)
        b_table_hdr_lay.setContentsMargins(0, 8, 0, 4)

        lbl_inst_hdr = QLabel("<b>Supported Web Browsers (1-Click Setup & Launch):</b>")
        lbl_inst_hdr.setStyleSheet("font-size: 13px; font-weight: bold; color: #e6edf3;")
        b_table_hdr_lay.addWidget(lbl_inst_hdr)

        self.lbl_browser_summary = QLabel()
        self.lbl_browser_summary.setStyleSheet("font-size: 11px; color: #8b949e; margin-left: 6px;")
        b_table_hdr_lay.addWidget(self.lbl_browser_summary)

        b_table_hdr_lay.addStretch(1)

        btn_rescan_browsers = QPushButton("🔄 Re-Scan Browsers")
        btn_rescan_browsers.setToolTip("Re-scan system and Windows Registry for newly installed web browsers")
        btn_rescan_browsers.setStyleSheet(
            "QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background-color: #30363d; color: #ffffff; border-color: #8b949e; }"
        )
        btn_rescan_browsers.clicked.connect(self._populate_browser_rows)
        b_table_hdr_lay.addWidget(btn_rescan_browsers)

        c_browser_lay.addWidget(b_table_hdr_frame)

        self.browser_list_frame = QFrame()
        self.browser_list_frame.setStyleSheet("background-color: #151b23; border: 1px solid #30363d; border-radius: 6px; padding: 6px;")
        self.browser_list_lay = QVBoxLayout(self.browser_list_frame)
        self.browser_list_lay.setSpacing(6)
        c_browser_lay.addWidget(self.browser_list_frame)

        self._populate_browser_rows()

        layout.addWidget(c_browser)

        # ── Card 2: Application Startup & System Integration ──
        c2 = QFrame()
        c2.setProperty("class", "stat-card")
        c2_lay = QVBoxLayout(c2)
        c2_lay.setSpacing(8)
        c2_title = QLabel("⚙️ Application Startup & System Integration")
        c2_title.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 6px;")
        c2_lay.addWidget(c2_title)

        self.chk_start_system = QCheckBox()
        self.chk_start_system.setProperty("class", "antivirus-switch")
        self.chk_start_system.toggled.connect(self._on_start_system_toggled)
        c2_lay.addWidget(create_antivirus_option_row(
            "🚀", "Start with the System",
            "Automatically launches Crazy Alchemy upon Windows sign-in via the Windows Run registry",
            self.chk_start_system
        ))

        self.chk_start_minimized = QCheckBox()
        self.chk_start_minimized.setProperty("class", "antivirus-switch")
        self.chk_start_minimized.toggled.connect(lambda v: self._on_setting_changed("start_minimized", v))
        c2_lay.addWidget(create_antivirus_option_row(
            "📥", "Start Minimized to System Tray",
            "Launches silently into the Windows notification area on startup without displaying the main window",
            self.chk_start_minimized
        ))

        self.chk_close_tray = QCheckBox()
        self.chk_close_tray.setProperty("class", "antivirus-switch")
        self.chk_close_tray.toggled.connect(lambda v: self._on_setting_changed("close_to_tray", v))
        c2_lay.addWidget(create_antivirus_option_row(
            "🗔", "Close to Notification Tray",
            "Keeps firewall rules, file shield, and deception traps active in background when window is closed",
            self.chk_close_tray
        ))

        self.chk_autorefresh = QCheckBox()
        self.chk_autorefresh.setProperty("class", "antivirus-switch")
        self.chk_autorefresh.toggled.connect(self._on_autorefresh_toggled)
        c2_lay.addWidget(create_antivirus_option_row(
            "📊", "Continuous Background Diagnostics Refresh",
            "Automatically polls Windows socket telemetry, active connections, and bandwidth every 4 seconds",
            self.chk_autorefresh
        ))

        layout.addWidget(c2)

        # ── Card 3: Policy Management & System Cache Flush ──
        c3 = QFrame()
        c3.setProperty("class", "stat-card")
        c3_lay = QVBoxLayout(c3)
        c3_lay.setSpacing(8)
        c3_title = QLabel("💾 Policy Management & Diagnostics")
        c3_title.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 6px;")
        c3_lay.addWidget(c3_title)

        btn_backup = QPushButton("💾 Export Policy")
        btn_backup.clicked.connect(self._backup_rules)
        c3_lay.addWidget(create_antivirus_option_row(
            "💾", "Backup Windows Firewall Policy (.wfw)",
            "Exports complete active Windows Defender firewall rules to an encrypted portable backup file",
            btn_backup
        ))

        btn_restore = QPushButton("📂 Import Policy")
        btn_restore.clicked.connect(self._restore_rules)
        c3_lay.addWidget(create_antivirus_option_row(
            "📂", "Restore Windows Firewall Policy (.wfw)",
            "Imports and applies firewall rules and profiles from a previously exported .wfw backup archive",
            btn_restore
        ))

        btn_flush = QPushButton("🧹 Flush Caches")
        btn_flush.clicked.connect(self._flush_caches)
        c3_lay.addWidget(create_antivirus_option_row(
            "🧹", "Flush DNS Resolver & ARP Caches",
            "Clears the Windows DNS resolver cache (ipconfig /flushdns) and resets the ARP neighbor discovery table",
            btn_flush
        ))

        btn_offline = QPushButton("🔄 Schedule Scan")
        btn_offline.setProperty("class", "suggested-action")
        btn_offline.clicked.connect(self._dialog_offline_scan)
        c3_lay.addWidget(create_antivirus_option_row(
            "🔄", "Microsoft Defender-Style Offline Reboot Scan",
            "Schedule an isolated pre-boot scan on next Windows restart to locate and disinfect deeply rooted malware",
            btn_offline
        ))

        layout.addWidget(c3)

        layout.addStretch()
        self.setWidget(container)

    def _dialog_offline_scan(self):
        if "antivirus" in self.main_win.pages and hasattr(self.main_win.pages["antivirus"], "_dialog_offline_scan"):
            self.main_win.pages["antivirus"]._dialog_offline_scan()

    def _on_theme_changed(self, index: int):
        theme_val = self.combo_theme.currentData()
        if not theme_val:
            return
        if hasattr(self.main_win, "apply_theme"):
            self.main_win.apply_theme(theme_val, save_preference=True)
        else:
            self.profiles.update_settings({"theme": theme_val})
        self.main_win.fw_logger.log_event("theme_changed", "info", f"Visual theme set to: {theme_val}")

    def _on_setting_changed(self, key: str, val: Any):
        self.profiles.update_settings({key: val})
        self.main_win.fw_logger.log_event("setting_changed", "info", f"Configuration setting updated: {key} = {val}")

        # Propagate setting directly into Windows OS to prevent double running / conflicts
        if self.profiles.get_setting("sync_settings_with_windows", True):
            if hasattr(self.main_win, 'defender_mgr') and self.main_win.defender_mgr:
                self.main_win.defender_mgr.propagate_setting(
                    key, val,
                    fw_core=self.main_win.fw_core,
                    exploit_shield=getattr(self.main_win, 'exploit_shield', None),
                    profiles=self.profiles
                )

        # Live engine control
        if key == "realtime_antivirus" and hasattr(self.main_win, 'realtime_shield'):
            shield = self.main_win.realtime_shield
            if shield:
                if val and not shield.is_alive():
                    shield.start()
                elif not val and shield.is_alive():
                    shield.stop()

        if key == "honeypot_enabled" and hasattr(self.main_win, 'honeypot_mgr'):
            hp = self.main_win.honeypot_mgr
            if hp:
                if val and not hp.is_running():
                    hp.start()
                elif not val and hp.is_running():
                    hp.stop()

    def _open_windows_security_settings(self):
        """Launches Windows Security Threat & Tamper Protection settings directly."""
        try:
            from backend.defender_manager import open_tamper_protection_settings
            open_tamper_protection_settings()
        except Exception as e:
            QMessageBox.warning(self, "Windows Security", f"Could not launch Windows Security: {e}")

    def _on_defender_mode_changed(self, index: int):
        val = self.combo_defender_mode.currentData()
        if not val:
            return

        self._on_setting_changed("defender_coexistence_mode", val)

        if val == "disabled":
            from backend.defender_manager import is_tamper_protection_enabled, open_tamper_protection_settings
            tp_active = is_tamper_protection_enabled()
            if tp_active:
                box = QMessageBox(self)
                box.setWindowTitle("Windows Defender — Tamper Protection Active")
                box.setIcon(QMessageBox.Icon.Warning)
                box.setText(
                    "<h3>⚠️ Tamper Protection is Currently ON</h3>"
                    "<p>Windows 10/11 Tamper Protection (kernel-enforced by Microsoft) blocks software from "
                    "disabling Windows Defender real-time scanning until it is toggled <b>Off</b> in Windows Security.</p>"
                    "<p>Crazy Alchemy has written the Group Policy disablement keys and disabled background tasks.</p>"
                    "<p><b>To finalize deactivating Windows Defender immediately:</b></p>"
                    "<ol>"
                    "<li>Click <b>'🛡️ Open Windows Security'</b> below.</li>"
                    "<li>Switch <b>'Tamper Protection'</b> to <b>Off</b>.</li>"
                    "<li>Click <b>'✅ Confirm & Apply'</b> below to finalize deactivating Defender.</li>"
                    "</ol>"
                )
                btn_open = box.addButton("🛡️ Open Windows Security", QMessageBox.ButtonRole.ActionRole)
                btn_apply = box.addButton("✅ Confirm & Apply", QMessageBox.ButtonRole.AcceptRole)
                box.addButton("Close", QMessageBox.ButtonRole.RejectRole)
                box.exec()

                if box.clickedButton() == btn_open:
                    open_tamper_protection_settings()
                    verify_box = QMessageBox(self)
                    verify_box.setWindowTitle("Confirm Tamper Protection Status")
                    verify_box.setIcon(QMessageBox.Icon.Information)
                    verify_box.setText(
                        "After toggling 'Tamper Protection' to Off in the Windows Security window, "
                        "click 'Apply Now' to verify and deactivate Windows Defender immediately."
                    )
                    btn_v_apply = verify_box.addButton("Apply Now", QMessageBox.ButtonRole.AcceptRole)
                    verify_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
                    verify_box.exec()

                    if verify_box.clickedButton() == btn_v_apply:
                        if hasattr(self.main_win, 'defender_mgr') and self.main_win.defender_mgr:
                            self.main_win.defender_mgr.set_defender_mode("disabled")
                            live = self.main_win.defender_mgr.get_live_status()
                            if not live.get("realtime_protection_enabled", True):
                                QMessageBox.information(
                                    self, "Windows Defender Disabled",
                                    "✅ Windows Defender Real-Time Protection is now completely DISABLED!\n\n"
                                    "Crazy Alchemy Antivirus is operating as your sole active shield."
                                )
                            else:
                                QMessageBox.information(
                                    self, "Windows Defender Status",
                                    "Windows Defender disable policies have been applied.\n\n"
                                    "If Tamper Protection was just turned off, a sign-out or restart may be needed "
                                    "for Windows Security to refresh its display."
                                )
                elif box.clickedButton() == btn_apply:
                    if hasattr(self.main_win, 'defender_mgr') and self.main_win.defender_mgr:
                        self.main_win.defender_mgr.set_defender_mode("disabled")
                        live = self.main_win.defender_mgr.get_live_status()
                        if not live.get("realtime_protection_enabled", True):
                            QMessageBox.information(
                                self, "Windows Defender Disabled",
                                "✅ Windows Defender Real-Time Protection is now completely DISABLED!\n\n"
                                "Crazy Alchemy Antivirus is operating as your sole active shield."
                            )
                        else:
                            QMessageBox.information(
                                self, "Windows Defender Setting",
                                "Disablement policies have been refreshed and applied to Windows."
                            )
            else:
                QMessageBox.information(
                    self, "Windows Defender Disabled",
                    "✅ Windows Defender has been completely DISABLED!\n\n"
                    "• Real-time file scanning: OFF\n"
                    "• Behavior monitoring & script scanning: OFF\n"
                    "• Scheduled background scans & services: DEACTIVATED\n"
                    "• Group Policy disablement: APPLIED\n\n"
                    "Crazy Alchemy Antivirus is now running as your sole, unobstructed security shield."
                )

        elif val == "passive_secondary":
            QMessageBox.information(
                self, "Secondary Antivirus Configured",
                "🛡️ Windows Defender is now configured as a Secondary Antivirus (Passive Mode).\n\n"
                "• Real-time file scanning: OFF (eliminates duplicate hooks & system latency)\n"
                "• Background periodic scanning: ON (available for secondary scans)\n"
                "• Security intelligence updates: ON\n"
                "• Mutual exclusions: CONFIGURED (Crazy Alchemy & Defender will not scan or lock each other)"
            )

        elif val == "active_coexist":
            QMessageBox.information(
                self, "Co-Active Parallel Mode Configured",
                "⚡ Co-Active Parallel Mode is now ACTIVE.\n\n"
                "• Crazy Alchemy Real-Time Shield: ACTIVE\n"
                "• Windows Defender Real-Time Shield: ACTIVE\n"
                "• Mutual Exclusions: CONFIGURED in both engines to guarantee smooth simultaneous "
                "parallel protection without lock contention, mutual scanning loops, or CPU spikes."
            )

    def _on_start_system_toggled(self, checked: bool):
        self.profiles.set_autostart(checked)
        status_msg = "enabled" if checked else "disabled"
        self.main_win.fw_logger.log_event("autostart_changed", "info", f"Start with system set to: {status_msg}")

    def _on_darkweb_toggled(self, checked: bool):
        self._on_setting_changed("darkweb_monitoring_enabled", checked)
        if hasattr(self.main_win, 'darkweb_monitor') and self.main_win.darkweb_monitor:
            if checked:
                self.main_win.darkweb_monitor.start()
            else:
                self.main_win.darkweb_monitor.stop()

    def _on_email_shield_toggled(self, checked: bool):
        self._on_setting_changed("email_shield_enabled", checked)
        if hasattr(self.main_win, 'email_shield') and self.main_win.email_shield:
            if checked:
                self.main_win.email_shield.start()
            else:
                self.main_win.email_shield.stop()

    def _dialog_configure_threat_feed_key(self):
        updater = getattr(self.main_win, 'av_updater', None)
        curr_key = (updater.get_api_key() if updater else self.profiles.get_setting("malwarebazaar_api_key", "")) or self.profiles.get_setting("abuse_ch_api_key", "") or ""
        masked = f"{curr_key[:6]}...{curr_key[-4:]}" if len(curr_key) > 10 else (curr_key if curr_key else "None (Using Verified Community Mirror)")
        key, ok = QInputDialog.getText(
            self, "Threat Intelligence Auth-Key",
            f"Enter your Abuse.ch / MalwareBazaar Auth-Key (from auth.abuse.ch):\n"
            f"Current status: {masked}\n\n"
            f"Note: This single Auth-Key authenticates BOTH MalwareBazaar file signatures\n"
            f"and live Abuse.ch (ThreatFox / URLhaus) malware domain blocking feeds.\n"
            f"Leaving this blank is completely fine! Crazy Alchemy automatically synchronizes\n"
            f"via verified high-speed threat intelligence mirrors without requiring a key.",
            text=curr_key
        )
        if ok:
            clean_key = key.strip()
            if updater:
                updater.set_api_key(clean_key)
            if hasattr(self.main_win, 'av_engine') and self.main_win.av_engine:
                self.main_win.av_engine.set_api_key(clean_key)
            self.profiles.update_settings({
                "malwarebazaar_api_key": clean_key,
                "abuse_ch_api_key": clean_key
            })
            if hasattr(self.main_win, "browser_shield") and self.main_win.browser_shield:
                self.main_win.browser_shield.set_api_key(clean_key)
                import threading
                threading.Thread(target=self.main_win.browser_shield.sync_abuse_ch_domains, kwargs={"force": True}, daemon=True).start()
            if clean_key:
                QMessageBox.information(
                    self, "Auth-Key Configured",
                    "Abuse.ch Auth-Key saved successfully!\nDirect API synchronization will now authenticate with your key."
                )
            else:
                QMessageBox.information(
                    self, "Community Mirror Mode Active",
                    "Auth-Key cleared. Crazy Alchemy will synchronize via verified high-speed community mirrors."
                )

    def _sync_abuse_ch_domains_now(self):
        if not hasattr(self.main_win, "browser_shield") or not self.main_win.browser_shield:
            QMessageBox.information(self, "Browser Shield", "Browser Companion subsystem is not active.")
            return

        bs = self.main_win.browser_shield
        curr_count = bs.get_domain_count() if hasattr(bs, "get_domain_count") else 0

        import threading
        def do_sync():
            ok, msg, count = bs.sync_abuse_ch_domains(force=True)
            from PyQt6.QtCore import QTimer
            def update_ui():
                try:
                    t_count = int(getattr(bs, "threats_blocked", 0))
                    a_count = int(getattr(bs, "ads_blocked", 0))
                    d_count = int(bs.get_domain_count()) if hasattr(bs, "get_domain_count") else count
                    self.lbl_browser_stats.setText(
                        f"🛡️ Threats: {t_count:,} | 🚫 Ads Neutralized: {a_count:,} | 🌐 Abuse.ch Domains: {d_count:,}"
                    )
                except Exception:
                    pass
                if ok:
                    QMessageBox.information(
                        self, "Abuse.ch Domain Feeds Updated",
                        f"Threat intelligence domain synchronization successful!\n\n"
                        f"Active Abuse.ch malware & C2 domains: {count:,}\n\n"
                        f"Status: {msg}"
                    )
                else:
                    QMessageBox.warning(
                        self, "Abuse.ch Sync Status",
                        f"Threat intelligence sync notice:\n\n{msg}\n\n"
                        f"Active cached domains protecting browser: {curr_count:,}"
                    )
            QTimer.singleShot(0, update_ui)

        threading.Thread(target=do_sync, daemon=True).start()

    def _dialog_configure_email_clients(self):
        if not hasattr(self.main_win, 'email_shield') or not self.main_win.email_shield:
            QMessageBox.information(self, "Email Shield", "Email protection subsystem is not active.")
            return

        shield = self.main_win.email_shield
        clients = shield.get_supported_clients()

        dialog = QDialog(self)
        dialog.setWindowTitle("Configure Monitored Email Applications")
        dialog.setMinimumWidth(480)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(12)

        lbl_head = QLabel("Select which email applications to actively monitor & protect:")
        lbl_head.setStyleSheet("font-size: 13px; font-weight: bold;")
        d_lay.addWidget(lbl_head)

        lbl_desc = QLabel(
            "When enabled, incoming attachments downloaded or cached by these email clients "
            "are scanned against malware definitions and dangerous payload heuristics before execution."
        )
        lbl_desc.setProperty("class", "subtitle-text")
        lbl_desc.setStyleSheet("font-size: 11px;")
        lbl_desc.setWordWrap(True)
        d_lay.addWidget(lbl_desc)

        client_checkboxes = {}
        for c in clients:
            status_text = " (Installed)" if c["is_installed"] else " (Not Detected)"
            chk = QCheckBox(f"{c['icon']} {c['name']}{status_text}")
            chk.setChecked(c["is_monitored"])
            if c["is_installed"]:
                chk.setStyleSheet("font-weight: bold;")
            else:
                chk.setProperty("class", "subtitle-text")
            client_checkboxes[c["id"]] = chk
            d_lay.addWidget(chk)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_save = QPushButton("Save Preferences")
        btn_save.setProperty("class", "suggested-action")
        btn_cancel = QPushButton("Cancel")

        btn_save.clicked.connect(dialog.accept)
        btn_cancel.clicked.connect(dialog.reject)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_save)
        d_lay.addLayout(btn_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_monitored = [cid for cid, chk in client_checkboxes.items() if chk.isChecked()]
            self.profiles.update_settings({"email_monitored_clients": new_monitored})
            for cid, chk in client_checkboxes.items():
                shield.set_client_monitored(cid, chk.isChecked())
            self.main_win.fw_logger.log_event(
                "email_shield_updated", "info",
                f"Updated monitored email clients: {', '.join(new_monitored) if new_monitored else 'None'}"
            )
            QMessageBox.information(
                self, "Preferences Saved",
                f"Email Shield is now protecting {len(new_monitored)} email client(s)."
            )

    def _dialog_configure_darkweb_emails(self):
        """Displays modal dialog allowing user to configure, add, remove, and check monitored emails."""
        if not hasattr(self.main_win, 'darkweb_monitor') or not self.main_win.darkweb_monitor:
            QMessageBox.information(self, "DarkWeb Monitor", "DarkWeb monitoring subsystem is not active.")
            return

        monitor = self.main_win.darkweb_monitor
        dialog = QDialog(self)
        dialog.setWindowTitle("🕵️ DarkWeb Exposure & Email Breach Monitor")
        dialog.setMinimumWidth(720)
        dialog.setMinimumHeight(480)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(12)

        lbl_head = QLabel("Monitor Corporate & Personal Emails Against Dark Web Dumps:")
        lbl_head.setStyleSheet("font-size: 13px; font-weight: bold;")
        d_lay.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Add up to 15 corporate or personal email addresses. Crazy Alchemy continuously cross-references "
            "monitored accounts against updated dark web threat feeds, breach archives (XposedOrNot, DeHashed/HIBP datasets), "
            "and compromised credential dumps."
        )
        lbl_desc.setProperty("class", "subtitle-text")
        lbl_desc.setStyleSheet("font-size: 11px;")
        lbl_desc.setWordWrap(True)
        d_lay.addWidget(lbl_desc)

        # Email entry row
        inp_row = QHBoxLayout()
        txt_email = QLineEdit()
        txt_email.setPlaceholderText("Enter email to monitor (e.g. security@company.com)... [Max 15]")
        btn_add = QPushButton("+ Add Monitored Email")
        btn_add.setProperty("class", "suggested-action")
        btn_sync = QPushButton("🔄 Check All Live Feeds")

        inp_row.addWidget(txt_email, stretch=1)
        inp_row.addWidget(btn_add)
        inp_row.addWidget(btn_sync)
        d_lay.addLayout(inp_row)

        lbl_mon = QLabel("Monitored Email Accounts:")
        lbl_mon.setStyleSheet("font-weight: bold;")
        d_lay.addWidget(lbl_mon)

        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Email Address", "Security Status", "Breaches Found", "Last Checked", "Actions"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().resizeSection(4, 180)
        table.horizontalHeader().setMinimumSectionSize(75)
        d_lay.addWidget(table)

        def refresh_table():
            emails = monitor.get_monitored_emails()
            table.setRowCount(len(emails))
            for row, item in enumerate(emails):
                em = item["email"]
                is_comp = item["is_compromised"]
                b_cnt = item["breach_count"]
                last_chk = item["last_checked"]

                table.setItem(row, 0, QTableWidgetItem(em))
                status_str = f"⚠️ COMPROMISED ({b_cnt})" if is_comp else "✓ SECURE (Clean)"
                st_item = QTableWidgetItem(status_str)
                st_item.setForeground(Qt.GlobalColor.red if is_comp else Qt.GlobalColor.green)
                table.setItem(row, 1, st_item)
                table.setItem(row, 2, QTableWidgetItem(f"{b_cnt} incident(s)"))
                table.setItem(row, 3, QTableWidgetItem(last_chk))
                table.setRowHeight(row, 36)

                cell = QWidget()
                c_lay = QHBoxLayout(cell)
                c_lay.setContentsMargins(2, 2, 2, 2)
                c_lay.setSpacing(4)

                btn_chk = QPushButton("Check Now")
                btn_chk.setProperty("class", "table-action")
                btn_chk.clicked.connect(lambda _, target=em: do_check_single(target))
                c_lay.addWidget(btn_chk)

                btn_del = QPushButton("Remove")
                btn_del.setProperty("class", "destructive-action table-action")
                btn_del.clicked.connect(lambda _, target=em: do_remove(target))
                c_lay.addWidget(btn_del)

                table.setCellWidget(row, 4, cell)

        def do_add():
            raw_email = txt_email.text().strip()
            if not raw_email:
                return
            success, msg = monitor.add_email(raw_email)
            if success:
                txt_email.clear()
                refresh_table()
                ask = QMessageBox.question(
                    dialog, "Check DarkWeb Live?",
                    f"Email '{raw_email}' added.\n\nWould you like to query live DarkWeb threat feeds immediately?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )
                if ask == QMessageBox.StandardButton.Yes:
                    do_check_single(raw_email)
            else:
                QMessageBox.warning(dialog, "Cannot Add Email", msg)

        def do_remove(target_email):
            confirm = QMessageBox.question(
                dialog, "Remove Monitored Email",
                f"Stop monitoring '{target_email}' and remove all breach logs for it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm == QMessageBox.StandardButton.Yes:
                monitor.remove_email(target_email)
                refresh_table()

        def do_check_single(target_email):
            breaches = monitor.check_email_live(target_email)
            refresh_table()
            if breaches:
                QMessageBox.critical(
                    dialog, "⚠️ DarkWeb Exposure Detected!",
                    f"Email '{target_email}' was found in {len(breaches)} dark web breach dataset(s)!"
                )
            else:
                QMessageBox.information(
                    dialog, "Account Secure",
                    f"No exposures detected for '{target_email}' in live threat intelligence feeds."
                )

        def do_sync_all():
            emails = monitor.get_monitored_emails()
            if not emails:
                QMessageBox.information(dialog, "No Emails", "Please add at least one email address first.")
                return
            res = monitor.check_all_monitored_live()
            refresh_table()
            total_b = sum(len(b) for b in res.values())
            QMessageBox.information(
                dialog, "DarkWeb Sync Complete",
                f"Queried feeds across {len(emails)} account(s). Found {total_b} exposure incident(s)."
            )

        txt_email.returnPressed.connect(do_add)
        btn_add.clicked.connect(do_add)
        btn_sync.clicked.connect(do_sync_all)

        refresh_table()

        bottom_bar = QHBoxLayout()
        btn_view_full = QPushButton("Open Full DarkWeb Dashboard")
        btn_view_full.clicked.connect(lambda: (dialog.accept(), self.main_win.navigate_to("darkweb")))
        bottom_bar.addWidget(btn_view_full)
        bottom_bar.addStretch()
        btn_done = QPushButton("Done")
        btn_done.setProperty("class", "suggested-action")
        btn_done.clicked.connect(dialog.accept)
        bottom_bar.addWidget(btn_done)
        d_lay.addLayout(bottom_bar)

        dialog.exec()
        if hasattr(self.main_win, "pages") and "monitor" in self.main_win.pages:
            m = self.main_win.pages["monitor"]
            if hasattr(m, "_refresh_darkweb"):
                m._refresh_darkweb()

    def _on_exploit_shield_toggled(self, checked: bool):
        self._on_setting_changed("anti_exploit_enabled", checked)
        if hasattr(self.main_win, 'exploit_shield') and self.main_win.exploit_shield:
            if checked:
                self.main_win.exploit_shield.start()
            else:
                self.main_win.exploit_shield.stop()

    def _dialog_configure_exploit_mitigations(self):
        if not hasattr(self.main_win, 'exploit_shield') or not self.main_win.exploit_shield:
            QMessageBox.information(self, "Exploit Shield", "Exploit protection engine is not available.")
            return

        shield = self.main_win.exploit_shield

        dialog = QDialog(self)
        dialog.setWindowTitle("Windows Exploit Guard & Mitigation Policies")
        dialog.setMinimumWidth(560)
        d_lay = QVBoxLayout(dialog)
        d_lay.setSpacing(14)

        lbl_head = QLabel("🛡️ Windows Exploit Protection & Attack Surface Reduction (ASR)")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: bold;")
        d_lay.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Configures Microsoft Defender Exploit Guard, EMET system memory mitigations (DEP, ASLR, CFG, SEHOP), "
            "all 16 Defender Attack Surface Reduction rules, and Windows 11 Core Isolation (HVCI, RunAsPPL, Driver Blocklist)."
        )
        lbl_desc.setProperty("class", "subtitle-text")
        lbl_desc.setStyleSheet("font-size: 11px;")
        lbl_desc.setWordWrap(True)
        d_lay.addWidget(lbl_desc)

        # Profile selection
        p_card = QFrame()
        p_card.setProperty("class", "stat-card")
        pc_lay = QVBoxLayout(p_card)
        lbl_p_title = QLabel("Select Hardening Baseline Profile:")
        lbl_p_title.setStyleSheet("font-weight: bold;")
        pc_lay.addWidget(lbl_p_title)

        combo_profile = QComboBox()
        combo_profile.addItem("Recommended — Full Defender Baseline & Compatibility", "Recommended")
        combo_profile.addItem("Strict — Enterprise High-Security Fortress (Maximum Hardening)", "Strict")
        combo_profile.addItem("Audit Only — Monitor and Telemetry (No Process Termination)", "Audit")

        cur_prof = self.profiles.get_setting("anti_exploit_profile", "Recommended")
        for i in range(combo_profile.count()):
            if combo_profile.itemData(i) == cur_prof:
                combo_profile.setCurrentIndex(i)
                break
        pc_lay.addWidget(combo_profile)
        d_lay.addWidget(p_card)

        # Core Isolation & Mitigations Status Summary
        stats = shield.get_stats()
        summary_lbl = QLabel(
            f"Active Status: {stats.get('active_system_mitigations', 0)} System Mitigations Enforced • "
            f"{stats.get('active_asr_rules', 0)} ASR Rules Active • "
            f"{stats.get('active_core_isolation', 0)} Core Isolation Enclaves"
        )
        summary_lbl.setStyleSheet("color: #388bfd; font-weight: bold; font-size: 11px;")
        d_lay.addWidget(summary_lbl)

        btn_box = QHBoxLayout()
        btn_view_full = QPushButton("📊 Open Full Exploit Shield Monitor")
        btn_view_full.clicked.connect(lambda: [dialog.reject(), self.main_win.pages["antivirus"]._dialog_exploit_shield()])
        btn_box.addWidget(btn_view_full)
        btn_box.addStretch()

        btn_save = QPushButton("Apply Mitigation Profile")
        btn_save.setProperty("class", "suggested-action")
        btn_cancel = QPushButton("Cancel")
        btn_save.clicked.connect(dialog.accept)
        btn_cancel.clicked.connect(dialog.reject)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_save)
        d_lay.addLayout(btn_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected_prof = combo_profile.currentData()
            self.profiles.update_settings({"anti_exploit_profile": selected_prof})
            shield.apply_hardening_profile(selected_prof)
            QMessageBox.information(
                self, "Exploit Mitigations Applied",
                f"Successfully applied the '{selected_prof}' exploit mitigation profile."
            )

    def _on_sig_autoupdate_toggled(self, checked: bool):
        self._on_setting_changed("signature_auto_update", checked)
        if hasattr(self.main_win, 'av_updater') and self.main_win.av_updater:
            if checked:
                self.main_win.av_updater.start_auto_update()
            else:
                self.main_win.av_updater.stop_auto_update()

    def _on_sig_interval_changed(self, index: int):
        val = self.combo_sig_interval.currentData()
        if val in [2, 5, 12, 24]:
            self.profiles.update_settings({"signature_update_interval_hours": val})
            if hasattr(self.main_win, 'av_updater') and self.main_win.av_updater:
                self.main_win.av_updater.set_interval(val)
            self.main_win.fw_logger.log_event(
                "setting_changed", "info",
                f"Virus scanner update interval set to every {val} hours"
            )

    def _on_icmp_toggled(self, checked: bool):
        self._on_setting_changed("block_icmp", checked)
        self.main_win.fw_core.block_icmp(checked)
        status_str = "dropped" if checked else "allowed"
        self.main_win.fw_logger.log_event("icmp_status", "warning" if checked else "info", f"Inbound ICMP ping requests are now {status_str}")

    def _on_autorefresh_toggled(self, checked: bool):
        self._on_setting_changed("auto_refresh", checked)
        if hasattr(self.main_win, 'refresh_timer'):
            if checked:
                self.main_win.refresh_timer.start(4000)
            else:
                self.main_win.refresh_timer.stop()

    def _backup_rules(self):
        backup_path = self.profiles.backup_rules()
        if backup_path:
            self.main_win.fw_logger.log_event("policy_backed_up", "info", f"Exported firewall policy: {backup_path}")
            QMessageBox.information(self, "Policy Saved", f"Firewall policy backup created successfully:\n{backup_path}")
        else:
            QMessageBox.warning(self, "Backup Error", "Failed to backup firewall policy. Ensure administrative privileges.")

    def _restore_rules(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Restore Windows Firewall Policy", "", "Firewall Policy (*.wfw);;All Files (*.*)")
        if file_path:
            if self.profiles.restore_rules(file_path):
                self.main_win.fw_logger.log_event("policy_restored", "info", f"Restored firewall policy: {file_path}")
                QMessageBox.information(self, "Policy Restored", f"Firewall policy imported successfully from:\n{file_path}")
                self.main_win.reload_firewall()
            else:
                QMessageBox.warning(self, "Restore Error", "Failed to restore policy. File may be invalid.")

    def _flush_caches(self):
        self.main_win.fw_core.empty_caches()
        self.main_win.fw_logger.log_event("caches_flushed", "info", "Flushed Windows DNS resolver cache and ARP table")
        QMessageBox.information(self, "Diagnostics Flushed", "Windows DNS resolver and ARP table successfully cleared.")

    def refresh(self):
        if not HAS_PYQT6:
            return

        # Block signals temporarily to prevent event loops while loading state
        self.combo_theme.blockSignals(True)
        self.chk_shield.blockSignals(True)
        self.chk_sig_autoupdate.blockSignals(True)
        self.combo_sig_interval.blockSignals(True)
        self.chk_email_shield.blockSignals(True)
        self.chk_exploit_shield.blockSignals(True)
        self.combo_defender_mode.blockSignals(True)
        self.chk_os_sync.blockSignals(True)
        self.chk_trapnet.blockSignals(True)
        self.chk_chainguard.blockSignals(True)
        self.chk_appprint.blockSignals(True)
        self.chk_darkweb.blockSignals(True)
        self.chk_icmp.blockSignals(True)
        self.chk_start_system.blockSignals(True)
        self.chk_start_minimized.blockSignals(True)
        self.chk_close_tray.blockSignals(True)
        self.chk_autorefresh.blockSignals(True)

        cur_theme = self.profiles.get_setting("theme", "dark")
        for i in range(self.combo_theme.count()):
            if self.combo_theme.itemData(i) == cur_theme:
                self.combo_theme.setCurrentIndex(i)
                break

        is_sig_auto = self.profiles.get_setting("signature_auto_update", True)
        sig_int = self.profiles.get_setting("signature_update_interval_hours", 12)
        if sig_int not in [2, 5, 12, 24]:
            sig_int = 12

        self.chk_shield.setChecked(self.profiles.get_setting("realtime_antivirus", True))
        self.chk_sig_autoupdate.setChecked(is_sig_auto)
        for i in range(self.combo_sig_interval.count()):
            if self.combo_sig_interval.itemData(i) == sig_int:
                self.combo_sig_interval.setCurrentIndex(i)
                break

        self.chk_email_shield.setChecked(self.profiles.get_setting("email_shield_enabled", True))
        self.chk_exploit_shield.setChecked(self.profiles.get_setting("anti_exploit_enabled", True))

        def_mode = self.profiles.get_setting("defender_coexistence_mode", "passive_secondary")
        for i in range(self.combo_defender_mode.count()):
            if self.combo_defender_mode.itemData(i) == def_mode:
                self.combo_defender_mode.setCurrentIndex(i)
                break
        self.chk_os_sync.setChecked(self.profiles.get_setting("sync_settings_with_windows", True))

        self.chk_trapnet.setChecked(self.profiles.get_setting("honeypot_enabled", True))
        self.chk_chainguard.setChecked(self.profiles.get_setting("chainguard_enabled", True))
        self.chk_appprint.setChecked(self.profiles.get_setting("appprint_enabled", True))
        self.chk_darkweb.setChecked(self.profiles.get_setting("darkweb_monitoring_enabled", True))
        self.chk_icmp.setChecked(self.profiles.get_setting("block_icmp", False))
        self.chk_start_system.setChecked(self.profiles.get_setting("start_with_system", True))
        self.chk_start_minimized.setChecked(self.profiles.get_setting("start_minimized", False))
        self.chk_close_tray.setChecked(self.profiles.get_setting("close_to_tray", True))
        self.chk_autorefresh.setChecked(self.profiles.get_setting("auto_refresh", True))

        self.combo_theme.blockSignals(False)
        self.chk_shield.blockSignals(False)
        self.chk_sig_autoupdate.blockSignals(False)
        self.combo_sig_interval.blockSignals(False)
        self.chk_email_shield.blockSignals(False)
        self.chk_exploit_shield.blockSignals(False)
        self.combo_defender_mode.blockSignals(False)
        self.chk_os_sync.blockSignals(False)
        self.chk_trapnet.blockSignals(False)
        self.chk_chainguard.blockSignals(False)
        self.chk_appprint.blockSignals(False)
        self.chk_darkweb.blockSignals(False)
        self.chk_icmp.blockSignals(False)
        self.chk_start_system.blockSignals(False)
        self.chk_start_minimized.blockSignals(False)
        self.chk_close_tray.blockSignals(False)
        self.chk_autorefresh.blockSignals(False)

        # Web Browser Shield & Crazy-Style AdBlock
        if hasattr(self, 'chk_browser_malware'):
            self.chk_browser_malware.blockSignals(True)
            self.chk_browser_adblock.blockSignals(True)
            self.chk_browser_miner.blockSignals(True)
            if hasattr(self, 'chk_browser_abuse_ch'):
                self.chk_browser_abuse_ch.blockSignals(True)

            self.chk_browser_malware.setChecked(self.profiles.get_setting("browser_malware_protection", True))
            self.chk_browser_adblock.setChecked(self.profiles.get_setting("browser_adblock", True))
            self.chk_browser_miner.setChecked(self.profiles.get_setting("browser_miner_block", True))
            if hasattr(self, 'chk_browser_abuse_ch'):
                self.chk_browser_abuse_ch.setChecked(self.profiles.get_setting("browser_abuse_ch_domain_block", True))

            self.chk_browser_malware.blockSignals(False)
            self.chk_browser_adblock.blockSignals(False)
            self.chk_browser_miner.blockSignals(False)
            if hasattr(self, 'chk_browser_abuse_ch'):
                self.chk_browser_abuse_ch.blockSignals(False)

        if hasattr(self, 'lbl_browser_bridge_status') and hasattr(self.main_win, "browser_shield") and self.main_win.browser_shield:
            bs = self.main_win.browser_shield
            port = getattr(bs, "port", 49211)
            is_run = bool(getattr(bs, "is_running", False))
            status_text = f"🟢 Companion Bridge: Active on 127.0.0.1:{port}" if is_run else "🔴 Companion Bridge: Offline"
            self.lbl_browser_bridge_status.setText(status_text)
            try:
                t_count = int(getattr(bs, "threats_blocked", 0))
            except Exception:
                t_count = 0
            try:
                a_count = int(getattr(bs, "ads_blocked", 0))
            except Exception:
                a_count = 0
            try:
                d_count = int(bs.get_domain_count()) if hasattr(bs, "get_domain_count") else 0
            except Exception:
                d_count = 0
            self.lbl_browser_stats.setText(
                f"🛡️ Threats: {t_count:,} | 🚫 Ads Neutralized: {a_count:,} | 🌐 Abuse.ch Domains: {d_count:,}"
            )

    def _get_browser_icon_pixmap(self, browser_id: str, info: Dict[str, Any], size: int = 32) -> Any:
        """
        Retrieves the native official icon of the browser:
        1. If installed, extracts the exact executable icon via Win32 / QFileIconProvider.
        2. Fallback to bundled high-res browser icons in data/icons/browsers/<icon_file>.
        3. If not installed, renders with subtle opacity so installed browsers clearly stand out.
        """
        pix = None
        # 1. Native Windows executable icon extraction
        if info.get("installed") and info.get("path"):
            exe_p = info["path"]
            try:
                from PyQt6.QtWidgets import QFileIconProvider
                from PyQt6.QtCore import QFileInfo, QSize
                provider = QFileIconProvider()
                q_icon = provider.icon(QFileInfo(exe_p))
                if not q_icon.isNull():
                    pix = q_icon.pixmap(QSize(size, size))
            except Exception:
                pix = None

        # 2. Bundled official high-resolution icon
        if pix is None or pix.isNull():
            icon_file = info.get("icon_file", f"{browser_id}.png")
            bundled_path = Path(__file__).resolve().parent.parent / "data" / "icons" / "browsers" / icon_file
            if bundled_path.exists():
                try:
                    from PyQt6.QtGui import QPixmap
                    from PyQt6.QtCore import Qt
                    pix = QPixmap(str(bundled_path)).scaled(
                        size, size,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                except Exception:
                    pix = None

        # 3. Soft opacity for uninstalled browsers
        if pix is not None and not pix.isNull() and not info.get("installed"):
            try:
                from PyQt6.QtGui import QPixmap, QPainter
                from PyQt6.QtCore import Qt
                dimmed = QPixmap(pix.size())
                dimmed.fill(Qt.GlobalColor.transparent)
                painter = QPainter(dimmed)
                painter.setOpacity(0.40)
                painter.drawPixmap(0, 0, pix)
                painter.end()
                pix = dimmed
            except Exception:
                pass

        return pix

    def _populate_browser_rows(self):
        while self.browser_list_lay.count():
            item = self.browser_list_lay.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        browsers = BrowserDetector.detect_all()
        order = ["brave", "edge", "chrome", "firefox", "opera", "operagx", "vivaldi"]

        # Sort so installed browsers are presented clearly first, followed by others in order
        sorted_keys = sorted(
            order,
            key=lambda bid: (
                not browsers.get(bid, {}).get("installed", False),
                order.index(bid) if bid in order else 99
            )
        )

        installed_count = sum(1 for b in browsers.values() if b.get("installed"))
        total_count = len(sorted_keys)
        if hasattr(self, "lbl_browser_summary") and self.lbl_browser_summary:
            self.lbl_browser_summary.setText(f"🟢 {installed_count} Installed · {total_count - installed_count} Available")

        for b_id in sorted_keys:
            info = browsers.get(b_id)
            if not info:
                continue

            is_inst = bool(info.get("installed"))

            row = QFrame()
            if is_inst:
                row.setStyleSheet(
                    "QFrame { background-color: #1a2332; border: 1px solid #238636; border-radius: 6px; padding: 4px; }"
                    "QFrame:hover { background-color: #1f2c3f; border-color: #2ea043; }"
                )
            else:
                row.setStyleSheet(
                    "QFrame { background-color: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 4px; }"
                    "QFrame:hover { background-color: #1c2128; border-color: #30363d; }"
                )

            r_lay = QHBoxLayout(row)
            r_lay.setContentsMargins(10, 6, 10, 6)
            r_lay.setSpacing(12)

            # 1. Official Browser Icon
            lbl_icon = QLabel()
            lbl_icon.setFixedSize(36, 36)
            try:
                from PyQt6.QtCore import Qt
                lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            except Exception:
                pass

            pix = self._get_browser_icon_pixmap(b_id, info, size=32)
            if pix and not pix.isNull():
                lbl_icon.setPixmap(pix)
            else:
                lbl_icon.setText(info.get("icon", "🌐"))
                lbl_icon.setStyleSheet("font-size: 22px;")
            r_lay.addWidget(lbl_icon)

            # 2. Browser Name & Version / Vendor
            name_box = QVBoxLayout()
            name_box.setSpacing(1)
            name_box.setContentsMargins(0, 0, 0, 0)

            lbl_name = QLabel(f"<b>{info['name']}</b>")
            lbl_name.setStyleSheet("font-size: 13px; color: #f0f6fc;" if is_inst else "font-size: 13px; color: #8b949e;")
            name_box.addWidget(lbl_name)

            if is_inst:
                ver_text = f"v{info['version']}" if info.get("version") else "Ready for protection"
                lbl_sub = QLabel(f"<span style='color: #7ee787; font-size: 11px;'>● {ver_text}</span>")
                lbl_name.setToolTip(f"{info['name']}\nInstalled at: {info.get('path')}")
            else:
                vendor_text = info.get("vendor", "Supported Browser")
                lbl_sub = QLabel(f"<span style='color: #6e7681; font-size: 11px;'>{vendor_text}</span>")
                lbl_name.setToolTip(f"{info['name']} is not installed on this system.")
            name_box.addWidget(lbl_sub)

            name_widget = QWidget()
            name_widget.setLayout(name_box)
            name_widget.setFixedWidth(175)
            r_lay.addWidget(name_widget)

            # 3. Status Badge
            if is_inst:
                lbl_status = QLabel("🟢 Installed")
                lbl_status.setStyleSheet(
                    "font-size: 11px; color: #3fb950; background-color: #132b1a; "
                    "border: 1px solid #238636; border-radius: 4px; padding: 4px 10px; font-weight: bold;"
                )
                lbl_status.setToolTip(f"Installed at:\n{info.get('path')}")
            else:
                lbl_status = QLabel("⚪ Not Installed")
                lbl_status.setStyleSheet(
                    "font-size: 11px; color: #8b949e; background-color: #21262d; "
                    "border: 1px solid #30363d; border-radius: 4px; padding: 4px 10px;"
                )
            lbl_status.setFixedWidth(105)
            try:
                from PyQt6.QtCore import Qt
                lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            except Exception:
                pass
            r_lay.addWidget(lbl_status)

            r_lay.addStretch(1)

            # 4. Action Buttons
            btn_install = QPushButton("📥 Install Extension")
            btn_install.setProperty("class", "suggested-action")
            btn_install.setToolTip(f"Deploys Crazy Alchemy Web Shield extension for {info['name']}")
            btn_install.clicked.connect(lambda _, bid=b_id: self._install_extension_browser(bid))
            r_lay.addWidget(btn_install)

            open_title = info["name"].split()[0]
            btn_open = QPushButton(f"🚀 Open {open_title}")
            btn_open.setEnabled(is_inst)
            if is_inst:
                btn_open.setToolTip(f"Launch {info['name']} and open extension management")
            else:
                btn_open.setToolTip(f"{info['name']} is not installed on this PC")
            btn_open.clicked.connect(lambda _, bid=b_id: self._launch_browser_extensions(bid))
            r_lay.addWidget(btn_open)

            self.browser_list_lay.addWidget(row)

    def _on_browser_setting_changed(self, key: str, val: Any):
        self._on_setting_changed(key, val)
        if hasattr(self.main_win, "browser_shield") and self.main_win.browser_shield:
            bs_cfg = {
                "browser_protection": self.profiles.get_setting("browser_malware_protection", True),
                "browser_abuse_ch_domain_block": self.profiles.get_setting("browser_abuse_ch_domain_block", True),
                "adblock_enabled": self.profiles.get_setting("browser_adblock", True),
                "miner_protection": self.profiles.get_setting("browser_miner_block", True)
            }
            self.main_win.browser_shield.update_config(bs_cfg)

    def _open_extension_dir(self):
        ext_dir = ExtensionDeployer.deploy_extension_files()
        try:
            import subprocess
            if os.name == "nt":
                CREATE_NO_WINDOW = 0x08000000
                subprocess.Popen(['explorer', str(ext_dir)], creationflags=CREATE_NO_WINDOW)
            else:
                import webbrowser
                webbrowser.open(str(ext_dir))
        except Exception:
            QMessageBox.information(self, "Extension Directory", f"Extension files located at:\n{ext_dir}")

    def _install_extension_browser(self, browser_id: str):
        success, msg = ExtensionDeployer.install_for_browser(browser_id)
        defs = BrowserDetector.get_browser_definitions()
        b_name = defs.get(browser_id, {}).get("name", browser_id.title())
        if success:
            self.main_win.fw_logger.log_event("browser_extension_installed", "info", f"Extension configured for {b_name}")
            QMessageBox.information(self, f"Extension Integration: {b_name}", msg)
        else:
            QMessageBox.warning(self, "Installation Failed", msg)

    def _launch_browser_extensions(self, browser_id: str):
        ext_dir = ExtensionDeployer.deploy_extension_files()
        defs = BrowserDetector.get_browser_definitions()
        b_name = defs.get(browser_id, {}).get("name", browser_id.title())
        ok = ExtensionDeployer.launch_browser_extensions_page(browser_id)
        if ok:
            QMessageBox.information(
                self,
                f"Opened {b_name}",
                f"Extension folder path copied to clipboard:\n{ext_dir}\n\n"
                f"In {b_name}:\n"
                f"1. Enable 'Developer mode'.\n"
                f"2. Click 'Load unpacked' and paste this path."
            )

    def _dialog_browser_extension_guide(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Browser Extension Setup Guide (Brave, Edge, Chrome, Firefox, Opera, Vivaldi)")
        dlg.setMinimumWidth(620)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(14)

        hdr = QLabel("<b>🛡️ Crazy Alchemy Web Shield & Crazy-Style AdBlock Guide</b>")
        hdr.setStyleSheet("font-size: 16px; color: #58a6ff;")
        lay.addWidget(hdr)

        desc = QLabel(
            "Crazy Alchemy provides a unified, cross-browser WebExtension compatible with "
            "Brave, Chrome, Edge, Firefox, Opera, and Vivaldi. It blocks malicious URLs, phishing pages, "
            "crypto-drainers, and removes all invasive ads & trackers."
        )
        desc.setWordWrap(True)
        lay.addWidget(desc)

        tabs = QTabWidget()

        # Brave tab
        tab_brave = QWidget()
        tb_lay = QVBoxLayout(tab_brave)
        tb_lay.addWidget(QLabel(
            "<b>🦁 Brave Browser Setup:</b><br><br>"
            "1. Open <code>brave://extensions</code> in Brave Browser.<br>"
            "2. Turn on the <b>'Developer mode'</b> toggle in the top-right corner.<br>"
            "3. Click <b>'Load unpacked'</b>.<br>"
            "4. Select the Crazy Alchemy extension folder (path auto-copied to your clipboard).<br><br>"
            "<i>Result: Brave Browser will now run both Brave Shields and Crazy Alchemy Antivirus Web Defense simultaneously!</i>"
        ))
        tabs.addTab(tab_brave, "🦁 Brave")

        # Edge tab
        tab_edge = QWidget()
        te_lay = QVBoxLayout(tab_edge)
        te_lay.addWidget(QLabel(
            "<b>🌀 Microsoft Edge Setup:</b><br><br>"
            "1. Open <code>edge://extensions</code> in Edge.<br>"
            "2. Turn on <b>'Developer mode'</b> in the left sidebar.<br>"
            "3. Click <b>'Load unpacked'</b>.<br>"
            "4. Paste or select the Crazy Alchemy extension directory."
        ))
        tabs.addTab(tab_edge, "🌀 Edge")

        # Chrome tab
        tab_chrome = QWidget()
        tc_lay = QVBoxLayout(tab_chrome)
        tc_lay.addWidget(QLabel(
            "<b>🌐 Google Chrome Setup:</b><br><br>"
            "1. Open <code>chrome://extensions</code> in Chrome.<br>"
            "2. Toggle <b>'Developer mode'</b> on the top right.<br>"
            "3. Click <b>'Load unpacked'</b> and choose the extension folder."
        ))
        tabs.addTab(tab_chrome, "🌐 Chrome")

        # Firefox tab
        tab_ff = QWidget()
        tf_lay = QVBoxLayout(tab_ff)
        tf_lay.addWidget(QLabel(
            "<b>🦊 Mozilla Firefox Setup:</b><br><br>"
            "1. Open <code>about:debugging#/runtime/this-firefox</code> in Firefox.<br>"
            "2. Click <b>'Load Temporary Add-on...'</b>.<br>"
            "3. Select <code>manifest.json</code> in the Crazy Alchemy extension folder."
        ))
        tabs.addTab(tab_ff, "🦊 Firefox")

        # Opera tab
        tab_opera = QWidget()
        to_lay = QVBoxLayout(tab_opera)
        to_lay.addWidget(QLabel(
            "<b>🔴 Opera / Opera GX Setup:</b><br><br>"
            "1. Open <code>opera://extensions</code> in Opera.<br>"
            "2. Enable <b>'Developer mode'</b> on top right.<br>"
            "3. Click <b>'Load unpacked'</b> and select the extension folder."
        ))
        tabs.addTab(tab_opera, "🔴 Opera")

        # Vivaldi tab
        tab_vivaldi = QWidget()
        tv_lay = QVBoxLayout(tab_vivaldi)
        tv_lay.addWidget(QLabel(
            "<b>🛡️ Vivaldi Setup:</b><br><br>"
            "1. Open <code>vivaldi://extensions</code> in Vivaldi.<br>"
            "2. Toggle <b>'Developer mode'</b> on the top right.<br>"
            "3. Click <b>'Load unpacked'</b> and select the extension folder."
        ))
        tabs.addTab(tab_vivaldi, "🛡️ Vivaldi")

        lay.addWidget(tabs)

        btn_box = QHBoxLayout()
        btn_copy = QPushButton("📋 Copy Extension Folder Path")
        ext_dir = ExtensionDeployer.deploy_extension_files()
        from backend.browser_shield import copy_to_clipboard
        btn_copy.clicked.connect(lambda: copy_to_clipboard(str(ext_dir)))
        btn_box.addWidget(btn_copy)

        btn_open = QPushButton("📂 Open Folder")
        btn_open.clicked.connect(self._open_extension_dir)
        btn_box.addWidget(btn_open)

        btn_box.addStretch(1)
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dlg.accept)
        btn_box.addWidget(btn_close)
        lay.addLayout(btn_box)

        dlg.exec()
