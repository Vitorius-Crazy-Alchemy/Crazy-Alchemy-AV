"""
Vitorius Firewall Win - Windows 11 Main Application Window
Modern Fluent/Adwaita layout with navigation sidebar, header actions (Panic, Reload),
and stacked page views replicating the Linux workflow 1:1.
"""

import sys
import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger('vitorius.win.app')

try:
    from PyQt6.QtWidgets import (
        QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QListWidget,
        QListWidgetItem, QStackedWidget, QLabel, QPushButton, QFrame,
        QMessageBox, QApplication
    )
    from PyQt6.QtCore import Qt, QTimer, QSize
    from PyQt6.QtGui import QIcon, QCloseEvent, QKeySequence, QShortcut, QPixmap, QPainter, QPainterPath
    HAS_PYQT6 = True
except ImportError:
    HAS_PYQT6 = False
    class QMainWindow: pass
    class QWidget: pass

from ui.styles import (
    FLUENT_DARK_STYLE, FLUENT_LIGHT_STYLE,
    get_theme_stylesheet, get_system_theme
)
from ui.tray_win import WindowsTrayIndicator
from ui.taskbar_win import WindowsTaskbarProgress, set_app_user_model_id


class VitoriusFirewallMainWindow(QMainWindow if HAS_PYQT6 else object):
    """Main Application Window for Windows 11."""

    def __init__(self, fw_core, av_engine, av_updater, monitor, scanner, profiles, fw_logger, project_dir: Path,
                 honeypot_mgr=None, chainguard_engine=None, appprint_engine=None, realtime_shield=None,
                 offline_scanner=None, darkweb_monitor=None, email_shield=None, exploit_shield=None,
                 defender_mgr=None, browser_shield=None):
        if HAS_PYQT6:
            super().__init__()

        self.fw_core = fw_core
        self.av_engine = av_engine
        self.av_updater = av_updater
        self.monitor = monitor
        self.scanner = scanner
        self.profiles = profiles
        self.fw_logger = fw_logger
        self.project_dir = project_dir
        self.honeypot_mgr = honeypot_mgr
        self.chainguard_engine = chainguard_engine
        self.appprint_engine = appprint_engine
        self.realtime_shield = realtime_shield
        self.offline_scanner = offline_scanner
        self.darkweb_monitor = darkweb_monitor
        self.email_shield = email_shield
        self.exploit_shield = exploit_shield
        self.defender_mgr = defender_mgr
        self._force_quit = False

        # Browser Web Shield & Crazy-Style AdBlock Companion
        if browser_shield:
            self.browser_shield = browser_shield
        else:
            try:
                from backend.browser_shield import BrowserCompanionServer, ExtensionDeployer
                ExtensionDeployer.deploy_extension_files()
                self.browser_shield = BrowserCompanionServer(
                    port=49211,
                    fw_logger=self.fw_logger,
                    profiles=self.profiles
                )
                if self.profiles.get_setting("browser_protection", True):
                    self.browser_shield.start()
            except Exception as e:
                logger.debug(f"Browser companion setup notice: {e}")
                self.browser_shield = None

        self.setWindowTitle("Crazy Alchemy")
        self.resize(1120, 740)
        if HAS_PYQT6:
            self.setMinimumSize(960, 640)

        # Set taskbar ID and icons
        set_app_user_model_id()
        self.icon_path = project_dir / "data" / "icons" / "vitorius-firewall.ico"
        self.panic_icon_path = project_dir / "data" / "icons" / "vitorius-panic.ico"

        if HAS_PYQT6 and self.icon_path.exists():
            self.setWindowIcon(QIcon(str(self.icon_path)))

        self.pages = {}
        self.taskbar = WindowsTaskbarProgress()
        self.current_theme = self.profiles.get_setting("theme", "dark")
        self._init_ui()

        # Initialize System Tray
        self.tray = WindowsTrayIndicator(self, self.icon_path, self.panic_icon_path)

        # Automatic background monitor & refresh timer
        self.monitor.start()
        if HAS_PYQT6:
            self.refresh_timer = QTimer(self)
            self.refresh_timer.timeout.connect(self._on_timer_tick)
            self.refresh_timer.start(4000)

        # Startup log
        self.fw_logger.log_event("app_startup", "info", "Crazy Alchemy started successfully")

    def _init_ui(self):
        if not HAS_PYQT6:
            return

        self.apply_theme(self.current_theme, save_preference=False)

        central = QWidget()
        central.setObjectName("CentralWidget")
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── 1. Left Sidebar Navigation Rail ──
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(240)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(10, 14, 10, 14)
        sb_layout.setSpacing(8)

        # Top-Left Logo / Picture (crazy_alchemy.jpg)
        img_path = self.project_dir / "crazy_alchemy.jpg"
        if not img_path.exists():
            img_path = Path(__file__).resolve().parent.parent / "crazy_alchemy.jpg"

        if img_path.exists():
            logo_lbl = QLabel()
            logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            raw_pixmap = QPixmap(str(img_path))
            if not raw_pixmap.isNull():
                # Smooth scaling to fit perfectly within the 240px sidebar (150x150, KeepAspectRatio)
                scaled_pixmap = raw_pixmap.scaled(
                    150, 150,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                # Apply antialiased rounded corners for high-end aesthetic
                rounded = QPixmap(scaled_pixmap.size())
                rounded.fill(Qt.GlobalColor.transparent)
                painter = QPainter(rounded)
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                clip_path = QPainterPath()
                clip_path.addRoundedRect(0, 0, scaled_pixmap.width(), scaled_pixmap.height(), 12, 12)
                painter.setClipPath(clip_path)
                painter.drawPixmap(0, 0, scaled_pixmap)
                painter.end()

                logo_lbl.setPixmap(rounded)
                logo_lbl.setStyleSheet("padding: 2px; margin-bottom: 2px;")
                sb_layout.addWidget(logo_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

        # App Brand Header
        brand_box = QHBoxLayout()
        brand_icon = QLabel("🛡️")
        brand_icon.setStyleSheet("font-size: 20px;")
        brand_lbl = QLabel("Crazy Alchemy")
        brand_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        brand_box.addWidget(brand_icon)
        brand_box.addWidget(brand_lbl)
        brand_box.addStretch()
        sb_layout.addLayout(brand_box)

        # Navigation List
        self.nav_list = QListWidget()
        self.nav_list.setObjectName("NavList")
        nav_items = [
            ("dashboard", "📊 Dashboard"),
            ("antivirus", "🦠 Antivirus & Threats"),
            ("rules", "🧱 Firewall Rules"),
            ("monitor", "📡 Network Monitor"),
            ("apps", "💻 Services & Apps"),
            ("profiles", "🌐 Security Profiles"),
            ("logs", "📜 Event Log"),
            ("settings", "⚙️ Settings"),
        ]

        for p_id, label in nav_items:
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, p_id)
            self.nav_list.addItem(item)

        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        sb_layout.addWidget(self.nav_list, stretch=1)

        # Bottom Status Indicator Pill
        self.status_pill = QLabel("🛡️ Protection Active")
        self.status_pill.setProperty("class", "status-pill-active")
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sb_layout.addWidget(self.status_pill)

        main_layout.addWidget(sidebar)

        # ── 2. Content Area & Header ──
        content_box = QWidget()
        c_layout = QVBoxLayout(content_box)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(0)

        # Top Header Bar
        self.header_frame = QFrame()
        self.header_frame.setObjectName("HeaderBar")
        h_layout = QHBoxLayout(self.header_frame)
        h_layout.setContentsMargins(20, 10, 20, 10)

        self.header_title = QLabel("Dashboard")
        self.header_title.setObjectName("HeaderTitle")
        self.header_title.setStyleSheet("font-size: 15px; font-weight: bold;")
        h_layout.addWidget(self.header_title)
        h_layout.addStretch()

        # Panic Button in Header
        self.btn_panic = QPushButton("⛔ Panic Lockdown")
        self.btn_panic.setProperty("class", "destructive-action")
        self.btn_panic.setToolTip("Block ALL inbound and outbound network traffic immediately")
        self.btn_panic.clicked.connect(self.toggle_panic_mode)
        h_layout.addWidget(self.btn_panic)

        btn_reload = QPushButton("🔄")
        btn_reload.setToolTip("Reload firewall rules")
        btn_reload.clicked.connect(self.reload_firewall)
        h_layout.addWidget(btn_reload)

        btn_about = QPushButton("ℹ️")
        btn_about.setToolTip("About Crazy Alchemy")
        btn_about.clicked.connect(self._show_about_dialog)
        h_layout.addWidget(btn_about)

        # Keyboard shortcuts
        QShortcut(QKeySequence("Alt+P"), self, self.toggle_panic_mode)
        QShortcut(QKeySequence("Ctrl+R"), self, self.reload_firewall)
        for idx in range(8):
            QShortcut(QKeySequence(f"Ctrl+{idx+1}"), self, lambda i=idx: self.nav_list.setCurrentRow(i))

        c_layout.addWidget(self.header_frame)

        # Stacked Pages
        self.stack = QStackedWidget()
        from ui.pages_win import (
            DashboardPage, AntivirusPage, RulesPage, MonitorPage,
            AppsPage, ProfilesPage, LogsPage, SettingsPage
        )

        self.pages = {
            "dashboard": DashboardPage(self),
            "antivirus": AntivirusPage(self),
            "rules": RulesPage(self),
            "monitor": MonitorPage(self),
            "apps": AppsPage(self),
            "profiles": ProfilesPage(self),
            "logs": LogsPage(self),
            "settings": SettingsPage(self),
        }

        for p_id, widget in self.pages.items():
            self.stack.addWidget(widget)

        c_layout.addWidget(self.stack)
        main_layout.addWidget(content_box, stretch=1)

        self.setCentralWidget(central)
        self.nav_list.setCurrentRow(0)

    def _on_nav_changed(self, row: int):
        if not HAS_PYQT6 or row < 0:
            return
        item = self.nav_list.item(row)
        p_id = item.data(Qt.ItemDataRole.UserRole)
        widget = self.pages.get(p_id)
        if widget:
            self.stack.setCurrentWidget(widget)
            self.header_title.setText(item.text().split(" ", 1)[1])
            if hasattr(widget, 'refresh'):
                widget.refresh()

    def navigate_to(self, page_id: str, tab_index: Optional[int] = None):
        if not HAS_PYQT6:
            return
        if page_id == "darkweb":
            page_id = "monitor"
            tab_index = 4

        for row in range(self.nav_list.count()):
            item = self.nav_list.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == page_id:
                self.nav_list.setCurrentRow(row)
                if tab_index is not None and page_id in self.pages:
                    p = self.pages[page_id]
                    if hasattr(p, "tabs"):
                        p.tabs.setCurrentIndex(tab_index)
                break

    def apply_theme(self, theme_name: str = "dark", save_preference: bool = True):
        """Applies High-Contrast Dark or Fluent Light theme dynamically across all UI components."""
        if not HAS_PYQT6:
            return
        theme_name = str(theme_name).lower().strip()
        if theme_name not in ["dark", "light", "system"]:
            theme_name = "dark"

        self.current_theme = theme_name
        qss = get_theme_stylesheet(theme_name)
        self.setStyleSheet(qss)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss)

        if save_preference:
            self.profiles.update_settings({"theme": theme_name})
            self.fw_logger.log_event("theme_changed", "info", f"Theme switched to: {theme_name}")

        # Propagate theme notification to pages if supported
        if hasattr(self, "pages") and isinstance(self.pages, dict):
            for p_id, page in self.pages.items():
                if hasattr(page, "on_theme_changed"):
                    try:
                        page.on_theme_changed(theme_name)
                    except Exception as e:
                        logger.debug(f"Page theme notice ({p_id}): {e}")

    def toggle_panic_mode(self):
        is_panic = self.fw_core.get_panic_mode(force_refresh=True)
        new_state = not is_panic

        if new_state:
            confirm = QMessageBox.critical(
                self,
                "Engage Panic Lockdown?",
                "This will immediately cut 100% of all incoming and outgoing network traffic across all network adapters.\n\nEngage Panic Lockdown now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel
            )
            if confirm != QMessageBox.StandardButton.Yes:
                return

        ok = self.fw_core.set_panic_mode(new_state)
        if ok:
            if new_state:
                self.fw_logger.log_event("panic_on", "critical", "Panic Lockdown ENABLED on Windows 11 — All traffic blocked")
                self.tray.show_notification("Panic Mode Active", "All network traffic severed.", is_warning=True)
            else:
                self.fw_logger.log_event("panic_off", "info", "Panic Lockdown DISABLED — Traffic restored")
                self.tray.show_notification("Traffic Restored", "Panic lockdown lifted. Normal network traffic resumed.")
            self._update_status_ui()
            current_page = self.stack.currentWidget()
            if hasattr(current_page, 'refresh'):
                current_page.refresh()
        else:
            action_desc = "engage" if new_state else "lift"
            QMessageBox.critical(
                self,
                "Panic Lockdown Error",
                f"Failed to {action_desc} Windows Panic Lockdown.\n\n"
                "Modifying Windows Defender Firewall policies requires Administrator privileges. "
                "Please run Crazy Alchemy as Administrator, or approve the Windows UAC elevation prompt."
            )
            self._update_status_ui()

    def reload_firewall(self):
        self.fw_core.reload()
        self.fw_logger.log_event("firewall_reloaded", "info", "Windows Firewall rules reloaded")
        self._update_status_ui()
        current_page = self.stack.currentWidget()
        if hasattr(current_page, 'refresh'):
            current_page.refresh()

    def _show_about_dialog(self):
        QMessageBox.about(
            self,
            "About Crazy Alchemy",
            "<h2>Crazy Alchemy v3.0</h2>"
            "<p><b>Enterprise-Grade Windows 11 Firewall & Tri-Engine Antivirus Suite</b></p>"
            "<p>Featuring TrapNet Deception Decoy Ports, ChainGuard Ancestry Validation, and AppPrint Network DNA.</p>"
            "<p><b>Author:</b> Vitorius<br><b>Version:</b> 3.0<br><b>License:</b> MIT License<br><b>Target:</b> Windows 11</p>"
        )

    def switch_profile(self, name: str):
        # Auto-backup firewall rules before profile switch if enabled in settings
        backup_path = None
        if self.profiles.get_setting("backup_on_profile_change", True):
            try:
                backup_path = self.profiles.backup_rules()
                if backup_path:
                    self.fw_logger.log_event("profile_backup", "info", f"Pre-switch firewall policy backup saved: {backup_path}")
            except Exception as e:
                logger.debug(f"Pre-switch backup notice: {e}")

        if self.profiles.set_active_profile(name):
            prof_data = self.profiles.get_profiles().get(name, {})
            self.fw_core.apply_profile_rules(name, prof_data)

            # Synchronize exploit shield hardening profile with profile posture
            if self.exploit_shield:
                try:
                    if name in ("Maximum Security", "Corporate"):
                        self.exploit_shield.apply_hardening_profile("Strict")
                    elif name == "Gaming":
                        self.exploit_shield.apply_hardening_profile("Audit")
                    else:
                        self.exploit_shield.apply_hardening_profile("Recommended")
                except Exception as e:
                    logger.debug(f"Exploit shield sync notice: {e}")

            self.fw_logger.log_event("profile_switch", "info", f"Switched security posture to {name}", {
                "profile": name,
                "tier": prof_data.get("tier", "standard"),
                "icmp_block": prof_data.get("icmp_block", False),
                "allow_outbound": prof_data.get("allow_outbound", True),
                "backup_created": bool(backup_path)
            })
            self.tray.show_notification("Profile Changed", f"Security posture set to {name}")
            self._update_status_ui()

    def _update_status_ui(self):
        if not HAS_PYQT6:
            return
        is_panic = self.fw_core.get_panic_mode()
        active_prof = self.profiles.get_active_profile()

        if is_panic:
            self.status_pill.setText("⚠️ PANIC LOCKDOWN")
            self.status_pill.setProperty("class", "status-pill-panic")
            self.btn_panic.setText("🟢 Lift Panic")
            self.btn_panic.setProperty("class", "suggested-action")
        else:
            self.status_pill.setText("🛡️ Protected (Active)")
            self.status_pill.setProperty("class", "status-pill-active")
            self.btn_panic.setText("⛔ Panic Lockdown")
            self.btn_panic.setProperty("class", "destructive-action")

        self.status_pill.style().unpolish(self.status_pill)
        self.status_pill.style().polish(self.status_pill)
        self.btn_panic.style().unpolish(self.btn_panic)
        self.btn_panic.style().polish(self.btn_panic)

        self.tray.update_status(profile_name=active_prof, is_panic=is_panic)

    def _on_timer_tick(self):
        self._update_status_ui()
        current_page = self.stack.currentWidget()
        if hasattr(current_page, 'refresh'):
            current_page.refresh()

    def start_quick_scan(self):
        """Starts quick threat scan from tray or shortcut."""
        self.showNormal()
        self.activateWindow()
        self.navigate_to("antivirus")
        if "antivirus" in self.pages and hasattr(self.pages["antivirus"], "start_quick_scan"):
            self.pages["antivirus"].start_quick_scan()

    def showEvent(self, event):
        if HAS_PYQT6:
            super().showEvent(event)
            if hasattr(self, 'taskbar') and not self.taskbar.hwnd:
                try:
                    hwnd = int(self.winId())
                    self.taskbar.set_hwnd(hwnd)
                except Exception:
                    pass

            if not hasattr(self, '_checked_offline_results'):
                self._checked_offline_results = True
                QTimer.singleShot(600, self._check_offline_scan_results)

    def _check_offline_scan_results(self):
        """Displays post-boot offline scan remediation report if results exist."""
        if not self.offline_scanner:
            return
        results = self.offline_scanner.get_last_results()
        if results:
            threats_cleaned = results.get("threats_cleaned", 0)
            fps_suppressed = results.get("false_positives_suppressed", 0)
            files_scanned = results.get("files_scanned", 0)
            dur = results.get("duration_seconds", 0)
            sigs = results.get("active_signatures", 0)
            cleaned_items = results.get("cleaned_items", [])

            if threats_cleaned > 0:
                msg = f"🛡️ Microsoft Defender-Style Offline Scan Completed!\n\n"
                msg += f"• Files Audited: {files_scanned:,}\n"
                msg += f"• Threats Found & Cleaned: {threats_cleaned}\n"
                if fps_suppressed > 0:
                    msg += f"• Legitimate Files Protected (Valid Signatures): {fps_suppressed}\n"
                if sigs > 0:
                    msg += f"• Built-in Malware Signatures Active: {sigs:,}\n"
                msg += f"• Scan Duration: {dur}s\n\n"
                msg += "Neutralized Threats:\n"
                for itm in cleaned_items[:6]:
                    msg += f"- {itm.get('threat_name')} ({itm.get('action')})\n  Path: {itm.get('file_path')}\n"
                if len(cleaned_items) > 6:
                    msg += f"... and {len(cleaned_items) - 6} more.\n"
                msg += "\nAll threats have been securely neutralized and isolated into the Quarantine Vault."
                QMessageBox.warning(self, "Offline Scan Remediation Report", msg)
            else:
                msg = f"🛡️ Offline Reboot Scan Completed\n\n"
                msg += f"• Files Audited: {files_scanned:,}\n"
                msg += f"• Threats Found: 0 (System is Clean)\n"
                if fps_suppressed > 0:
                    msg += f"• Legitimate Files Protected (Valid Signatures): {fps_suppressed}\n"
                if sigs > 0:
                    msg += f"• Built-in Malware Signatures Active: {sigs:,}\n"
                msg += f"• Scan Duration: {dur}s\n\n"
                msg += "All offline system drivers, startup tasks, and critical hotspots are verified clean."
                QMessageBox.information(self, "Offline Scan Results", msg)

            self.offline_scanner.acknowledge_results()

    def closeEvent(self, event: QCloseEvent):
        """Minimize to tray on window close if enabled in settings."""
        if getattr(self, "_force_quit", False):
            event.accept()
            return

        if self.profiles.get_setting("close_to_tray", True):
            event.ignore()
            self.hide()
            self.tray.show_notification("Crazy Alchemy", "Application running in background tray.")
        else:
            self.safe_exit()

    def safe_exit(self):
        self._force_quit = True
        logger.info("Executing safe application exit for Crazy Alchemy...")

        # 1. Immediately hide and destroy system tray icon so it disappears from taskbar
        if hasattr(self, 'tray') and self.tray:
            try:
                if hasattr(self.tray, 'tray_icon') and self.tray.tray_icon:
                    self.tray.tray_icon.hide()
            except Exception:
                pass

        # 2. Stop all active background monitors and threads
        try:
            self.monitor.stop()
        except Exception:
            pass
        if self.honeypot_mgr:
            try: self.honeypot_mgr.stop()
            except Exception: pass
        if self.chainguard_engine:
            try: self.chainguard_engine.stop()
            except Exception: pass
        if self.appprint_engine:
            try: self.appprint_engine.stop()
            except Exception: pass
        if self.realtime_shield:
            try: self.realtime_shield.stop()
            except Exception: pass
        if self.darkweb_monitor:
            try: self.darkweb_monitor.stop()
            except Exception: pass
        if self.email_shield:
            try: self.email_shield.stop()
            except Exception: pass
        if self.exploit_shield:
            try: self.exploit_shield.stop()
            except Exception: pass
        if hasattr(self, 'profiles') and hasattr(self.profiles, 'adaptive'):
            try: self.profiles.adaptive.stop()
            except Exception: pass
        if hasattr(self, 'browser_shield') and self.browser_shield:
            try: self.browser_shield.stop()
            except Exception: pass
        if self.av_updater:
            try: self.av_updater.stop_auto_update()
            except Exception: pass

        # 3. Close GUI window and quit Qt event loop
        if HAS_PYQT6:
            try:
                self.close()
            except Exception:
                pass
            app = QApplication.instance()
            if app:
                try:
                    app.quit()
                except Exception:
                    pass

        # 4. Immediate and clean process exit
        import os
        os._exit(0)
