"""
Vitorius Firewall Win - Windows 11 System Tray Indicator
Integrates with the Windows Notification Area (Taskbar Tray) with dynamic
status icons, context menu, and desktop notifications.
"""

import sys
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger('vitorius.win.tray')

try:
    from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
    from PyQt6.QtGui import QIcon, QAction
    from PyQt6.QtCore import pyqtSignal, QObject
    HAS_PYQT6 = True
except ImportError:
    HAS_PYQT6 = False
    logger.warning("PyQt6 not available in current environment — tray will run when deployed with PyQt6.")


class WindowsTrayIndicator(QObject if HAS_PYQT6 else object):
    """Windows Notification Area (System Tray) Controller."""

    def __init__(self, app_win, icon_path: Path, panic_icon_path: Path):
        if HAS_PYQT6:
            super().__init__()
        self.app_win = app_win
        self.icon_path = icon_path
        self.panic_icon_path = panic_icon_path
        self.tray_icon = None
        self._init_tray()

    def _init_tray(self):
        if not HAS_PYQT6:
            return

        self.normal_icon = QIcon(str(self.icon_path))
        self.panic_icon = QIcon(str(self.panic_icon_path))

        self.tray_icon = QSystemTrayIcon(self.normal_icon, self.app_win)
        self.tray_icon.setToolTip("Crazy Alchemy — Protected")

        menu = QMenu()

        # Open Window
        act_open = QAction("🛡️ Open Crazy Alchemy", menu)
        act_open.triggered.connect(self._on_open_clicked)
        menu.addAction(act_open)

        menu.addSeparator()

        # Quick Scan
        act_scan = QAction("🔍 Quick Threat Scan", menu)
        act_scan.triggered.connect(self._on_quick_scan_clicked)
        menu.addAction(act_scan)

        # Panic Lockdown
        self.act_panic = QAction("⛔ Panic Lockdown (Block All)", menu)
        self.act_panic.triggered.connect(self._on_panic_clicked)
        menu.addAction(self.act_panic)

        menu.addSeparator()

        # Profiles Submenu
        profile_menu = menu.addMenu("🌐 Security Profile")
        for p_name in ["Home", "Public", "Corporate", "Gaming", "Maximum Security"]:
            act_p = QAction(p_name, profile_menu)
            act_p.triggered.connect(lambda checked, name=p_name: self._on_switch_profile(name))
            profile_menu.addAction(act_p)

        # Reload
        act_reload = QAction("🔄 Reload Firewall Rules", menu)
        act_reload.triggered.connect(self._on_reload_clicked)
        menu.addAction(act_reload)

        menu.addSeparator()

        # Exit
        act_exit = QAction("❌ Exit", menu)
        act_exit.triggered.connect(self._on_exit_clicked)
        menu.addAction(act_exit)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()
        logger.info("Windows System Tray Indicator initialized.")

    def _on_tray_activated(self, reason):
        # Trigger on double-click or middle-click
        if reason in (QSystemTrayIcon.ActivationReason.DoubleClick, QSystemTrayIcon.ActivationReason.Trigger):
            self._on_open_clicked()

    def _on_open_clicked(self):
        if self.app_win:
            self.app_win.showNormal()
            self.app_win.activateWindow()

    def _on_quick_scan_clicked(self):
        if self.app_win and hasattr(self.app_win, 'start_quick_scan'):
            self.app_win.start_quick_scan()

    def _on_panic_clicked(self):
        if self.app_win and hasattr(self.app_win, 'toggle_panic_mode'):
            self.app_win.toggle_panic_mode()

    def _on_switch_profile(self, name: str):
        if self.app_win and hasattr(self.app_win, 'switch_profile'):
            self.app_win.switch_profile(name)

    def _on_reload_clicked(self):
        if self.app_win and hasattr(self.app_win, 'reload_firewall'):
            self.app_win.reload_firewall()

    def _on_exit_clicked(self):
        logger.info("Tray context menu exit clicked.")
        if self.tray_icon:
            try:
                self.tray_icon.hide()
            except Exception:
                pass
        if self.app_win and hasattr(self.app_win, 'safe_exit'):
            self.app_win.safe_exit()
        else:
            if HAS_PYQT6:
                app = QApplication.instance()
                if app:
                    app.quit()
            import os
            os._exit(0)

    def update_status(self, profile_name: str, is_panic: bool, threats_count: int = 0):
        if not self.tray_icon:
            return

        if is_panic:
            self.tray_icon.setIcon(self.panic_icon)
            self.tray_icon.setToolTip("⚠️ PANIC LOCKDOWN ACTIVE — All Network Traffic Severed")
            self.act_panic.setText("🟢 Lift Panic Lockdown (Restore)")
        else:
            self.tray_icon.setIcon(self.normal_icon)
            self.act_panic.setText("⛔ Panic Lockdown (Block All)")
            if threats_count > 0:
                self.tray_icon.setToolTip(f"Crazy Alchemy — {profile_name} (⚠️ {threats_count} Threats Quarantined)")
            else:
                self.tray_icon.setToolTip(f"Crazy Alchemy — {profile_name} Protected")

    def show_notification(self, title: str, message: str, is_warning: bool = False):
        if not self.tray_icon:
            return
        icon_type = QSystemTrayIcon.MessageIcon.Warning if is_warning else QSystemTrayIcon.MessageIcon.Information
        self.tray_icon.showMessage(title, message, icon_type, 4000)
