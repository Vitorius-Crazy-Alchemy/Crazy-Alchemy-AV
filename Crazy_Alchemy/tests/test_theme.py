"""
Crazy Alchemy - Visual Theme & Contrast Unit Tests
Verifies High-Contrast Dark Theme, Fluent Light Theme, and System Theme Detection.
"""

import unittest
from unittest.mock import MagicMock, patch
import sys

from ui.styles import (
    get_system_theme,
    get_theme_stylesheet,
    FLUENT_DARK_STYLE,
    FLUENT_LIGHT_STYLE
)


class TestThemeEngine(unittest.TestCase):
    """Tests theme detection, stylesheet rendering, and contrast requirements."""

    def test_get_system_theme_light(self):
        with patch("sys.platform", "win32"), \
             patch("winreg.OpenKey"), \
             patch("winreg.QueryValueEx", return_value=(1, 4)):
            self.assertEqual(get_system_theme(), "light")

    def test_get_system_theme_dark(self):
        with patch("sys.platform", "win32"), \
             patch("winreg.OpenKey"), \
             patch("winreg.QueryValueEx", return_value=(0, 4)):
            self.assertEqual(get_system_theme(), "dark")

    def test_get_system_theme_fallback_on_error(self):
        with patch("sys.platform", "win32"), \
             patch("winreg.OpenKey", side_effect=OSError("Registry access denied")):
            self.assertEqual(get_system_theme(), "dark")

    def test_get_theme_stylesheet_dark(self):
        qss = get_theme_stylesheet("dark")
        self.assertIn("#1A1A1A", qss)
        self.assertIn("#FFFFFF", qss)
        self.assertIn("#D1D5DB", qss)
        self.assertIn("subtitle-text", qss)
        self.assertIn("stat-card", qss)

    def test_get_theme_stylesheet_light(self):
        qss = get_theme_stylesheet("light")
        self.assertIn("#F4F6F8", qss)
        self.assertIn("#1F2428", qss)
        self.assertIn("#4B5563", qss)
        self.assertIn("subtitle-text", qss)
        self.assertIn("stat-card", qss)

    def test_get_theme_stylesheet_system(self):
        with patch("ui.styles.get_system_theme", return_value="light"):
            qss_light = get_theme_stylesheet("system")
            self.assertEqual(qss_light, FLUENT_LIGHT_STYLE)

        with patch("ui.styles.get_system_theme", return_value="dark"):
            qss_dark = get_theme_stylesheet("system")
            self.assertEqual(qss_dark, FLUENT_DARK_STYLE)

    def test_high_contrast_typography_rules(self):
        """Ensures that dark theme eliminates washed-out, barely visible text."""
        # Must have pure white primary label text
        self.assertIn("color: #FFFFFF;", FLUENT_DARK_STYLE)
        # Must style QLabel, TableWidget, and Subtitles explicitly so Windows default black doesn't bleed through
        self.assertIn("QLabel", FLUENT_DARK_STYLE)
        self.assertIn("QTableWidget", FLUENT_DARK_STYLE)
        self.assertIn("QHeaderView::section", FLUENT_DARK_STYLE)
        self.assertIn("QCheckBox.antivirus-switch", FLUENT_DARK_STYLE)
        self.assertIn("QCheckBox[class=\"antivirus-switch\"]", FLUENT_DARK_STYLE)


class TestSettingsPageThemeIntegration(unittest.TestCase):
    """Tests that SettingsPage provides a visual theme selector and notifies the main window."""

    @classmethod
    def setUpClass(cls):
        try:
            from PyQt6.QtWidgets import QApplication
            cls.app = QApplication.instance() or QApplication(["test_theme_app", "-platform", "offscreen"])
            cls.has_qt = True
        except Exception:
            cls.has_qt = False

    def setUp(self):
        if not self.has_qt:
            self.skipTest("PyQt6 not available in this test environment")

    def test_settings_page_theme_controls(self):
        from ui.pages_win import SettingsPage

        mock_main = MagicMock()
        mock_profiles = MagicMock()
        mock_profiles.get_setting.side_effect = lambda k, d=None: "dark" if k == "theme" else d
        mock_main.profiles = mock_profiles
        mock_main.fw_logger = MagicMock()

        page = SettingsPage(mock_main)

        self.assertTrue(hasattr(page, "combo_theme"))
        self.assertEqual(page.combo_theme.count(), 3)

        # Check theme options data
        themes = [page.combo_theme.itemData(i) for i in range(page.combo_theme.count())]
        self.assertIn("dark", themes)
        self.assertIn("light", themes)
        self.assertIn("system", themes)

        # Pre-selected value matches current setting
        self.assertEqual(page.combo_theme.currentData(), "dark")

        # Switching to light theme calls main_win.apply_theme("light")
        light_idx = page.combo_theme.findData("light")
        page.combo_theme.setCurrentIndex(light_idx)
        mock_main.apply_theme.assert_called_with("light", save_preference=True)

    def test_settings_page_refresh_syncs_theme(self):
        from ui.pages_win import SettingsPage

        mock_main = MagicMock()
        mock_profiles = MagicMock()
        settings_store = {"theme": "light"}
        mock_profiles.get_setting.side_effect = lambda k, d=None: settings_store.get(k, d)
        mock_main.profiles = mock_profiles
        mock_main.fw_logger = MagicMock()

        page = SettingsPage(mock_main)
        page.refresh()

        self.assertEqual(page.combo_theme.currentData(), "light")


class TestAppWinThemeApplication(unittest.TestCase):
    """Tests CrazyAlchemyWin.apply_theme behavior."""

    @classmethod
    def setUpClass(cls):
        try:
            from PyQt6.QtWidgets import QApplication
            cls.app = QApplication.instance() or QApplication(["test_theme_app2", "-platform", "offscreen"])
            cls.has_qt = True
        except Exception:
            cls.has_qt = False

    def setUp(self):
        if not self.has_qt:
            self.skipTest("PyQt6 not available in this test environment")

    def test_apply_theme_logic(self):
        from ui.app_win import VitoriusFirewallMainWindow
        from pathlib import Path

        with patch.object(VitoriusFirewallMainWindow, "_init_ui"):
            mock_fw_core = MagicMock()
            mock_av_engine = MagicMock()
            mock_av_updater = MagicMock()
            mock_monitor = MagicMock()
            mock_scanner = MagicMock()
            mock_profiles = MagicMock()
            mock_logger = MagicMock()
            mock_profiles.get_setting.return_value = "dark"

            win = VitoriusFirewallMainWindow(
                mock_fw_core, mock_av_engine, mock_av_updater, mock_monitor,
                mock_scanner, mock_profiles, mock_logger, Path(".")
            )
            win.pages = {}

            win.apply_theme("light", save_preference=True)
            self.assertEqual(win.current_theme, "light")
            mock_profiles.update_settings.assert_called_with({"theme": "light"})

            win.apply_theme("dark", save_preference=True)
            self.assertEqual(win.current_theme, "dark")
            mock_profiles.update_settings.assert_called_with({"theme": "dark"})


if __name__ == "__main__":
    unittest.main()
