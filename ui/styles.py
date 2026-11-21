"""
Crazy Alchemy - Windows 11 Fluent & Adwaita QSS Stylesheets
Provides modern Windows 11 High-Contrast Dark and Light visual themes
with rounded cards, high-contrast typography, and maximum text readability.
"""

import sys
import logging

logger = logging.getLogger("crazyalchemy.styles")


def get_system_theme() -> str:
    """
    Detects whether Windows 10/11 is configured in Dark mode or Light mode.
    Reads HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\\AppsUseLightTheme.
    Returns 'light' if 1, otherwise 'dark'.
    """
    if sys.platform != "win32":
        return "dark"
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            val, _ = winreg.QueryValueEx(k, "AppsUseLightTheme")
            return "light" if val == 1 else "dark"
    except Exception:
        return "dark"


def get_theme_stylesheet(theme_mode: str = "dark") -> str:
    """
    Returns the appropriate QSS stylesheet string based on theme mode.
    Accepted values: 'dark', 'light', 'system'.
    """
    mode = str(theme_mode).lower().strip()
    if mode == "system":
        mode = get_system_theme()

    if mode == "light":
        return FLUENT_LIGHT_STYLE
    return FLUENT_DARK_STYLE


# ==============================================================================
# 🌙 HIGH-CONTRAST FLUENT DARK THEME
# Maximum readability with pure white text and crisp silver secondary accents
# ==============================================================================
FLUENT_DARK_STYLE = """
/* ── Windows 11 Fluent High-Contrast Dark Theme ── */
QMainWindow, QDialog, QWidget#CentralWidget, QScrollArea {
    background-color: #1A1A1A;
    color: #FFFFFF;
    font-family: 'Segoe UI Variable Display', 'Segoe UI', -apple-system, sans-serif;
    font-size: 13px;
}

/* ── Typography & Global Text Visibility ── */
QLabel {
    color: #FFFFFF;
    background-color: transparent;
}

QLabel.subtitle-text, QLabel[class="subtitle-text"], QLabel#RowSubtitle, QLabel.card-subcaption, QLabel[class="card-subcaption"] {
    color: #D1D5DB;
    background-color: transparent;
}

QLabel.card-caption, QLabel[class="card-caption"] {
    font-size: 12px;
    color: #E5E7EB;
    font-weight: 500;
    background-color: transparent;
}

QLabel.meta-text, QLabel[class="meta-text"] {
    color: #9CA3AF;
    background-color: transparent;
}

QLabel#RowTitle, QLabel.option-title, QLabel[class="option-title"] {
    font-size: 13px;
    font-weight: bold;
    color: #FFFFFF;
    background-color: transparent;
}

QLabel#HeroTitle {
    font-size: 16px;
    font-weight: bold;
    color: #FFFFFF;
    background-color: transparent;
}

QLabel#HeroSub {
    font-size: 12px;
    color: #E5E7EB;
    background-color: transparent;
}

QLabel#HeroPills {
    font-size: 11px;
    font-weight: 500;
    color: #58A6FF;
    background-color: transparent;
}

/* ── Left Sidebar Navigation Rail ── */
QWidget#Sidebar {
    background-color: #141414;
    border-right: 1px solid #2D2D2D;
}

QListWidget#NavList {
    background-color: transparent;
    border: none;
    outline: none;
    padding: 6px 4px;
}

QListWidget#NavList::item {
    border-radius: 6px;
    padding: 8px 12px;
    margin: 1px 4px 2px 4px;
    color: #E5E7EB;
    border-left: 3px solid transparent;
}

QListWidget#NavList::item:hover {
    background-color: rgba(255, 255, 255, 0.08);
    color: #FFFFFF;
}

QListWidget#NavList::item:selected {
    background-color: rgba(0, 120, 212, 0.28);
    color: #FFFFFF;
    font-weight: bold;
    border-left: 3px solid #0078D4;
}

/* ── Top Header Bar ── */
QFrame#HeaderBar {
    background-color: #222222;
    border-bottom: 1px solid #333333;
}

QLabel#HeaderTitle {
    font-size: 15px;
    font-weight: bold;
    color: #FFFFFF;
}

/* ── Card Containers & Setting Rows ── */
QFrame.stat-card, QFrame[class="stat-card"], QFrame.content-card, QFrame[class="content-card"] {
    background-color: #252525;
    border: 1px solid #383838;
    border-radius: 8px;
    padding: 14px;
}

QFrame.stat-card:hover, QFrame[class="stat-card"]:hover {
    border: 1px solid #4F4F4F;
    background-color: #282828;
}

QFrame.setting-row, QFrame[class="setting-row"] {
    background-color: #252525;
    border: 1px solid #363636;
    border-radius: 6px;
    padding: 8px 14px;
    margin-bottom: 3px;
}

QFrame.setting-row:hover, QFrame[class="setting-row"]:hover {
    background-color: #2A2A2A;
    border: 1px solid #4C4C4C;
}

QFrame.action-row, QFrame[class="action-row"] {
    background-color: #252525;
    border: 1px solid #383838;
    border-radius: 6px;
    padding: 8px 12px;
    margin-bottom: 4px;
}

/* ── Buttons ── */
QPushButton {
    background-color: #333333;
    color: #FFFFFF;
    border: 1px solid #484848;
    border-radius: 5px;
    padding: 6px 12px;
    min-height: 26px;
    font-weight: 500;
    font-size: 12px;
}

QPushButton:hover {
    background-color: #3E3E3E;
    border-color: #606060;
}

QPushButton:pressed {
    background-color: #252525;
}

QPushButton:disabled {
    background-color: #222222;
    color: #666666;
    border-color: #333333;
}

QPushButton.suggested-action, QPushButton[class="suggested-action"] {
    background-color: #0078D4;
    border: 1px solid #006CBE;
    color: #FFFFFF;
    font-weight: bold;
}

QPushButton.suggested-action:hover, QPushButton[class="suggested-action"]:hover {
    background-color: #1084D9;
    border-color: #2094E9;
}

QPushButton.destructive-action, QPushButton[class="destructive-action"] {
    background-color: #C42B1C;
    border: 1px solid #B02316;
    color: #FFFFFF;
    font-weight: bold;
}

QPushButton.destructive-action:hover, QPushButton[class="destructive-action"]:hover {
    background-color: #D83B2B;
    border-color: #E84B3B;
}

/* Compact Table Action Buttons (guaranteed no cropping in cells) */
QPushButton.table-action, QPushButton[class="table-action"] {
    padding: 2px 8px;
    min-height: 22px;
    font-size: 11px;
    border-radius: 4px;
}

/* Action Center / Quick Action Grid Buttons */
QPushButton.action-card-btn, QPushButton[class="action-card-btn"] {
    min-height: 36px;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
    border-radius: 6px;
}

/* ── Tables and Tree Views ── */
QTableWidget, QTreeWidget {
    background-color: #242424;
    border: 1px solid #383838;
    border-radius: 6px;
    gridline-color: #2E2E2E;
    color: #FFFFFF;
    selection-background-color: rgba(0, 120, 212, 0.35);
    selection-color: #FFFFFF;
    outline: none;
}

QTableWidget::item {
    color: #FFFFFF;
    padding: 4px 8px;
    border-bottom: 1px solid #2D2D2D;
}

QTableWidget::item:selected {
    background-color: rgba(0, 120, 212, 0.35);
    color: #FFFFFF;
}
}

QTableWidget::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
}

QHeaderView::section {
    background-color: #1C1C1C;
    color: #FFFFFF;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #0078D4;
    font-weight: bold;
}

/* ── Tabs (QTabWidget) ── */
QTabWidget::pane {
    border: 1px solid #383838;
    background-color: #202020;
    border-radius: 6px;
}

QTabBar::tab {
    background-color: #292929;
    color: #D1D5DB;
    border: 1px solid #383838;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 500;
}

QTabBar::tab:selected {
    background-color: #202020;
    color: #58A6FF;
    border-bottom: 2px solid #0078D4;
    font-weight: bold;
}

QTabBar::tab:hover {
    background-color: #333333;
    color: #FFFFFF;
}

/* ── Inputs, LineEdits, and TextEdits ── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: #242424;
    color: #FFFFFF;
    border: 1px solid #404040;
    border-bottom: 2px solid #0078D4;
    border-radius: 5px;
    padding: 6px 10px;
    font-size: 12px;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #0078D4;
    border-bottom: 2px solid #57A9FB;
    background-color: #2A2A2A;
}

/* ── Combo Boxes & Option Dropdowns ── */
QComboBox {
    background-color: #2E2E2E;
    color: #FFFFFF;
    border: 1px solid #484848;
    border-radius: 5px;
    padding: 5px 12px;
    min-height: 24px;
    font-size: 12px;
    font-weight: 500;
}

QComboBox:hover {
    background-color: #383838;
    border-color: #606060;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 22px;
    border-left: 1px solid #404040;
    border-top-right-radius: 5px;
    border-bottom-right-radius: 5px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #CCCCCC;
    width: 0;
    height: 0;
}

QComboBox QAbstractItemView {
    background-color: #222222;
    color: #FFFFFF;
    border: 1px solid #484848;
    border-radius: 6px;
    padding: 4px;
    outline: none;
}

/* Precise item highlight under UI window without oversized blockiness */
QComboBox QAbstractItemView::item {
    min-height: 26px;
    padding: 4px 10px;
    border-radius: 4px;
    margin: 1px 3px;
    color: #FFFFFF;
}

QComboBox QAbstractItemView::item:hover,
QComboBox QAbstractItemView::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
    border-radius: 4px;
}

/* ── Context Menus & Sub-Window Popups ── */
QMenu {
    background-color: #222222;
    color: #FFFFFF;
    border: 1px solid #383838;
    border-radius: 6px;
    padding: 4px;
}

QMenu::item {
    padding: 5px 18px 5px 10px;
    border-radius: 4px;
    margin: 1px 2px;
    color: #FFFFFF;
}

QMenu::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
    border-radius: 4px;
}

QMenu::separator {
    height: 1px;
    background-color: #383838;
    margin: 4px 6px;
}

/* ── General List Widgets & Event Log Items ── */
QListWidget {
    background-color: #202020;
    border: 1px solid #333333;
    border-radius: 6px;
    padding: 4px;
    outline: none;
    color: #FFFFFF;
}

QListWidget::item {
    padding: 6px 10px;
    border-radius: 4px;
    margin: 1px 2px;
    color: #FFFFFF;
}

QListWidget::item:hover {
    background-color: rgba(255, 255, 255, 0.06);
}

QListWidget::item:selected {
    background-color: rgba(0, 120, 212, 0.3);
    color: #FFFFFF;
}

QListWidget#EventsList {
    background-color: #1C1C1C;
    border: 1px solid #333333;
    border-radius: 6px;
    font-family: 'Consolas', 'Segoe UI Mono', monospace;
    font-size: 12px;
    padding: 6px;
}

QListWidget#EventsList::item {
    padding: 5px 8px;
    border-bottom: 1px solid #282828;
    border-radius: 3px;
    margin-bottom: 2px;
    color: #E5E7EB;
}

QListWidget#EventsList::item:hover {
    background-color: #262626;
    color: #FFFFFF;
}

/* ── Checkboxes and Radio Buttons ── */
QCheckBox, QRadioButton {
    color: #FFFFFF;
    font-size: 13px;
    spacing: 8px;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #555555;
    border-radius: 3px;
    background-color: #2C2C2C;
}

QCheckBox::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

QRadioButton::indicator {
    border-radius: 8px;
}

QRadioButton::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

/* ── Antivirus Slider Switch ── */
QCheckBox.antivirus-switch, QCheckBox[class="antivirus-switch"] {
    font-size: 13px;
    font-weight: 600;
    color: #FFFFFF;
    spacing: 10px;
}

QCheckBox.antivirus-switch::indicator, QCheckBox[class="antivirus-switch"]::indicator {
    width: 38px;
    height: 20px;
    border-radius: 10px;
    background-color: #4A4A4A;
    border: 1px solid #5A5A5A;
}

QCheckBox.antivirus-switch::indicator:checked, QCheckBox[class="antivirus-switch"]::indicator:checked {
    background-color: #0078D4;
    border: 1px solid #1683D8;
}

QCheckBox.antivirus-switch::indicator:hover, QCheckBox[class="antivirus-switch"]::indicator:hover {
    border-color: #888888;
}

/* ── Group Boxes ── */
QGroupBox {
    color: #FFFFFF;
    font-weight: bold;
    border: 1px solid #383838;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 14px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
    color: #58A6FF;
}

/* ── Antivirus Hero Status Banners ── */
QFrame.hero-protected, QFrame[class="hero-protected"] {
    background-color: #12281a;
    border: 1px solid #1c663b;
    border-radius: 10px;
    padding: 18px;
}

QFrame.hero-warning, QFrame[class="hero-warning"] {
    background-color: #2e230a;
    border: 1px solid #7d5910;
    border-radius: 10px;
    padding: 18px;
}

QFrame.hero-danger, QFrame[class="hero-danger"] {
    background-color: #331518;
    border: 1px solid #85222b;
    border-radius: 10px;
    padding: 18px;
}

/* ── Progress Bar ── */
QProgressBar {
    border: 1px solid #383838;
    border-radius: 4px;
    text-align: center;
    background-color: #242424;
    color: #FFFFFF;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #238636;
    border-radius: 3px;
}

/* ── Status Indicator Pills ── */
QLabel.status-pill-active, QLabel[class="status-pill-active"] {
    background-color: rgba(35, 134, 54, 0.25);
    color: #7EE787;
    border: 1px solid #238636;
    border-radius: 12px;
    padding: 4px 10px;
    font-weight: bold;
}

QLabel.status-pill-panic, QLabel[class="status-pill-panic"] {
    background-color: rgba(196, 43, 28, 0.25);
    color: #FF99A4;
    border: 1px solid #C42B1C;
    border-radius: 12px;
    padding: 4px 10px;
    font-weight: bold;
}

/* ── Scrollbars ── */
QScrollBar:vertical {
    background: #1A1A1A;
    width: 12px;
    margin: 0;
    border: none;
}

QScrollBar::handle:vertical {
    background: #404040;
    min-height: 25px;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background: #555555;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background: #1A1A1A;
    height: 12px;
    margin: 0;
    border: none;
}

QScrollBar::handle:horizontal {
    background: #404040;
    min-width: 25px;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:horizontal:hover {
    background: #555555;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
"""


# ==============================================================================
# ☀️ FLUENT LIGHT THEME
# Clean modern Windows 11 light surface with high-contrast dark typography
# ==============================================================================
FLUENT_LIGHT_STYLE = """
/* ── Windows 11 Fluent Light Theme ── */
QMainWindow, QDialog, QWidget#CentralWidget, QScrollArea {
    background-color: #F4F6F8;
    color: #1F2428;
    font-family: 'Segoe UI Variable Display', 'Segoe UI', -apple-system, sans-serif;
    font-size: 13px;
}

/* ── Typography & Global Text Visibility ── */
QLabel {
    color: #1F2428;
    background-color: transparent;
}

QLabel.subtitle-text, QLabel[class="subtitle-text"], QLabel#RowSubtitle, QLabel.card-subcaption, QLabel[class="card-subcaption"] {
    color: #4B5563;
    background-color: transparent;
}

QLabel.card-caption, QLabel[class="card-caption"] {
    font-size: 12px;
    color: #374151;
    font-weight: 500;
    background-color: transparent;
}

QLabel.meta-text, QLabel[class="meta-text"] {
    color: #6B7280;
    background-color: transparent;
}

QLabel#RowTitle, QLabel.option-title, QLabel[class="option-title"] {
    font-size: 13px;
    font-weight: bold;
    color: #111827;
    background-color: transparent;
}

QLabel#HeroTitle {
    font-size: 16px;
    font-weight: bold;
    color: #0F5132;
    background-color: transparent;
}

QLabel#HeroSub {
    font-size: 12px;
    color: #166534;
    background-color: transparent;
}

QLabel#HeroPills {
    font-size: 11px;
    font-weight: 600;
    color: #0066CC;
    background-color: transparent;
}

/* ── Left Sidebar Navigation Rail ── */
QWidget#Sidebar {
    background-color: #E8ECEF;
    border-right: 1px solid #D1D5DB;
}

QListWidget#NavList {
    background-color: transparent;
    border: none;
    outline: none;
    padding: 6px 4px;
}

QListWidget#NavList::item {
    border-radius: 6px;
    padding: 8px 12px;
    margin: 1px 4px 2px 4px;
    color: #374151;
    border-left: 3px solid transparent;
}

QListWidget#NavList::item:hover {
    background-color: rgba(0, 0, 0, 0.06);
    color: #111827;
}

QListWidget#NavList::item:selected {
    background-color: rgba(0, 120, 212, 0.16);
    color: #0078D4;
    font-weight: bold;
    border-left: 3px solid #0078D4;
}

/* ── Top Header Bar ── */
QFrame#HeaderBar {
    background-color: #FFFFFF;
    border-bottom: 1px solid #E5E7EB;
}

QLabel#HeaderTitle {
    font-size: 15px;
    font-weight: bold;
    color: #111827;
}

/* ── Card Containers & Setting Rows ── */
QFrame.stat-card, QFrame[class="stat-card"], QFrame.content-card, QFrame[class="content-card"] {
    background-color: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 8px;
    padding: 14px;
}

QFrame.stat-card:hover, QFrame[class="stat-card"]:hover {
    border: 1px solid #0078D4;
    background-color: #FAFAFA;
}

QFrame.setting-row, QFrame[class="setting-row"] {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    padding: 8px 14px;
    margin-bottom: 3px;
}

QFrame.setting-row:hover, QFrame[class="setting-row"]:hover {
    background-color: #F8FAFC;
    border: 1px solid #0078D4;
}

QFrame.action-row, QFrame[class="action-row"] {
    background-color: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 6px;
    padding: 8px 12px;
    margin-bottom: 4px;
}

/* ── Buttons ── */
QPushButton {
    background-color: #FFFFFF;
    color: #1F2428;
    border: 1px solid #D1D5DB;
    border-radius: 5px;
    padding: 6px 12px;
    min-height: 26px;
    font-weight: 500;
    font-size: 12px;
}

QPushButton:hover {
    background-color: #F3F4F6;
    border-color: #9CA3AF;
}

QPushButton:pressed {
    background-color: #E5E7EB;
}

QPushButton:disabled {
    background-color: #F3F4F6;
    color: #9CA3AF;
    border-color: #E5E7EB;
}

QPushButton.suggested-action, QPushButton[class="suggested-action"] {
    background-color: #0078D4;
    border: 1px solid #006CBE;
    color: #FFFFFF;
    font-weight: bold;
}

QPushButton.suggested-action:hover, QPushButton[class="suggested-action"]:hover {
    background-color: #1084D9;
    border-color: #1084D9;
}

QPushButton.destructive-action, QPushButton[class="destructive-action"] {
    background-color: #DC2626;
    border: 1px solid #B91C1C;
    color: #FFFFFF;
    font-weight: bold;
}

QPushButton.destructive-action:hover, QPushButton[class="destructive-action"]:hover {
    background-color: #EF4444;
    border-color: #DC2626;
}

/* Compact Table Action Buttons (guaranteed no cropping in cells) */
QPushButton.table-action, QPushButton[class="table-action"] {
    padding: 2px 8px;
    min-height: 22px;
    font-size: 11px;
    border-radius: 4px;
}

/* Action Center / Quick Action Grid Buttons */
QPushButton.action-card-btn, QPushButton[class="action-card-btn"] {
    min-height: 36px;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
    border-radius: 6px;
}

/* ── Tables and Tree Views ── */
QTableWidget, QTreeWidget {
    background-color: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 6px;
    gridline-color: #F3F4F6;
    color: #1F2428;
    selection-background-color: rgba(0, 120, 212, 0.18);
    selection-color: #111827;
    outline: none;
}

QTableWidget::item {
    color: #1F2428;
    padding: 4px 8px;
    border-bottom: 1px solid #F3F4F6;
}

QTableWidget::item:selected {
    background-color: rgba(0, 120, 212, 0.18);
    color: #111827;
}

QHeaderView::section {
    background-color: #F9FAFB;
    color: #111827;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #0078D4;
    font-weight: bold;
}

/* ── Tabs (QTabWidget) ── */
QTabWidget::pane {
    border: 1px solid #E5E7EB;
    background-color: #FFFFFF;
    border-radius: 6px;
}

QTabBar::tab {
    background-color: #E5E7EB;
    color: #4B5563;
    border: 1px solid #D1D5DB;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 500;
}

QTabBar::tab:selected {
    background-color: #FFFFFF;
    color: #0078D4;
    border-bottom: 2px solid #0078D4;
    font-weight: bold;
}

QTabBar::tab:hover {
    background-color: #F3F4F6;
    color: #111827;
}

/* ── Inputs, LineEdits, and TextEdits ── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: #FFFFFF;
    color: #1F2428;
    border: 1px solid #D1D5DB;
    border-bottom: 2px solid #0078D4;
    border-radius: 5px;
    padding: 6px 10px;
    font-size: 12px;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #0078D4;
    border-bottom: 2px solid #1084D9;
    background-color: #FFFFFF;
}

/* ── Combo Boxes & Option Dropdowns ── */
QComboBox {
    background-color: #FFFFFF;
    color: #1F2428;
    border: 1px solid #D1D5DB;
    border-radius: 5px;
    padding: 5px 12px;
    min-height: 24px;
    font-size: 12px;
    font-weight: 500;
}

QComboBox:hover {
    background-color: #F9FAFB;
    border-color: #0078D4;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 22px;
    border-left: 1px solid #D1D5DB;
    border-top-right-radius: 5px;
    border-bottom-right-radius: 5px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #555555;
    width: 0;
    height: 0;
}

QComboBox QAbstractItemView {
    background-color: #FFFFFF;
    color: #1F2428;
    border: 1px solid #D1D5DB;
    border-radius: 6px;
    padding: 4px;
    outline: none;
}

/* Precise item highlight under UI window without oversized blockiness */
QComboBox QAbstractItemView::item {
    min-height: 26px;
    padding: 4px 10px;
    border-radius: 4px;
    margin: 1px 3px;
    color: #1F2428;
}

QComboBox QAbstractItemView::item:hover,
QComboBox QAbstractItemView::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
    border-radius: 4px;
}

/* ── Context Menus & Sub-Window Popups ── */
QMenu {
    background-color: #FFFFFF;
    color: #1F2428;
    border: 1px solid #D1D5DB;
    border-radius: 6px;
    padding: 4px;
}

QMenu::item {
    padding: 5px 18px 5px 10px;
    border-radius: 4px;
    margin: 1px 2px;
    color: #1F2428;
}

QMenu::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
    border-radius: 4px;
}

QMenu::separator {
    height: 1px;
    background-color: #E5E7EB;
    margin: 4px 6px;
}

/* ── General List Widgets & Event Log Items ── */
QListWidget {
    background-color: #FFFFFF;
    border: 1px solid #D1D5DB;
    border-radius: 6px;
    padding: 4px;
    outline: none;
    color: #1F2428;
}

QListWidget::item {
    padding: 6px 10px;
    border-radius: 4px;
    margin: 1px 2px;
    color: #1F2428;
}

QListWidget::item:hover {
    background-color: rgba(0, 0, 0, 0.05);
}

QListWidget::item:selected {
    background-color: rgba(0, 120, 212, 0.2);
    color: #0078D4;
}

QListWidget#EventsList {
    background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    font-family: 'Consolas', 'Segoe UI Mono', monospace;
    font-size: 12px;
    padding: 6px;
}

QListWidget#EventsList::item {
    padding: 5px 8px;
    border-bottom: 1px solid #EDF2F7;
    border-radius: 3px;
    margin-bottom: 2px;
    color: #2D3748;
}

QListWidget#EventsList::item:hover {
    background-color: #EDF2F7;
    color: #1A202C;
}

/* ── Checkboxes and Radio Buttons ── */
QCheckBox, QRadioButton {
    color: #1F2428;
    font-size: 13px;
    spacing: 8px;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #9CA3AF;
    border-radius: 3px;
    background-color: #FFFFFF;
}

QCheckBox::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

QRadioButton::indicator {
    border-radius: 8px;
}

QRadioButton::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

/* ── Antivirus Slider Switch ── */
QCheckBox.antivirus-switch, QCheckBox[class="antivirus-switch"] {
    font-size: 13px;
    font-weight: 600;
    color: #1F2428;
    spacing: 10px;
}

QCheckBox.antivirus-switch::indicator, QCheckBox[class="antivirus-switch"]::indicator {
    width: 38px;
    height: 20px;
    border-radius: 10px;
    background-color: #D1D5DB;
    border: 1px solid #9CA3AF;
}

QCheckBox.antivirus-switch::indicator:checked, QCheckBox[class="antivirus-switch"]::indicator:checked {
    background-color: #0078D4;
    border: 1px solid #006CBE;
}

QCheckBox.antivirus-switch::indicator:hover, QCheckBox[class="antivirus-switch"]::indicator:hover {
    border-color: #6B7280;
}

/* ── Group Boxes ── */
QGroupBox {
    color: #111827;
    font-weight: bold;
    border: 1px solid #E5E7EB;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 14px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
    color: #0078D4;
}

/* ── Antivirus Hero Status Banners ── */
QFrame.hero-protected, QFrame[class="hero-protected"] {
    background-color: #ECFDF5;
    border: 1px solid #A7F3D0;
    border-radius: 10px;
    padding: 18px;
}

QFrame.hero-warning, QFrame[class="hero-warning"] {
    background-color: #FFFBEB;
    border: 1px solid #FDE68A;
    border-radius: 10px;
    padding: 18px;
}

QFrame.hero-danger, QFrame[class="hero-danger"] {
    background-color: #FEF2F2;
    border: 1px solid #FECACA;
    border-radius: 10px;
    padding: 18px;
}

/* ── Progress Bar ── */
QProgressBar {
    border: 1px solid #D1D5DB;
    border-radius: 4px;
    text-align: center;
    background-color: #E5E7EB;
    color: #111827;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #10B981;
    border-radius: 3px;
}

/* ── Status Indicator Pills ── */
QLabel.status-pill-active, QLabel[class="status-pill-active"] {
    background-color: rgba(16, 185, 129, 0.15);
    color: #059669;
    border: 1px solid #10B981;
    border-radius: 12px;
    padding: 4px 10px;
    font-weight: bold;
}

QLabel.status-pill-panic, QLabel[class="status-pill-panic"] {
    background-color: rgba(220, 38, 38, 0.15);
    color: #DC2626;
    border: 1px solid #DC2626;
    border-radius: 12px;
    padding: 4px 10px;
    font-weight: bold;
}

/* ── Scrollbars ── */
QScrollBar:vertical {
    background: #F4F6F8;
    width: 12px;
    margin: 0;
    border: none;
}

QScrollBar::handle:vertical {
    background: #C5CBD3;
    min-height: 25px;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background: #9CA3AF;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background: #F4F6F8;
    height: 12px;
    margin: 0;
    border: none;
}

QScrollBar::handle:horizontal {
    background: #C5CBD3;
    min-width: 25px;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:horizontal:hover {
    background: #9CA3AF;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
"""
