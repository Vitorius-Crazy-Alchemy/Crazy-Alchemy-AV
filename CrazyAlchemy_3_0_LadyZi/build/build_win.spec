# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Build Specification for Vitorius Firewall Win

block_cipher = None

a = Analysis(
    ['../main_win.py'],
    pathex=['..'],
    binaries=[],
    datas=[
        ('../data/icons/*.png', 'data/icons'),
        ('../data/icons/vitorius-firewall.ico', 'data/icons'),
        ('../data/icons/vitorius-panic.ico', 'data/icons'),
        ('../data/signatures/*.db', 'data/signatures'),
        ('../data/signatures/rules/*.yar', 'data/signatures/rules'),
        ('../data/default_config_win.json', 'data'),
        ('../data/browser_extension/*', 'data/browser_extension'),
    ],
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'yara',
        'psutil',
        'watchdog',
        'watchdog.observers',
        'watchdog.events',
        'win32serviceutil',
        'win32service',
        'win32event',
        'servicemanager',
        'win32pipe',
        'win32file',
        'win32api',
        'win32con',
        'sqlite3',
        'backend.honeypot',
        'backend.chainguard',
        'backend.appprint',
        'backend.offline_scanner',
        'backend.darkweb_monitor',
        'backend.email_shield',
        'backend.exploit_shield',
        'backend.defender_manager',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='VitoriusFirewallWin',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Windowed GUI application
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='../data/icons/vitorius-firewall.ico',
    uac_admin=True  # Requests Windows Administrator elevation on launch
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='VitoriusFirewallWin'
)
