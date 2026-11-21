# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Build Specification for Standalone setup.exe (Zero VBScript / Windows 11 Native Installer)

block_cipher = None

a = Analysis(
    ['setup_win.py'],
    pathex=['.', '..'],
    binaries=[],
    datas=[
        ('../data/icons/*.ico', 'data/icons'),
        ('../data/icons/*.png', 'data/icons'),
        ('../requirements.txt', '.'),
        ('../prerequisites/*.py', 'prerequisites'),
        ('../prerequisites/*.txt', 'prerequisites'),
        ('../prerequisites/*.bat', 'prerequisites'),
    ],
    hiddenimports=[
        'winreg',
        'ctypes',
        'ctypes.wintypes',
        'importlib.metadata',
        'shutil',
        'subprocess',
        'backend.uninstaller',
        'backend.elevation_win',
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Shows real-time installation progress and terminal status
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='../data/icons/vitorius-firewall.ico',
    uac_admin=True  # Requests native Administrator UAC elevation prompt on launch
)
