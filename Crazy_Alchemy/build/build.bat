@echo off
REM ========================================================
REM Crazy Alchemy - 1-Click Automated Build & Packaging Script
REM 100% VBScript-Free / Windows Script Host-Free Installer
REM ========================================================

echo [1/4] Installing Required Dependencies...
pip install -r ..\requirements.txt

echo [2/4] Initializing Baseline Signature Database...
python ..\data\signatures\seed_hashes.py

echo [3/4] Compiling Crazy Alchemy with PyInstaller...
pyinstaller --clean -y build_win.spec

echo [4/4] Building setup.exe (Zero VBScript / Pure Native)...
REM Check if Inno Setup is available
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    echo Building native setup.exe with Inno Setup (Pascal Script / Native C PE)...
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
) else (
    echo Inno Setup not found. Building standalone native setup.exe with PyInstaller...
    pyinstaller --clean -y build_setup_exe.spec
    mkdir ..\dist_installer 2>nul
    copy dist\setup.exe ..\dist_installer\setup.exe
)

echo ========================================================
echo Build Complete!
echo Native installer executable: dist_installer\setup.exe
echo (100% VBScript-Free / Zero Windows Script Host Dependency)
echo ========================================================
pause
