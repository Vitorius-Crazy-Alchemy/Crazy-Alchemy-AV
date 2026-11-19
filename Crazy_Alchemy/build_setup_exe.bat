@echo off
setlocal enabledelayedexpansion
title Crazy Alchemy - Setup.exe Builder
color 0B

echo ===============================================================================
echo   Crazy Alchemy v2.0 - 1-Click Setup.exe Compiler
echo   Builds standalone native Windows installer (setup.exe)
echo ===============================================================================
echo.

set "SCRIPT_DIR=%~dp0"

REM 1. Check Python
set "PYTHON_EXE="
where python >nul 2>nul
if %errorlevel% equ 0 (
    set "PYTHON_EXE=python"
) else (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_EXE=py -3"
    )
)

if "%PYTHON_EXE%"=="" (
    echo [ERROR] Python not found in system PATH.
    pause
    exit /b 1
)

echo [*] Phase 1/3: Installing prerequisites & PyInstaller...
call "%SCRIPT_DIR%prerequisites\install_prerequisites.bat"

echo.
echo [*] Phase 2/3: Compiling standalone setup.exe with PyInstaller...
cd /d "%SCRIPT_DIR%build"
%PYTHON_EXE% -m PyInstaller --clean -y build_setup_exe.spec

if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] PyInstaller compilation of setup.exe failed!
    pause
    exit /b 1
)

echo.
echo [*] Phase 3/3: Finalizing Installer Binaries...
if not exist "%SCRIPT_DIR%dist_installer" mkdir "%SCRIPT_DIR%dist_installer"
copy /y "%SCRIPT_DIR%build\dist\setup.exe" "%SCRIPT_DIR%dist_installer\setup.exe" >nul
copy /y "%SCRIPT_DIR%build\dist\setup.exe" "%SCRIPT_DIR%setup.exe" >nul

color 0A
echo ===============================================================================
echo   [SUCCESS] setup.exe has been built successfully!
echo   Installer locations:
echo     1. %SCRIPT_DIR%setup.exe
echo     2. %SCRIPT_DIR%dist_installer\setup.exe
echo.
echo   You can now double-click setup.exe on any Windows machine to install
echo   all prerequisites, Vitorius Firewall Win, Desktop icon, and Tray autostart!
echo ===============================================================================
echo.
pause
exit /b 0
