@echo off
setlocal enabledelayedexpansion
title Crazy Alchemy - Setup & Installation
color 0B

echo ===============================================================================
echo   Crazy Alchemy v3.0 LadyZi - 1-Click Installer
echo   Prerequisites Installation + Desktop Icon + System Tray Autostart
echo ===============================================================================
echo.

REM 1. Check for Administrator privileges and self-elevate if necessary
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Administrator privileges required for system installation.
    echo [*] Requesting elevation via Windows UAC...
    if "%~1"=="" (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo [*] Elevated Administrator execution confirmed.
echo.

REM 2. If compiled setup.exe exists, launch it directly
if exist "%SCRIPT_DIR%setup.exe" (
    echo [*] Launching standalone setup.exe...
    start "" "%SCRIPT_DIR%setup.exe" %*
    exit /b 0
)

if exist "%SCRIPT_DIR%dist_installer\setup.exe" (
    echo [*] Launching dist_installer\setup.exe...
    start "" "%SCRIPT_DIR%dist_installer\setup.exe" %*
    exit /b 0
)

REM 2. Search for Python
set "PYTHON_EXE="

py -3 -c "import sys; print(sys.executable)" >nul 2>nul
if %errorlevel% equ 0 set "PYTHON_EXE=py -3"

if "%PYTHON_EXE%"=="" (
    python -c "import sys; print(sys.executable)" >nul 2>nul
    if %errorlevel% equ 0 set "PYTHON_EXE=python"
)

if "%PYTHON_EXE%"=="" (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

if "%PYTHON_EXE%"=="" (
    for /d %%D in ("%ProgramFiles%\Python3*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

REM If Python is still missing, prompt or trigger prerequisites downloader
if "%PYTHON_EXE%"=="" (
    echo [*] Python not detected on this system.
    if exist "%SCRIPT_DIR%download_prerequisites.bat" (
        echo [*] Launching automated prerequisites downloader...
        call "%SCRIPT_DIR%download_prerequisites.bat"
    )
    
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
    if "%PYTHON_EXE%"=="" set "PYTHON_EXE=python"
)

echo [*] Running Crazy Alchemy Setup Engine with %PYTHON_EXE%...
%PYTHON_EXE% "%SCRIPT_DIR%build\setup_win.py" %*

if %errorlevel% equ 0 (
    color 0A
    echo.
    echo ===============================================================================
    echo   Setup Completed Successfully!
    echo ===============================================================================
)

echo.
pause
exit /b %errorlevel%
