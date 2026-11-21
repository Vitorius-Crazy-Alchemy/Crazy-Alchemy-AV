@echo off
setlocal enabledelayedexpansion
title Crazy Alchemy v3.0 - Prerequisites Downloader
color 0B

echo ===============================================================================
echo   Crazy Alchemy v3.0 LadyZi - Prerequisites Downloader
echo   Downloads Python 3.12 installer and all offline wheels for air-gapped setups
echo ===============================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "PREREQ_DIR=%SCRIPT_DIR%prerequisites"
set "WHEELS_DIR=%PREREQ_DIR%\wheels"
set "REQ_FILE=%SCRIPT_DIR%requirements.txt"
set "REQ_BUILD=%SCRIPT_DIR%requirements-build.txt"
set "PY_URL=https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe"
set "PY_INSTALLER=%PREREQ_DIR%\python-3.12.8-amd64.exe"

REM Step 1: Create target directories
echo [*] [1/4] Creating prerequisites directories...
if not exist "%PREREQ_DIR%" mkdir "%PREREQ_DIR%"
if not exist "%WHEELS_DIR%" mkdir "%WHEELS_DIR%"
if exist "%REQ_FILE%" copy /y "%REQ_FILE%" "%PREREQ_DIR%\requirements.txt" >nul
if exist "%REQ_BUILD%" copy /y "%REQ_BUILD%" "%PREREQ_DIR%\requirements-build.txt" >nul
echo [OK] Folder structure ready: %PREREQ_DIR%
echo.

REM Step 2: Download Python 3.12 64-bit installer
echo [*] [2/4] Downloading official Python 3.12 64-bit Windows installer...
if exist "%PY_INSTALLER%" (
    echo [OK] Python installer already present: %PY_INSTALLER%
) else (
    echo [*] Fetching from: %PY_URL%
    where curl.exe >nul 2>nul
    if !errorlevel! equ 0 (
        curl.exe -L --progress-bar -o "%PY_INSTALLER%" "%PY_URL%"
    ) else (
        powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('%PY_URL%', '%PY_INSTALLER%')"
    )
    if exist "%PY_INSTALLER%" (
        echo [OK] Successfully downloaded: %PY_INSTALLER%
    ) else (
        echo [!] Warning: Failed to download Python installer automatically.
    )
)
echo.

REM Step 3: Locate Python environment for wheel downloads
echo [*] [3/4] Locating Python environment for wheel downloads...
set "PYTHON_EXE="
where python >nul 2>nul
if %errorlevel% equ 0 set "PYTHON_EXE=python"
if "%PYTHON_EXE%"=="" (
    where py >nul 2>nul
    if %errorlevel% equ 0 set "PYTHON_EXE=py -3"
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

if "%PYTHON_EXE%"=="" (
    echo [!] Python not currently found in PATH.
    if exist "%PY_INSTALLER%" (
        echo [*] Launching downloaded Python 3.12 installer...
        start /wait "" "%PY_INSTALLER%" /passive InstallAllUsers=0 PrependPath=1 Include_pip=1
        for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
            if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
        )
    )
)

REM Step 4: Download offline binary wheels
echo.
echo [*] [4/4] Downloading offline dependency wheels into:
echo     %WHEELS_DIR%
echo.

if not "%PYTHON_EXE%"=="" (
    echo [*] Using: %PYTHON_EXE%
    echo [*] Downloading runtime packages: PyQt6, psutil, watchdog, yara-python, pywin32...
    %PYTHON_EXE% -m pip download -r "%REQ_FILE%" -d "%WHEELS_DIR%" --only-binary=:all:
    
    if exist "%REQ_BUILD%" (
        echo [*] Downloading packaging and build packages: pyinstaller...
        %PYTHON_EXE% -m pip download -r "%REQ_BUILD%" -d "%WHEELS_DIR%" --only-binary=:all:
    )

    echo [*] Downloading helper packages: wheel, setuptools...
    %PYTHON_EXE% -m pip download wheel setuptools -d "%WHEELS_DIR%" --only-binary=:all:
) else (
    echo [!] Python not available to download wheels via pip.
    echo Please install Python using %PY_INSTALLER% and run this script again.
)

echo.
echo ===============================================================================
echo   Download Summary
echo ===============================================================================
if exist "%PY_INSTALLER%" (
    echo   [OK] Python Installer: %PY_INSTALLER%
)
dir /b "%WHEELS_DIR%\*.whl" 2>nul | find /c /v "" > "%TEMP%\whl_count.tmp"
set /p WHL_COUNT=<"%TEMP%\whl_count.tmp"
del "%TEMP%\whl_count.tmp" 2>nul
echo   [OK] Offline Wheels:   %WHL_COUNT% wheel packages in %WHEELS_DIR%
echo.
echo   All prerequisites have been downloaded and organized into:
echo   %PREREQ_DIR%
echo ===============================================================================
echo.
pause
