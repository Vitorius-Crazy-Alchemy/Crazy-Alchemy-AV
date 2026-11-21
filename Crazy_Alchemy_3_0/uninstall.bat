@echo off
setlocal enabledelayedexpansion
title Crazy Alchemy - Local Uninstaller
color 0C

echo ===============================================================================
echo   Crazy Alchemy v3.0 - Local Uninstaller
echo   Cleanly Remove Windows Service, Firewall Rules, Shortcuts, and Program Files
echo ===============================================================================
echo.

REM 1. Check for Administrator privileges and self-elevate if necessary
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Administrator privileges required for clean uninstallation.
    echo [*] Requesting elevation via Windows UAC...
    if "%~1"=="" (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

set "SCRIPT_DIR=%~dp0"
echo [*] Elevated Administrator execution confirmed.
echo.

REM Prompt confirmation unless silent flag passed
set "IS_SILENT=0"
if /i "%~1"=="--silent" set "IS_SILENT=1"
if /i "%~1"=="-s" set "IS_SILENT=1"
if /i "%~1"=="--yes" set "IS_SILENT=1"
if /i "%~1"=="-y" set "IS_SILENT=1"
if /i "%~1"=="/quiet" set "IS_SILENT=1"

if "!IS_SILENT!"=="0" (
    echo Are you sure you want to completely uninstall Crazy Alchemy?
    echo [Y] Yes, uninstall completely
    echo [N] No, cancel
    echo.
    set /p "USER_CONFIRM=Enter choice [Y/N]: "
    if /i not "!USER_CONFIRM!"=="Y" (
        echo.
        echo [-] Uninstallation canceled by user.
        pause
        exit /b 0
    )
    echo.
)

REM 2. Resolve target installation directory from Registry or standard paths
set "TARGET_INSTALL_DIR="
for /f "tokens=2* skip=2" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /v InstallLocation 2^>nul') do set "TARGET_INSTALL_DIR=%%B"
if "%TARGET_INSTALL_DIR%"=="" for /f "tokens=2* skip=2" %%A in ('reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /v InstallLocation 2^>nul') do set "TARGET_INSTALL_DIR=%%B"
if "%TARGET_INSTALL_DIR%"=="" for /f "tokens=2* skip=2" %%A in ('reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /v InstallLocation 2^>nul') do set "TARGET_INSTALL_DIR=%%B"
if "%TARGET_INSTALL_DIR%"=="" if exist "%ProgramFiles%\Crazy Alchemy" set "TARGET_INSTALL_DIR=%ProgramFiles%\Crazy Alchemy"
if "%TARGET_INSTALL_DIR%"=="" if exist "%LOCALAPPDATA%\Programs\Crazy Alchemy" set "TARGET_INSTALL_DIR=%LOCALAPPDATA%\Programs\Crazy Alchemy"

if defined TARGET_INSTALL_DIR (
    if "!TARGET_INSTALL_DIR:~-1!"=="\" set "TARGET_INSTALL_DIR=!TARGET_INSTALL_DIR:~0,-1!"
    echo [*] Detected Installation Directory: !TARGET_INSTALL_DIR!
)

REM 3. Locate Python interpreter
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

if "%PYTHON_EXE%"=="" (
    for /d %%D in ("C:\Program Files\Python3*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

if "%PYTHON_EXE%"=="" (
    for /d %%D in ("C:\Users\*\AppData\Local\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
    )
)

REM 4. Run uninstaller via Python engine if available
set "UNINST_SUCCESS=0"

if not "%PYTHON_EXE%"=="" (
    if exist "%SCRIPT_DIR%backend\uninstaller.py" (
        echo [*] Invoking Crazy Alchemy Uninstaller Engine with %PYTHON_EXE%...
        if exist "!PYTHON_EXE!" (
            "!PYTHON_EXE!" "%SCRIPT_DIR%backend\uninstaller.py" %*
        ) else (
            %PYTHON_EXE% "%SCRIPT_DIR%backend\uninstaller.py" %*
        )
        if !errorlevel! equ 0 set "UNINST_SUCCESS=1"
    ) else if exist "%SCRIPT_DIR%build\setup_win.py" (
        echo [*] Invoking Crazy Alchemy Setup Engine with %PYTHON_EXE%...
        if exist "!PYTHON_EXE!" (
            "!PYTHON_EXE!" "%SCRIPT_DIR%build\setup_win.py" --uninstall %*
        ) else (
            %PYTHON_EXE% "%SCRIPT_DIR%build\setup_win.py" --uninstall %*
        )
        if !errorlevel! equ 0 set "UNINST_SUCCESS=1"
    ) else if exist "%SCRIPT_DIR%setup_win.py" (
        echo [*] Invoking Crazy Alchemy Setup Engine with %PYTHON_EXE%...
        if exist "!PYTHON_EXE!" (
            "!PYTHON_EXE!" "%SCRIPT_DIR%setup_win.py" --uninstall %*
        ) else (
            %PYTHON_EXE% "%SCRIPT_DIR%setup_win.py" --uninstall %*
        )
        if !errorlevel! equ 0 set "UNINST_SUCCESS=1"
    ) else if exist "%SCRIPT_DIR%main_win.py" (
        echo [*] Invoking main_win.py uninstaller with %PYTHON_EXE%...
        if exist "!PYTHON_EXE!" (
            "!PYTHON_EXE!" "%SCRIPT_DIR%main_win.py" --uninstall %*
        ) else (
            %PYTHON_EXE% "%SCRIPT_DIR%main_win.py" --uninstall %*
        )
        if !errorlevel! equ 0 set "UNINST_SUCCESS=1"
    )
)

if "!UNINST_SUCCESS!"=="0" (
    if exist "%SCRIPT_DIR%CrazyAlchemy.exe" (
        echo [*] Invoking CrazyAlchemy.exe --uninstall...
        "%SCRIPT_DIR%CrazyAlchemy.exe" --uninstall
        if !errorlevel! equ 0 set "UNINST_SUCCESS=1"
    ) else if exist "%SCRIPT_DIR%VitoriusFirewallWin.exe" (
        echo [*] Invoking VitoriusFirewallWin.exe --uninstall...
        "%SCRIPT_DIR%VitoriusFirewallWin.exe" --uninstall
        if !errorlevel! equ 0 set "UNINST_SUCCESS=1"
    )
)

REM 5. Standalone native batch cleanup fallback (if Python/Exe missing or failed)
if "!UNINST_SUCCESS!"=="0" (
    echo [-] Python engine unavailable or returned non-zero.
    echo [*] Executing native standalone Windows cleanup fallback...

    echo [*] [1/6] Terminating active application instances...
    taskkill /F /IM CrazyAlchemy.exe /T >nul 2>&1
    taskkill /F /IM VitoriusFirewallWin.exe /T >nul 2>&1
    taskkill /F /IM vitorius_service.exe /T >nul 2>&1
    taskkill /F /FI "WINDOWTITLE eq Crazy Alchemy*" >nul 2>&1
    taskkill /F /FI "WINDOWTITLE eq Vitorius Firewall Win*" >nul 2>&1

    echo [*] [2/6] Stopping and removing Windows Services...
    net stop CrazyAlchemyService >nul 2>&1
    sc stop CrazyAlchemyService >nul 2>&1
    sc delete CrazyAlchemyService >nul 2>&1
    net stop VitoriusFirewallCoreSvc >nul 2>&1
    sc stop VitoriusFirewallCoreSvc >nul 2>&1
    sc delete VitoriusFirewallCoreSvc >nul 2>&1
    net stop VitoriusFirewallService >nul 2>&1
    sc stop VitoriusFirewallService >nul 2>&1
    sc delete VitoriusFirewallService >nul 2>&1

    echo [*] [3/6] Reverting Windows Firewall, Defender, and Exploit Guard to factory defaults...
    if defined TARGET_INSTALL_DIR (
        netsh advfirewall firewall delete rule name=all dir=in profile=any program="!TARGET_INSTALL_DIR!\CrazyAlchemy.exe" >nul 2>&1
        netsh advfirewall firewall delete rule name=all dir=in profile=any program="!TARGET_INSTALL_DIR!\VitoriusFirewallWin.exe" >nul 2>&1
    )
    netsh advfirewall firewall delete rule name="VitoriusFW_PANIC_IN" >nul 2>&1
    netsh advfirewall firewall delete rule name="VitoriusFW_PANIC_OUT" >nul 2>&1
    netsh advfirewall firewall delete rule name="VFW_PANIC_IN" >nul 2>&1
    netsh advfirewall firewall delete rule name="VFW_PANIC_OUT" >nul 2>&1
    netsh advfirewall firewall delete rule name="CrazyAlchemy_Service" >nul 2>&1
    netsh advfirewall firewall delete rule name="CrazyAlchemy_UI" >nul 2>&1
    netsh advfirewall reset >nul 2>&1
    netsh advfirewall set allprofiles state on >nul 2>&1
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1

    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /f >nul 2>&1
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" /f >nul 2>&1
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /f >nul 2>&1
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >nul 2>&1
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /f >nul 2>&1
    powershell -NoProfile -NonInteractive -Command "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue; Set-ProcessMitigation -System -Reset -ErrorAction SilentlyContinue; Set-MpPreference -AttackSurfaceReductionRules_Ids @() -AttackSurfaceReductionRules_Actions @() -ErrorAction SilentlyContinue" >nul 2>&1
    ipconfig /flushdns >nul 2>&1
    netsh interface ip delete arpcache >nul 2>&1
    nbtstat -R >nul 2>&1

    echo [*] [4/6] Removing shortcuts, Task Scheduler tasks, and registry integration...
    del /F /Q "%USERPROFILE%\Desktop\Crazy Alchemy.lnk" >nul 2>&1
    del /F /Q "%USERPROFILE%\Desktop\Vitorius Firewall Win.lnk" >nul 2>&1
    del /F /Q "%PUBLIC%\Desktop\Crazy Alchemy.lnk" >nul 2>&1
    del /F /Q "%PUBLIC%\Desktop\Vitorius Firewall Win.lnk" >nul 2>&1
    del /F /Q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Crazy Alchemy.lnk" >nul 2>&1
    del /F /Q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Vitorius Firewall Win.lnk" >nul 2>&1
    del /F /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\Crazy Alchemy.lnk" >nul 2>&1
    del /F /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\Vitorius Firewall Win.lnk" >nul 2>&1
    rmdir /S /Q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Crazy Alchemy" >nul 2>&1
    rmdir /S /Q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Vitorius Firewall Win" >nul 2>&1
    rmdir /S /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Crazy Alchemy" >nul 2>&1
    rmdir /S /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Vitorius Firewall Win" >nul 2>&1

    schtasks /Delete /TN "CrazyAlchemy" /F >nul 2>&1
    schtasks /Delete /TN "CrazyAlchemyAutostart" /F >nul 2>&1
    schtasks /Delete /TN "CrazyAlchemyOfflineScan" /F >nul 2>&1
    schtasks /Delete /TN "CrazyAlchemy_ElevationBypass" /F >nul 2>&1
    schtasks /Delete /TN "VitoriusOfflineScan" /F >nul 2>&1
    schtasks /Delete /TN "VitoriusFirewallWin" /F >nul 2>&1
    schtasks /Delete /TN "VitoriusFirewallWinAutostart" /F >nul 2>&1
    schtasks /Delete /TN "VitoriusFirewallService" /F >nul 2>&1

    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CrazyAlchemy" /f >nul 2>&1
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "VitoriusFirewallWin" /f >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CrazyAlchemy" /f /reg:64 >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CrazyAlchemy" /f /reg:32 >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "VitoriusFirewallWin" /f /reg:64 >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "VitoriusFirewallWin" /f /reg:32 >nul 2>&1

    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f /reg:64 >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f /reg:32 >nul 2>&1
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin" /f >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin" /f /reg:64 >nul 2>&1
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin" /f /reg:32 >nul 2>&1

    reg delete "HKCU\Software\CrazyAlchemy" /f >nul 2>&1
    reg delete "HKLM\Software\CrazyAlchemy" /f /reg:64 >nul 2>&1
    reg delete "HKLM\Software\CrazyAlchemy" /f /reg:32 >nul 2>&1
    reg delete "HKCU\Software\VitoriusFirewallWin" /f >nul 2>&1
    reg delete "HKLM\Software\VitoriusFirewallWin" /f /reg:64 >nul 2>&1
    reg delete "HKLM\Software\VitoriusFirewallWin" /f /reg:32 >nul 2>&1

    reg delete "HKCR\*\shell\CrazyAlchemyScan" /f >nul 2>&1
    reg delete "HKCR\Directory\shell\CrazyAlchemyScan" /f >nul 2>&1
    reg delete "HKCR\Directory\Background\shell\CrazyAlchemyScan" /f >nul 2>&1
    reg delete "HKCR\*\shell\VitoriusScan" /f >nul 2>&1
    reg delete "HKCR\Directory\shell\VitoriusScan" /f >nul 2>&1
    reg delete "HKCR\Directory\Background\shell\VitoriusScan" /f >nul 2>&1

    echo [*] [5/6] Removing application settings, user options, caches, databases, and temporary files...
    rmdir /S /Q "%APPDATA%\VitoriusFirewallWin" >nul 2>&1
    rmdir /S /Q "%APPDATA%\CrazyAlchemy" >nul 2>&1
    rmdir /S /Q "%USERPROFILE%\.vitorius_firewall_win" >nul 2>&1
    rmdir /S /Q "%USERPROFILE%\.crazy_alchemy" >nul 2>&1
    rmdir /S /Q "%LOCALAPPDATA%\VitoriusFirewallWin" >nul 2>&1
    rmdir /S /Q "%LOCALAPPDATA%\CrazyAlchemy" >nul 2>&1
    rmdir /S /Q "%ProgramData%\VitoriusFirewallWin" >nul 2>&1
    rmdir /S /Q "%ProgramData%\CrazyAlchemy" >nul 2>&1
    rmdir /S /Q "%TEMP%\VitoriusFirewallWin" >nul 2>&1
    rmdir /S /Q "%TEMP%\vitorius_firewall_win" >nul 2>&1
    rmdir /S /Q "%TEMP%\CrazyAlchemy" >nul 2>&1
    rmdir /S /Q "%TEMP%\crazy_alchemy" >nul 2>&1
    rmdir /S /Q "%TEMP%\vitorius_quarantine" >nul 2>&1
    del /F /Q "%TEMP%\VitoriusTweaks_*.log" >nul 2>&1

    set "UNINST_SUCCESS=1"
)

REM 6. Clean up installation directory and purge Control Panel registration
echo [*] [6/6] Cleaning up installation directory and Control Panel registration...

reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f /reg:64 >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f /reg:32 >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f >nul 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy" /f >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\CrazyAlchemy', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VitoriusFirewallWin' -Recurse -Force -ErrorAction SilentlyContinue" >nul 2>&1

if defined TARGET_INSTALL_DIR if exist "!TARGET_INSTALL_DIR!" (
    if not exist "!TARGET_INSTALL_DIR!\.git" (
        rmdir /S /Q "!TARGET_INSTALL_DIR!\backend" >nul 2>&1
        rmdir /S /Q "!TARGET_INSTALL_DIR!\ui" >nul 2>&1
        rmdir /S /Q "!TARGET_INSTALL_DIR!\data" >nul 2>&1
        rmdir /S /Q "!TARGET_INSTALL_DIR!\service" >nul 2>&1
        rmdir /S /Q "!TARGET_INSTALL_DIR!\prerequisites" >nul 2>&1
        rmdir /S /Q "!TARGET_INSTALL_DIR!\build" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\*.py" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\*.txt" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\*.jpg" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\*.mp3" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\*.ico" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\CrazyAlchemy.bat" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\setup.bat" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\VitoriusFirewallWin.bat" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\CrazyAlchemy.exe" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\VitoriusFirewallWin.exe" >nul 2>&1
        del /F /Q "!TARGET_INSTALL_DIR!\data\signatures\malware_hashes.db" >nul 2>&1
    )
)

:finalize
color 0A
echo.
echo ===============================================================================
echo   [SUCCESS] Crazy Alchemy uninstalled completely!
echo ===============================================================================
echo.

if "!IS_SILENT!"=="0" (
    echo Press any key to complete uninstallation and close this window...
    pause >nul
)

cd /d "%TEMP%"

if defined TARGET_INSTALL_DIR if exist "!TARGET_INSTALL_DIR!" (
    if not exist "!TARGET_INSTALL_DIR!\.git" (
        start "" /b cmd /c "timeout /t 1 /nobreak >nul & del /f /q \"!TARGET_INSTALL_DIR!\uninstall.bat\" >nul 2>&1 & rmdir /s /q \"!TARGET_INSTALL_DIR!\" >nul 2>&1"
    )
)

exit /b 0
