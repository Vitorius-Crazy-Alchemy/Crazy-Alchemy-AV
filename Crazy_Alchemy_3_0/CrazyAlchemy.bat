@echo off
rem ===============================================================================
rem Crazy Alchemy v3.0 - 1-Click Silent Elevated Launcher (Zero UAC Prompt)
rem ===============================================================================

schtasks /run /tn "CrazyAlchemy" >nul 2>nul
if %errorlevel% equ 0 exit /b 0

set "SCRIPT_DIR=%~dp0"
set "PYTHON_EXE="

for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%D\pythonw.exe" set "PYTHON_EXE=%%D\pythonw.exe"
)
if "%PYTHON_EXE%"=="" (
    for /d %%D in ("%ProgramFiles%\Python3*") do (
        if exist "%%D\pythonw.exe" set "PYTHON_EXE=%%D\pythonw.exe"
    )
)
if "%PYTHON_EXE%"=="" (
    where pythonw >nul 2>nul && set "PYTHON_EXE=pythonw.exe"
)
if "%PYTHON_EXE%"=="" set "PYTHON_EXE=python.exe"

start "" "%PYTHON_EXE%" "%SCRIPT_DIR%main_win.py" %*
exit /b 0
