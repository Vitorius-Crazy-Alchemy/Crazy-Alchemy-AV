"""
Crazy Alchemy - Windows Elevation & UAC Prompt Suppression Subsystem
Enterprise-Grade Windows 11 Task Scheduler Elevation Bypass

Implements standard Windows Task Scheduler HighestAvailable elevation architecture:
1. Registers on-demand task 'CrazyAlchemy' with RunLevel: HighestAvailable
   allowing instantaneous elevated launch with ZERO User Account Control (UAC) prompts.
2. Registers startup task 'CrazyAlchemyAutostart' triggered ONLOGON with RunLevel: HighestAvailable
   guaranteeing silent background tray startup after reboot with ZERO UAC prompts.
3. Automatically strips Zone.Identifier alternate data streams ('Mark of the Web')
   to prevent Windows 'Open File - Security Warning: Do you want to run this file?'.
4. Removes legacy non-elevated Registry Run and Startup folder shortcuts to eliminate
   conflicting elevation prompts upon system login.
"""

import sys
import os
import subprocess
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("crazyalchemy.elevation")

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def is_elevated() -> bool:
    """Checks whether the current process possesses Administrator privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.getuid() == 0 if hasattr(os, "getuid") else False


def build_task_scheduler_xml(
    command: str,
    arguments: str = "",
    work_dir: str = "",
    description: str = "Crazy Alchemy Protection Shield",
    on_logon: bool = False,
    highest_privileges: bool = True
) -> str:
    """
    Generates a compliant Task Scheduler 2.0 XML definition with HighestAvailable privileges.
    Uses InteractiveToken so the GUI application executes directly on the interactive user desktop.
    """
    run_level = "HighestAvailable" if highest_privileges else "LeastPrivilege"
    
    triggers_block = ""
    if on_logon:
        triggers_block = """    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT3S</Delay>
    </LogonTrigger>"""

    args_elem = f"<Arguments>{arguments}</Arguments>" if arguments else ""
    work_dir_elem = f"<WorkingDirectory>{work_dir}</WorkingDirectory>" if work_dir else ""

    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
    <Author>Crazy Alchemy</Author>
  </RegistrationInfo>
  <Triggers>
{triggers_block}
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>{run_level}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      {args_elem}
      {work_dir_elem}
    </Exec>
  </Actions>
</Task>
"""
    return xml


def register_elevation_bypass_task(
    target_exe: Optional[str] = None,
    script_path: Optional[str] = None,
    install_dir: Optional[Path] = None,
    app_name: str = "CrazyAlchemy"
) -> bool:
    """
    Registers the elevated Task Scheduler entries with HighestAvailable privileges:
    1. '{app_name}': On-demand elevated launch without UAC prompt.
    2. '{app_name}Autostart': Silent elevated tray launch upon user login after reboot.
    Must be called from an elevated process (during setup or upon first elevated run).
    """
    if sys.platform != "win32":
        return True

    try:
        if not install_dir:
            if script_path:
                install_dir = Path(script_path).resolve().parent
            else:
                install_dir = Path(__file__).resolve().parent.parent

        # Resolve command and script
        if not target_exe:
            if getattr(sys, "frozen", False):
                cmd_path = sys.executable
                cmd_args = ""
            else:
                py_exe = sys.executable
                pythonw = Path(py_exe).parent / "pythonw.exe"
                cmd_path = str(pythonw if pythonw.exists() else py_exe)
                target_script = script_path if script_path else str(install_dir / "main_win.py")
                cmd_args = f'"{target_script}"'
        else:
            p_target = Path(target_exe)
            if p_target.suffix.lower() == ".exe":
                cmd_path = str(p_target)
                cmd_args = ""
            elif p_target.suffix.lower() == ".bat":
                # For batch launchers, point directly to pythonw runner
                py_exe = sys.executable
                pythonw = Path(py_exe).parent / "pythonw.exe"
                cmd_path = str(pythonw if pythonw.exists() else py_exe)
                target_script = str(install_dir / "main_win.py")
                cmd_args = f'"{target_script}"'
            else:
                cmd_path = str(p_target)
                cmd_args = ""

        temp_dir = Path(os.environ.get("TEMP", str(install_dir)))

        # 1. On-Demand Task (Instant elevated GUI with zero UAC prompts)
        task_on_demand = app_name
        xml_content_demand = build_task_scheduler_xml(
            command=cmd_path,
            arguments=cmd_args,
            work_dir=str(install_dir),
            description="Crazy Alchemy Real-Time Protection (Elevated On-Demand)",
            on_logon=False,
            highest_privileges=True
        )
        xml_file_demand = temp_dir / f"{app_name}_demand.xml"
        xml_file_demand.write_text(xml_content_demand, encoding="utf-16")

        res_demand = subprocess.run(
            ["schtasks", "/create", "/tn", task_on_demand, "/xml", str(xml_file_demand), "/f"],
            capture_output=True, text=True, creationflags=CREATE_NO_WINDOW
        )
        if xml_file_demand.exists():
            xml_file_demand.unlink()

        if res_demand.returncode == 0:
            logger.info(f"Registered elevated task '{task_on_demand}' with HighestAvailable privileges.")
        else:
            logger.warning(f"Failed to register on-demand task '{task_on_demand}': {res_demand.stderr.strip()}")

        # 2. Autostart Task (Silent elevated system tray launch on login after reboot)
        task_autostart = f"{app_name}Autostart"
        autostart_args = f"{cmd_args} --minimized".strip() if cmd_args else "--minimized"
        xml_content_auto = build_task_scheduler_xml(
            command=cmd_path,
            arguments=autostart_args,
            work_dir=str(install_dir),
            description="Crazy Alchemy System Tray Protection (Elevated Startup)",
            on_logon=True,
            highest_privileges=True
        )
        xml_file_auto = temp_dir / f"{app_name}_auto.xml"
        xml_file_auto.write_text(xml_content_auto, encoding="utf-16")

        res_auto = subprocess.run(
            ["schtasks", "/create", "/tn", task_autostart, "/xml", str(xml_file_auto), "/f"],
            capture_output=True, text=True, creationflags=CREATE_NO_WINDOW
        )
        if xml_file_auto.exists():
            xml_file_auto.unlink()

        if res_auto.returncode == 0:
            logger.info(f"Registered elevated autostart task '{task_autostart}' with HighestAvailable privileges.")
        else:
            logger.warning(f"Failed to register autostart task '{task_autostart}': {res_auto.stderr.strip()}")

        return res_demand.returncode == 0
    except Exception as e:
        logger.warning(f"Error registering elevation bypass tasks: {e}")
        return False


def dispatch_elevated_bypass_task(task_name: str = "CrazyAlchemy") -> bool:
    """
    Launches the application via the pre-authorized elevated Task Scheduler task.
    Executes cleanly without displaying ANY User Account Control (UAC) prompt.
    Returns True if successfully dispatched, False if the task is not registered.
    """
    if sys.platform != "win32":
        return False

    try:
        # Check if the task is registered in Task Scheduler
        query_cmd = ["schtasks", "/query", "/tn", task_name]
        q_res = subprocess.run(query_cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if q_res.returncode != 0:
            return False

        # Run task
        run_cmd = ["schtasks", "/run", "/tn", task_name]
        r_res = subprocess.run(run_cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if r_res.returncode == 0:
            logger.info(f"Successfully launched elevated instance via Task Scheduler task '{task_name}'.")
            return True
        else:
            logger.debug(f"Task Scheduler run notice: {r_res.stderr.strip()}")
            return False
    except Exception as e:
        logger.debug(f"Elevation bypass dispatch notice: {e}")
        return False


def clean_non_elevated_autostart_entries(app_name: str = "CrazyAlchemy"):
    """
    Removes legacy non-elevated autostart entries (Registry Run key and Startup folder shortcuts).
    This prevents duplicate launches and prevents non-elevated processes from triggering
    UAC confirmation prompts upon system reboot.
    """
    if sys.platform != "win32":
        return

    # 1. Clean Registry Run key
    try:
        import winreg
        for hkey in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hkey, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as k:
                    for key_name in [app_name, "VitoriusFirewallWin", "Crazy Alchemy", "CrazyAlchemy"]:
                        try:
                            winreg.DeleteValue(k, key_name)
                            logger.info(f"Removed non-elevated Registry autostart key '{key_name}'.")
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Registry autostart cleanup notice: {e}")

    # 2. Clean Startup folder shortcuts
    try:
        startup_dirs = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        ]
        for s_dir in startup_dirs:
            if s_dir.exists():
                for f in s_dir.glob("*.lnk"):
                    if any(w in f.name.lower() for w in ["crazy", "alchemy", "vitorius"]):
                        try:
                            f.unlink()
                            logger.info(f"Removed non-elevated Startup folder shortcut '{f.name}'.")
                        except Exception:
                            pass
    except Exception as e:
        logger.debug(f"Startup folder shortcut cleanup notice: {e}")


def remove_elevation_bypass_tasks(app_name: str = "CrazyAlchemy") -> bool:
    """Removes elevated Task Scheduler entries during uninstallation."""
    if sys.platform != "win32":
        return True

    success = True
    for tn in [app_name, f"{app_name}Autostart", f"{app_name}OfflineScan", "VitoriusOfflineScan"]:
        try:
            res = subprocess.run(
                ["schtasks", "/delete", "/tn", tn, "/f"],
                capture_output=True, text=True, creationflags=CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                logger.info(f"Removed Task Scheduler entry: {tn}")
        except Exception:
            success = False
    return success


def unblock_directory_files(target_dir: Path):
    """
    Removes Zone.Identifier alternate data streams ('Mark of the Web') from all files in target_dir.
    This prevents Windows from asking 'Open File - Security Warning: Do you want to run this file?'.
    """
    if sys.platform != "win32" or not target_dir.exists():
        return

    try:
        # Use PowerShell Unblock-File
        ps_cmd = f"Get-ChildItem -Path '{str(target_dir)}' -Recurse -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue"
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, creationflags=CREATE_NO_WINDOW
        )
    except Exception as e:
        logger.debug(f"Unblock files notice: {e}")
