#!/usr/bin/env python3
"""
Vitorius Firewall Win - Main Executable Entry Point
Enterprise-Grade Windows 11 Firewall & Antivirus Security Suite
Created by Vitorius
License: MIT
"""

import sys
import os
from pathlib import Path
import logging

__version__ = '2.0'
__codename__ = 'LudaCris'
__author__ = 'Vitorius'
__license__ = 'MIT'
__title__ = 'Crazy Alchemy'
__full_title__ = 'Crazy Alchemy v2.0 (LudaCris)'

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('vitorius.win')

from backend.core_win import WindowsFirewallCore
from backend.antivirus import AntivirusEngine
from backend.antivirus_updater import SignatureUpdater
from backend.realtime_shield import RealtimeShield
from backend.monitor_win import WindowsNetworkMonitor
from backend.scanner_win import WindowsServiceAppScanner
from backend.profiles_win import WindowsProfileManager, FirewallLogger
from backend.honeypot import HoneypotManager
from backend.chainguard import ChainGuardEngine
from backend.appprint import AppPrintEngine
from backend.darkweb_monitor import DarkWebMonitor
from backend.email_shield import EmailClientShield
from backend.exploit_shield import ExploitShield
from backend.defender_manager import WindowsDefenderManager
from backend.elevation_win import (
    is_elevated, dispatch_elevated_bypass_task,
    register_elevation_bypass_task, clean_non_elevated_autostart_entries,
    unblock_directory_files
)


def check_and_request_elevation() -> bool:
    """
    If running on Windows without elevation:
    1. If a pre-authorized elevated Task Scheduler task exists, launch it directly
       with ZERO UAC prompts and exit immediately.
    2. Otherwise, request elevation ONCE via ShellExecuteW 'runas'.
    When running WITH elevation:
    - Automatically register/refresh the Task Scheduler bypass tasks so all
      subsequent launches and reboots execute silently with ZERO UAC prompts.
    """
    if sys.platform == "win32":
        if not is_elevated():
            if "--no-elevate" in sys.argv or os.environ.get("VFW_NO_ELEVATE") == "1":
                return False
            # Do not auto-elevate during help, version, uninstallation, or CLI panic
            if any(arg in sys.argv for arg in ["-h", "--help", "-v", "--version", "--uninstall", "-u", "--panic", "--unpanic"]):
                return False

            # If user wants minimized tray startup, check autostart task
            task_to_run = "CrazyAlchemyAutostart" if "--minimized" in sys.argv else "CrazyAlchemy"

            # Check if Task Scheduler bypass task exists and dispatch silently (ZERO UAC prompt)
            if dispatch_elevated_bypass_task(task_to_run):
                sys.exit(0)

            # Task not registered yet: Request elevation ONCE
            try:
                import ctypes
                params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
                script_path = str(Path(sys.argv[0]).resolve())
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{script_path}" {params}'.strip(), None, 1
                )
                if ret > 32:
                    sys.exit(0)
            except Exception as e:
                logger.debug(f"Elevation request notice: {e}")
        else:
            # Process is elevated! Register Task Scheduler bypass tasks so it never prompts again
            try:
                script_path = str(Path(sys.argv[0]).resolve())
                register_elevation_bypass_task(script_path=script_path)
                clean_non_elevated_autostart_entries()
            except Exception as e:
                logger.debug(f"Elevation task auto-registration notice: {e}")

    return False


def acquire_single_instance_mutex(mutex_name: str = "Local\\CrazyAlchemyWinMutex"):
    """Ensures only a single instance of Crazy Alchemy runs simultaneously per user session."""
    if sys.platform == "win32":
        try:
            import ctypes
            ERROR_ALREADY_EXISTS = 183
            ERROR_ACCESS_DENIED = 5
            handle = ctypes.windll.kernel32.CreateMutexW(None, True, mutex_name)
            last_error = ctypes.windll.kernel32.GetLastError()
            if last_error == ERROR_ALREADY_EXISTS:
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                return False, None
            if last_error == ERROR_ACCESS_DENIED and handle == 0:
                # If access denied on Global namespace, retry with Local namespace
                handle = ctypes.windll.kernel32.CreateMutexW(None, True, "Local\\CrazyAlchemyWinMutex")
                if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
                    if handle:
                        ctypes.windll.kernel32.CloseHandle(handle)
                    return False, None
            return True, handle
        except Exception:
            return True, None
    return True, None


def main():
    # Handle Uninstallation CLI request (must run independently of GUI mutex and terminate running app)
    if '--uninstall' in sys.argv or '-u' in sys.argv:
        from build.setup_win import run_uninstallation
        run_uninstallation()
        return 0

    # Handle Windows Service command line flags first (must run independently of GUI mutex)
    if len(sys.argv) > 1 and sys.argv[1].startswith("--service"):
        from service.vitorius_service import handle_service_cli
        handle_service_cli()
        return 0

    # Handle offline reboot scanner
    if '--offline-scan' in sys.argv:
        from backend.offline_scanner import run_offline_scan_cli
        return run_offline_scan_cli()

    # Handle quick command-line unpanic (should execute even if GUI instance is running)
    if '--unpanic' in sys.argv or '--disable-panic' in sys.argv:
        core = WindowsFirewallCore()
        print("Disabling Windows panic mode...")
        if core.disable_panic_mode():
            print("✓ Panic mode disabled. Windows network traffic restored.")
            FirewallLogger().log_event('panic_off', 'info', 'Panic mode disabled via CLI')
            return 0
        else:
            print("✗ Failed to disable panic mode (verify Administrator elevation).")
            return 1

    # Handle quick command-line panic (should execute even if GUI instance is running)
    if '--panic' in sys.argv or '--enable-panic' in sys.argv:
        core = WindowsFirewallCore()
        print("Enabling Windows panic mode...")
        if core.enable_panic_mode():
            print("✓ Panic mode enabled. Windows network traffic blocked.")
            FirewallLogger().log_event('panic_on', 'critical', 'Panic mode enabled via CLI')
            return 0
        else:
            print("✗ Failed to enable panic mode (verify Administrator elevation).")
            return 1

    # Request Windows Administrator elevation for GUI execution if needed
    check_and_request_elevation()

    # Check Windows Administrator elevation for firewall configuration
    if sys.platform == "win32" and not is_elevated():
        logger.warning(
            "Crazy Alchemy is running WITHOUT Administrator privileges. "
            "Modifying firewall rules, IP blocking, and Panic Lockdown require elevation. "
            "Please restart with 'Run as administrator' for full defensive protection."
        )

    # Check if an offline scan is pending from a scheduled reboot
    # This acts as an ironclad safeguard if Windows skipped RunOnce/Task Scheduler
    from backend.offline_scanner import OfflineScanManager
    startup_offline_mgr = OfflineScanManager(data_dir=PROJECT_DIR / "data")
    if startup_offline_mgr.is_pending() and '--offline-scan' not in sys.argv and '--no-offline-scan' not in sys.argv:
        logger.info("Detected pending offline scan scheduled prior to reboot. Launching offline scan now...")
        from backend.offline_scanner import run_offline_scan_cli
        run_offline_scan_cli()

    # Enforce single instance for GUI
    has_lock, mutex_handle = acquire_single_instance_mutex()
    if not has_lock:
        print("Another instance of Crazy Alchemy is already active.")
        return 0

    # Check PyQt6 availability
    try:
        from PyQt6.QtWidgets import QApplication
        from ui.app_win import VitoriusFirewallMainWindow
    except ImportError:
        logger.error("PyQt6 is required to run Crazy Alchemy GUI.")
        print("Error: PyQt6 is not installed. Please install with: pip install PyQt6")
        return 1

    logger.info(f"Starting {__full_title__} on Windows 11...")

    # Initialize Backend Subsystems
    default_config = PROJECT_DIR / "data" / "default_config_win.json"
    fw_core = WindowsFirewallCore()
    av_engine = AntivirusEngine(data_dir=PROJECT_DIR / "data")
    monitor = WindowsNetworkMonitor()
    scanner = WindowsServiceAppScanner()
    profiles = WindowsProfileManager(str(default_config))
    fw_logger = FirewallLogger()

    # Initialize Signature Updater with user-configured interval (2, 5, 12, or 24 hours)
    update_interval = profiles.get_setting("signature_update_interval_hours", 12)
    if update_interval not in [2, 5, 12, 24]:
        update_interval = 12

    mb_api_key = profiles.get_setting("malwarebazaar_api_key", None)

    av_updater = SignatureUpdater(
        db_path=PROJECT_DIR / "data" / "signatures" / "malware_hashes.db",
        interval_hours=update_interval,
        fw_logger=fw_logger,
        api_key=mb_api_key
    )
    if profiles.get_setting("signature_auto_update", True):
        av_updater.start_auto_update()

    # Start Real-Time File Shield if enabled
    shield = None
    if profiles.get_setting("realtime_antivirus", True):
        shield = RealtimeShield(av_engine, on_threat_cb=lambda t: fw_logger.log_event("threat_shield", "critical", f"Shield quarantined: {t.threat_name}"))
        shield.start()

    # Start TrapNet Deception Decoy Ports
    honeypot_mgr = HoneypotManager(
        block_callback=fw_core.block_ip,
        alert_callback=lambda ev: fw_logger.log_event("honeypot_trap", "critical", f"Intruder banned: {ev.source_ip} on port {ev.trap_port}")
    )
    honeypot_mgr.start()

    # Start ChainGuard Process Lineage Validator
    chainguard_engine = ChainGuardEngine(
        alert_callback=lambda cg: fw_logger.log_event("chainguard_alert", "critical", f"Suspicious lineage for PID {cg.pid} ({cg.process_name}): {' -> '.join(cg.full_chain)}")
    )
    chainguard_engine.start()

    # Start AppPrint Network DNA Profiling
    appprint_engine = AppPrintEngine(
        alert_callback=lambda an: fw_logger.log_event("appprint_anomaly", "warning", f"AppPrint anomaly: {an.app_name} -> {an.details}")
    )
    appprint_engine.start()

    # Start DarkWeb Identity & Breach Intelligence Monitor
    darkweb_monitor = DarkWebMonitor(
        data_dir=PROJECT_DIR / "data",
        fw_logger=fw_logger,
        check_interval_hours=profiles.get_setting("darkweb_check_interval_hours", 6)
    )
    if profiles.get_setting("darkweb_monitoring_enabled", True):
        darkweb_monitor.start()

    # Start Email Client Antivirus Shield (Outlook, Thunderbird, WinMail, eM Client, Mailbird)
    email_shield = EmailClientShield(
        av_engine=av_engine,
        fw_logger=fw_logger,
        alert_callback=lambda threat, client, reason: fw_logger.log_event(
            "email_shield_threat", "critical",
            f"Email Shield ({client}) intercepted threat: {threat.threat_name} ({reason})"
        ),
        enabled_clients=profiles.get_setting("email_monitored_clients", ["outlook", "thunderbird", "winmail", "emclient", "mailbird"])
    )
    if profiles.get_setting("email_shield_enabled", True):
        email_shield.start()

    # Start Anti-Exploit, Memory Protection & Attack Surface Reduction Engine
    exploit_shield = ExploitShield(
        fw_logger=fw_logger,
        alert_callback=lambda ev: fw_logger.log_event(
            "exploit_shield_threat", "critical",
            f"Exploit Shield blocked {ev.exploit_type} on PID {ev.pid} ({ev.process_name}): {ev.details}"
        ),
        auto_kill_exploits=profiles.get_setting("anti_exploit_auto_kill", True)
    )
    if profiles.get_setting("anti_exploit_enabled", True):
        exploit_shield.apply_hardening_profile(profiles.get_setting("anti_exploit_profile", "Recommended"))
        exploit_shield.start()

    # Windows Defender Antivirus Coexistence & Setting Propagation Manager
    defender_mgr = WindowsDefenderManager(fw_logger=fw_logger)
    defender_mgr.initialize_startup_coexistence(profiles.get_setting("defender_coexistence_mode", "passive_secondary"))

    # Offline Antivirus Scan Manager
    from backend.offline_scanner import OfflineScanManager
    offline_scanner = OfflineScanManager(
        data_dir=PROJECT_DIR / "data",
        fw_core=fw_core,
        av_engine=av_engine,
        fw_logger=fw_logger
    )

    # Browser Web Shield & Brave-Style AdBlock Companion
    from backend.browser_shield import BrowserCompanionServer, ExtensionDeployer
    try:
        ExtensionDeployer.deploy_extension_files()
    except Exception as e:
        logger.debug(f"Extension deployment notice: {e}")
    browser_shield = BrowserCompanionServer(
        port=49211,
        fw_logger=fw_logger,
        profiles=profiles
    )
    if profiles.get_setting("browser_protection", True):
        browser_shield.start()

    # Install global exception hook to prevent crash-to-desktop from unhandled slot exceptions
    def global_excepthook(exc_type, exc_val, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_val, exc_tb)
            return
        logger.critical("Uncaught Exception in GUI loop:", exc_info=(exc_type, exc_val, exc_tb))
        try:
            from PyQt6.QtWidgets import QMessageBox, QApplication
            if QApplication.instance():
                QMessageBox.critical(
                    None,
                    "Application Notice",
                    f"An error occurred in Crazy Alchemy:\n\n{exc_val}\n\n"
                    "The application recovered cleanly and prevented a crash to desktop. See logs for details."
                )
        except Exception:
            pass

    sys.excepthook = global_excepthook

    # Launch GUI Application
    app = QApplication(sys.argv)
    app.setApplicationName(__title__)
    app.setApplicationDisplayName(__title__)

    win = VitoriusFirewallMainWindow(
        fw_core=fw_core,
        av_engine=av_engine,
        av_updater=av_updater,
        monitor=monitor,
        scanner=scanner,
        profiles=profiles,
        fw_logger=fw_logger,
        project_dir=PROJECT_DIR,
        honeypot_mgr=honeypot_mgr,
        chainguard_engine=chainguard_engine,
        appprint_engine=appprint_engine,
        realtime_shield=shield,
        offline_scanner=offline_scanner,
        darkweb_monitor=darkweb_monitor,
        email_shield=email_shield,
        exploit_shield=exploit_shield,
        defender_mgr=defender_mgr,
        browser_shield=browser_shield
    )

    # Check if started minimized to system tray
    start_minimized = (
        '--minimized' in sys.argv or
        '-m' in sys.argv or
        '--tray' in sys.argv or
        profiles.get_setting("start_minimized", False)
    )

    # Handle Explorer Context Menu scan
    if '--scan' in sys.argv:
        try:
            scan_idx = sys.argv.index('--scan')
            if scan_idx + 1 < len(sys.argv):
                target_path = sys.argv[scan_idx + 1]
                win.show()
                win.navigate_to("antivirus")
                win.pages["antivirus"]._start_scan_thread(target_path)
        except Exception as e:
            logger.debug(f"Error handling scan arg: {e}")
            win.show()
    elif not start_minimized:
        win.show()
    else:
        logger.info("Started minimized in Windows Notification Area (System Tray).")

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
