"""
Vitorius Firewall Win - Windows Background Service
Runs under LocalSystem to maintain persistent firewall enforcement and
real-time file system protection even before any user logs in.
"""

import sys
import os
import time
import logging
import threading
import json
from pathlib import Path

# Add project root to sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from backend.core_win import WindowsFirewallCore
from backend.antivirus import AntivirusEngine
from backend.realtime_shield import RealtimeShield

logger = logging.getLogger('vitorius.service')

PIPE_NAME = r"\\.\pipe\VitoriusFirewallWinIPC"

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32pipe
    import win32file
    HAS_WIN32SERVICE = True
except ImportError:
    HAS_WIN32SERVICE = False
    logger.warning("pywin32 not installed — Windows Service framework running in daemon simulation mode.")


class CoreServiceDaemon:
    """Core logic of the persistent background service."""

    def __init__(self):
        self.running = False
        self.fw_core = WindowsFirewallCore()
        self.av_engine = AntivirusEngine()
        self.shield = RealtimeShield(self.av_engine, on_threat_cb=self._on_threat)
        self._pipe_thread = None

    def _on_threat(self, threat):
        logger.critical(f"SERVICE DETECTED THREAT: {threat.threat_name} in {threat.file_path}")

    def start(self):
        self.running = True
        logger.info("Vitorius Background Service initializing...")
        self.shield.start()
        self._pipe_thread = threading.Thread(target=self._ipc_pipe_loop, daemon=True, name="service-pipe")
        self._pipe_thread.start()
        logger.info("Vitorius Background Service running.")

    def stop(self):
        self.running = False
        self.shield.stop()
        logger.info("Vitorius Background Service stopped.")

    def _ipc_pipe_loop(self):
        """Listens on Windows Named Pipe for commands from UI or Tray."""
        if not HAS_WIN32SERVICE:
            return

        while self.running:
            try:
                pipe = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    65536, 65536, 0, None
                )
                win32pipe.ConnectNamedPipe(pipe, None)
                data = win32file.ReadFile(pipe, 64 * 1024)
                req_text = data[1].decode('utf-8').strip()
                resp = self._handle_ipc_request(req_text)
                win32file.WriteFile(pipe, json.dumps(resp).encode('utf-8'))
                win32pipe.DisconnectNamedPipe(pipe)
                win32file.CloseHandle(pipe)
            except Exception as e:
                if self.running:
                    time.sleep(0.5)

    def _handle_ipc_request(self, request_str: str) -> dict:
        try:
            req = json.loads(request_str)
            action = req.get("action")
            if action == "GET_STATUS":
                return {
                    "status": "ok",
                    "panic_mode": self.fw_core.get_panic_mode(),
                    "shield_active": self.shield.is_running
                }
            elif action == "SET_PANIC":
                enable = req.get("enable", False)
                ok = self.fw_core.set_panic_mode(enable)
                return {"status": "ok" if ok else "error", "panic_mode": enable}
            return {"status": "unknown_action"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


if HAS_WIN32SERVICE:
    class VitoriusWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "VitoriusFirewallService"
        _svc_display_name_ = "Vitorius Firewall & Antivirus Core Service"
        _svc_description_ = "Maintains persistent enterprise firewall policies and real-time antivirus file protection."

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.daemon = CoreServiceDaemon()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
            self.daemon.stop()
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            self.daemon.start()
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


def handle_service_cli():
    if not HAS_WIN32SERVICE:
        print("pywin32 is required to install or manage Windows Services.")
        return

    # Check if running as a Windows Service under SCM (e.g. "--service run")
    if len(sys.argv) > 2 and sys.argv[2] == "run":
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(VitoriusWindowsService)
            servicemanager.StartServiceCtrlDispatcher()
            return
        except Exception as e:
            logger.error(f"Error starting service control dispatcher: {e}")
            return

    # Strip '--service' argument so HandleCommandLine gets standard verbs:
    # e.g. ['app.exe', '--service', 'install'] -> ['app.exe', 'install']
    filtered_argv = [sys.argv[0]] + [arg for arg in sys.argv[1:] if not arg.startswith("--service")]
    if len(filtered_argv) == 1:
        filtered_argv.append("debug")

    win32serviceutil.HandleCommandLine(VitoriusWindowsService, argv=filtered_argv)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].startswith("--service"):
        handle_service_cli()
    else:
        d = CoreServiceDaemon()
        d.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            d.stop()
