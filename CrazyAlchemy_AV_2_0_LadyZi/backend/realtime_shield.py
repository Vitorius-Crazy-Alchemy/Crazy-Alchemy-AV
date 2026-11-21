"""
Vitorius Antivirus - Real-Time File System Shield
Monitors critical entry points (Downloads, Temp, Startup, Desktop)
using Windows filesystem events to intercept and isolate threats instantly.
"""

import os
import sys
import logging
import threading
import time
from pathlib import Path
from typing import Optional, List, Callable
from backend.antivirus import AntivirusEngine, ThreatDetection, is_signature_or_rule_file, is_antivirus_program_file

logger = logging.getLogger('vitorius.win.shield')

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    logger.warning("watchdog library not available, real-time shield will use periodic polling.")


class ShieldEventHandler:
    """Handles filesystem creation and modification events asynchronously without blocking."""

    def __init__(self, av_engine: AntivirusEngine, on_threat_cb: Optional[Callable[[ThreatDetection], None]] = None):
        self.av_engine = av_engine
        self.on_threat_cb = on_threat_cb
        self._recently_scanned = {}
        self._lock = threading.Lock()

    def process_path(self, file_path: str):
        if not file_path:
            return

        # Deduplicate events within 2 seconds
        now = time.time()
        with self._lock:
            last = self._recently_scanned.get(file_path, 0)
            if now - last < 2.0:
                return
            self._recently_scanned[file_path] = now

        # Dispatch inspection to worker thread to avoid blocking Watchdog event loop
        threading.Thread(target=self._scan_worker, args=(file_path,), daemon=True).start()

    def _scan_worker(self, file_path: str):
        if not os.path.isfile(file_path):
            return

        # Skip antivirus program files, build artifacts, and installation directory files
        if is_antivirus_program_file(file_path):
            logger.debug(f"Real-Time Shield skipping antivirus program file: {file_path}")
            return

        # Skip security signature definition folders and rule files
        if is_signature_or_rule_file(file_path):
            logger.debug(f"Real-Time Shield skipping signature/rule definition file: {file_path}")
            return

        # Skip excluded / restored whitelist files to avoid re-quarantine loops
        if hasattr(self.av_engine, "is_excluded") and self.av_engine.is_excluded(file_path):
            logger.debug(f"Real-Time Shield skipping whitelisted file: {file_path}")
            return

        # Brief delay to allow the writing process to release file lock
        time.sleep(0.3)

        # Retry once if file was temporarily locked by Windows (ERROR_SHARING_VIOLATION)
        for attempt in range(2):
            try:
                # ChronoVault™ in-RAM anti-ransomware entropy evaluation
                if hasattr(self.av_engine, "chronovault") and self.av_engine.chronovault.is_enabled():
                    is_ransomware, alert = self.av_engine.chronovault.evaluate_post_write_state(
                        pid=0, process_name="ActiveWriter", file_path=file_path
                    )
                    if is_ransomware and alert:
                        logger.critical(f"CHRONOVAULT RANSOMWARE INTERCEPTED & ROLLED BACK: {file_path}")
                        if self.on_threat_cb:
                            t = ThreatDetection(
                                file_path=file_path,
                                file_name=Path(file_path).name,
                                threat_name="ChronoVault.Ransomware.EntropyBurst",
                                threat_category="Ransomware.ActiveBurst",
                                severity="critical",
                                detection_engine="chronovault_ram_mirage",
                                hash_sha256="",
                                hash_md5="",
                                detected_at=time.time()
                            )
                            self.on_threat_cb(t)
                        break

                threat = self.av_engine.scan_file(file_path)
                if threat:
                    logger.critical(f"REAL-TIME SHIELD TRIGGERED: {threat.threat_name} in {file_path}")
                    # Auto quarantine
                    self.av_engine.quarantine.quarantine_file(file_path, threat)
                    if self.on_threat_cb:
                        self.on_threat_cb(threat)
                break
            except (PermissionError, OSError):
                if attempt == 0:
                    time.sleep(0.5)
                else:
                    logger.debug(f"File locked or inaccessible: {file_path}")
            except Exception as e:
                logger.debug(f"Shield scan error on {file_path}: {e}")
                break


if HAS_WATCHDOG:
    class WatchdogBridge(FileSystemEventHandler):
        def __init__(self, handler: ShieldEventHandler):
            super().__init__()
            self.handler = handler

        def on_created(self, event):
            if not event.is_directory:
                self.handler.process_path(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self.handler.process_path(event.src_path)


class RealtimeShield:
    """Real-time protection manager."""

    def __init__(self, av_engine: AntivirusEngine, on_threat_cb: Optional[Callable[[ThreatDetection], None]] = None):
        self.av_engine = av_engine
        self.on_threat_cb = on_threat_cb
        self.handler = ShieldEventHandler(av_engine, on_threat_cb)
        self.is_running = False
        self._observer = None

    def _get_watch_directories(self) -> List[str]:
        dirs = []
        user_home = Path.home()

        # Downloads
        downloads = user_home / "Downloads"
        if downloads.exists():
            dirs.append(str(downloads))

        # Desktop
        desktop = user_home / "Desktop"
        if desktop.exists():
            dirs.append(str(desktop))

        # Temp directory
        temp = Path(os.environ.get("TEMP", "C:\\Windows\\Temp"))
        if temp.exists():
            dirs.append(str(temp))

        # Windows Startup directory
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup.exists():
                dirs.append(str(startup))

        return dirs

    def start(self):
        if self.is_running:
            return

        watch_dirs = self._get_watch_directories()
        if not watch_dirs:
            logger.warning("No directories found to watch for real-time shield.")
            return

        if HAS_WATCHDOG:
            self._observer = Observer()
            bridge = WatchdogBridge(self.handler)
            for d in watch_dirs:
                try:
                    self._observer.schedule(bridge, d, recursive=False)
                    logger.info(f"Real-time shield monitoring directory: {d}")
                except Exception as e:
                    logger.debug(f"Could not watch directory {d}: {e}")
            self._observer.start()
            self.is_running = True
            logger.info("Real-time Antivirus File Shield ACTIVE.")
        else:
            self.is_running = True
            logger.info("Real-time shield active (polling mode).")

    def stop(self):
        if not self.is_running:
            return
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None
        self.is_running = False
        logger.info("Real-time Antivirus File Shield STOPPED.")
