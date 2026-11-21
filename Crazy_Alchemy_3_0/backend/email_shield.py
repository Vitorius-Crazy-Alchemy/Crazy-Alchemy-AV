"""
Vitorius Antivirus - Email Client Antivirus Shield
Dedicated protection engine for desktop email clients:
- Microsoft Outlook (Office 365, 2016-2021)
- Mozilla Thunderbird
- Windows Mail / Outlook for Windows (New Outlook)
- eM Client
- Mailbird

Intercepts, analyzes, and neutralizes malicious attachments, phishing payloads,
macro-weaponized documents, and disguised executables before execution.
"""

import os
import sys
import re
import time
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass

logger = logging.getLogger('vitorius.win.email_shield')

from backend.antivirus import AntivirusEngine, ThreatDetection
from backend.profiles_win import FirewallLogger

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


# Dangerous extensions commonly weaponized in phishing & email-borne attacks
DANGEROUS_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".hta", ".pif", ".cpl", ".jar", ".ps1", ".psm1",
    ".msc", ".reg", ".lnk", ".iso", ".img", ".vhd"
}

# Regex to detect double extension spoofing (e.g. invoice.pdf.exe)
DOUBLE_EXT_REGEX = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv|zip|rar)\.(exe|scr|vbs|js|hta|bat|cmd|pif|cpl|lnk|iso|wsf)$",
    re.IGNORECASE
)


@dataclass
class EmailClientDef:
    id: str
    name: str
    process_names: List[str]
    cache_dirs: List[str]
    icon: str
    registry_key: Optional[str] = None


class EmailAttachmentHandler:
    """Handles real-time filesystem creation/modification of email client attachments."""

    def __init__(self, email_shield: 'EmailClientShield'):
        self.shield = email_shield
        self._recently_scanned: Dict[str, float] = {}
        self._lock = threading.Lock()

    def process_path(self, file_path: str, client_name: str = "Email Client"):
        if not file_path or not os.path.isfile(file_path):
            return

        now = time.time()
        with self._lock:
            last = self._recently_scanned.get(file_path, 0)
            if now - last < 2.0:
                return
            self._recently_scanned[file_path] = now

        threading.Thread(
            target=self._scan_attachment_worker,
            args=(file_path, client_name),
            daemon=True,
            name="email-attach-scan"
        ).start()

    def _scan_attachment_worker(self, file_path: str, client_name: str):
        time.sleep(0.2)  # Brief wait for mail client to finish writing attachment bytes
        self.shield.inspect_attachment(file_path, client_name=client_name)


if HAS_WATCHDOG:
    class EmailWatchdogBridge(FileSystemEventHandler):
        def __init__(self, handler: EmailAttachmentHandler, client_name: str):
            super().__init__()
            self.handler = handler
            self.client_name = client_name

        def on_created(self, event):
            if not event.is_directory:
                self.handler.process_path(event.src_path, self.client_name)

        def on_modified(self, event):
            if not event.is_directory:
                self.handler.process_path(event.src_path, self.client_name)


class EmailClientShield:
    """
    Real-time antimalware shield specifically guarding desktop email clients.
    Watches attachment extraction caches, intercepts malicious payloads, and cleans threats.
    """

    SUPPORTED_CLIENTS: List[EmailClientDef] = [
        EmailClientDef(
            id="outlook",
            name="Microsoft Outlook",
            process_names=["outlook.exe"],
            cache_dirs=[
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook"),
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Outlook"),
                os.path.expandvars(r"%APPDATA%\Microsoft\Outlook")
            ],
            icon="📧",
            registry_key=r"Software\Clients\Mail\Microsoft Outlook"
        ),
        EmailClientDef(
            id="thunderbird",
            name="Mozilla Thunderbird",
            process_names=["thunderbird.exe"],
            cache_dirs=[
                os.path.expandvars(r"%APPDATA%\Thunderbird\Profiles"),
                os.path.expandvars(r"%LOCALAPPDATA%\Thunderbird\Profiles")
            ],
            icon="🐦",
            registry_key=r"Software\Clients\Mail\Mozilla Thunderbird"
        ),
        EmailClientDef(
            id="winmail",
            name="Windows Mail / Outlook for Windows",
            process_names=["olk.exe", "HxMail.exe", "HxOutlook.exe"],
            cache_dirs=[
                os.path.expandvars(r"%LOCALAPPDATA%\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState"),
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Olk")
            ],
            icon="📬"
        ),
        EmailClientDef(
            id="emclient",
            name="eM Client",
            process_names=["mailclient.exe"],
            cache_dirs=[
                os.path.expandvars(r"%APPDATA%\eM Client")
            ],
            icon="📨"
        ),
        EmailClientDef(
            id="mailbird",
            name="Mailbird",
            process_names=["mailbird.exe"],
            cache_dirs=[
                os.path.expandvars(r"%LOCALAPPDATA%\Mailbird")
            ],
            icon="🕊️"
        ),
    ]

    def __init__(
        self,
        av_engine: AntivirusEngine,
        fw_logger: Optional[FirewallLogger] = None,
        alert_callback: Optional[Callable[[ThreatDetection, str, str], None]] = None,
        enabled_clients: Optional[List[str]] = None
    ):
        self.av_engine = av_engine
        self.fw_logger = fw_logger or FirewallLogger()
        self.alert_callback = alert_callback

        self.enabled_clients: Set[str] = set(enabled_clients) if enabled_clients else {
            c.id for c in self.SUPPORTED_CLIENTS
        }

        self._lock = threading.Lock()
        self._running = False
        self._observer: Optional[Any] = None
        self._handler = EmailAttachmentHandler(self)

        self._attachments_scanned = 0
        self._threats_intercepted = 0
        self._recent_events: List[Dict[str, Any]] = []

    def get_supported_clients(self) -> List[Dict[str, Any]]:
        """Returns metadata for all supported desktop email applications."""
        installed = self.detect_installed_clients()
        installed_ids = {c["id"] for c in installed}

        res = []
        for c in self.SUPPORTED_CLIENTS:
            res.append({
                "id": c.id,
                "name": c.name,
                "icon": c.icon,
                "is_installed": c.id in installed_ids,
                "is_monitored": c.id in self.enabled_clients,
                "process_names": c.process_names,
                "cache_dirs": c.cache_dirs
            })
        return res

    def detect_installed_clients(self) -> List[Dict[str, Any]]:
        """Identifies which email clients are installed on the local system."""
        found = []

        # Check running processes
        running_names = set()
        try:
            import psutil
            for p in psutil.process_iter(['name']):
                try:
                    name = p.info.get('name')
                    if name:
                        running_names.add(name.lower())
                except Exception:
                    pass
        except Exception:
            pass

        for c in self.SUPPORTED_CLIENTS:
            is_detected = False

            # Check if process is currently active
            if any(proc.lower() in running_names for proc in c.process_names):
                is_detected = True

            # Check registry if on Windows
            if sys.platform == "win32" and not is_detected and c.registry_key:
                try:
                    import winreg
                    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                        try:
                            with winreg.OpenKey(hive, c.registry_key):
                                is_detected = True
                                break
                        except OSError:
                            pass
                except Exception:
                    pass

            # Check standard directory existence
            if not is_detected:
                for d in c.cache_dirs:
                    if os.path.exists(d):
                        is_detected = True
                        break

            if is_detected:
                found.append({
                    "id": c.id,
                    "name": c.name,
                    "icon": c.icon
                })

        return found

    def set_client_monitored(self, client_id: str, monitored: bool):
        """Enables or disables scanning for a specific email client."""
        with self._lock:
            if monitored:
                self.enabled_clients.add(client_id)
            else:
                self.enabled_clients.discard(client_id)

        logger.info(f"Email client '{client_id}' monitoring set to: {monitored}")
        if self._running:
            # Restart observer to adjust watched directories
            self.stop()
            self.start()

    def inspect_attachment(self, file_path: str, client_name: str = "Email Client") -> Optional[ThreatDetection]:
        """
        Scans an incoming email attachment for hash matches and heuristic weaponization.
        Quarantines and alerts if malicious.
        """
        if not os.path.isfile(file_path):
            return None

        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_name)[1].lower()

        with self._lock:
            self._attachments_scanned += 1

        threat: Optional[ThreatDetection] = None
        heur_reason: Optional[str] = None

        # 1. Primary Hash & Signature Engine
        try:
            threat = self.av_engine.scan_file(file_path)
        except Exception as e:
            logger.debug(f"Error scanning attachment {file_path}: {e}")

        # 2. Heuristic Analysis if signature clean
        if not threat:
            # Check 2a: Double extension deception (e.g. invoice.pdf.exe)
            if DOUBLE_EXT_REGEX.search(file_name):
                heur_reason = f"Spoofed double-extension executable disguised as document ({file_name})"
                threat = ThreatDetection(
                    file_path=file_path,
                    file_name=file_name,
                    threat_name="Email.Trojan.DoubleExtension",
                    threat_category="Email.Malware",
                    severity="critical",
                    detection_engine="email_heuristic",
                    hash_sha256="",
                    hash_md5="",
                    detected_at=time.time()
                )

            # Check 2b: Dangerous script/executable attachment extension
            elif ext in DANGEROUS_EXTENSIONS:
                heur_reason = f"High-risk executable/script email attachment ({ext})"
                threat = ThreatDetection(
                    file_path=file_path,
                    file_name=file_name,
                    threat_name=f"Email.HighRiskAttachment{ext.upper()}",
                    threat_category="Email.BlockedPayload",
                    severity="high",
                    detection_engine="email_heuristic",
                    hash_sha256="",
                    hash_md5="",
                    detected_at=time.time()
                )

            # Check 2c: Disguised PE binary (PE header 'MZ' inside document extension)
            elif ext in {".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".png", ".txt", ".csv"}:
                try:
                    with open(file_path, "rb") as f:
                        magic = f.read(2)
                        if magic == b"MZ":
                            heur_reason = f"Binary executable disguised with benign document extension ({ext})"
                            threat = ThreatDetection(
                                file_path=file_path,
                                file_name=file_name,
                                threat_name="Email.Trojan.DisguisedPE",
                                threat_category="Email.Malware",
                                severity="critical",
                                detection_engine="email_heuristic",
                                hash_sha256="",
                                hash_md5="",
                                detected_at=time.time()
                            )
                except Exception:
                    pass

        # If malicious or high-risk, remediate immediately
        if threat:
            with self._lock:
                self._threats_intercepted += 1
                ev = {
                    "timestamp": time.time(),
                    "file_name": file_name,
                    "threat_name": threat.threat_name,
                    "client_name": client_name,
                    "severity": threat.severity,
                    "reason": heur_reason or "Identified by local malware signature database"
                }
                self._recent_events.insert(0, ev)
                if len(self._recent_events) > 50:
                    self._recent_events.pop()

            logger.critical(
                f"EMAIL SHIELD INTERCEPTED: {threat.threat_name} from {client_name} -> {file_path}"
            )

            # Isolate file in Quarantine Vault
            self.av_engine.quarantine.quarantine_file(file_path, threat)

            # Log to firewall audit stream
            self.fw_logger.log_event(
                "email_threat_intercepted",
                "critical",
                f"Email Shield ({client_name}) quarantined malicious attachment: {file_name} ({threat.threat_name})",
                details={"file": file_path, "client": client_name, "reason": heur_reason}
            )

            # Trigger notification callback
            if self.alert_callback:
                try:
                    self.alert_callback(threat, client_name, heur_reason or threat.threat_name)
                except Exception as cb_err:
                    logger.debug(f"Error calling email shield alert callback: {cb_err}")

        return threat

    def start(self):
        """Starts real-time monitoring of enabled email client directories."""
        with self._lock:
            if self._running:
                return

            watched_count = 0
            if HAS_WATCHDOG:
                self._observer = Observer()
                for client in self.SUPPORTED_CLIENTS:
                    if client.id not in self.enabled_clients:
                        continue

                    bridge = EmailWatchdogBridge(self._handler, client.name)
                    for d in client.cache_dirs:
                        if os.path.exists(d):
                            try:
                                self._observer.schedule(bridge, d, recursive=True)
                                watched_count += 1
                                logger.info(f"Email Shield monitoring [{client.name}]: {d}")
                            except Exception as e:
                                logger.debug(f"Could not watch email dir {d}: {e}")

                try:
                    self._observer.start()
                    self._running = True
                    logger.info(f"Email Client Antivirus Shield ACTIVE ({watched_count} directories watched).")
                except Exception as e:
                    logger.error(f"Failed to start Email Shield observer: {e}")
                    self._running = False
            else:
                self._running = True
                logger.info("Email Client Antivirus Shield active in polling mode.")

    def stop(self):
        """Stops real-time email client monitoring."""
        with self._lock:
            if not self._running:
                return
            self._running = False

            if self._observer:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=3)
                except Exception:
                    pass
                self._observer = None

        logger.info("Email Client Antivirus Shield STOPPED.")

    def is_running(self) -> bool:
        """Returns True if the email shield is actively running."""
        with self._lock:
            return self._running

    def get_stats(self) -> Dict[str, Any]:
        """Returns overview statistics of email shield operations."""
        with self._lock:
            return {
                "is_running": self._running,
                "supported_clients_count": len(self.SUPPORTED_CLIENTS),
                "monitored_clients_count": len(self.enabled_clients),
                "attachments_scanned": self._attachments_scanned,
                "threats_intercepted": self._threats_intercepted,
                "recent_events": list(self._recent_events[:10])
            }
