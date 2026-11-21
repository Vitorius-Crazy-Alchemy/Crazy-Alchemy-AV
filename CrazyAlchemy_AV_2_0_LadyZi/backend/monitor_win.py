"""
Vitorius Firewall Win - Network Monitor for Windows 11
Real-time network connection monitoring and per-adapter bandwidth tracking using psutil.
"""

import time
import socket
import logging
import threading
from typing import List, Dict, Any, Optional

logger = logging.getLogger('vitorius.win.monitor')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available — network monitor requires psutil.")


KNOWN_SERVICES = {
    22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 993: 'IMAPS',
    995: 'POP3S', 587: 'SMTP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
    21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3389: 'RDP',
    5900: 'VNC', 1080: 'SOCKS', 8888: 'Alt-HTTP', 9090: 'Web-Admin',
    27015: 'Steam', 25565: 'Minecraft', 6667: 'IRC', 50001: 'Discord',
}


class ConnectionInfo:
    """Represents a single active network connection on Windows 11."""
    __slots__ = (
        'protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port',
        'state', 'pid', 'program', 'service'
    )

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k, ''))
        if not self.service and isinstance(self.remote_port, int):
            self.service = KNOWN_SERVICES.get(self.remote_port, '')
        if not self.service and isinstance(self.local_port, int):
            self.service = KNOWN_SERVICES.get(self.local_port, '')

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class WindowsBandwidthTracker:
    """Tracks upload and download rates per network adapter on Windows 11."""

    def __init__(self):
        self._prev_stats = {}
        self._prev_time = 0
        self._rates = {}

    def update(self) -> dict:
        if not HAS_PSUTIL:
            return {}

        current_time = time.time()
        try:
            current_stats = psutil.net_io_counters(pernic=True)
        except Exception:
            return self._rates

        if self._prev_stats and self._prev_time:
            dt = current_time - self._prev_time
            if dt > 0:
                for iface, stats in current_stats.items():
                    # Skip loopback or pseudo interfaces
                    if "Loopback" in iface:
                        continue
                    prev = self._prev_stats.get(iface)
                    if prev:
                        rx_rate = (stats.bytes_recv - prev.bytes_recv) / dt
                        tx_rate = (stats.bytes_sent - prev.bytes_sent) / dt
                        self._rates[iface] = {
                            'rx_bytes_sec': max(0.0, rx_rate),
                            'tx_bytes_sec': max(0.0, tx_rate),
                            'rx_total': stats.bytes_recv,
                            'tx_total': stats.bytes_sent,
                        }

        self._prev_stats = current_stats
        self._prev_time = current_time
        return self._rates


class WindowsNetworkMonitor:
    """Real-time network connection and socket monitor."""

    def __init__(self, fw_core: Optional[Any] = None):
        self.fw_core = fw_core
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._connections: List[ConnectionInfo] = []
        self._bandwidth = WindowsBandwidthTracker()
        self._lock = threading.Lock()
        self._refresh_interval = 2.0
        self._pid_name_cache: Dict[int, str] = {}

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="win-net-monitor")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _resolve_process_name(self, pid: Optional[int]) -> str:
        if not pid or pid == 0:
            return "System"
        if pid in self._pid_name_cache:
            return self._pid_name_cache[pid]
        try:
            p = psutil.Process(pid)
            name = p.name()
            self._pid_name_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"

    def _collect_connections(self) -> List[ConnectionInfo]:
        if not HAS_PSUTIL:
            return []

        results = []
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                l_ip = c.laddr.ip if c.laddr else ""
                l_port = c.laddr.port if c.laddr else 0
                r_ip = c.raddr.ip if c.raddr else ""
                r_port = c.raddr.port if c.raddr else 0
                state = c.status if c.status else "NONE"
                prog = self._resolve_process_name(c.pid)

                results.append(ConnectionInfo(
                    protocol=proto,
                    local_ip=l_ip,
                    local_port=l_port,
                    remote_ip=r_ip,
                    remote_port=r_port,
                    state=state,
                    pid=c.pid or 0,
                    program=prog
                ))

                # Real-time Pillar 2: LineageGuard & BeaconEntropyShaper evaluation
                if self.fw_core and r_ip and r_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                    try:
                        if hasattr(self.fw_core, "lineage_guard") and self.fw_core.lineage_guard.is_enabled():
                            self.fw_core.lineage_guard.evaluate_socket_attempt(
                                pid=c.pid or 0, remote_ip=r_ip, remote_port=r_port, process_name_override=prog
                            )
                        if hasattr(self.fw_core, "beacon_shaper") and self.fw_core.beacon_shaper.is_enabled():
                            self.fw_core.beacon_shaper.record_connection_event(
                                remote_ip=r_ip, remote_port=r_port, process_name=prog
                            )
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Error gathering connections: {e}")

        return results

    def _monitor_loop(self):
        while self._running:
            try:
                conns = self._collect_connections()
                bw = self._bandwidth.update()
                with self._lock:
                    self._connections = conns
            except Exception as e:
                logger.debug(f"Monitor loop error: {e}")
            time.sleep(self._refresh_interval)

    def get_connections(self) -> List[ConnectionInfo]:
        with self._lock:
            return list(self._connections)

    def get_connection_stats(self) -> Dict[str, int]:
        with self._lock:
            total = len(self._connections)
            established = sum(1 for c in self._connections if c.state == 'ESTABLISHED')
            listening = sum(1 for c in self._connections if c.state == 'LISTEN')
            tcp_count = sum(1 for c in self._connections if c.protocol == 'TCP')
            udp_count = total - tcp_count
            return {
                'total': total,
                'established': established,
                'listening': listening,
                'tcp': tcp_count,
                'udp': udp_count,
            }

    def get_bandwidth(self) -> dict:
        return self._bandwidth.update()

    def get_interfaces(self) -> List[dict]:
        if not HAS_PSUTIL:
            return []
        res = []
        try:
            stats = psutil.net_if_stats()
            for iface_name, stat in stats.items():
                if "Loopback" in iface_name:
                    continue
                res.append({
                    'name': iface_name,
                    'is_up': stat.isup,
                    'speed': stat.speed
                })
        except Exception:
            pass
        return res
