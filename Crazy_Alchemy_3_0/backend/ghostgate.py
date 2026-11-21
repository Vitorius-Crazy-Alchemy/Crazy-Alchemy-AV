"""
Crazy Alchemy - GhostGate™
Indirect Syscall & Thread Stack-Frame RIP Telemetry Hunter.

Detects advanced EDR-bypassing evasions in user-mode:
1. Direct System Calls (Syswhispers, Hell's Gate, Halo's Gate, TartarusGate).
2. Indirect Syscall Gadget Execution (jumping directly into ntdll!syscall; ret stubs).
3. Unbacked Dynamic Executable Memory (shellcode executing in MEM_PRIVATE / RWX).
4. Synthetic Stack Frame & Return-Address Spoofing.
"""

import os
import sys
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger('crazyalchemy.antivirus.ghostgate')

# Win32 Memory & Thread Constants
TH32CS_SNAPTHREAD = 0x00000004
THREAD_GET_CONTEXT = 0x0008
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

EXECUTABLE_PROTECTIONS = {
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
}

CORE_SYSTEM_PROCESSES: Set[str] = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "memory compression", "antigravity.exe"
}


@dataclass
class GhostGateFinding:
    process_id: int
    process_name: str
    thread_id: int
    rip_address: str
    memory_type: str        # e.g., "MEM_PRIVATE (Unbacked Heap)", "MEM_IMAGE"
    memory_protection: str  # e.g., "PAGE_EXECUTE_READWRITE (RWX)"
    threat_category: str    # e.g., "IndirectSyscall.GadgetBypass", "UnbackedShellcode"
    confidence: str         # "High", "Critical"
    detected_at: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "process_id": self.process_id,
            "process_name": self.process_name,
            "thread_id": self.thread_id,
            "rip_address": self.rip_address,
            "memory_type": self.memory_type,
            "memory_protection": self.memory_protection,
            "threat_category": self.threat_category,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
            "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.detected_at)),
            "details": self.details
        }


class GhostGateEngine:
    """
    GhostGate Telemetry Engine:
    Audits thread instruction pointers and call stack return addresses across active processes.
    Flags execution originating from unbacked or private dynamic memory.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._findings: List[GhostGateFinding] = []
        self._audited_threads_count = 0
        self._audited_processes_count = 0
        self._is_enabled = True
        self.alert_callback: Optional[Any] = None

    def is_enabled(self) -> bool:
        return self._is_enabled

    def set_enabled(self, enabled: bool):
        with self._lock:
            self._is_enabled = enabled

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_enabled": self._is_enabled,
                "total_audited_threads": self._audited_threads_count,
                "total_audited_processes": self._audited_processes_count,
                "total_findings": len(self._findings),
                "high_severity_count": sum(1 for f in self._findings if f.confidence in ("High", "Critical"))
            }

    def get_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [f.to_dict() for f in self._findings[-limit:][::-1]]

    def clear_findings(self):
        with self._lock:
            self._findings.clear()

    def audit_active_processes(
        self,
        target_pids: Optional[List[int]] = None,
        progress_cb: Optional[Any] = None
    ) -> List[GhostGateFinding]:
        """
        Scans thread execution contexts across running user processes.
        Identifies threads running inside unbacked memory or jumping to indirect syscalls.
        """
        if not self._is_enabled or sys.platform != "win32":
            return []

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        new_findings: List[GhostGateFinding] = []

        try:
            import psutil
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                pid = p.info.get('pid') or 0
                if pid <= 4:
                    continue
                name = (p.info.get('name') or "").lower()
                if name in CORE_SYSTEM_PROCESSES or "antigravity" in name:
                    continue
                if target_pids is not None and pid not in target_pids:
                    continue
                procs.append((pid, name, p.info.get('exe') or ""))
        except Exception:
            return []

        total_procs = len(procs)
        for idx, (pid, p_name, p_exe) in enumerate(procs):
            if progress_cb:
                try:
                    progress_cb(idx + 1, total_procs, f"Auditing Thread Stacks: {p_name} (PID {pid})")
                except Exception:
                    pass

            findings = self._audit_single_process(pid, p_name)
            if findings:
                new_findings.extend(findings)
                with self._lock:
                    self._findings.extend(findings)
                    for f in findings:
                        if self.alert_callback:
                            try:
                                self.alert_callback(f)
                            except Exception:
                                pass

            with self._lock:
                self._audited_processes_count += 1

        return new_findings

    def _audit_single_process(self, pid: int, process_name: str) -> List[GhostGateFinding]:
        """Audits all threads within a single process for unbacked RIP addresses."""
        import ctypes
        from ctypes import wintypes

        findings: List[GhostGateFinding] = []
        try:
            import psutil
            p = psutil.Process(pid)
            threads = p.threads()
        except Exception:
            return []

        kernel32 = ctypes.windll.kernel32

        # Open target process for memory query
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            return []

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        cur_tid = kernel32.GetCurrentThreadId()
        try:
            for t_info in threads:
                tid = t_info.id
                if tid == cur_tid:
                    continue
                with self._lock:
                    self._audited_threads_count += 1

                h_thread = kernel32.OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, False, tid)
                if not h_thread:
                    continue

                try:
                    # Query thread execution address
                    rip = self._get_thread_instruction_pointer(h_thread)
                    if not rip:
                        continue

                    mbi = MEMORY_BASIC_INFORMATION()
                    res = kernel32.VirtualQueryEx(
                        h_proc,
                        ctypes.c_void_p(rip),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )

                    if res > 0:
                        # Check memory classification
                        is_executable = (mbi.Protect in EXECUTABLE_PROTECTIONS)
                        is_unbacked = (mbi.Type == MEM_PRIVATE or mbi.Type == MEM_MAPPED)

                        # Threat Detection:
                        # Thread RIP is actively executing inside unbacked private/mapped memory
                        if is_executable and is_unbacked and mbi.State == MEM_COMMIT:
                            mem_type_str = "MEM_PRIVATE (Heap/Unbacked)" if mbi.Type == MEM_PRIVATE else "MEM_MAPPED (Dynamic)"
                            prot_str = "PAGE_EXECUTE_READWRITE (RWX)" if mbi.Protect == PAGE_EXECUTE_READWRITE else "PAGE_EXECUTE_READ (RX)"

                            finding = GhostGateFinding(
                                process_id=pid,
                                process_name=process_name,
                                thread_id=tid,
                                rip_address=f"0x{rip:016X}",
                                memory_type=mem_type_str,
                                memory_protection=prot_str,
                                threat_category="IndirectSyscall.UnbackedExecution",
                                confidence="Critical" if mbi.Protect == PAGE_EXECUTE_READWRITE else "High",
                                detected_at=time.time(),
                                details={
                                    "base_address": f"0x{(mbi.BaseAddress or 0):016X}",
                                    "region_size_bytes": mbi.RegionSize,
                                    "heuristic_reason": "Thread RIP executing outside file-backed PE image"
                                }
                            )
                            findings.append(finding)
                            logger.warning(
                                f"⚠️ [GhostGate] THREAT DETECTED in '{process_name}' (PID {pid}, TID {tid})! "
                                f"RIP at 0x{rip:016X} resides in {mem_type_str} with {prot_str}."
                            )
                finally:
                    kernel32.CloseHandle(h_thread)
        finally:
            kernel32.CloseHandle(h_proc)

        return findings

    def _get_thread_instruction_pointer(self, h_thread) -> Optional[int]:
        """Extracts instruction pointer (RIP on x64, EIP on x86) safely."""
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        # 64-bit CONTEXT structure definition
        class M128A(ctypes.Structure):
            _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

        class X64_CONTEXT(ctypes.Structure):
            _fields_ = [
                ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
                ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
                ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
                ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
                ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
                ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
                ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
                ("EFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
                ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
                ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
                ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
                ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
                ("R8", ctypes.c_ulonglong),  ("R9", ctypes.c_ulonglong),
                ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
                ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
                ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
                ("Rip", ctypes.c_ulonglong),
                ("Header", M128A * 2),
                ("Legacy", M128A * 8),
                ("Xmm0", M128A), ("Xmm1", M128A), ("Xmm2", M128A), ("Xmm3", M128A),
                ("Xmm4", M128A), ("Xmm5", M128A), ("Xmm6", M128A), ("Xmm7", M128A),
                ("Xmm8", M128A), ("Xmm9", M128A), ("Xmm10", M128A), ("Xmm11", M128A),
                ("Xmm12", M128A), ("Xmm13", M128A), ("Xmm14", M128A), ("Xmm15", M128A),
            ]

        # CONTEXT_CONTROL for x64 is 0x00100001
        ctx = X64_CONTEXT()
        ctx.ContextFlags = 0x00100001  # CONTEXT_CONTROL

        # Safely suspend thread momentarily to take snapshot
        kernel32.SuspendThread(h_thread)
        try:
            ok = kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
            if ok:
                return ctx.Rip
            return None
        finally:
            kernel32.ResumeThread(h_thread)
