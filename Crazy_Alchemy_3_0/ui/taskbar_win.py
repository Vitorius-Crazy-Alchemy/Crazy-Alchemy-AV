"""
Vitorius Firewall Win - Windows 11 Taskbar Integration
Uses native Win32 COM ITaskbarList3 and AppUserModelID to display native
taskbar progress during scans and dynamic status badges.
"""

import sys
import ctypes
import logging
from typing import Optional

logger = logging.getLogger('vitorius.win.taskbar')

# Flags for ITaskbarList3::SetProgressState
TBPF_NOPROGRESS = 0x00000000
TBPF_INDETERMINATE = 0x00000001
TBPF_NORMAL = 0x00000002        # Green progress bar
TBPF_ERROR = 0x00000004         # Red progress bar
TBPF_PAUSED = 0x00000008        # Yellow progress bar

APP_USER_MODEL_ID = "CrazyAlchemy.SecuritySuite.3.0"


def set_app_user_model_id():
    """Sets explicit AppUserModelID so Windows 11 taskbar groups the app and pins correctly."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
        logger.info(f"Registered AppUserModelID: {APP_USER_MODEL_ID}")
    except (AttributeError, OSError) as e:
        logger.debug(f"Could not set AppUserModelID: {e}")


class WindowsTaskbarProgress:
    """Controls the native Windows 11 Taskbar progress bar and overlay states via ITaskbarList3."""

    def __init__(self, hwnd: Optional[int] = None):
        self.hwnd = hwnd
        self._taskbar = None
        self._init_taskbar()

    def _init_taskbar(self):
        if sys.platform != "win32":
            return

        try:
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8)
                ]

            def str_to_guid(guid_str: str) -> GUID:
                guid = GUID()
                ctypes.windll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid_str), ctypes.byref(guid))
                return guid

            # CLSID_TaskbarList = {56FDF344-FD6D-11d0-958A-006097C9A090}
            # IID_ITaskbarList3 = {EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF}
            CLSID_TaskbarList = str_to_guid("{56FDF344-FD6D-11d0-958A-006097C9A090}")
            IID_ITaskbarList3 = str_to_guid("{EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF}")

            class ITaskbarList3Vtbl(ctypes.Structure):
                _fields_ = [
                    # IUnknown
                    ("QueryInterface", ctypes.c_void_p),
                    ("AddRef", ctypes.c_void_p),
                    ("Release", ctypes.c_void_p),
                    # ITaskbarList
                    ("HrInit", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p)),
                    ("AddTab", ctypes.c_void_p),
                    ("DeleteTab", ctypes.c_void_p),
                    ("ActivateTab", ctypes.c_void_p),
                    ("SetActiveAlt", ctypes.c_void_p),
                    # ITaskbarList2
                    ("MarkFullscreenWindow", ctypes.c_void_p),
                    # ITaskbarList3
                    ("SetProgressValue", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, wintypes.HWND, ctypes.c_uint64, ctypes.c_uint64)),
                    ("SetProgressState", ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, wintypes.HWND, ctypes.c_int)),
                    ("RegisterTab", ctypes.c_void_p),
                    ("UnregisterTab", ctypes.c_void_p),
                    ("SetTabOrder", ctypes.c_void_p),
                    ("SetTabActive", ctypes.c_void_p),
                    ("ThumbBarAddButtons", ctypes.c_void_p),
                    ("ThumbBarUpdateButtons", ctypes.c_void_p),
                    ("ThumbBarSetImageList", ctypes.c_void_p),
                    ("SetOverlayIcon", ctypes.c_void_p),
                    ("SetThumbnailTooltip", ctypes.c_void_p),
                    ("SetThumbnailClip", ctypes.c_void_p),
                ]

            class ITaskbarList3(ctypes.Structure):
                _fields_ = [("lpVtbl", ctypes.POINTER(ITaskbarList3Vtbl))]

            ctypes.windll.ole32.CoInitialize(None)
            p_taskbar = ctypes.POINTER(ITaskbarList3)()
            hr = ctypes.windll.ole32.CoCreateInstance(
                ctypes.byref(CLSID_TaskbarList),
                None,
                1,  # CLSCTX_INPROC_SERVER
                ctypes.byref(IID_ITaskbarList3),
                ctypes.byref(p_taskbar)
            )

            if hr == 0 and p_taskbar:
                p_taskbar.contents.lpVtbl.contents.HrInit(p_taskbar)
                self._taskbar = p_taskbar
                logger.info("Native Windows 11 ITaskbarList3 COM interface armed successfully.")
        except Exception as e:
            logger.debug(f"Could not initialize Windows Taskbar COM interface: {e}")
            self._taskbar = None

    def set_hwnd(self, hwnd: Optional[int]):
        """Sets target window handle (HWND)."""
        self.hwnd = int(hwnd) if hwnd else None

    def set_progress(self, current: int, total: int = 100):
        """Update native Windows 11 taskbar progress value and green bar."""
        if not self.hwnd or not self._taskbar or total <= 0:
            return
        try:
            # Set state to normal (green)
            self._taskbar.contents.lpVtbl.contents.SetProgressState(self._taskbar, self.hwnd, TBPF_NORMAL)
            self._taskbar.contents.lpVtbl.contents.SetProgressValue(self._taskbar, self.hwnd, max(0, current), total)
        except Exception as e:
            logger.debug(f"Taskbar progress error: {e}")

    def set_state(self, state_flag: int):
        """Set taskbar progress state: TBPF_NORMAL, TBPF_ERROR, TBPF_PAUSED, TBPF_NOPROGRESS."""
        if not self.hwnd or not self._taskbar:
            return
        try:
            self._taskbar.contents.lpVtbl.contents.SetProgressState(self._taskbar, self.hwnd, state_flag)
        except Exception as e:
            logger.debug(f"Taskbar state error: {e}")

    def clear(self):
        """Clears taskbar progress."""
        self.set_state(TBPF_NOPROGRESS)
