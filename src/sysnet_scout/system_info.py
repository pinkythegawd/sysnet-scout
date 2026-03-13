from __future__ import annotations

import ctypes
import os
import platform
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional


def bytes_to_human(num_bytes: Optional[int]) -> str:
    if num_bytes is None:
        return "unknown"
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num_bytes)
    for unit in units:
        if size < step:
            return f"{size:.2f} {unit}"
        size /= step
    return f"{size:.2f} EB"


def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0])
    except OSError:
        return "unknown"


def _get_total_memory_bytes() -> Optional[int]:
    if os.name == "nt":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        mem = MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
            return int(mem.ullTotalPhys)
        return None

    meminfo_path = "/proc/meminfo"
    if os.path.exists(meminfo_path):
        try:
            with open(meminfo_path, "r", encoding="utf-8") as meminfo:
                for line in meminfo:
                    if line.startswith("MemTotal:"):
                        kb_value = int(line.split()[1])
                        return kb_value * 1024
        except (OSError, ValueError):
            return None

    if hasattr(os, "sysconf"):
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            total_pages = int(os.sysconf("SC_PHYS_PAGES"))
            return page_size * total_pages
        except (OSError, ValueError, TypeError):
            return None

    return None


def _get_uptime_seconds() -> Optional[float]:
    if os.name == "nt":
        try:
            milliseconds = ctypes.windll.kernel32.GetTickCount64()
            return float(milliseconds) / 1000.0
        except AttributeError:
            return None

    uptime_path = "/proc/uptime"
    if os.path.exists(uptime_path):
        try:
            with open(uptime_path, "r", encoding="utf-8") as uptime_file:
                return float(uptime_file.readline().split()[0])
        except (OSError, ValueError):
            return None

    return None


def collect_system_info() -> Dict[str, str]:
    total_memory = _get_total_memory_bytes()
    uptime_seconds = _get_uptime_seconds()

    if uptime_seconds is None:
        uptime_str = "unknown"
    else:
        days, rem = divmod(int(uptime_seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"

    mac = uuid.getnode()
    mac_str = ":".join(f"{(mac >> offset) & 0xFF:02x}" for offset in range(40, -1, -8))

    return {
        "tool": "SysNet Scout",
        "author": "pinkythegawd (MikePinku)",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hostname": socket.gethostname(),
        "local_ip": _get_local_ip(),
        "mac_address": mac_str,
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_cores_logical": str(os.cpu_count() or "unknown"),
        "memory_total": bytes_to_human(total_memory),
        "uptime": uptime_str,
        "processor": platform.processor() or "unknown",
        "time_zone": time.tzname[0] if time.tzname else "unknown",
    }
