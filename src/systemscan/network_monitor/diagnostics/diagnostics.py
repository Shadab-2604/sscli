"""Diagnostic utilities for checking capture permissions, drivers, and network visibility."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any


class CaptureDiagnostics:
    """Evaluates host system environment for packet capture and monitoring capabilities."""

    @classmethod
    def run_diagnostics(cls) -> dict[str, Any]:
        """Perform comprehensive pre-flight check across OS, drivers, permissions, and dependencies."""
        os_family = platform.system()
        has_scapy = False
        try:
            import scapy  # noqa: F401

            has_scapy = True
        except ImportError:
            pass

        is_elevated = False
        if os_family == "Windows":
            try:
                import ctypes

                is_elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                pass
        else:
            is_elevated = hasattr(os, "geteuid") and os.geteuid() == 0

        # Check Npcap / libpcap
        pcap_status = "Missing"
        if os_family == "Windows":
            sys32 = os.environ.get("WINDIR", "C:\\Windows") + "\\System32"
            if os.path.exists(os.path.join(sys32, "Npcap")) or os.path.exists(
                os.path.join(sys32, "wpcap.dll")
            ):
                pcap_status = "Available (Npcap / WinPcap detected)"
            else:
                pcap_status = (
                    "Not installed (Npcap required for live raw socket capture on Windows)"
                )
        elif os_family == "Linux":
            if (
                shutil.which("tcpdump")
                or os.path.exists("/usr/lib/libpcap.so")
                or os.path.exists("/usr/lib/x86_64-linux-gnu/libpcap.so")
            ):
                pcap_status = "Available (libpcap detected)"
            else:
                pcap_status = "Available"
        elif os_family == "Darwin":
            pcap_status = "Available (macOS native BPF / libpcap)"

        return {
            "os": os_family,
            "architecture": platform.machine(),
            "python_version": sys.version.split()[0],
            "is_elevated": is_elevated,
            "scapy_installed": has_scapy,
            "pcap_driver_status": pcap_status,
            "can_capture_local": has_scapy and (is_elevated or os_family != "Windows"),
            "network_wide_sensor_configured": False,
        }
