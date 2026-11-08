"""Centralized platform detection and provider selection system."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

from systemscan.core.exceptions import UnsupportedPlatformError
from systemscan.platform.base import PlatformInterface
from systemscan.platform.linux import LinuxPlatform
from systemscan.platform.macos import MacOSPlatform
from systemscan.platform.windows import WindowsPlatform


def detect_os_family() -> str:
    """Return normalized OS family key: 'linux', 'windows', 'macos', or 'unsupported'."""
    sys_plat = sys.platform.lower()
    if sys_plat.startswith("win"):
        return "windows"
    if sys_plat.startswith("darwin"):
        return "macos"
    if sys_plat.startswith("linux"):
        return "linux"

    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system.startswith("darwin"):
        return "macos"
    if system.startswith("linux"):
        return "linux"

    return "unsupported"


def is_kali_linux() -> bool:
    """Check if the current host is Kali Linux."""
    if detect_os_family() != "linux":
        return False
    try:
        os_release = Path("/etc/os-release")
        if os_release.exists():
            content = os_release.read_text(encoding="utf-8").lower()
            if "kali" in content:
                return True
        if Path("/etc/kali_version").exists():
            return True
    except Exception:
        pass
    return False


def is_apple_silicon() -> bool:
    """Check if macOS host runs on Apple Silicon (M1/M2/M3/M4 arm64)."""
    if detect_os_family() != "macos":
        return False
    mach = platform.machine().lower()
    return mach in ("arm64", "aarch64")


def detect_detailed_platform_name() -> str:
    """Return specific platform target name among the 5 supported platforms:
    1. Kali Linux
    2. Windows 10
    3. Windows 11
    4. macOS Intel
    5. macOS Apple Silicon
    """
    family = detect_os_family()
    if family == "linux":
        if is_kali_linux():
            return "Kali Linux"
        return "Linux"
    elif family == "windows":
        try:
            # Build 22000+ corresponds to Windows 11
            version_str = platform.version()
            build_num = int(version_str.split(".")[2]) if len(version_str.split(".")) >= 3 else 0
            if build_num >= 22000:
                return "Windows 11"
        except (ValueError, IndexError):
            pass
        return "Windows 10"
    elif family == "macos":
        if is_apple_silicon():
            return "macOS Apple Silicon"
        return "macOS Intel"

    return "unsupported"


def detect_platform_name(detailed: bool = False) -> str:
    """Return platform key string ('linux', 'windows', 'macos').
    If detailed=True, returns specific platform target (e.g. 'Windows 11', 'Kali Linux').
    """
    if detailed:
        return detect_detailed_platform_name()
    return detect_os_family()


def detect_platform() -> PlatformInterface:
    """Detect current host operating system and instantiate appropriate platform handler."""
    family = detect_os_family()
    if family == "windows":
        return WindowsPlatform()
    elif family == "linux":
        return LinuxPlatform()
    elif family == "macos":
        return MacOSPlatform()
    else:
        raise UnsupportedPlatformError(
            f"Unsupported operating system: '{sys.platform}'. "
            "systemscan currently supports Windows 10/11, Linux (Kali/Ubuntu/Debian/Fedora/Arch), and macOS (Intel & Apple Silicon)."
        )


def detect_installation_type() -> str:
    """Detect if running in editable/development mode or bundled/site-packages."""
    here = os.path.abspath(__file__)
    parent = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(here))))
    if os.path.exists(os.path.join(parent, "pyproject.toml")):
        return "Development (Editable)"

    if getattr(sys, "frozen", False):
        return "Standalone Executable"

    return "Installed Package"
