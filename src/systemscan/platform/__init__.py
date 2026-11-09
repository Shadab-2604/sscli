"""Platform abstraction package for systemscan."""

from systemscan.platform.base import (
    CapabilityStatus,
    OSType,
    PlatformCapabilities,
    PlatformInterface,
)
from systemscan.platform.detection import (
    detect_installation_type,
    detect_platform,
    detect_platform_name,
    is_android,
    is_apple_silicon,
    is_kali_linux,
    is_nethunter,
    is_termux,
)
from systemscan.platform.linux import LinuxPlatform
from systemscan.platform.macos import MacOSPlatform
from systemscan.platform.windows import WindowsPlatform

# Global detected platform instance for current environment
current_platform: PlatformInterface = detect_platform()

__all__ = [
    "CapabilityStatus",
    "LinuxPlatform",
    "MacOSPlatform",
    "OSType",
    "PlatformCapabilities",
    "PlatformInterface",
    "WindowsPlatform",
    "current_platform",
    "detect_installation_type",
    "detect_platform",
    "detect_platform_name",
    "is_android",
    "is_apple_silicon",
    "is_kali_linux",
    "is_nethunter",
    "is_termux",
]
