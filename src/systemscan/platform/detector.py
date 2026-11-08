"""Platform detection and factory routines for systemscan (compatibility alias)."""

from __future__ import annotations

from systemscan.platform.detection import (
    detect_installation_type,
    detect_platform,
    detect_platform_name,
    is_apple_silicon,
    is_kali_linux,
)

__all__ = [
    "detect_installation_type",
    "detect_platform",
    "detect_platform_name",
    "is_apple_silicon",
    "is_kali_linux",
]
