"""Filesystem platform providers package and factory selector."""

from __future__ import annotations

import sys

from systemscan.filesystem.providers.base import FilesystemProvider
from systemscan.filesystem.providers.linux import LinuxFilesystemProvider
from systemscan.filesystem.providers.macos import MacOSFilesystemProvider
from systemscan.filesystem.providers.windows import WindowsFilesystemProvider


def get_filesystem_provider() -> FilesystemProvider:
    """Return the active platform-specific filesystem provider."""
    if sys.platform == "win32":
        return WindowsFilesystemProvider()
    elif sys.platform == "darwin":
        return MacOSFilesystemProvider()
    return LinuxFilesystemProvider()


__all__ = [
    "FilesystemProvider",
    "LinuxFilesystemProvider",
    "MacOSFilesystemProvider",
    "WindowsFilesystemProvider",
    "get_filesystem_provider",
]
