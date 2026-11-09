"""macOS native filesystem, APFS/HFS+ paths, and POSIX permissions provider."""

from __future__ import annotations

import os
from pathlib import Path

from systemscan.logging.logger import get_logger

logger = get_logger("platform.macos.filesystem")


class MacOSFilesystemProvider:
    """macOS filesystem path conventions, Library dirs, and POSIX permissions."""

    @staticmethod
    def get_standard_directories() -> dict[str, Path]:
        """Resolve standard macOS user and application Library paths."""
        home = Path(os.path.expanduser("~"))
        return {
            "home": home,
            "library": home / "Library",
            "application_support": home / "Library" / "Application Support",
            "caches": home / "Library" / "Caches",
            "logs": home / "Library" / "Logs",
        }

    @staticmethod
    def get_volumes() -> list[Path]:
        """Enumerate mounted volumes in /Volumes."""
        volumes_dir = Path("/Volumes")
        if volumes_dir.exists():
            return [p for p in volumes_dir.iterdir() if p.is_dir()]
        return []
