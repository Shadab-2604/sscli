"""Platform-specific discovery of user, application, and system cache folders."""

from __future__ import annotations

import os
import sys
from pathlib import Path


class CacheDiscoveryEngine:
    """Discovers standard application and user cache targets across Windows, Linux, and macOS."""

    @classmethod
    def get_standard_cache_directories(cls) -> list[tuple[str, Path]]:
        """
        Return list of (category_label, directory_path) for safe cache candidates.
        """
        targets: list[tuple[str, Path]] = []

        if sys.platform.startswith("win"):
            targets.extend(cls._get_windows_cache_targets())
        elif sys.platform.startswith("darwin"):
            targets.extend(cls._get_macos_cache_targets())
        else:
            targets.extend(cls._get_linux_cache_targets())

        return [(cat, p) for cat, p in targets if p.exists() and p.is_dir()]

    @classmethod
    def _get_windows_cache_targets(cls) -> list[tuple[str, Path]]:
        targets = []
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            lad = Path(local_app)
            # User temporary directory
            targets.append(("Temporary Files", lad / "Temp"))
            # Pip cache
            targets.append(("Application Cache", lad / "pip" / "cache"))
            # NuGet cache
            targets.append(("Application Cache", lad / "NuGet" / "v3-cache"))
            # CrashDumps
            targets.append(("Application Cache", lad / "CrashDumps"))

        # Windows Temp (if accessible)
        win_dir = os.environ.get("WINDIR", "C:\\Windows")
        targets.append(("System Temporary", Path(win_dir) / "Temp"))
        return targets

    @classmethod
    def _get_linux_cache_targets(cls) -> list[tuple[str, Path]]:
        targets = []
        home = Path.home()
        cache = home / ".cache"

        if cache.exists():
            targets.append(("User Cache", cache))

        targets.append(("Temporary Files", Path("/tmp")))
        targets.append(("System Temporary", Path("/var/tmp")))
        return targets

    @classmethod
    def _get_macos_cache_targets(cls) -> list[tuple[str, Path]]:
        targets = []
        home = Path.home()
        lib_cache = home / "Library" / "Caches"

        if lib_cache.exists():
            targets.append(("User Cache", lib_cache))

        targets.append(("Temporary Files", Path("/tmp")))
        targets.append(("System Temporary", Path("/var/tmp")))
        return targets
