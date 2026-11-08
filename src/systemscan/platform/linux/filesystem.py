"""Linux native filesystem, POSIX permissions, and XDG hierarchy provider."""

from __future__ import annotations

import os
from pathlib import Path

from systemscan.logging.logger import get_logger

logger = get_logger("platform.linux.filesystem")


class LinuxFilesystemProvider:
    """Linux filesystem path conventions, XDG locations, and POSIX mode queries."""

    @staticmethod
    def get_xdg_directories() -> dict[str, Path]:
        """Resolve standard XDG base directory specification paths."""
        home = Path(os.path.expanduser("~"))
        return {
            "config": Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")),
            "data": Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share")),
            "cache": Path(os.environ.get("XDG_CACHE_HOME", home / ".cache")),
            "state": Path(os.environ.get("XDG_STATE_HOME", home / ".local" / "state")),
        }

    @staticmethod
    def get_posix_permissions(path: Path) -> dict[str, int | str | None]:
        """Extract detailed POSIX permissions, owner UID, and group GID."""
        try:
            stat_res = path.stat()
            return {
                "mode": stat_res.st_mode,
                "permissions_octal": oct(stat_res.st_mode & 0o777),
                "uid": stat_res.st_uid,
                "gid": stat_res.st_gid,
            }
        except (PermissionError, OSError) as e:
            logger.debug(f"Unable to read POSIX stat for {path}: {e}")
            return {"mode": None, "permissions_octal": None, "uid": None, "gid": None}

    @staticmethod
    def is_pseudo_filesystem(path: str) -> bool:
        """Check if path is located on a pseudo/virtual filesystem."""
        normalized = path.lower()
        return any(
            normalized.startswith(prefix)
            for prefix in ("/proc", "/sys", "/dev", "/run", "/var/run")
        )

