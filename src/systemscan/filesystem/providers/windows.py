"""Windows-specific filesystem discovery and attribute inspection."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import psutil

from systemscan.filesystem.models import FilesystemRootInfo
from systemscan.filesystem.providers.base import FilesystemProvider


class WindowsFilesystemProvider(FilesystemProvider):
    """Windows implementation querying logical drive volumes and file attributes."""

    FILE_ATTRIBUTE_HIDDEN = 0x02
    FILE_ATTRIBUTE_SYSTEM = 0x04
    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400

    def discover_roots(self) -> list[FilesystemRootInfo]:
        """Discover all active logical drives and mounted volumes on Windows."""
        roots: list[FilesystemRootInfo] = []
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception:
            partitions = []

        for p in partitions:
            mount = p.mountpoint
            if not mount:
                continue

            # Capacity metrics
            total_b = None
            free_b = None
            try:
                usage = shutil.disk_usage(mount)
                total_b = usage.total
                free_b = usage.free
            except (OSError, PermissionError):
                pass

            is_removable = "removable" in p.opts.lower() or "cdrom" in p.opts.lower()
            is_ro = "ro" in p.opts.lower()

            roots.append(
                FilesystemRootInfo(
                    path=mount,
                    name=p.device or mount,
                    filesystem_type=p.fstype or "NTFS",
                    is_removable=is_removable,
                    is_network="remote" in p.opts.lower() or mount.startswith("\\\\"),
                    is_readonly=is_ro,
                    is_virtual=False,
                    total_bytes=total_b,
                    free_bytes=free_b,
                )
            )

        return roots

    def is_hidden(self, path: Path | str, st: os.stat_result | None = None) -> bool:
        """Check for Windows FILE_ATTRIBUTE_HIDDEN or dot prefix."""
        p = Path(path)
        if p.name.startswith(".") and p.name not in (".", ".."):
            return True

        try:
            stat_res = st or p.stat(follow_symlinks=False)
            attrs = getattr(stat_res, "st_file_attributes", 0)
            return bool(attrs & (self.FILE_ATTRIBUTE_HIDDEN | self.FILE_ATTRIBUTE_SYSTEM))
        except OSError:
            return False

    def is_reparse_point(self, path: Path | str) -> bool:
        """Check for Windows directory junction or reparse point."""
        try:
            p = Path(path)
            stat_res = p.stat(follow_symlinks=False)
            attrs = getattr(stat_res, "st_file_attributes", 0)
            return bool(attrs & self.FILE_ATTRIBUTE_REPARSE_POINT)
        except OSError:
            return False
