"""macOS-specific filesystem discovery and volume inspection."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import psutil

from systemscan.filesystem.models import FilesystemRootInfo
from systemscan.filesystem.providers.base import FilesystemProvider


class MacOSFilesystemProvider(FilesystemProvider):
    """macOS implementation discovering APFS volumes and /Volumes mounts."""

    def discover_roots(self) -> list[FilesystemRootInfo]:
        """Discover all active mountpoints and APFS/HFS+ volumes on macOS."""
        roots: list[FilesystemRootInfo] = []
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception:
            partitions = []

        seen_mounts: set[str] = set()

        for p in partitions:
            mount = p.mountpoint
            if not mount or mount in seen_mounts:
                continue
            seen_mounts.add(mount)

            total_b = None
            free_b = None
            try:
                usage = shutil.disk_usage(mount)
                total_b = usage.total
                free_b = usage.free
            except (OSError, PermissionError):
                pass

            fstype = (p.fstype or "").lower()
            is_virtual = fstype in ("devfs", "autofs", "procfs")
            is_ro = "ro" in p.opts.lower()
            is_removable = mount.startswith("/Volumes/") and mount != "/Volumes/Macintosh HD"

            roots.append(
                FilesystemRootInfo(
                    path=mount,
                    name=p.device or mount,
                    filesystem_type=p.fstype or "apfs",
                    is_removable=is_removable,
                    is_network=fstype in ("smbfs", "afpfs", "nfs"),
                    is_readonly=is_ro,
                    is_virtual=is_virtual,
                    total_bytes=total_b,
                    free_bytes=free_b,
                )
            )

        if "/" not in seen_mounts and Path("/").exists():
            usage_root = None
            try:
                usage_root = shutil.disk_usage("/")
            except OSError:
                pass
            roots.insert(
                0,
                FilesystemRootInfo(
                    path="/",
                    name="System Root",
                    filesystem_type="apfs",
                    is_removable=False,
                    is_network=False,
                    is_readonly=False,
                    is_virtual=False,
                    total_bytes=usage_root.total if usage_root else None,
                    free_bytes=usage_root.free if usage_root else None,
                ),
            )

        return roots

    def is_hidden(self, path: Path | str, st: os.stat_result | None = None) -> bool:
        """Check for dot prefix or macOS flags."""
        p = Path(path)
        if p.name.startswith(".") and p.name not in (".", ".."):
            return True
        # Check macOS UF_HIDDEN flag (0x8000) if available in st_flags
        if st is not None and hasattr(st, "st_flags"):
            UF_HIDDEN = 0x8000
            if getattr(st, "st_flags", 0) & UF_HIDDEN:
                return True
        return False

    def is_reparse_point(self, path: Path | str) -> bool:
        return False
