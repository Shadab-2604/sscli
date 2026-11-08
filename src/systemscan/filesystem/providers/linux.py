"""Linux-specific filesystem discovery and attribute inspection."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import psutil

from systemscan.filesystem.models import FilesystemRootInfo
from systemscan.filesystem.providers.base import FilesystemProvider


class LinuxFilesystemProvider(FilesystemProvider):
    """Linux implementation querying mounted filesystems and pseudo-filesystems."""

    VIRTUAL_FS_TYPES = {
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "tmpfs",
        "cgroup",
        "cgroup2",
        "securityfs",
        "pstore",
        "bpf",
        "hugetlbfs",
        "mqueue",
        "debugfs",
        "tracefs",
        "autofs",
    }

    def discover_roots(self) -> list[FilesystemRootInfo]:
        """Discover all active mountpoints and physical/virtual partitions on Linux."""
        roots: list[FilesystemRootInfo] = []
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception:
            partitions = []

        # Always ensure root '/' is present
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
            is_virtual = fstype in self.VIRTUAL_FS_TYPES
            is_ro = "ro" in p.opts.lower()
            is_net = fstype in ("nfs", "nfs4", "cifs", "smb", "sshfs")

            roots.append(
                FilesystemRootInfo(
                    path=mount,
                    name=p.device or mount,
                    filesystem_type=p.fstype or "ext4",
                    is_removable=mount.startswith(("/media", "/run/media", "/mnt")),
                    is_network=is_net,
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
                    name="Root Filesystem",
                    filesystem_type="ext4",
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
        """Check for Unix dot prefix."""
        p = Path(path)
        return p.name.startswith(".") and p.name not in (".", "..")

    def is_reparse_point(self, path: Path | str) -> bool:
        """Reparse points do not apply to native Linux filesystems."""
        return False
