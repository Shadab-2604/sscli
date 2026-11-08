"""Filesystem discovery engine for mounted volumes, roots, and logical drives."""

from __future__ import annotations

from pathlib import Path

from systemscan.filesystem.models import FilesystemRootInfo
from systemscan.filesystem.providers import get_filesystem_provider


class FilesystemDiscovery:
    """Discovers accessible filesystem roots, mounted volumes, and storage partitions."""

    def __init__(self) -> None:
        self.provider = get_filesystem_provider()

    def discover_all_roots(self) -> list[FilesystemRootInfo]:
        """Discover all active mountpoints and partitions on the host system."""
        return self.provider.discover_roots()

    def discover_accessible_roots(
        self,
        include_network: bool = False,
        include_virtual: bool = False,
    ) -> list[Path]:
        """Discover validated, accessible filesystem root Paths suitable for full volume scanning."""
        all_roots = self.discover_all_roots()
        accessible: list[Path] = []

        for r in all_roots:
            if not include_virtual and r.is_virtual:
                continue
            if not include_network and r.is_network:
                continue

            try:
                p = Path(r.path).resolve()
                if p.exists() and p not in accessible:
                    accessible.append(p)
            except (OSError, ValueError):
                continue

        return accessible

    def get_root_for_path(self, target_path: Path | str) -> FilesystemRootInfo | None:
        """Find the mounted filesystem root record hosting the target path."""
        p = Path(target_path).resolve()
        roots = self.discover_all_roots()

        matching_root: FilesystemRootInfo | None = None
        max_prefix_len = -1

        for r in roots:
            try:
                root_path = Path(r.path).resolve()
                # Check if p starts with root_path
                p.relative_to(root_path)
                root_str = str(root_path)
                if len(root_str) > max_prefix_len:
                    max_prefix_len = len(root_str)
                    matching_root = r
            except (ValueError, OSError):
                pass

        return matching_root
