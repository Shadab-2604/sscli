"""Symbolic link safety manager, cycle detection, and boundary enforcement."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from systemscan.filesystem.models import SymlinkPolicy


class SymlinkManager:
    """Evaluates symbolic links, junctions, and reparse points with cycle protection."""

    def __init__(self, policy: SymlinkPolicy = SymlinkPolicy.RECORD_NO_FOLLOW) -> None:
        self.policy = policy
        self._visited_real_paths: set[str] = set()

    def reset(self) -> None:
        """Reset visited paths for a new traversal run."""
        self._visited_real_paths.clear()

    @staticmethod
    def is_symlink(entry: os.DirEntry[str] | Path) -> bool:
        """Check whether entry is a symbolic link or Windows junction/reparse point."""
        try:
            if isinstance(entry, Path):
                return entry.is_symlink()
            return entry.is_symlink()
        except OSError:
            return False

    @staticmethod
    def read_link_target(path: Path | str) -> str | None:
        """Safely read destination target of a symbolic link."""
        try:
            return os.readlink(path)
        except OSError:
            return None

    @staticmethod
    def is_broken_link(path: Path | str) -> bool:
        """Check whether symbolic link points to a non-existent target."""
        try:
            p = Path(path)
            if not p.is_symlink():
                return False
            # If resolve() target does not exist, link is broken
            return not p.resolve().exists()
        except OSError:
            return True

    def should_traverse(
        self,
        symlink_path: Path,
        approved_roots: list[Path],
    ) -> tuple[bool, str | None]:
        """Determine whether a symbolic link directory can be safely traversed.

        Returns (True, None) if permitted, or (False, reason) if blocked.
        """
        if self.policy == SymlinkPolicy.IGNORE:
            return False, "Symlinks ignored by policy"

        if self.policy == SymlinkPolicy.RECORD_NO_FOLLOW:
            return False, "Symlink followed disabled (RECORD_NO_FOLLOW)"

        # Policy is FOLLOW_SAFE
        try:
            real_target = symlink_path.resolve()
        except (OSError, RuntimeError) as e:
            return False, f"Failed to resolve symlink target: {e}"

        if not real_target.exists():
            return False, "Broken symlink destination does not exist"

        if not real_target.is_dir():
            return False, "Symlink target is not a directory"

        norm_real = str(real_target).lower() if sys.platform == "win32" else str(real_target)

        # 1. Cycle detection: Prevent infinite recursion loops
        if norm_real in self._visited_real_paths:
            return False, f"Cyclic recursion detected: {real_target} already traversed"

        # 2. Root Boundary Enforcement: Target must remain inside approved scan roots
        stays_in_boundary = False
        for root in approved_roots:
            try:
                real_target.relative_to(root)
                stays_in_boundary = True
                break
            except ValueError:
                pass

        if not stays_in_boundary:
            return False, f"Symlink escapes approved scan roots: {real_target}"

        # Register visited path
        self._visited_real_paths.add(norm_real)
        return True, None
