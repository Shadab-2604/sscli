"""Configurable filesystem exclusion engine with default operating system safety rules."""

from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path

from systemscan.filesystem.models import ExclusionConfig


class ExclusionManager:
    """Evaluates filesystem paths against configured exclusion rules and safety boundaries."""

    # Default platform-specific virtual and pseudo filesystems that must not be traversed
    LINUX_SAFETY_EXCLUSIONS = {
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/snap",
        "/var/run",
    }

    WINDOWS_SAFETY_EXCLUSIONS = {
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        "dumpstack.log",
        "System Volume Information",
        "$Recycle.Bin",
    }

    MACOS_SAFETY_EXCLUSIONS = {
        "/dev",
        "/net",
        "/home",
        "/System/Volumes/Data/private/var/vm",
        "/.vol",
    }

    def __init__(self, config: ExclusionConfig | None = None) -> None:
        self.config = config or ExclusionConfig()
        self._exact_paths: set[str] = set()
        self._dir_prefixes: list[str] = []
        self._globs: list[str] = list(self.config.exclude_globs)
        self._extensions: set[str] = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in self.config.exclude_extensions
        }

        # Initialize default safety exclusions unless explicitly overridden
        if not self.config.override_defaults:
            self._load_platform_safety_defaults()

        # Load user configured exact paths
        for p in self.config.exclude_paths:
            norm = self._normalize_path_str(p)
            self._exact_paths.add(norm)
            self._dir_prefixes.append(norm)

    def _load_platform_safety_defaults(self) -> None:
        """Inject platform-appropriate pseudo-filesystem and virtual device exclusions."""
        if sys.platform.startswith("linux"):
            for p in self.LINUX_SAFETY_EXCLUSIONS:
                norm = self._normalize_path_str(p)
                self._exact_paths.add(norm)
                self._dir_prefixes.append(norm)
        elif sys.platform == "win32":
            for name in self.WINDOWS_SAFETY_EXCLUSIONS:
                self._globs.append(f"*{name}*")
        elif sys.platform == "darwin":
            for p in self.MACOS_SAFETY_EXCLUSIONS:
                norm = self._normalize_path_str(p)
                self._exact_paths.add(norm)
                self._dir_prefixes.append(norm)

    @staticmethod
    def _normalize_path_str(p: str | Path) -> str:
        """Normalize path string for exact and prefix comparison."""
        try:
            return str(Path(p).resolve()).lower()
        except Exception:
            return str(p).lower()

    def is_excluded(
        self,
        path: Path | str,
        name: str | None = None,
        is_dir: bool = False,
        size_bytes: int | None = None,
        depth: int = 0,
        is_hidden: bool = False,
        max_depth: int | None = None,
    ) -> tuple[bool, str | None]:
        """Determine whether a path or directory should be excluded from traversal.

        Returns (True, reason) if excluded, or (False, None) if permitted.
        """
        # 1. Depth check
        if max_depth is not None and depth > max_depth:
            return True, f"Max depth ({max_depth}) exceeded at depth {depth}"

        # 2. Hidden filter
        if self.config.exclude_hidden and is_hidden:
            return True, "Hidden paths excluded by policy"

        norm_path = self._normalize_path_str(path)
        entry_name = name or Path(path).name

        # 3. Exact path match
        if norm_path in self._exact_paths:
            return True, f"Matched exact exclusion: {path}"

        # 4. Directory prefix match (path is inside an excluded directory)
        for prefix in self._dir_prefixes:
            if norm_path.startswith(prefix.rstrip(os.sep) + os.sep) or norm_path == prefix:
                return True, f"Within excluded directory subtree: {prefix}"

        # 5. Extension check (files only)
        if not is_dir and self._extensions:
            ext = Path(entry_name).suffix.lower()
            if ext in self._extensions:
                return True, f"Matched excluded extension: {ext}"

        # 6. Glob pattern match
        for pattern in self._globs:
            if fnmatch.fnmatch(entry_name, pattern) or fnmatch.fnmatch(norm_path, pattern):
                return True, f"Matched exclusion glob: {pattern}"

        # 7. Size limits (files only)
        if not is_dir and size_bytes is not None:
            if (
                self.config.max_file_size_bytes is not None
                and size_bytes > self.config.max_file_size_bytes
            ):
                return True, f"Exceeds max file size ({self.config.max_file_size_bytes} bytes)"
            if (
                self.config.min_file_size_bytes is not None
                and size_bytes < self.config.min_file_size_bytes
            ):
                return True, f"Below min file size ({self.config.min_file_size_bytes} bytes)"

        return False, None
