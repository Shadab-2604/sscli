"""Base interface for platform-specific filesystem operations."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from systemscan.filesystem.models import FilesystemRootInfo


class FilesystemProvider(ABC):
    """Abstract contract for platform-specific filesystem discovery and attribute queries."""

    @abstractmethod
    def discover_roots(self) -> list[FilesystemRootInfo]:
        """Discover all accessible mounted filesystem roots and storage volumes."""
        pass

    @abstractmethod
    def is_hidden(self, path: Path | str, st: os.stat_result | None = None) -> bool:
        """Evaluate whether a path possesses platform-specific hidden attributes."""
        pass

    @abstractmethod
    def is_reparse_point(self, path: Path | str) -> bool:
        """Check whether a directory is a junction or reparse point."""
        pass
