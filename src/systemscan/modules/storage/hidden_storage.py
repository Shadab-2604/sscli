"""Analysis of storage space consumed by hidden files, directories, and recycle bins."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from systemscan.filesystem.models import DirectoryMetadata, FileMetadata
from systemscan.modules.storage.models import LargeDirectoryRecord, LargeFileRecord


class HiddenStorageAnalyzer:
    """Isolates and aggregates disk consumption contributed by hidden and system metadata."""

    def __init__(self) -> None:
        self.total_hidden_files = 0
        self.total_hidden_bytes = 0
        self.total_hidden_directories = 0
        self._largest_hidden_files: list[LargeFileRecord] = []
        self._largest_hidden_dirs: list[LargeDirectoryRecord] = []

    def inspect_file(self, file_meta: FileMetadata) -> None:
        """Accumulate hidden file statistics."""
        if file_meta.is_hidden:
            file_size = getattr(file_meta, "size_bytes", getattr(file_meta, "size", 0))
            self.total_hidden_files += 1
            self.total_hidden_bytes += file_size
            p = Path(file_meta.path)
            self._largest_hidden_files.append(
                LargeFileRecord(
                    path=file_meta.path,
                    name=file_meta.name,
                    size_bytes=file_size,
                    extension=p.suffix.lower(),
                    modified_at=file_meta.modified_time or datetime.now(timezone.utc),
                    is_hidden=True,
                    volume=str(p.drive if p.drive else "/"),
                )
            )

    def inspect_directory(self, dir_meta: DirectoryMetadata) -> None:
        """Record hidden directory counts."""
        if dir_meta.is_hidden:
            self.total_hidden_directories += 1

    def get_largest_hidden_files(self, limit: int = 25) -> list[LargeFileRecord]:
        """Return largest hidden files sorted descending by size."""
        self._largest_hidden_files.sort(key=lambda x: x.size_bytes, reverse=True)
        return self._largest_hidden_files[:limit]
