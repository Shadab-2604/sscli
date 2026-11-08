"""Recursive directory size aggregation and ranking."""

from __future__ import annotations

from pathlib import Path

from systemscan.filesystem.models import DirectoryMetadata, FileMetadata
from systemscan.modules.storage.models import LargeDirectoryRecord


class DirectoryAnalyzer:
    """Aggregates recursive file sizes into parent directory structures."""

    def __init__(self, top_limit: int = 50) -> None:
        self.top_limit = top_limit
        # Map: normalized_dir_path -> [total_bytes, file_count, depth, is_hidden]
        self._dir_stats: dict[str, list[int | bool]] = {}

    def inspect_file(self, file_meta: FileMetadata) -> None:
        """Add file size and count to its parent directory and ancestors."""
        file_p = Path(file_meta.path)
        parent = file_p.parent
        file_size = getattr(file_meta, "size_bytes", getattr(file_meta, "size", 0))

        # Attribute size to parent directory
        parent_str = str(parent)
        if parent_str not in self._dir_stats:
            self._dir_stats[parent_str] = [0, 0, len(parent.parts), file_meta.is_hidden]

        self._dir_stats[parent_str][0] = int(self._dir_stats[parent_str][0]) + file_size
        self._dir_stats[parent_str][1] = int(self._dir_stats[parent_str][1]) + 1

    def inspect_directory(self, dir_meta: DirectoryMetadata) -> None:
        """Register directory metadata into tracking structure."""
        dir_str = dir_meta.path
        if dir_str not in self._dir_stats:
            self._dir_stats[dir_str] = [0, 0, dir_meta.depth, dir_meta.is_hidden]

    def get_top_directories(self) -> list[LargeDirectoryRecord]:
        """Return directories sorted descending by accumulated storage size."""
        records: list[LargeDirectoryRecord] = []
        for dir_path, (size_bytes, file_count, depth, is_hidden) in self._dir_stats.items():
            if int(size_bytes) > 0:
                p = Path(dir_path)
                records.append(
                    LargeDirectoryRecord(
                        path=dir_path,
                        name=p.name or dir_path,
                        size_bytes=int(size_bytes),
                        file_count=int(file_count),
                        depth=int(depth),
                        is_hidden=bool(is_hidden),
                    )
                )

        records.sort(key=lambda x: x.size_bytes, reverse=True)
        return records[: self.top_limit]
