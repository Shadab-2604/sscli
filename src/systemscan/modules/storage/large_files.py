"""Large file discovery and threshold evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from systemscan.filesystem.models import FileMetadata
from systemscan.modules.storage.models import LargeFileRecord

# Standard threshold brackets in bytes
THRESHOLDS = {
    "100MB": 100 * 1024 * 1024,
    "500MB": 500 * 1024 * 1024,
    "1GB": 1024 * 1024 * 1024,
    "5GB": 5 * 1024 * 1024 * 1024,
}


class LargeFileAnalyzer:
    """Collects and ranks files exceeding configured size thresholds."""

    def __init__(self, min_size_bytes: int = 100 * 1024 * 1024, top_limit: int = 100) -> None:
        self.min_size_bytes = min_size_bytes
        self.top_limit = top_limit
        self._candidates: list[LargeFileRecord] = []

    def inspect_file(self, file_meta: FileMetadata, volume_label: str = "") -> None:
        """Evaluate a file item from the traversal stream."""
        file_size = getattr(file_meta, "size_bytes", getattr(file_meta, "size", 0))
        if file_size >= self.min_size_bytes:
            p = Path(file_meta.path)
            record = LargeFileRecord(
                path=file_meta.path,
                name=file_meta.name,
                size_bytes=file_size,
                extension=p.suffix.lower(),
                modified_at=file_meta.modified_time or datetime.now(timezone.utc),
                is_hidden=file_meta.is_hidden,
                volume=volume_label or str(p.drive if p.drive else "/"),
            )
            self._candidates.append(record)

    def get_top_large_files(self) -> list[LargeFileRecord]:
        """Return the largest files discovered, sorted descending by size."""
        self._candidates.sort(key=lambda x: x.size_bytes, reverse=True)
        return self._candidates[: self.top_limit]

    def get_count_above_threshold(self, threshold_bytes: int) -> int:
        """Count discovered files exceeding a given threshold."""
        return sum(1 for f in self._candidates if f.size_bytes >= threshold_bytes)
