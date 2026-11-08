"""Analysis of files based on modification age and dormancy thresholds."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from systemscan.filesystem.models import FileMetadata
from systemscan.modules.storage.models import LargeFileRecord


class AgeAnalyzer:
    """Classifies files by chronological dormancy thresholds (30, 90, 180, 365+ days)."""

    def __init__(self, now: datetime | None = None) -> None:
        self.now = now or datetime.now(timezone.utc)
        # Buckets for counts and accumulated bytes
        self._brackets: dict[str, list[int]] = {
            "30+ days": [0, 0],
            "90+ days": [0, 0],
            "180+ days": [0, 0],
            "365+ days": [0, 0],
        }
        self._oldest_files: list[LargeFileRecord] = []

    def inspect_file(self, file_meta: FileMetadata) -> None:
        """Evaluate file age against thresholds."""
        mod_time = file_meta.modified_time or self.now
        delta = self.now - mod_time
        days = delta.days
        size = getattr(file_meta, "size_bytes", getattr(file_meta, "size", 0))

        if days >= 365:
            self._brackets["365+ days"][0] += 1
            self._brackets["365+ days"][1] += size
        elif days >= 180:
            self._brackets["180+ days"][0] += 1
            self._brackets["180+ days"][1] += size
        elif days >= 90:
            self._brackets["90+ days"][0] += 1
            self._brackets["90+ days"][1] += size
        elif days >= 30:
            self._brackets["30+ days"][0] += 1
            self._brackets["30+ days"][1] += size

        if days >= 180:
            p = Path(file_meta.path)
            self._oldest_files.append(
                LargeFileRecord(
                    path=file_meta.path,
                    name=file_meta.name,
                    size_bytes=size,
                    extension=p.suffix.lower(),
                    modified_at=mod_time,
                    is_hidden=file_meta.is_hidden,
                    volume=str(p.drive if p.drive else "/"),
                )
            )

    def get_brackets_summary(self) -> dict[str, dict[str, int]]:
        """Return file count and byte breakdown per age bracket."""
        return {k: {"count": v[0], "total_bytes": v[1]} for k, v in self._brackets.items()}

    def get_oldest_large_files(self, limit: int = 50) -> list[LargeFileRecord]:
        """Return oldest files sorted descending by age (oldest first)."""
        self._oldest_files.sort(key=lambda x: x.modified_at)
        return self._oldest_files[:limit]
