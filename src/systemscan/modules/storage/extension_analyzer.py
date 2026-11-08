"""Storage distribution analysis by file extension."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from systemscan.filesystem.models import FileMetadata
from systemscan.modules.storage.models import ExtensionStat


class ExtensionAnalyzer:
    """Aggregates file counts and byte contributions categorized by file extension."""

    def __init__(self) -> None:
        # Map: ext -> [count, total_bytes, largest_bytes]
        self._stats: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
        self.total_scanned_bytes = 0

    def inspect_file(self, file_meta: FileMetadata) -> None:
        """Categorize file and record statistics."""
        p = Path(file_meta.path)
        ext = p.suffix.lower() if p.suffix else "(no extension)"
        size = getattr(file_meta, "size_bytes", getattr(file_meta, "size", 0))

        entry = self._stats[ext]
        entry[0] += 1
        entry[1] += size
        if size > entry[2]:
            entry[2] = size

        self.total_scanned_bytes += size

    def get_extension_summary(self, top_limit: int = 30) -> list[ExtensionStat]:
        """Return extension stats sorted descending by total storage consumed."""
        summary: list[ExtensionStat] = []
        tot = self.total_scanned_bytes or 1

        for ext, (count, total_bytes, largest_bytes) in self._stats.items():
            pct = round((total_bytes / tot) * 100.0, 2)
            avg = total_bytes // count if count > 0 else 0
            summary.append(
                ExtensionStat(
                    extension=ext,
                    file_count=count,
                    total_bytes=total_bytes,
                    average_bytes=avg,
                    largest_file_bytes=largest_bytes,
                    percentage_of_total=pct,
                )
            )

        summary.sort(key=lambda x: x.total_bytes, reverse=True)
        return summary[:top_limit]
