"""Thread-safe statistics collector and telemetry aggregator for filesystem scans."""

from __future__ import annotations

import threading
import time

from systemscan.filesystem.models import FileType, ScanStatistics


class ScanStatisticsCollector:
    """Thread-safe statistics collector tracking real-time filesystem traversal counters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stats = ScanStatistics()
        self._start_time: float | None = None
        self._end_time: float | None = None

    def start(self) -> None:
        """Mark scan commencement time."""
        with self._lock:
            self._start_time = time.monotonic()
            self._end_time = None

    def finish(self) -> None:
        """Mark scan completion time and compute final rates."""
        with self._lock:
            self._end_time = time.monotonic()
            if self._start_time is not None:
                duration = max(0.001, self._end_time - self._start_time)
                self._stats.scan_duration_seconds = round(duration, 3)
                self._stats.traversal_speed_files_per_sec = round(
                    self._stats.files_scanned / duration, 1
                )

    def record_directory_discovered(self, is_hidden: bool = False) -> None:
        with self._lock:
            self._stats.directories_discovered += 1
            if is_hidden:
                self._stats.hidden_directories += 1

    def record_directory_scanned(self, depth: int) -> None:
        with self._lock:
            self._stats.directories_scanned += 1
            if depth > self._stats.max_depth_reached:
                self._stats.max_depth_reached = depth

    def record_file_discovered(
        self,
        size_bytes: int = 0,
        is_hidden: bool = False,
        is_symlink: bool = False,
        file_type: FileType = FileType.REGULAR_FILE,
    ) -> None:
        with self._lock:
            self._stats.files_discovered += 1
            self._stats.total_accessible_bytes += size_bytes
            if is_hidden:
                self._stats.hidden_files += 1
            if is_symlink:
                self._stats.symlinks_discovered += 1
            if file_type not in (FileType.REGULAR_FILE, FileType.DIRECTORY, FileType.SYMLINK):
                self._stats.special_entries += 1

    def record_file_scanned(self) -> None:
        with self._lock:
            self._stats.files_scanned += 1

    def record_broken_link(self) -> None:
        with self._lock:
            self._stats.broken_links += 1

    def record_special_entry(self) -> None:
        with self._lock:
            self._stats.special_entries += 1

    def record_skipped(self) -> None:
        with self._lock:
            self._stats.skipped_paths += 1

    def record_excluded(self) -> None:
        with self._lock:
            self._stats.excluded_paths += 1

    def record_permission_error(self) -> None:
        with self._lock:
            self._stats.permission_errors += 1

    def record_io_error(self) -> None:
        with self._lock:
            self._stats.io_errors += 1

    def set_current_path(self, path: str) -> None:
        with self._lock:
            self._stats.current_path = path

    def snapshot(self) -> ScanStatistics:
        """Return a detached snapshot of current statistical metrics."""
        with self._lock:
            # If scan is still running, calculate current elapsed duration and rate
            if self._start_time is not None and self._end_time is None:
                duration = max(0.001, time.monotonic() - self._start_time)
                self._stats.scan_duration_seconds = round(duration, 3)
                self._stats.traversal_speed_files_per_sec = round(
                    self._stats.files_scanned / duration, 1
                )
            return self._stats.model_copy()
