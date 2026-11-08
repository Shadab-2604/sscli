"""Incremental scan engine with metadata-based change detection and verification policies."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from systemscan.engine.models import FileScanRecord, IncrementalVerificationMode
from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("engine.incremental")


class IncrementalScanEngine:
    """Tracks file metadata history to accelerate scans by skipping unchanged files."""

    def __init__(
        self,
        cache_path: Path | None = None,
        verification_mode: IncrementalVerificationMode = IncrementalVerificationMode.BALANCED,
        periodic_hash_verification: bool = True,
        rehash_age_days: int = 30,
    ) -> None:
        self.cache_path = cache_path or (AppPaths().data_dir / "incremental_cache.json")
        self.verification_mode = verification_mode
        self.periodic_hash_verification = periodic_hash_verification
        self.rehash_age_days = rehash_age_days

        self._cache: dict[str, FileScanRecord] = {}
        self._dirty = False
        self._load_cache()

    def _load_cache(self) -> None:
        """Load persistent cache from disk."""
        if not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
            for path_str, record_data in raw.items():
                self._cache[path_str] = FileScanRecord.model_validate(record_data)
        except Exception as e:
            logger.warning(f"Failed to load incremental cache: {e}. Starting fresh.")
            self._cache = {}

    def save_cache(self) -> None:
        """Atomically persist cache to disk."""
        if not self._dirty:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        payload = {k: v.model_dump(mode="json") for k, v in self._cache.items()}
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.cache_path)
        self._dirty = False

    def should_scan_file(
        self,
        path: str,
        size_bytes: int,
        modified_time: float,
        inode: int | None = None,
        force_thorough: bool = False,
    ) -> tuple[bool, FileScanRecord | None]:
        """Determine whether a file requires re-evaluation.

        Returns:
            (should_scan, cached_record_if_present)
        """
        # Thorough mode forces full re-inspection
        if force_thorough or self.verification_mode == IncrementalVerificationMode.THOROUGH:
            return True, self._cache.get(path)

        cached = self._cache.get(path)
        if cached is None:
            # New file -> must scan
            return True, None

        # Check metadata match
        size_matches = cached.size_bytes == size_bytes
        # Allow 1-second floating timestamp tolerance for cross-filesystem precision
        mtime_matches = abs(cached.modified_time - modified_time) < 1.0

        if not (size_matches and mtime_matches):
            # File modified or resized -> must re-scan
            return True, cached

        # Inode identity check if available
        if inode is not None and cached.inode is not None and cached.inode != inode:
            return True, cached

        # If previously flagged as suspicious/malware, always re-verify
        if cached.status != "CLEAN" or cached.findings_count > 0:
            return True, cached

        # Fast mode: metadata match is sufficient to skip
        if self.verification_mode == IncrementalVerificationMode.FAST:
            return False, cached

        # Balanced mode: periodic re-verification check
        if self.periodic_hash_verification:
            now = datetime.now(timezone.utc)
            record_age_days = (now - cached.last_scanned).total_seconds() / 86400.0
            if record_age_days >= self.rehash_age_days:
                return True, cached

        return False, cached

    def record_scan_result(
        self,
        path: str,
        size_bytes: int,
        modified_time: float,
        inode: int | None = None,
        sha256: str | None = None,
        status: str = "CLEAN",
        findings_count: int = 0,
    ) -> None:
        """Update or insert scan record into cache."""
        record = FileScanRecord(
            path=path,
            size_bytes=size_bytes,
            modified_time=modified_time,
            inode=inode,
            sha256=sha256,
            last_scanned=datetime.now(timezone.utc),
            status=status,
            findings_count=findings_count,
        )
        self._cache[path] = record
        self._dirty = True

    def clear(self) -> None:
        """Clear the incremental cache."""
        self._cache.clear()
        if self.cache_path.exists():
            try:
                self.cache_path.unlink()
            except OSError:
                pass
        self._dirty = False
