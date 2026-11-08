"""Multi-stage duplicate file detection using size grouping, partial hashing, and SHA-256 verification."""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from pathlib import Path

from systemscan.filesystem.models import FileMetadata
from systemscan.modules.malware.hash_analyzer import HashAnalyzer
from systemscan.modules.storage.models import DuplicateGroup

logger = logging.getLogger("systemscan.storage.duplicates")

# Partial header fingerprint size: 4 KB
PARTIAL_HEADER_BYTES = 4096


class DuplicateDetector:
    """Discovers duplicate files using staged size filtering, partial fingerprinting, and cryptographic SHA-256."""

    def __init__(self, min_size_bytes: int = 1) -> None:
        self.min_size_bytes = min_size_bytes
        # Stage 1: Group by file size
        self._size_groups: dict[int, list[str]] = defaultdict(list)
        self._hasher = HashAnalyzer()

    def inspect_file(self, file_meta: FileMetadata) -> None:
        """Register file into size grouping ledger. Filters out symlinks and sub-threshold files."""
        if file_meta.is_symlink:
            return
        file_size = getattr(file_meta, "size_bytes", getattr(file_meta, "size", 0))
        if file_size >= self.min_size_bytes:
            self._size_groups[file_size].append(file_meta.path)

    def find_duplicates(self) -> list[DuplicateGroup]:
        """
        Execute multi-stage verification on size collision candidates.
        Returns list of DuplicateGroup instances sorted by reclaimable space descending.
        """
        duplicate_groups: list[DuplicateGroup] = []

        # Stage 1: Filter size groups with at least 2 files
        size_candidates = {sz: paths for sz, paths in self._size_groups.items() if len(paths) >= 2}

        for size_bytes, candidate_paths in size_candidates.items():
            # Stage 2: Partial fingerprint check (first 4KB) if files are large enough (>4KB)
            if size_bytes > PARTIAL_HEADER_BYTES:
                partial_map: dict[str, list[str]] = defaultdict(list)
                for path_str in candidate_paths:
                    p_hash = self._get_partial_hash(path_str)
                    if p_hash:
                        partial_map[p_hash].append(path_str)

                # Filter out singletons
                verified_buckets = [paths for paths in partial_map.values() if len(paths) >= 2]
            else:
                verified_buckets = [candidate_paths]

            # Stage 3 & 4: Full SHA-256 verification
            for bucket in verified_buckets:
                full_hash_map: dict[str, list[str]] = defaultdict(list)
                for path_str in bucket:
                    record = self._hasher.calculate_hash(path_str)
                    if record.status == "valid" and record.sha256:
                        full_hash_map[record.sha256].append(path_str)

                # Collect groups with matching verified hashes
                for sha256_hash, matched_paths in full_hash_map.items():
                    if len(matched_paths) >= 2:
                        total_bytes = size_bytes * len(matched_paths)
                        reclaimable = size_bytes * (len(matched_paths) - 1)
                        duplicate_groups.append(
                            DuplicateGroup(
                                sha256=sha256_hash,
                                file_size_bytes=size_bytes,
                                copy_count=len(matched_paths),
                                paths=matched_paths,
                                total_group_bytes=total_bytes,
                                reclaimable_bytes=reclaimable,
                            )
                        )

        # Sort descending by total reclaimable storage
        duplicate_groups.sort(key=lambda x: x.reclaimable_bytes, reverse=True)
        return duplicate_groups

    def _get_partial_hash(self, path_str: str) -> str | None:
        """Compute quick MD5 of the first 4 KB."""
        p = Path(path_str)
        try:
            with open(p, "rb") as f:
                head = f.read(PARTIAL_HEADER_BYTES)
            return hashlib.md5(head).hexdigest()
        except (PermissionError, OSError):
            return None
