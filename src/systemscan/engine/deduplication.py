"""Scan deduplication, overlapping target pruning, and concurrent conflict management."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from systemscan.logging.logger import get_logger

logger = get_logger("engine.deduplication")


class ScanDeduplicationManager:
    """Detects and resolves redundant scan requests, overlapping paths, and worker collisions."""

    def __init__(self) -> None:
        self._active_scans: dict[str, set[str]] = {}  # scan_id -> set of normalized root paths

    @staticmethod
    def normalize_and_prune_paths(paths: Sequence[str | Path]) -> list[Path]:
        """Normalize paths and eliminate redundant subdirectories covered by ancestor roots."""
        resolved_paths: list[Path] = []
        for p in paths:
            try:
                resolved = Path(p).resolve()
                if resolved.exists():
                    resolved_paths.append(resolved)
                else:
                    logger.warning(f"Target path does not exist and was skipped: {p}")
            except OSError as e:
                logger.debug(f"Failed to resolve path '{p}': {e}")

        # Sort shortest path first
        sorted_paths = sorted(set(resolved_paths), key=lambda p: len(p.parts))
        pruned: list[Path] = []

        for candidate in sorted_paths:
            # If candidate is a subpath of any already-approved root, prune it
            is_redundant = False
            for root in pruned:
                try:
                    candidate.relative_to(root)
                    is_redundant = True
                    logger.debug(
                        f"Pruned redundant descendant scan target: '{candidate}' (covered by '{root}')"
                    )
                    break
                except ValueError:
                    continue

            if not is_redundant:
                pruned.append(candidate)

        return pruned

    def register_active_scan(self, scan_id: str, targets: list[Path]) -> None:
        """Register active scan roots to detect overlapping concurrent scans."""
        target_strs = {str(p) for p in targets}
        # Check for conflicts with already running scans
        for other_id, other_targets in self._active_scans.items():
            overlap = target_strs.intersection(other_targets)
            if overlap:
                logger.warning(
                    f"Scan '{scan_id}' targets paths {overlap} already under inspection by active scan '{other_id}'."
                )

        self._active_scans[scan_id] = target_strs

    def unregister_active_scan(self, scan_id: str) -> None:
        """Deregister a completed or cancelled scan session."""
        self._active_scans.pop(scan_id, None)
