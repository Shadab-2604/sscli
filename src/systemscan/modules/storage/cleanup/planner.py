"""Generates pre-execution cleanup previews with safety classification and category breakdowns."""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from systemscan.modules.storage.cache.browser_cache import BrowserCacheAnalyzer
from systemscan.modules.storage.cache.discovery import CacheDiscoveryEngine
from systemscan.modules.storage.cleanup.safety import CleanupSafetyValidator
from systemscan.modules.storage.models import (
    CleanupCandidate,
    CleanupPreview,
    CleanupSafetyCategory,
    StorageCategory,
)

logger = logging.getLogger("systemscan.storage.planner")


class CleanupPlanner:
    """Discovers cleanup candidates across cache, temp, and old logs and builds a preview."""

    @classmethod
    def generate_preview(
        cls,
        target_paths: list[Path] | None = None,
        include_browser_cache: bool = True,
    ) -> CleanupPreview:
        """Scan candidate locations and construct pre-execution preview."""
        preview_id = str(uuid.uuid4())[:8]
        candidates: list[CleanupCandidate] = []

        category_counts: dict[str, int] = defaultdict(int)
        category_bytes: dict[str, int] = defaultdict(int)
        total_reclaimable = 0
        protected_count = 0
        protected_bytes = 0
        review_count = 0
        review_bytes = 0

        # 1. Standard System & User Cache / Temp Locations
        if target_paths:
            candidate_dirs = [("Custom Target", p) for p in target_paths if p.exists()]
        else:
            candidate_dirs = CacheDiscoveryEngine.get_standard_cache_directories()

        for label, dir_path in candidate_dirs:
            cls._scan_directory_candidates(label, dir_path, candidates)

        # 2. Browser Cache Locations
        if include_browser_cache and not target_paths:
            browser_records = BrowserCacheAnalyzer.discover_browser_caches()
            for b_rec in browser_records:
                if b_rec.is_browser_running:
                    # Skip or mark as review if browser is running
                    logger.debug(
                        f"Skipping active browser cache {b_rec.browser_name} (browser running)"
                    )
                    continue
                cls._scan_directory_candidates(
                    f"Browser Cache ({b_rec.browser_name})",
                    Path(b_rec.cache_path),
                    candidates,
                    category=StorageCategory.BROWSER_CACHE,
                )

        # Classify and aggregate metrics
        for cand in candidates:
            cat_name = cand.category.value
            if cand.safety == CleanupSafetyCategory.SAFE_CANDIDATE:
                cand.can_delete = True
                category_counts[cat_name] += 1
                category_bytes[cat_name] += cand.size_bytes
                total_reclaimable += cand.size_bytes
            elif cand.safety == CleanupSafetyCategory.PROTECTED:
                protected_count += 1
                protected_bytes += cand.size_bytes
            else:
                review_count += 1
                review_bytes += cand.size_bytes

        return CleanupPreview(
            preview_id=preview_id,
            category_counts=dict(category_counts),
            category_bytes=dict(category_bytes),
            total_files=len(candidates),
            total_reclaimable_bytes=total_reclaimable,
            protected_count=protected_count,
            protected_bytes=protected_bytes,
            review_required_count=review_count,
            review_required_bytes=review_bytes,
            candidates=candidates,
        )

    @classmethod
    def _scan_directory_candidates(
        cls,
        label: str,
        dir_path: Path,
        sink: list[CleanupCandidate],
        category: StorageCategory | None = None,
    ) -> None:
        """Inspect files within candidate directory applying safety checks."""
        try:
            for item in dir_path.iterdir():
                if item.is_file():
                    try:
                        st = item.stat()
                        size = st.st_size
                        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                    except (PermissionError, OSError):
                        continue

                    # Determine category
                    cat = category
                    if cat is None:
                        if "temp" in label.lower() or "tmp" in str(item).lower():
                            cat = StorageCategory.TEMPORARY_FILES
                        elif item.suffix.lower() == ".log":
                            cat = StorageCategory.OLD_LOGS
                        else:
                            cat = StorageCategory.USER_CACHE

                    safety, reason = CleanupSafetyValidator.evaluate_safety(
                        item, check_locked=False
                    )

                    sink.append(
                        CleanupCandidate(
                            candidate_id=str(uuid.uuid4()),
                            path=str(item),
                            size_bytes=size,
                            modified_at=mtime,
                            category=cat,
                            safety=safety,
                            reason=reason,
                            can_delete=(safety == CleanupSafetyCategory.SAFE_CANDIDATE),
                        )
                    )
        except (PermissionError, OSError):
            pass
