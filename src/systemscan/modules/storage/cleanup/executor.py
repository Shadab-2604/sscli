"""Safe deletion execution with re-validation, path traversal protection, and error isolation."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from systemscan.modules.storage.cleanup.audit import CleanupAuditLogger
from systemscan.modules.storage.cleanup.safety import CleanupSafetyValidator
from systemscan.modules.storage.models import (
    CleanupAuditRecord,
    CleanupPreview,
    CleanupSafetyCategory,
)

logger = logging.getLogger("systemscan.storage.executor")


class SafeCleanupExecutor:
    """Executes confirmed cleanup operations with pre-deletion safety re-validation."""

    def __init__(self, audit_logger: CleanupAuditLogger | None = None) -> None:
        self.audit_logger = audit_logger or CleanupAuditLogger()

    def execute_cleanup(
        self,
        preview: CleanupPreview,
        authorized: bool = False,
        dry_run: bool = False,
    ) -> CleanupAuditRecord:
        """
        Execute cleanup over approved candidates.
        Requires explicit `authorized=True` unless `dry_run=True`.
        """
        operation_id = str(uuid.uuid4())[:8]

        if not authorized and not dry_run:
            raise PermissionError(
                "Cleanup operation aborted: explicit user authorization is mandatory for deletion."
            )

        deleted_count = 0
        skipped_count = 0
        failed_count = 0
        actual_reclaimed_bytes = 0
        errors: list[dict[str, str]] = []

        status = "DRY_RUN" if dry_run else "COMPLETED"

        for cand in preview.candidates:
            # 1. Skip items not flagged as safe candidates
            if not cand.can_delete or cand.safety != CleanupSafetyCategory.SAFE_CANDIDATE:
                skipped_count += 1
                continue

            p = Path(cand.path).resolve()

            # 2. TOCTOU re-validation immediately before deletion
            if not p.exists() or not p.is_file():
                skipped_count += 1
                continue

            # Verify safety rules again
            safety, reason = CleanupSafetyValidator.evaluate_safety(p)
            if safety != CleanupSafetyCategory.SAFE_CANDIDATE:
                skipped_count += 1
                logger.warning(f"Skipping {p}: failed safety re-check ({reason})")
                continue

            # Check if file modified since preview
            try:
                st = p.stat()
                mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                if abs((mtime - cand.modified_at).total_seconds()) > 2.0:
                    skipped_count += 1
                    logger.warning(f"Skipping {p}: file modified after preview generated.")
                    continue
                file_size = st.st_size
            except (PermissionError, OSError) as e:
                failed_count += 1
                errors.append({"path": str(p), "error": str(e)})
                continue

            # 3. Perform Deletion or Dry-Run Simulation
            if dry_run:
                deleted_count += 1
                actual_reclaimed_bytes += file_size
                continue

            try:
                p.unlink()
                deleted_count += 1
                actual_reclaimed_bytes += file_size
                logger.debug(f"Safely deleted cleanup candidate: {p} ({file_size} bytes)")
            except (PermissionError, OSError) as e:
                failed_count += 1
                errors.append({"path": str(p), "error": str(e)})
                logger.warning(f"Failed to delete {p}: {e}")

        if failed_count > 0 and not dry_run:
            status = "PARTIAL"

        audit_rec = CleanupAuditRecord(
            operation_id=operation_id,
            timestamp=datetime.now(timezone.utc),
            user_authorized=authorized,
            dry_run=dry_run,
            selected_categories=list(preview.category_counts.keys()),
            deleted_files_count=deleted_count,
            skipped_files_count=skipped_count,
            failed_files_count=failed_count,
            actual_reclaimed_bytes=actual_reclaimed_bytes,
            errors=errors,
            status=status,
        )

        self.audit_logger.record_operation(audit_rec)
        return audit_rec
