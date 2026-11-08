"""Immutable audit logging for safe storage cleanup operations."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from systemscan.core.application import app_instance
from systemscan.modules.storage.models import CleanupAuditRecord

logger = logging.getLogger("systemscan.storage.audit")


class CleanupAuditLogger:
    """Stores persistent audit ledgers of all simulated dry-runs and confirmed cleanup executions."""

    def __init__(self, audit_dir: Path | None = None) -> None:
        if audit_dir:
            self.audit_dir = Path(audit_dir)
        else:
            self.audit_dir = app_instance.paths.data_dir / "cleanup_audits"

        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def record_operation(self, record: CleanupAuditRecord) -> Path:
        """Write audit record to timestamped JSON file."""
        ts_str = record.timestamp.strftime("%Y%m%d_%H%M%S")
        log_file = self.audit_dir / f"audit_{ts_str}_{record.operation_id}.json"

        try:
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(record.model_dump(mode="json"), f, indent=2)
            logger.info(f"Recorded cleanup audit entry to {log_file}")
            return log_file
        except Exception as e:
            logger.error(f"Failed to write cleanup audit log to {log_file}: {e}")
            return log_file

    def list_audits(self) -> list[CleanupAuditRecord]:
        """Return history of all recorded cleanup operations."""
        records: list[CleanupAuditRecord] = []
        for p in sorted(self.audit_dir.glob("audit_*.json"), reverse=True):
            try:
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                records.append(CleanupAuditRecord.model_validate(data))
            except Exception:
                continue
        return records
