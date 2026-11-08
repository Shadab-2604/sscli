"""Scan session history tracking, filtering, and persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from systemscan.engine.models import ScanHistoryRecord, ScanState, ScanType
from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("engine.history")


class ScanHistoryManager:
    """Manages persistent session history records, filtering, and retention pruning."""

    def __init__(self, history_file: Path | None = None, retention_days: int = 90) -> None:
        self.history_file = history_file or (AppPaths().data_dir / "scan_history.json")
        self.retention_days = max(1, retention_days)
        self._history: list[ScanHistoryRecord] = []
        self._load_history()

    def _load_history(self) -> None:
        """Load history file from disk."""
        if not self.history_file.exists():
            return
        try:
            raw = json.loads(self.history_file.read_text(encoding="utf-8"))
            self._history = [ScanHistoryRecord.model_validate(item) for item in raw]
        except Exception as e:
            logger.warning(f"Failed to load scan history: {e}. Starting fresh.")
            self._history = []

    def _save_history(self) -> None:
        """Atomically persist history records to disk."""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.history_file.with_suffix(".tmp")
        payload = [r.model_dump(mode="json") for r in self._history]
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.history_file)

    def record_session(self, record: ScanHistoryRecord) -> None:
        """Append a scan execution record to the history ledger."""
        # Replace if existing scan_id found, else append
        self._history = [r for r in self._history if r.scan_id != record.scan_id]
        self._history.append(record)
        self._prune_retention()
        self._save_history()
        logger.info(f"Recorded scan session '{record.scan_id}' in history ledger.")

    def get_session(self, scan_id: str) -> ScanHistoryRecord | None:
        """Retrieve a scan history record by scan ID."""
        for r in self._history:
            if r.scan_id == scan_id:
                return r
        return None

    def list_sessions(
        self,
        scan_type: ScanType | None = None,
        status: ScanState | None = None,
        limit: int = 50,
    ) -> list[ScanHistoryRecord]:
        """List historical scan records, sorted newest first with optional filters."""
        results = self._history
        if scan_type is not None:
            results = [r for r in results if r.scan_type == scan_type]
        if status is not None:
            results = [r for r in results if r.status == status]

        # Sort descending by started_at
        results = sorted(results, key=lambda r: r.started_at, reverse=True)
        return results[:limit]

    def clear_history(self, confirm: bool = False) -> bool:
        """Clear all historical scan records. Requires explicit confirmation."""
        if not confirm:
            raise PermissionError(
                "Explicit confirmation (confirm=True) is required to clear scan history."
            )

        self._history.clear()
        if self.history_file.exists():
            try:
                self.history_file.unlink()
                return True
            except OSError as e:
                logger.error(f"Failed to delete history file: {e}")
        return False

    def _prune_retention(self) -> None:
        """Prune records older than configured retention_days."""
        now = datetime.now(timezone.utc)
        cutoff_seconds = self.retention_days * 86400.0
        self._history = [
            r for r in self._history if (now - r.started_at).total_seconds() <= cutoff_seconds
        ]
