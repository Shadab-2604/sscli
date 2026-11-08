"""Persistent update transaction history and audit ledger."""

from __future__ import annotations

import json
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.update.models import UpdateTransaction
from systemscan.utils.paths import AppPaths

logger = get_logger("update.history")


class UpdateHistoryManager:
    """Records update transaction audit trails and manages history retention."""

    def __init__(self, history_file: Path | None = None) -> None:
        self.history_file = history_file or (AppPaths().data_dir / "update_history.json")
        self._history: list[UpdateTransaction] = []
        self._load_history()

    def _load_history(self) -> None:
        """Load history file from disk."""
        if not self.history_file.exists():
            return
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
            self._history = [UpdateTransaction.model_validate(item) for item in data]
        except Exception as e:
            logger.warning(f"Failed to read update history file: {e}")
            self._history = []

    def _save_history(self) -> None:
        """Atomically persist update transactions to disk."""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.history_file.with_suffix(".tmp")
        payload = [t.model_dump(mode="json") for t in self._history]
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.history_file)

    def record_transaction(self, transaction: UpdateTransaction) -> None:
        """Append or update a transaction record in the persistent ledger."""
        self._history = [t for t in self._history if t.transaction_id != transaction.transaction_id]
        self._history.append(transaction)
        self._save_history()

    def save_transaction(self, transaction: UpdateTransaction) -> None:
        """Alias for record_transaction."""
        self.record_transaction(transaction)

    def get_transaction(self, transaction_id: str) -> UpdateTransaction | None:
        """Retrieve an update transaction by ID."""
        for t in self._history:
            if t.transaction_id == transaction_id:
                return t
        return None

    def list_transactions(self, limit: int = 25) -> list[UpdateTransaction]:
        """List historical update transactions, sorted newest first."""
        return sorted(self._history, key=lambda t: t.started_at, reverse=True)[:limit]
