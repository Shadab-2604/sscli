"""Rollback recovery engine for restoring previous application versions."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.update.backup import UpdateBackupManager

logger = get_logger("update.rollback")


class RollbackError(Exception):
    """Raised when application rollback cannot be completed safely."""


class UpdateRollbackManager:
    """Restores application files from backup snapshots when updates fail or are rejected."""

    def __init__(self, backup_manager: UpdateBackupManager | None = None) -> None:
        self.backup_manager = backup_manager or UpdateBackupManager()

    def rollback(self, transaction_id: str | None = None) -> tuple[bool, str]:
        """Restore application source files from pre-update backup snapshot.

        Guarantees:
        - Never touches user configuration, reports, or scan history.
        - Restores only application code backed up prior to the failed transaction.
        """
        backup_dir: Path | None = None

        if transaction_id:
            candidate = self.backup_manager.backup_dir / transaction_id
            if candidate.exists() and candidate.is_dir():
                backup_dir = candidate
        else:
            backup_dir = self.backup_manager.get_latest_backup()

        if not backup_dir or not backup_dir.exists():
            msg = "No suitable pre-update backup snapshot found to perform rollback."
            logger.error(msg)
            return False, msg

        manifest_file = backup_dir / "manifest.json"
        if not manifest_file.exists():
            msg = f"Backup directory '{backup_dir}' is corrupted: missing manifest.json."
            logger.error(msg)
            return False, msg

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            source_dir = Path(manifest["source_dir"])
            pkg_name = source_dir.name
            backup_pkg_dir = backup_dir / pkg_name

            if not backup_pkg_dir.exists() or not backup_pkg_dir.is_dir():
                msg = f"Backup package directory '{backup_pkg_dir}' does not exist."
                logger.error(msg)
                return False, msg

            # Atomically restore application files
            # 1. Clean current installed package directory
            if source_dir.exists():
                shutil.rmtree(source_dir)

            # 2. Copy back from snapshot
            shutil.copytree(backup_pkg_dir, source_dir)

            logger.info(
                f"Rollback successfully restored '{source_dir}' from backup '{backup_dir.name}'"
            )
            return True, f"Application successfully rolled back from snapshot '{backup_dir.name}'."
        except Exception as e:
            msg = f"Failed to execute rollback from '{backup_dir}': {e}"
            logger.error(msg)
            return False, msg
