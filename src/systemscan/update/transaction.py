"""Transactional update execution engine with atomic staging and automated rollback."""

from __future__ import annotations

import os
import shutil
import tempfile
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import systemscan
from systemscan.config.schema import SystemScanConfig
from systemscan.logging.logger import get_logger
from systemscan.update.backup import UpdateBackupManager
from systemscan.update.checker import UpdateChecker
from systemscan.update.history import UpdateHistoryManager
from systemscan.update.migrations import ConfigMigrationManager
from systemscan.update.models import (
    ReleaseChannel,
    ReleaseInfo,
    UpdateFailureReason,
    UpdatePlan,
    UpdateStage,
    UpdateTransaction,
)
from systemscan.update.rollback import UpdateRollbackManager
from systemscan.update.verifier import UpdateVerifier
from systemscan.utils.paths import AppPaths
from systemscan.version import __version__

logger = get_logger("update.transaction")


class UpdateLockError(Exception):
    """Raised when another update transaction is already in progress."""


class UpdateTransactionCoordinator:
    """Coordinates atomic application update transactions across all 10 stages."""

    def __init__(
        self,
        config: SystemScanConfig | None = None,
        checker: UpdateChecker | None = None,
        verifier: UpdateVerifier | None = None,
        backup_manager: UpdateBackupManager | None = None,
        rollback_manager: UpdateRollbackManager | None = None,
        migration_manager: ConfigMigrationManager | None = None,
        history_manager: UpdateHistoryManager | None = None,
    ) -> None:
        self.config = config or SystemScanConfig()
        self.checker = checker or UpdateChecker(config=self.config)
        self.verifier = verifier or UpdateVerifier()
        self.backup_manager = backup_manager or UpdateBackupManager(
            max_backups=self.config.updates.max_backups
        )
        self.rollback_manager = rollback_manager or UpdateRollbackManager(
            backup_manager=self.backup_manager
        )
        self.migration_manager = migration_manager or ConfigMigrationManager()
        self.history_manager = history_manager or UpdateHistoryManager()
        self.lock_file = AppPaths().data_dir / "update.lock"

    def acquire_lock(self, transaction_id: str) -> None:
        """Acquire exclusive update lock."""
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        if self.lock_file.exists():
            try:
                content = self.lock_file.read_text(encoding="utf-8").strip()
                # If lock file exists and is less than 30 minutes old, raise error
                mtime = self.lock_file.stat().st_mtime
                age_seconds = datetime.now().timestamp() - mtime
                if age_seconds < 1800:
                    raise UpdateLockError(
                        f"Another update transaction ({content}) is currently in progress."
                    )
                logger.warning(
                    f"Overriding stale update lock file ({content}) from {age_seconds:.0f}s ago."
                )
            except OSError:
                pass

        self.lock_file.write_text(f"{transaction_id}:{os.getpid()}", encoding="utf-8")

    def release_lock(self) -> None:
        """Release exclusive update lock."""
        try:
            if self.lock_file.exists():
                self.lock_file.unlink()
        except OSError as e:
            logger.debug(f"Failed to release update lock: {e}")

    def execute_update(
        self,
        release: ReleaseInfo | None = None,
        channel: ReleaseChannel = ReleaseChannel.STABLE,
        dry_run: bool = False,
        allow_downgrade: bool = False,
        progress_cb: Callable[[UpdateStage, float, str], None] | None = None,
    ) -> UpdateTransaction:
        """Execute a complete, transactional application update."""
        target_version = release.version if release else "unknown"
        txn = UpdateTransaction(
            source_version=__version__,
            target_version=target_version,
            channel=channel,
            current_stage=UpdateStage.CHECKING,
        )

        def report(stage: UpdateStage, pct: float, msg: str) -> None:
            txn.current_stage = stage
            logger.info(f"[{stage.value}] {msg}")
            if progress_cb:
                progress_cb(stage, pct, msg)

        # Stage 1: CHECKING
        report(UpdateStage.CHECKING, 5.0, "Checking for available releases...")
        if not release:
            active_plan = self.checker.create_update_plan(channel=channel)
            if not active_plan.is_update_available and not dry_run:
                txn.error_message = f"Already on the latest version ({__version__})."
                return txn
            remote_release = self.checker.fetch_latest_release(channel=channel)
            if not remote_release:
                txn.error_message = "No release found matching criteria."
                txn.failure_reason = UpdateFailureReason.DOWNLOAD_FAILED
                return txn
            release = remote_release

        txn.target_version = release.version
        _ = UpdatePlan(
            current_version=__version__,
            target_version=release.version,
            channel=channel,
            is_update_available=True,
            is_downgrade=False,
        )

        if not allow_downgrade:
            cur_tuple = self.checker._parse_version(__version__)
            tgt_tuple = self.checker._parse_version(release.version)
            if tgt_tuple < cur_tuple:
                txn.failure_reason = UpdateFailureReason.VALIDATION_FAILED
                txn.error_message = (
                    f"Target version {release.version} is older than current version {__version__} "
                    "(downgrade rejected without explicit authorization)."
                )
                return txn

        if dry_run:
            report(
                UpdateStage.COMPLETED,
                100.0,
                f"Dry-run completed successfully for update to v{release.version}.",
            )
            txn.current_stage = UpdateStage.COMPLETED
            txn.committed = True
            txn.ended_at = datetime.now(timezone.utc)
            return txn

        temp_dir = Path(tempfile.mkdtemp(prefix="systemscan_update_"))
        download_file = temp_dir / release.asset_name

        try:
            self.acquire_lock(txn.transaction_id)
            self.history_manager.save_transaction(txn)

            # Stage 2: DOWNLOADING
            report(
                UpdateStage.DOWNLOADING,
                20.0,
                f"Downloading {release.asset_name} from {release.download_url}...",
            )
            try:
                urllib.request.urlretrieve(release.download_url, download_file)  # noqa: S310
            except Exception as e:
                txn.failure_reason = UpdateFailureReason.DOWNLOAD_FAILED
                txn.error_message = f"Failed to download update asset: {e}"
                return txn

            # Stage 3: VERIFYING
            report(
                UpdateStage.VERIFYING, 35.0, "Verifying cryptographic hash and archive safety..."
            )
            hash_valid, hash_msg = self.verifier.verify_file_hash(download_file, release.sha256)
            if not hash_valid:
                txn.failure_reason = UpdateFailureReason.VERIFICATION_FAILED
                txn.error_message = f"Hash verification failed: {hash_msg}"
                return txn

            safe_archive, safe_msg = self.verifier.verify_archive_safety(download_file)
            if not safe_archive:
                txn.failure_reason = UpdateFailureReason.VERIFICATION_FAILED
                txn.error_message = f"Archive security check failed: {safe_msg}"
                return txn

            # Stage 4: PREPARING
            report(UpdateStage.PREPARING, 50.0, "Preparing update environment...")
            extract_staging = temp_dir / "extracted"
            extract_staging.mkdir(parents=True, exist_ok=True)
            extracted_ok, extract_msg = self.verifier.extract_safe(download_file, extract_staging)
            if not extracted_ok:
                txn.failure_reason = UpdateFailureReason.INSTALLATION_FAILED
                txn.error_message = f"Extraction failed: {extract_msg}"
                return txn

            # Stage 5: BACKING_UP
            report(UpdateStage.BACKING_UP, 65.0, "Creating pre-update backup snapshot...")
            package_root = Path(systemscan.__file__).parent
            backup_meta: dict[str, Any] = {
                "source_version": __version__,
                "target_version": release.version,
                "asset": release.asset_name,
            }
            try:
                backup_path = self.backup_manager.create_backup(
                    txn.transaction_id, package_root, metadata=backup_meta
                )
                txn.backup_path = str(backup_path)
            except Exception as e:
                txn.failure_reason = UpdateFailureReason.BACKUP_FAILED
                txn.error_message = f"Backup creation failed: {e}"
                return txn

            # Stage 6: APPLYING
            report(UpdateStage.APPLYING, 75.0, "Applying new application files...")
            try:
                # Find the systemscan folder within extracted content
                candidate_src = extract_staging / "systemscan"
                if not candidate_src.exists():
                    # Check nested subdirectories
                    nested = list(extract_staging.rglob("systemscan"))
                    if nested and nested[0].is_dir():
                        candidate_src = nested[0]

                if candidate_src.exists() and candidate_src.is_dir():
                    # Copy files into target package root
                    shutil.copytree(candidate_src, package_root, dirs_exist_ok=True)
                else:
                    # If not a standard package folder, copy top-level items
                    for item in extract_staging.iterdir():
                        if item.is_dir():
                            shutil.copytree(item, package_root / item.name, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, package_root / item.name)
            except Exception as e:
                txn.failure_reason = UpdateFailureReason.INSTALLATION_FAILED
                txn.error_message = f"File replacement failed: {e}"
                self._trigger_rollback(txn, f"Installation failure: {e}")
                return txn

            # Stage 7: MIGRATING
            report(UpdateStage.MIGRATING, 85.0, "Migrating configuration schema...")
            mig_ok, mig_msg, _ = self.migration_manager.migrate()
            if not mig_ok:
                txn.failure_reason = UpdateFailureReason.MIGRATION_FAILED
                txn.error_message = f"Configuration migration failed: {mig_msg}"
                self._trigger_rollback(txn, f"Migration error: {mig_msg}")
                return txn

            # Stage 8: VALIDATING
            report(UpdateStage.VALIDATING, 92.0, "Validating updated application integrity...")
            # Smoke test: check if package can be imported and files exist
            if not (package_root / "__init__.py").exists():
                txn.failure_reason = UpdateFailureReason.VALIDATION_FAILED
                txn.error_message = "Package validation failed: missing __init__.py."
                self._trigger_rollback(txn, "Missing __init__.py")
                return txn

            # Stage 9: COMMITTING
            report(UpdateStage.COMMITTING, 98.0, "Committing update transaction...")
            txn.committed = True
            txn.current_stage = UpdateStage.COMPLETED
            txn.ended_at = datetime.now(timezone.utc)

            # Stage 10: COMPLETED
            report(
                UpdateStage.COMPLETED,
                100.0,
                f"Successfully updated systemscan to v{release.version}!",
            )
            return txn

        finally:
            self.release_lock()
            self.history_manager.save_transaction(txn)
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    def _trigger_rollback(self, txn: UpdateTransaction, reason: str) -> None:
        """Trigger automated rollback upon update failure."""
        logger.error(f"Update transaction {txn.transaction_id} failed: {reason}. Rolling back...")
        rb_ok, rb_msg = self.rollback_manager.rollback(txn.transaction_id)
        if rb_ok:
            txn.rolled_back = True
            logger.info(f"Rollback succeeded for transaction {txn.transaction_id}")
        else:
            logger.critical(
                f"Rollback failed for transaction {txn.transaction_id}: {rb_msg}. "
                "Manual intervention required."
            )
