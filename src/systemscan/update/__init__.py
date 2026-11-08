"""SystemScan Application Self-Update System.

Provides release checking, secure cryptographic verification, archive security checks,
transactional updates, automated rollback, and configuration migration.
"""

from __future__ import annotations

from systemscan.update.backup import UpdateBackupManager
from systemscan.update.checker import UpdateChecker
from systemscan.update.history import UpdateHistoryManager
from systemscan.update.migrations import ConfigMigrationManager, MigrationError
from systemscan.update.models import (
    ReleaseChannel,
    ReleaseInfo,
    UpdateFailureReason,
    UpdatePlan,
    UpdateStage,
    UpdateTransaction,
)
from systemscan.update.rollback import RollbackError, UpdateRollbackManager
from systemscan.update.transaction import UpdateLockError, UpdateTransactionCoordinator
from systemscan.update.verifier import ArchiveSecurityError, UpdateVerifier

__all__ = [
    "ArchiveSecurityError",
    "ConfigMigrationManager",
    "MigrationError",
    "ReleaseChannel",
    "ReleaseInfo",
    "RollbackError",
    "UpdateBackupManager",
    "UpdateChecker",
    "UpdateFailureReason",
    "UpdateHistoryManager",
    "UpdateLockError",
    "UpdatePlan",
    "UpdateRollbackManager",
    "UpdateStage",
    "UpdateTransaction",
    "UpdateTransactionCoordinator",
    "UpdateVerifier",
]
