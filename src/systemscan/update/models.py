"""Pydantic models, enumerations, and data contracts for Application Self-Update System."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from systemscan.version import __version__


class ReleaseChannel(str, Enum):
    """Release channels for application updates."""

    STABLE = "stable"
    BETA = "beta"
    DEV = "dev"


class UpdateStage(str, Enum):
    """Lifecycle stages of an atomic update transaction."""

    CHECKING = "CHECKING"
    DOWNLOADING = "DOWNLOADING"
    VERIFYING = "VERIFYING"
    PREPARING = "PREPARING"
    BACKING_UP = "BACKING_UP"
    APPLYING = "APPLYING"
    MIGRATING = "MIGRATING"
    VALIDATING = "VALIDATING"
    COMMITTING = "COMMITTING"
    COMPLETED = "COMPLETED"


class UpdateFailureReason(str, Enum):
    """Failure classifications for interrupted or rolled back update transactions."""

    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    BACKUP_FAILED = "BACKUP_FAILED"
    INSTALLATION_FAILED = "INSTALLATION_FAILED"
    MIGRATION_FAILED = "MIGRATION_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    ROLLED_BACK = "ROLLED_BACK"


class ReleaseInfo(BaseModel):
    """Metadata describing a published release artifact."""

    version: str = Field(description="Semantic version string (e.g. 1.1.0)")
    release_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Publish timestamp of the release",
    )
    channel: ReleaseChannel = Field(
        default=ReleaseChannel.STABLE, description="Target release distribution channel"
    )
    download_url: str = Field(description="HTTPS URL of release wheel or archive")
    sha256: str = Field(description="Cryptographic SHA-256 digest of release archive")
    min_python_version: str = Field(
        default="3.10", description="Minimum supported Python runtime version"
    )
    release_notes: str = Field(default="", description="Changelog and release notes summary")
    asset_name: str = Field(description="Filename of the downloadable release asset")
    asset_size_bytes: int = Field(default=0, ge=0, description="Size in bytes of release asset")
    signature: str | None = Field(default=None, description="Optional digital signature")


class UpdatePlan(BaseModel):
    """Calculated execution blueprint for applying an application update."""

    current_version: str = Field(default=__version__)
    target_version: str
    channel: ReleaseChannel
    is_update_available: bool
    is_downgrade: bool = False
    is_compatible: bool = True
    compatibility_reason: str = "Host environment and Python version are compatible."
    files_to_replace: list[str] = Field(default_factory=list)
    files_to_preserve: list[str] = Field(
        default_factory=lambda: [
            "config.json",
            "scan_history.json",
            "incremental_cache.json",
            "reports/*",
            "checkpoints/*",
            "network_baselines/*",
            "cleanup_audits/*",
            "logs/*",
        ]
    )
    dependency_changes: list[str] = Field(default_factory=list)
    requires_migration: bool = False


class UpdateTransaction(BaseModel):
    """Persistent audit ledger record tracking an update transaction."""

    transaction_id: str = Field(
        default_factory=lambda: f"upd-{uuid.uuid4().hex[:10]}",
        description="Unique transaction identifier",
    )
    from_version: str = Field(default=__version__)
    to_version: str = Field(default="")
    stage: UpdateStage = Field(default=UpdateStage.CHECKING)
    backup_path: str | None = Field(
        default=None, description="Path to pre-update snapshot directory"
    )
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = Field(default=None)
    failure_reason: UpdateFailureReason | None = Field(default=None)
    error_message: str | None = Field(default=None)
    rollback_performed: bool = Field(default=False)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data: Any) -> None:
        if "source_version" in data and "from_version" not in data:
            data["from_version"] = data.pop("source_version")
        if "target_version" in data and "to_version" not in data:
            data["to_version"] = data.pop("target_version")
        if "current_stage" in data and "stage" not in data:
            data["stage"] = data.pop("current_stage")
        if "channel" in data:
            chan = data.pop("channel")
            if "metadata" not in data:
                data["metadata"] = {}
            data["metadata"]["channel"] = chan.value if hasattr(chan, "value") else str(chan)
        super().__init__(**data)

    @property
    def source_version(self) -> str:
        return self.from_version

    @source_version.setter
    def source_version(self, value: str) -> None:
        self.from_version = value

    @property
    def target_version(self) -> str:
        return self.to_version

    @target_version.setter
    def target_version(self, value: str) -> None:
        self.to_version = value

    @property
    def channel(self) -> ReleaseChannel:
        val = self.metadata.get("channel", "stable")
        try:
            return ReleaseChannel(val)
        except ValueError:
            return ReleaseChannel.STABLE

    @property
    def current_stage(self) -> UpdateStage:
        return self.stage

    @current_stage.setter
    def current_stage(self, value: UpdateStage) -> None:
        self.stage = value

    @property
    def committed(self) -> bool:
        return self.stage == UpdateStage.COMPLETED

    @committed.setter
    def committed(self, value: bool) -> None:
        if value:
            self.stage = UpdateStage.COMPLETED

    @property
    def rolled_back(self) -> bool:
        return self.rollback_performed

    @rolled_back.setter
    def rolled_back(self, value: bool) -> None:
        self.rollback_performed = value

    @property
    def created_at(self) -> datetime:
        return self.started_at

    @property
    def ended_at(self) -> datetime | None:
        return self.completed_at

    @ended_at.setter
    def ended_at(self, value: datetime | None) -> None:
        self.completed_at = value
