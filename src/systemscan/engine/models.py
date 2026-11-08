"""Data contracts, lifecycle enumerations, and telemetry models for Scan Intelligence Engine."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanState(str, Enum):
    """Standardized scan lifecycle states."""

    QUEUED = "QUEUED"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSING = "PAUSING"
    PAUSED = "PAUSED"
    RESUMING = "RESUMING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ScanType(str, Enum):
    """Scan operation classifications."""

    FULL = "FULL"
    FILESYSTEM = "FILESYSTEM"
    MALWARE = "MALWARE"
    STORAGE = "STORAGE"
    CACHE = "CACHE"
    USB = "USB"
    NETWORK = "NETWORK"
    CUSTOM = "CUSTOM"


class ConcurrencyMode(str, Enum):
    """Concurrency governance modes."""

    ADAPTIVE = "ADAPTIVE"
    FIXED = "FIXED"
    SEQUENTIAL = "SEQUENTIAL"


class IncrementalVerificationMode(str, Enum):
    """Verification depth policies for incremental scanning."""

    FAST = "FAST"
    BALANCED = "BALANCED"
    THOROUGH = "THOROUGH"


class ResourceUsageSnapshot(BaseModel):
    """Point-in-time telemetry of host system resource consumption."""

    cpu_percent: float = Field(ge=0.0, le=100.0, description="Overall CPU utilization percentage")
    memory_percent: float = Field(
        ge=0.0, le=100.0, description="Virtual RAM utilization percentage"
    )
    memory_available_mb: float = Field(ge=0.0, description="Free/available RAM in megabytes")
    battery_percent: float | None = Field(
        default=None, ge=0.0, le=100.0, description="Battery charge % if battery present"
    )
    power_plugged: bool | None = Field(
        default=None, description="Whether AC power is currently connected"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Capture timestamp"
    )


class ScanProgressEvent(BaseModel):
    """Unified telemetry event broadcast across scan phases."""

    scan_id: str = Field(description="Unique scan session UUID")
    state: ScanState = Field(description="Current scan lifecycle state")
    current_phase: str = Field(description="Active execution phase label")
    current_target: str = Field(
        default="", description="File, directory, or network target currently inspected"
    )
    items_discovered: int = Field(default=0, ge=0, description="Total items identified")
    items_processed: int = Field(default=0, ge=0, description="Items completed inspection")
    items_skipped: int = Field(
        default=0, ge=0, description="Items skipped via exclusions or incremental cache"
    )
    items_failed: int = Field(
        default=0, ge=0, description="Items encountering read/permission errors"
    )
    bytes_processed: int = Field(default=0, ge=0, description="Total bytes processed")
    total_bytes_estimated: int | None = Field(
        default=None, ge=0, description="Estimated total bytes when known"
    )
    processing_rate_items_sec: float = Field(
        default=0.0, ge=0.0, description="Smoothed processing throughput (items/sec)"
    )
    processing_rate_bytes_sec: float = Field(
        default=0.0, ge=0.0, description="Smoothed byte throughput (bytes/sec)"
    )
    elapsed_seconds: float = Field(
        default=0.0, ge=0.0, description="Total elapsed runtime in seconds"
    )
    estimated_remaining_seconds: float | None = Field(
        default=None, ge=0.0, description="Dynamic ETA in seconds or None if unknown"
    )
    completion_percent: float | None = Field(
        default=None, ge=0.0, le=100.0, description="Measurable progress percentage"
    )
    resource_usage: ResourceUsageSnapshot | None = Field(
        default=None, description="Active host resource metrics"
    )

    @property
    def formatted_elapsed(self) -> str:
        """Format elapsed duration as HH:MM:SS."""
        secs = int(self.elapsed_seconds)
        hours, remainder = divmod(secs, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def formatted_remaining(self) -> str:
        """Format remaining ETA as HH:MM:SS or 'Unknown'."""
        if self.estimated_remaining_seconds is None:
            return "Calculating..."
        secs = int(self.estimated_remaining_seconds)
        hours, remainder = divmod(secs, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class FileScanRecord(BaseModel):
    """File metadata record preserved in incremental scanning cache."""

    path: str = Field(description="Canonical absolute file path")
    size_bytes: int = Field(ge=0, description="File size in bytes")
    modified_time: float = Field(description="POSIX timestamp of last modification")
    inode: int | None = Field(default=None, description="Filesystem inode number where supported")
    device_id: int | None = Field(default=None, description="Filesystem device ID")
    sha256: str | None = Field(default=None, description="Cached cryptographic SHA-256 digest")
    last_scanned: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Last scan timestamp"
    )
    status: str = Field(
        default="CLEAN", description="Inspection result (CLEAN, SUSPICIOUS, MALWARE, ERROR)"
    )
    findings_count: int = Field(
        default=0, ge=0, description="Number of security findings linked to file"
    )


class ScanCheckpoint(BaseModel):
    """Persistent snapshot capturing scan state for resilient pause/resume operations."""

    checkpoint_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique checkpoint identifier"
    )
    scan_id: str = Field(description="Session UUID of associated scan")
    schema_version: int = Field(default=1, ge=1, description="Checkpoint format schema version")
    scan_type: ScanType = Field(description="Original scan type")
    targets: list[str] = Field(default_factory=list, description="Target directories or paths")
    completed_phases: list[str] = Field(
        default_factory=list, description="Phases completed prior to checkpoint"
    )
    current_phase: str = Field(description="Phase underway when checkpoint was written")
    traversal_cursor: str | None = Field(
        default=None, description="Cursor representing progress within active phase"
    )
    processed_paths: list[str] = Field(
        default_factory=list, description="List of paths already processed"
    )
    progress: ScanProgressEvent = Field(description="Progress metrics at checkpoint moment")
    error_count: int = Field(default=0, ge=0, description="Error counter at checkpoint moment")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Checkpoint generation time"
    )
    last_updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Last update timestamp"
    )
    scan_config: dict[str, Any] = Field(
        default_factory=dict, description="Serialized configuration options"
    )


class ScanHistoryRecord(BaseModel):
    """Persistent ledger record detailing a historical scan execution."""

    scan_id: str = Field(description="Unique scan UUID")
    scan_type: ScanType = Field(description="Scan category executed")
    targets: list[str] = Field(default_factory=list, description="Target paths or scopes")
    status: ScanState = Field(description="Terminal execution status")
    started_at: datetime = Field(description="Execution start timestamp")
    ended_at: datetime | None = Field(default=None, description="Execution completion timestamp")
    duration_seconds: float = Field(
        default=0.0, ge=0.0, description="Total elapsed runtime in seconds"
    )
    items_discovered: int = Field(default=0, ge=0, description="Total items discovered")
    items_processed: int = Field(default=0, ge=0, description="Total items inspected")
    items_skipped: int = Field(default=0, ge=0, description="Total items skipped")
    items_failed: int = Field(default=0, ge=0, description="Total items encountering errors")
    bytes_processed: int = Field(default=0, ge=0, description="Total data volume scanned in bytes")
    findings_count: int = Field(default=0, ge=0, description="Total security findings identified")
    modules_executed: list[str] = Field(
        default_factory=list, description="Names of scanner modules executed"
    )
    performance_stats: dict[str, Any] = Field(
        default_factory=dict, description="Throughput, peak memory, and CPU metrics"
    )
    checkpoint_id: str | None = Field(
        default=None, description="Reference to final checkpoint if interrupted"
    )

    @property
    def completed_at(self) -> datetime | None:
        """Alias for ended_at."""
        return self.ended_at
