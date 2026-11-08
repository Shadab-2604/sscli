"""Pydantic data models and enumerations for Storage Intelligence & Safe Cleanup (Phase 6)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class CleanupSafetyCategory(str, Enum):
    """Safety classification determining cleanup eligibility."""

    SAFE_CANDIDATE = "SAFE_CANDIDATE"  # Supported cache/temp meeting all safety checks
    REQUIRES_REVIEW = "REQUIRES_REVIEW"  # Uncertain ownership, active app, or user review needed
    PROTECTED = "PROTECTED"  # System-critical, user data, databases; deletion forbidden


class StorageCategory(str, Enum):
    """Categorization of disk usage and cleanup candidates."""

    SYSTEM_CACHE = "system_cache"
    USER_CACHE = "user_cache"
    BROWSER_CACHE = "browser_cache"
    TEMPORARY_FILES = "temporary_files"
    OLD_LOGS = "old_logs"
    DUPLICATE_FILES = "duplicate_files"
    LARGE_FILES = "large_files"
    HIDDEN_FILES = "hidden_files"
    OLD_FILES = "old_files"
    OTHER = "other"


class DiskVolumeOverview(BaseModel):
    """Detailed capacity and usage metrics for a mounted storage volume."""

    mount_point: str = Field(description="Drive letter or POSIX mount directory")
    device: str = Field(description="Physical or logical device node")
    filesystem_type: str = Field(description="Filesystem format (NTFS, ext4, APFS, etc.)")
    total_bytes: int = Field(ge=0, description="Total storage capacity in bytes")
    used_bytes: int = Field(ge=0, description="Used capacity in bytes")
    free_bytes: int = Field(ge=0, description="Free available space in bytes")
    usage_percent: float = Field(ge=0.0, le=100.0, description="Percentage of space utilized")
    is_removable: bool = Field(default=False, description="Whether device is removable media")
    is_readonly: bool = Field(default=False, description="Whether volume is mounted read-only")
    is_low_space: bool = Field(
        default=False, description="Whether free space is beneath warning threshold"
    )

    @property
    def total_formatted(self) -> str:
        return format_bytes(self.total_bytes)

    @property
    def used_formatted(self) -> str:
        return format_bytes(self.used_bytes)

    @property
    def free_formatted(self) -> str:
        return format_bytes(self.free_bytes)


class LargeFileRecord(BaseModel):
    """Record describing a file exceeding configured size thresholds."""

    path: str = Field(description="Normalized absolute file path")
    name: str = Field(description="File basename")
    size_bytes: int = Field(ge=0, description="File size in bytes")
    extension: str = Field(default="", description="File extension")
    modified_at: datetime = Field(description="Last modification timestamp")
    is_hidden: bool = Field(default=False, description="Whether file is marked hidden")
    volume: str = Field(description="Associated mount point or drive letter")

    @property
    def size_formatted(self) -> str:
        return format_bytes(self.size_bytes)


class LargeDirectoryRecord(BaseModel):
    """Record describing an aggregated directory size."""

    path: str = Field(description="Normalized absolute directory path")
    name: str = Field(description="Directory basename")
    size_bytes: int = Field(ge=0, description="Total aggregated size of contained files in bytes")
    file_count: int = Field(ge=0, description="Total count of files in subtree")
    depth: int = Field(ge=0, description="Nesting depth from scan root")
    is_hidden: bool = Field(default=False, description="Whether directory is hidden")

    @property
    def size_formatted(self) -> str:
        return format_bytes(self.size_bytes)


class DuplicateGroup(BaseModel):
    """Group of files confirmed to share identical contents via verified cryptographic hash."""

    sha256: str = Field(description="Verified SHA-256 digest")
    file_size_bytes: int = Field(ge=0, description="Size of each individual file copy")
    copy_count: int = Field(ge=2, description="Number of duplicate copies discovered")
    paths: list[str] = Field(description="List of file paths sharing this exact content")
    total_group_bytes: int = Field(ge=0, description="Total size consumed by all copies")
    reclaimable_bytes: int = Field(
        ge=0, description="Reclaimable space if all but 1 copy were removed"
    )

    @property
    def file_size_formatted(self) -> str:
        return format_bytes(self.file_size_bytes)

    @property
    def reclaimable_formatted(self) -> str:
        return format_bytes(self.reclaimable_bytes)


class ExtensionStat(BaseModel):
    """Aggregated statistics for a specific file extension."""

    extension: str = Field(description="File extension or '(no extension)'")
    file_count: int = Field(ge=0, description="Total count of files with this extension")
    total_bytes: int = Field(ge=0, description="Total bytes consumed")
    average_bytes: int = Field(ge=0, description="Average size per file in bytes")
    largest_file_bytes: int = Field(ge=0, description="Size of largest file encountered")
    percentage_of_total: float = Field(ge=0.0, le=100.0, description="Storage share percentage")

    @property
    def total_formatted(self) -> str:
        return format_bytes(self.total_bytes)


class BrowserCacheRecord(BaseModel):
    """Detected web browser profile and associated cache storage."""

    browser_name: str = Field(description="Browser identity (Chrome, Edge, Firefox, Brave, etc.)")
    profile_name: str = Field(default="Default", description="Browser user profile")
    cache_path: str = Field(description="Absolute path to cache directory")
    size_bytes: int = Field(ge=0, description="Total cache size in bytes")
    file_count: int = Field(ge=0, description="Total files in cache directory")
    last_modified: datetime | None = Field(
        default=None, description="Most recent cache entry timestamp"
    )
    is_browser_running: bool = Field(
        default=False, description="Whether browser process is currently running"
    )

    @property
    def size_formatted(self) -> str:
        return format_bytes(self.size_bytes)


class CleanupCandidate(BaseModel):
    """An individual file evaluated for safe storage reclamation."""

    candidate_id: str = Field(description="Unique candidate UUID")
    path: str = Field(description="Normalized absolute file path")
    size_bytes: int = Field(ge=0, description="Reclaimable size in bytes")
    modified_at: datetime = Field(description="Last modified timestamp")
    category: StorageCategory = Field(description="Cleanup category")
    safety: CleanupSafetyCategory = Field(description="Safety classification")
    reason: str = Field(description="Technical rationale for identification")
    can_delete: bool = Field(
        default=False, description="Whether candidate meets all safety gates for deletion"
    )


class CleanupPreview(BaseModel):
    """Aggregated pre-execution preview of reclaimable storage."""

    preview_id: str = Field(description="Unique preview UUID")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Timestamp generated"
    )
    category_counts: dict[str, int] = Field(
        default_factory=dict, description="File counts per category"
    )
    category_bytes: dict[str, int] = Field(
        default_factory=dict, description="Reclaimable bytes per category"
    )
    total_files: int = Field(default=0, ge=0, description="Total candidate files evaluated")
    total_reclaimable_bytes: int = Field(
        default=0, ge=0, description="Total space in bytes eligible for safe reclamation"
    )
    protected_count: int = Field(
        default=0, ge=0, description="Total protected files identified (skipped)"
    )
    protected_bytes: int = Field(default=0, ge=0, description="Total protected bytes (skipped)")
    review_required_count: int = Field(
        default=0, ge=0, description="Items requiring human confirmation (skipped by default)"
    )
    review_required_bytes: int = Field(
        default=0, ge=0, description="Bytes requiring human confirmation"
    )
    candidates: list[CleanupCandidate] = Field(
        default_factory=list, description="Full candidate ledger"
    )

    @property
    def total_reclaimable_formatted(self) -> str:
        return format_bytes(self.total_reclaimable_bytes)


class CleanupAuditRecord(BaseModel):
    """Immutable audit record logging execution of a cleanup operation."""

    operation_id: str = Field(description="Unique operation UUID")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Execution timestamp"
    )
    user_authorized: bool = Field(description="Whether operator explicitly confirmed deletion")
    dry_run: bool = Field(default=False, description="Whether operation was a simulated dry-run")
    selected_categories: list[str] = Field(
        default_factory=list, description="Approved cleanup categories"
    )
    deleted_files_count: int = Field(default=0, ge=0, description="Count of files safely deleted")
    skipped_files_count: int = Field(
        default=0, ge=0, description="Count of files skipped due to safety checks"
    )
    failed_files_count: int = Field(default=0, ge=0, description="Count of files failing deletion")
    actual_reclaimed_bytes: int = Field(
        default=0, ge=0, description="Actual measured storage freed in bytes"
    )
    errors: list[dict[str, str]] = Field(
        default_factory=list, description="Error messages with associated paths"
    )
    status: str = Field(
        default="COMPLETED",
        description="Final status ('COMPLETED', 'PARTIAL', 'CANCELLED', 'DRY_RUN')",
    )

    @property
    def actual_reclaimed_formatted(self) -> str:
        return format_bytes(self.actual_reclaimed_bytes)


def format_bytes(num_bytes: int) -> str:
    """Format integer bytes into standard human-readable units."""
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(num_bytes)
    idx = 0
    while val >= 1024.0 and idx < len(units) - 1:
        val /= 1024.0
        idx += 1
    return f"{val:.1f} {units[idx]}"
