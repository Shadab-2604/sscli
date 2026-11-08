"""Pydantic models, enums, and data contracts for the filesystem engine."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from systemscan.utils.formatting import format_bytes


class FileType(str, Enum):
    """Classification of filesystem node types."""

    REGULAR_FILE = "regular_file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    SOCKET = "socket"
    FIFO = "fifo"
    BLOCK_DEVICE = "block_device"
    CHARACTER_DEVICE = "character_device"
    OTHER = "other"


class SymlinkPolicy(str, Enum):
    """Policies for handling symbolic links during filesystem traversal."""

    IGNORE = "ignore"
    RECORD_NO_FOLLOW = "record_no_follow"
    FOLLOW_SAFE = "follow_safe"


class ScanStatus(str, Enum):
    """Lifecycle status of a filesystem scan execution."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ErrorCategory(str, Enum):
    """Categories of filesystem errors encountered during inspection."""

    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    IO_ERROR = "io_error"
    PATH_TOO_LONG = "path_too_long"
    SYMLINK_LOOP = "symlink_loop"
    FILE_LOCKED = "file_locked"
    UNSUPPORTED = "unsupported"


class FileMetadata(BaseModel):
    """Structured, immutable metadata describing an individual file system entry."""

    path: str = Field(description="Canonical absolute path to the file.")
    name: str = Field(description="Filename with extension.")
    extension: str = Field(default="", description="Lowercased file extension with dot prefix.")
    size_bytes: int = Field(default=0, ge=0, description="Size in bytes.")
    created_time: datetime | None = Field(default=None, description="Creation timestamp.")
    modified_time: datetime | None = Field(default=None, description="Last modification timestamp.")
    accessed_time: datetime | None = Field(default=None, description="Last access timestamp.")
    inode: int | None = Field(default=None, description="Filesystem inode or unique identifier.")
    permissions_mode: int | None = Field(default=None, description="Raw integer st_mode bitfield.")
    permissions_str: str = Field(
        default="", description="Human-readable POSIX or Windows attribute string."
    )
    owner: str | None = Field(default=None, description="File owner user name or SID.")
    group: str | None = Field(default=None, description="File owner group name or SID.")
    is_hidden: bool = Field(default=False, description="Whether the file is marked hidden.")
    is_executable: bool = Field(default=False, description="Whether the file has execution bits.")
    is_readonly: bool = Field(default=False, description="Whether the file is write-protected.")
    is_symlink: bool = Field(default=False, description="Whether the entry is a symbolic link.")
    symlink_target: str | None = Field(default=None, description="Target destination if symlink.")
    file_type: FileType = Field(
        default=FileType.REGULAR_FILE, description="Filesystem node type classification."
    )
    device_id: int | None = Field(default=None, description="Device identifier hosting the file.")
    relative_path: str | None = Field(
        default=None, description="Path relative to scan root if applicable."
    )

    @property
    def size_formatted(self) -> str:
        """Return human-readable byte representation (KB, MB, GB, etc.)."""
        return format_bytes(self.size_bytes)


class DirectoryMetadata(BaseModel):
    """Metadata describing a traversed filesystem directory."""

    path: str = Field(description="Canonical absolute path of the directory.")
    name: str = Field(description="Directory folder name.")
    parent_path: str | None = Field(default=None, description="Parent folder path.")
    created_time: datetime | None = Field(default=None, description="Creation timestamp.")
    modified_time: datetime | None = Field(default=None, description="Last modification timestamp.")
    permissions_mode: int | None = Field(default=None, description="Raw integer st_mode.")
    permissions_str: str = Field(default="", description="Permissions string representation.")
    owner: str | None = Field(default=None, description="Directory owner user or SID.")
    group: str | None = Field(default=None, description="Directory group name or SID.")
    is_hidden: bool = Field(default=False, description="Whether directory is hidden.")
    depth: int = Field(default=0, ge=0, description="Directory nesting depth from scan root.")
    child_count: int | None = Field(
        default=None, ge=0, description="Immediate children count if enumerated."
    )


class FilesystemErrorRecord(BaseModel):
    """Record of an isolated error or permission denial encountered during traversal."""

    path: str = Field(description="Filesystem path where error occurred.")
    category: ErrorCategory = Field(description="Categorized classification of the error.")
    message: str = Field(description="Detailed error message.")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Timestamp when error was captured."
    )
    operation: str = Field(
        default="scandir", description="Filesystem operation attempted (e.g. stat, scandir)."
    )
    retry_appropriate: bool = Field(
        default=False, description="Whether retry could succeed under different conditions."
    )


class FilesystemRootInfo(BaseModel):
    """Metadata describing a mounted filesystem root or logical storage drive."""

    path: str = Field(description="Root mountpoint or logical drive path (e.g. / or C:\\).")
    name: str = Field(description="Descriptive root label or volume name.")
    filesystem_type: str = Field(
        default="unknown", description="Filesystem format (ext4, NTFS, APFS, etc.)."
    )
    is_removable: bool = Field(default=False, description="Whether volume is removable USB/media.")
    is_network: bool = Field(
        default=False, description="Whether volume is network-mounted (NFS/SMB)."
    )
    is_readonly: bool = Field(default=False, description="Whether root is mounted read-only.")
    is_virtual: bool = Field(
        default=False, description="Whether root is pseudo/virtual (proc, sysfs, devtmpfs)."
    )
    total_bytes: int | None = Field(default=None, description="Total capacity in bytes.")
    free_bytes: int | None = Field(default=None, description="Free available capacity in bytes.")

    @property
    def total_formatted(self) -> str:
        return format_bytes(self.total_bytes or 0)

    @property
    def free_formatted(self) -> str:
        return format_bytes(self.free_bytes or 0)


class ScanStatistics(BaseModel):
    """Aggregated counters and telemetry metrics for a filesystem scan run."""

    directories_discovered: int = Field(default=0, ge=0)
    directories_scanned: int = Field(default=0, ge=0)
    files_discovered: int = Field(default=0, ge=0)
    files_scanned: int = Field(default=0, ge=0)
    hidden_files: int = Field(default=0, ge=0)
    hidden_directories: int = Field(default=0, ge=0)
    symlinks_discovered: int = Field(default=0, ge=0)
    broken_links: int = Field(default=0, ge=0)
    special_entries: int = Field(default=0, ge=0)
    skipped_paths: int = Field(default=0, ge=0)
    excluded_paths: int = Field(default=0, ge=0)
    permission_errors: int = Field(default=0, ge=0)
    io_errors: int = Field(default=0, ge=0)
    total_accessible_bytes: int = Field(default=0, ge=0)
    scan_duration_seconds: float = Field(default=0.0, ge=0.0)
    traversal_speed_files_per_sec: float = Field(default=0.0, ge=0.0)
    current_path: str = Field(default="")
    max_depth_reached: int = Field(default=0, ge=0)

    @property
    def total_size_formatted(self) -> str:
        return format_bytes(self.total_accessible_bytes)


class ExclusionConfig(BaseModel):
    """Filtering and exclusion criteria for filesystem traversal."""

    exclude_paths: list[str] = Field(
        default_factory=list, description="Exact paths or directories to exclude."
    )
    exclude_globs: list[str] = Field(
        default_factory=list, description="Glob patterns matched against filenames and paths."
    )
    exclude_extensions: list[str] = Field(
        default_factory=list, description="File extensions to skip (e.g. ['.iso', '.vmdk'])."
    )
    exclude_filesystems: list[str] = Field(
        default_factory=list, description="Filesystem types to ignore (e.g. ['proc', 'sysfs'])."
    )
    max_file_size_bytes: int | None = Field(
        default=None, description="Optional maximum file size threshold."
    )
    min_file_size_bytes: int | None = Field(
        default=None, description="Optional minimum file size threshold."
    )
    exclude_hidden: bool = Field(
        default=False, description="When true, skip hidden files and folders."
    )
    override_defaults: bool = Field(
        default=False, description="Whether to bypass default system exclusions."
    )


class ScanConfig(BaseModel):
    """Configuration governing filesystem scan execution."""

    roots: list[str] = Field(description="List of target directory or file root paths.")
    max_depth: int | None = Field(
        default=None, ge=0, description="Maximum directory traversal depth from roots."
    )
    include_hidden: bool = Field(
        default=True, description="Whether to discover and inspect hidden files/directories."
    )
    symlink_policy: SymlinkPolicy = Field(
        default=SymlinkPolicy.RECORD_NO_FOLLOW,
        description="Policy for handling symbolic links.",
    )
    exclusions: ExclusionConfig = Field(
        default_factory=ExclusionConfig, description="Exclusion and filtering rules."
    )
    stay_on_filesystem: bool = Field(
        default=True, description="Do not cross mountpoint boundaries during recursive scan."
    )
    buffer_size: int = Field(
        default=1000, ge=10, description="Batch processing buffer size for streaming items."
    )


class ScanSummary(BaseModel):
    """Complete structured summary of a completed or cancelled filesystem scan."""

    scan_id: str = Field(description="Unique scan session identifier.")
    started_at: datetime = Field(description="Scan start timestamp.")
    completed_at: datetime | None = Field(default=None, description="Scan completion timestamp.")
    status: ScanStatus = Field(description="Final terminal scan state.")
    scan_mode: str = Field(description="Scan mode: custom_path, multi_path, or all_volumes.")
    roots: list[str] = Field(description="Target roots scanned.")
    statistics: ScanStatistics = Field(description="Telemetry and counter metrics.")
    errors: list[FilesystemErrorRecord] = Field(
        default_factory=list, description="Isolated filesystem errors encountered."
    )
    exclusions_applied: list[str] = Field(
        default_factory=list, description="List of exclusion rules activated during scan."
    )
