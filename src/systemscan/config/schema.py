"""Configuration schema definitions for systemscan."""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from systemscan.core.constants import (
    CONFIG_SCHEMA_VERSION,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_REMOVABLE_POLICY,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_WORKER_COUNT,
    LogLevel,
    UpdateChannel,
)


class AppPreferences(BaseModel):
    """Application user preferences."""

    debug: bool = Field(default=False, description="Enable diagnostic debugging mode")
    verbose: bool = Field(default=False, description="Enable verbose terminal output")
    color_output: bool = Field(default=True, description="Enable ANSI color terminal output")
    interactive_banner: bool = Field(
        default=True, description="Show startup banner on interactive launch"
    )
    include_hardware_serials: bool = Field(
        default=False,
        description="Include sensitive hardware serial numbers in inspection output",
    )


class ScannerConfig(BaseModel):
    """Configuration for scanner modules."""

    worker_count: int = Field(
        default=DEFAULT_WORKER_COUNT, ge=1, le=64, description="Parallel worker process count"
    )
    max_file_size_mb: int = Field(
        default=DEFAULT_MAX_FILE_SIZE_MB,
        ge=1,
        le=10240,
        description="Max file size in MB to inspect",
    )
    timeout_seconds: int = Field(
        default=DEFAULT_TIMEOUT_SECONDS, ge=10, le=86400, description="Operation timeout in seconds"
    )
    removable_device_policy: str = Field(
        default=DEFAULT_REMOVABLE_POLICY,
        description="Policy for removable media: prompt, ignore, scan",
    )
    exclusions: list[str] = Field(
        default_factory=lambda: [
            "/proc",
            "/sys",
            "/dev",
            "C:\\$Recycle.Bin",
            "C:\\System Volume Information",
            ".git",
            "node_modules",
            "__pycache__",
        ],
        description="Default paths and pattern exclusions",
    )

    @field_validator("removable_device_policy")
    @classmethod
    def validate_policy(cls, v: str) -> str:
        valid = {"prompt", "ignore", "scan"}
        if v.lower() not in valid:
            raise ValueError(f"Invalid removable_device_policy: {v}. Must be one of {valid}")
        return v.lower()


class UpdateConfig(BaseModel):
    """Configuration for application update management."""

    enabled: bool = Field(default=True, description="Enable update checking and transactions")
    channel: UpdateChannel = Field(
        default=UpdateChannel.STABLE, description="Release update channel"
    )
    update_source: str = Field(
        default="https://api.github.com/repos/Shadab-2604/sscli/releases",
        description="Remote source URL for updates",
    )
    auto_check: bool = Field(default=False, description="Check for updates on launch")
    auto_install: bool = Field(default=False, description="Automatically install approved updates")
    verify_signatures: bool = Field(
        default=True, description="Cryptographically verify update manifests and checksums"
    )
    backup_before_update: bool = Field(
        default=True, description="Create backup snapshot before applying updates"
    )
    rollback_enabled: bool = Field(
        default=True, description="Allow automatic rollback on failed updates"
    )
    max_backups: int = Field(default=3, ge=1, le=20, description="Maximum update backups to retain")


class DependencyConfig(BaseModel):
    """Configuration for dependency discovery and installation."""

    auto_install: bool = Field(
        default=False, description="Automatically install missing dependencies"
    )
    allow_global_install: bool = Field(
        default=False, description="Allow installation outside virtual environments"
    )
    prefer_lockfile: bool = Field(default=True, description="Prefer pinned versions from lockfiles")
    index_url: str | None = Field(default=None, description="Custom trusted package index URL")


class PerformanceConfig(BaseModel):
    """Configuration for concurrency and resource management."""

    mode: str = Field(
        default="adaptive", description="Concurrency mode: adaptive, fixed, sequential"
    )
    max_workers: int = Field(
        default=4, ge=1, le=64, description="Maximum concurrent worker threads"
    )
    adaptive_concurrency: bool = Field(
        default=True, description="Dynamically tune workers to system load"
    )
    max_memory_percent: float = Field(
        default=75.0, ge=10.0, le=95.0, description="Memory throttle ceiling %"
    )
    max_cpu_percent: float = Field(
        default=85.0, ge=10.0, le=100.0, description="CPU throttle ceiling %"
    )
    progress_refresh_interval: float = Field(
        default=1.0, ge=0.1, le=10.0, description="Progress update interval in seconds"
    )


class IncrementalConfig(BaseModel):
    """Configuration for incremental scanning and change detection."""

    enabled: bool = Field(default=True, description="Enable metadata-based incremental caching")
    verification_mode: str = Field(
        default="balanced", description="Verification mode: fast, balanced, thorough"
    )
    periodic_hash_verification: bool = Field(
        default=True, description="Periodically re-evaluate hashes of aging records"
    )


class CheckpointConfig(BaseModel):
    """Configuration for persistent scan checkpoints."""

    enabled: bool = Field(default=True, description="Enable persistent scan checkpoints")
    interval_seconds: int = Field(
        default=30, ge=5, le=3600, description="Auto-checkpoint interval in seconds"
    )
    retention_count: int = Field(
        default=10, ge=1, le=100, description="Maximum checkpoints to retain"
    )


class HistoryConfig(BaseModel):
    """Configuration for scan history tracking and retention."""

    enabled: bool = Field(default=True, description="Enable scan history session persistence")
    retention_days: int = Field(
        default=90, ge=1, le=3650, description="Days to retain scan history records"
    )


class ReportingConfig(BaseModel):
    """Configuration for scan report generation, formats, and retention."""

    default_format: str = Field(
        default="json", description="Default report export format: json, csv, txt"
    )
    auto_generate: bool = Field(
        default=True, description="Automatically generate report upon scan completion"
    )
    retention_days: int = Field(
        default=90, ge=1, le=3650, description="Days to retain generated report files"
    )
    redact_by_default: bool = Field(
        default=False, description="Redact sensitive data in exports by default"
    )
    generate_checksums: bool = Field(
        default=True, description="Generate SHA-256 checksum manifests alongside reports"
    )


class SystemScanConfig(BaseModel):
    """Root configuration model for systemscan."""

    schema_version: int = Field(
        default=CONFIG_SCHEMA_VERSION, description="Configuration schema version"
    )
    preferences: AppPreferences = Field(default_factory=AppPreferences)
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Global logging level")
    custom_report_dir: str | None = Field(
        default=None, description="Custom directory for scan reports"
    )
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    update: UpdateConfig = Field(default_factory=UpdateConfig)
    updates: UpdateConfig = Field(default_factory=UpdateConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    incremental: IncrementalConfig = Field(default_factory=IncrementalConfig)
    checkpoint: CheckpointConfig = Field(default_factory=CheckpointConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    dependencies: DependencyConfig = Field(default_factory=DependencyConfig)
    modules: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Module-specific configuration sections"
    )
