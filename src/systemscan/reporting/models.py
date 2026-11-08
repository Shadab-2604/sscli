"""Pydantic data models, enumerations, and schemas for the centralized Reporting & Export Engine."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from systemscan.engine.models import ScanState, ScanType
from systemscan.version import APP_NAME, __version__

REPORT_SCHEMA_VERSION = "1.0"


class ReportFormat(str, Enum):
    """Supported export and presentation formats."""

    JSON = "json"
    CSV = "csv"
    TXT = "txt"


class FindingSeverity(str, Enum):
    """Calibrated security finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, Enum):
    """Evidence-based confidence rating for findings."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class OverallScanResult(str, Enum):
    """Calculated overall security and inspection posture status."""

    NO_HIGH_PRIORITY_FINDINGS = "NO_HIGH_PRIORITY_FINDINGS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


class ReportMetadata(BaseModel):
    """Metadata regarding report creation, provenance, and redaction flags."""

    report_id: str = Field(
        default_factory=lambda: f"rep-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for this generated report",
    )
    scan_id: str = Field(description="Associated scan session identifier")
    scan_type: ScanType = Field(description="Classification of scan performed")
    scan_status: ScanState = Field(description="Terminal status of scan")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when report was generated",
    )
    generator_name: str = Field(default=APP_NAME, description="Application generating report")
    generator_version: str = Field(default=__version__, description="Application version")
    schema_version: str = Field(default=REPORT_SCHEMA_VERSION, description="Report schema version")
    is_redacted: bool = Field(
        default=False, description="Whether sensitive data has been sanitized"
    )
    redaction_policy: list[str] = Field(
        default_factory=list, description="Categories of redaction applied"
    )


class SystemSummary(BaseModel):
    """High-level snapshot of inspected host environment."""

    hostname: str = Field(default="unknown", description="Host machine name")
    os_name: str = Field(default="unknown", description="Operating system family")
    os_version: str = Field(default="unknown", description="Operating system release or build")
    kernel: str = Field(default="unknown", description="Kernel release version")
    architecture: str = Field(default="unknown", description="CPU instruction architecture")
    cpu_model: str = Field(default="unknown", description="Processor model name")
    cpu_physical_cores: int | None = Field(default=None, description="Physical CPU cores")
    cpu_logical_cores: int | None = Field(default=None, description="Logical CPU cores")
    ram_total_mb: float | None = Field(default=None, description="Total physical RAM in MB")
    primary_ip: str | None = Field(default=None, description="Primary active IP address")
    default_gateway: str | None = Field(default=None, description="Default network gateway")


class ScanStatistics(BaseModel):
    """Telemetry, rates, volume, and performance statistics for a scan."""

    duration_seconds: float = Field(default=0.0, ge=0.0, description="Total elapsed scan duration")
    items_discovered: int = Field(default=0, ge=0, description="Total items enumerated")
    items_processed: int = Field(default=0, ge=0, description="Total items inspected")
    items_skipped: int = Field(default=0, ge=0, description="Unchanged items skipped via cache")
    bytes_processed: int = Field(default=0, ge=0, description="Total volume processed in bytes")
    directories_inspected: int = Field(
        default=0, ge=0, description="Directories traversed where applicable"
    )
    errors_count: int = Field(default=0, ge=0, description="Total non-fatal errors encountered")
    findings_count: int = Field(default=0, ge=0, description="Total security findings discovered")
    average_throughput_items_sec: float = Field(
        default=0.0, ge=0.0, description="Average item throughput rate"
    )
    average_throughput_mb_sec: float = Field(
        default=0.0, ge=0.0, description="Average data throughput in MB/sec"
    )


class SeveritySummary(BaseModel):
    """Aggregate tally of security findings categorized by severity."""

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)


class ConfidenceSummary(BaseModel):
    """Aggregate tally of security findings categorized by evidence confidence."""

    confirmed: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)


class FindingRecord(BaseModel):
    """Standardized representation of a single security or intelligence finding."""

    finding_id: str = Field(
        default_factory=lambda: f"fnd-{uuid.uuid4().hex[:8]}",
        description="Unique finding identifier",
    )
    title: str = Field(description="Brief headline describing the observation")
    category: str = Field(description="Domain category: MALWARE, NETWORK, STORAGE, SYSTEM, etc.")
    severity: FindingSeverity = Field(description="Risk severity level")
    confidence: FindingConfidence = Field(description="Evidence reliability confidence level")
    description: str = Field(description="Detailed explanation of finding")
    evidence: str = Field(description="Factual, verifiable technical evidence")
    target: str = Field(
        description="Affected resource: file path, socket, interface, process, host, etc."
    )
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when finding was detected",
    )
    source_module: str = Field(description="Originating scanner or analysis module")
    remediation: str | None = Field(default=None, description="Recommended mitigation action")


class ErrorRecord(BaseModel):
    """Structured record of an operational failure or limitation encountered during scan."""

    error_id: str = Field(
        default_factory=lambda: f"err-{uuid.uuid4().hex[:8]}",
        description="Unique error identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when error occurred",
    )
    source_module: str = Field(description="Module encountering error")
    error_type: str = Field(description="Exception or category classification")
    message: str = Field(description="Descriptive diagnostic message")
    target: str | None = Field(default=None, description="Path or resource that failed")


class ExecutiveSummary(BaseModel):
    """Concise executive overview of scan results, security posture, and recommendations."""

    scan_id: str
    scan_type: ScanType
    scan_status: ScanState
    system_identifier: str
    os_description: str
    start_time: datetime
    completion_time: datetime
    duration_seconds: float
    items_analyzed: int
    data_processed_bytes: int
    items_skipped: int
    errors_count: int
    severity_summary: SeveritySummary
    confidence_summary: ConfidenceSummary
    overall_result: OverallScanResult
    critical_observations: list[str] = Field(default_factory=list)
    high_priority_recommendations: list[str] = Field(default_factory=list)
    completeness_percent: float = Field(default=100.0, ge=0.0, le=100.0)


class ScanReport(BaseModel):
    """Root document encapsulating all standardized scan data, findings, and module telemetry."""

    schema_version: str = Field(default=REPORT_SCHEMA_VERSION)
    metadata: ReportMetadata
    system_info: SystemSummary
    statistics: ScanStatistics
    executive_summary: ExecutiveSummary
    findings: list[FindingRecord] = Field(default_factory=list)
    errors: list[ErrorRecord] = Field(default_factory=list)
    modules_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific structured data (network details, storage breakdowns, etc.)",
    )

    @property
    def system_summary(self) -> SystemSummary:
        """Alias for system_info."""
        return self.system_info
