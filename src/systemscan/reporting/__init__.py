"""Reporting and export subsystem for systemscan.

Provides standardized report generation, executive summaries, finding classification,
privacy redaction, templates, cryptographic checksum manifests, and multi-format exports (JSON, CSV, TXT).
"""

from systemscan.reporting.exporter import ReportExporter
from systemscan.reporting.findings import FindingNormalizer
from systemscan.reporting.formats.csv_export import CSVReportExporter
from systemscan.reporting.formats.json_export import JSONReportExporter
from systemscan.reporting.formats.txt_export import TextReportExporter
from systemscan.reporting.generator import ReportGenerator
from systemscan.reporting.models import (
    REPORT_SCHEMA_VERSION,
    ConfidenceSummary,
    ErrorRecord,
    ExecutiveSummary,
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    OverallScanResult,
    ReportFormat,
    ReportMetadata,
    ScanReport,
    ScanStatistics,
    SeveritySummary,
    SystemSummary,
)
from systemscan.reporting.redaction import RedactionPolicy, ReportRedactor
from systemscan.reporting.storage import ReportStorageManager
from systemscan.reporting.summary import ExecutiveSummaryBuilder
from systemscan.reporting.templates.compact import CompactTemplate
from systemscan.reporting.templates.executive import ExecutiveTemplate
from systemscan.reporting.templates.technical import TechnicalTemplate
from systemscan.reporting.validator import ReportValidationError, ReportValidator

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "CSVReportExporter",
    "CompactTemplate",
    "ConfidenceSummary",
    "ErrorRecord",
    "ExecutiveSummary",
    "ExecutiveSummaryBuilder",
    "ExecutiveTemplate",
    "FindingConfidence",
    "FindingNormalizer",
    "FindingRecord",
    "FindingSeverity",
    "JSONReportExporter",
    "OverallScanResult",
    "RedactionPolicy",
    "ReportExporter",
    "ReportFormat",
    "ReportGenerator",
    "ReportMetadata",
    "ReportRedactor",
    "ReportStorageManager",
    "ReportValidationError",
    "ReportValidator",
    "ScanReport",
    "ScanStatistics",
    "SeveritySummary",
    "SystemSummary",
    "TechnicalTemplate",
    "TextReportExporter",
]
