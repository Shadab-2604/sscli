"""Report schema validation and cryptographic integrity verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

from systemscan.reporting.models import REPORT_SCHEMA_VERSION, ScanReport


class ReportValidationError(Exception):
    """Raised when a report violates schema constraints or internal consistency."""


class ReportValidator:
    """Validates report structures, internal metric consistency, and cryptographic file checksums."""

    @classmethod
    def validate_report(cls, report: ScanReport) -> list[str]:
        """Verify internal consistency and data contract conformance of a ScanReport."""
        errors: list[str] = []

        if report.schema_version != REPORT_SCHEMA_VERSION:
            errors.append(
                f"Unsupported schema version: '{report.schema_version}'. Expected '{REPORT_SCHEMA_VERSION}'."
            )

        if not report.metadata.report_id:
            errors.append("Report metadata is missing required 'report_id'.")
        if not report.metadata.scan_id:
            errors.append("Report metadata is missing required 'scan_id'.")

        # Verify summary counts match actual findings count
        sev = report.executive_summary.severity_summary
        actual_total = len(report.findings)
        if sev.total != actual_total:
            errors.append(
                f"Severity summary total ({sev.total}) does not match actual findings count ({actual_total})."
            )

        actual_critical = sum(1 for f in report.findings if f.severity.value == "CRITICAL")
        if sev.critical != actual_critical:
            errors.append(
                f"Severity summary critical count ({sev.critical}) does not match actual critical findings ({actual_critical})."
            )

        # Verify timestamp chronology
        if report.executive_summary.start_time > report.executive_summary.completion_time:
            errors.append("Executive summary start_time cannot be after completion_time.")

        # Verify each finding
        for idx, f in enumerate(report.findings):
            if not f.title or not f.title.strip():
                errors.append(f"Finding [{idx}] is missing a valid title.")
            if not f.target or not f.target.strip():
                errors.append(f"Finding [{idx}] is missing a target resource identifier.")

        return errors

    @classmethod
    def assert_valid(cls, report: ScanReport) -> None:
        """Validate report and raise ReportValidationError if violations are found."""
        issues = cls.validate_report(report)
        if issues:
            raise ReportValidationError(
                f"Report '{report.metadata.report_id}' failed validation: {'; '.join(issues)}"
            )

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Compute SHA-256 digest of a report file using streaming 64 KB chunk reads."""
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def create_checksum_manifest(cls, file_path: Path) -> Path:
        """Write a standard .sha256 checksum manifest alongside the target report file."""
        digest = cls.compute_sha256(file_path)
        manifest_path = file_path.with_suffix(file_path.suffix + ".sha256")
        manifest_path.write_text(f"{digest}  {file_path.name}\n", encoding="utf-8")
        return manifest_path

    @classmethod
    def verify_checksum_manifest(cls, file_path: Path) -> bool:
        """Verify report file integrity against its .sha256 manifest."""
        manifest_path = file_path.with_suffix(file_path.suffix + ".sha256")
        if not manifest_path.exists():
            return False

        line = manifest_path.read_text(encoding="utf-8").strip()
        parts = line.split()
        if not parts:
            return False
        expected_digest = parts[0]
        actual_digest = cls.compute_sha256(file_path)
        return expected_digest.lower() == actual_digest.lower()
