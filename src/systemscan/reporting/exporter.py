"""Unified export coordinator dispatching reports across formats and destinations."""

from __future__ import annotations

from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.reporting.models import ReportFormat, ScanReport
from systemscan.reporting.redaction import RedactionPolicy, ReportRedactor
from systemscan.reporting.storage import ReportStorageManager
from systemscan.reporting.validator import ReportValidator

logger = get_logger("reporting.exporter")


class ReportExporter:
    """Coordinates format selection, redaction, and atomic disk persistence."""

    def __init__(self, storage_manager: ReportStorageManager | None = None) -> None:
        self.storage_manager = storage_manager or ReportStorageManager()

    def export(
        self,
        report: ScanReport,
        fmt: ReportFormat | str = ReportFormat.JSON,
        output_path: Path | None = None,
        overwrite: bool = False,
        redact: bool = False,
        redaction_policy: RedactionPolicy | None = None,
        generate_checksum: bool = True,
        txt_style: str = "technical",
    ) -> Path:
        """Export report with optional privacy redaction and integrity checksum."""
        # Convert format representation safely
        target_fmt: ReportFormat
        if isinstance(fmt, ReportFormat):
            target_fmt = fmt
        elif hasattr(fmt, "value"):
            target_fmt = ReportFormat(str(fmt.value).lower().strip())
        else:
            raw_str = str(fmt).lower().strip()
            if "." in raw_str:
                raw_str = raw_str.split(".")[-1]
            target_fmt = ReportFormat(raw_str)

        # Validate source report integrity
        ReportValidator.assert_valid(report)

        # Apply redaction if requested (on a deep copy)
        export_target_report = report
        if redact:
            redactor = ReportRedactor(policy=redaction_policy)
            export_target_report = redactor.redact_report(report)

        # Persist report via storage manager
        saved_path = self.storage_manager.save_report(
            report=export_target_report,
            fmt=target_fmt,
            custom_path=output_path,
            overwrite=overwrite,
            generate_checksum=generate_checksum,
            txt_style=txt_style,
        )

        logger.info(f"Report exported successfully to '{saved_path}' ({target_fmt.value.upper()})")
        return saved_path
