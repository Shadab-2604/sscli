"""CSV format report exporter for spreadsheets, data pipelines, and analytics."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from systemscan.reporting.models import ScanReport


class CSVReportExporter:
    """Exports structured scan findings, executive summaries, and errors to RFC 4180 CSV."""

    @classmethod
    def export_findings_csv(cls, report: ScanReport) -> str:
        """Serialize security findings into CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        writer.writerow(
            [
                "finding_id",
                "scan_id",
                "title",
                "category",
                "severity",
                "confidence",
                "target",
                "detected_at",
                "source_module",
                "description",
                "evidence",
                "remediation",
            ]
        )

        for f in report.findings:
            writer.writerow(
                [
                    f.finding_id,
                    report.metadata.scan_id,
                    f.title,
                    f.category,
                    f.severity.value,
                    f.confidence.value,
                    f.target,
                    f.detected_at.isoformat(),
                    f.source_module,
                    f.description,
                    f.evidence,
                    f.remediation or "",
                ]
            )

        return output.getvalue()

    @classmethod
    def export_summary_csv(cls, report: ScanReport) -> str:
        """Serialize executive and system summary into a tabular CSV record."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        s = report.executive_summary
        sev = s.severity_summary

        writer.writerow(
            [
                "report_id",
                "scan_id",
                "scan_type",
                "status",
                "system_identifier",
                "os_description",
                "start_time",
                "completion_time",
                "duration_seconds",
                "items_analyzed",
                "data_processed_bytes",
                "items_skipped",
                "errors_count",
                "critical_findings",
                "high_findings",
                "medium_findings",
                "low_findings",
                "info_findings",
                "total_findings",
                "overall_result",
                "completeness_percent",
            ]
        )

        writer.writerow(
            [
                report.metadata.report_id,
                s.scan_id,
                s.scan_type.value,
                s.scan_status.value,
                s.system_identifier,
                s.os_description,
                s.start_time.isoformat(),
                s.completion_time.isoformat(),
                round(s.duration_seconds, 2),
                s.items_analyzed,
                s.data_processed_bytes,
                s.items_skipped,
                s.errors_count,
                sev.critical,
                sev.high,
                sev.medium,
                sev.low,
                sev.info,
                sev.total,
                s.overall_result.value,
                s.completeness_percent,
            ]
        )

        return output.getvalue()

    @classmethod
    def export_errors_csv(cls, report: ScanReport) -> str:
        """Serialize operational errors and permission limits into CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        writer.writerow(
            [
                "error_id",
                "scan_id",
                "timestamp",
                "source_module",
                "error_type",
                "message",
                "target",
            ]
        )

        for e in report.errors:
            writer.writerow(
                [
                    e.error_id,
                    report.metadata.scan_id,
                    e.timestamp.isoformat(),
                    e.source_module,
                    e.error_type,
                    e.message,
                    e.target or "",
                ]
            )

        return output.getvalue()

    @classmethod
    def export_to_file(cls, report: ScanReport, output_path: Path) -> Path:
        """Write findings CSV to destination path atomically."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = output_path.with_suffix(".tmp")
        payload = cls.export_findings_csv(report)
        tmp_path.write_text(payload, encoding="utf-8-sig")
        tmp_path.replace(output_path)
        return output_path

    @classmethod
    def export_bundle_to_dir(cls, report: ScanReport, target_dir: Path) -> dict[str, Path]:
        """Export findings, summary, and error CSV tables into a directory."""
        target_dir.mkdir(parents=True, exist_ok=True)
        results: dict[str, Path] = {}

        # 1. Summary CSV
        summary_path = target_dir / f"{report.metadata.report_id}_summary.csv"
        summary_tmp = summary_path.with_suffix(".tmp")
        summary_tmp.write_text(cls.export_summary_csv(report), encoding="utf-8-sig")
        summary_tmp.replace(summary_path)
        results["summary"] = summary_path

        # 2. Findings CSV
        findings_path = target_dir / f"{report.metadata.report_id}_findings.csv"
        findings_tmp = findings_path.with_suffix(".tmp")
        findings_tmp.write_text(cls.export_findings_csv(report), encoding="utf-8-sig")
        findings_tmp.replace(findings_path)
        results["findings"] = findings_path

        # 3. Errors CSV
        errors_path = target_dir / f"{report.metadata.report_id}_errors.csv"
        errors_tmp = errors_path.with_suffix(".tmp")
        errors_tmp.write_text(cls.export_errors_csv(report), encoding="utf-8-sig")
        errors_tmp.replace(errors_path)
        results["errors"] = errors_path

        return results
