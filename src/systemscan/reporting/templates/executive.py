"""Executive summary text report template."""

from __future__ import annotations

from systemscan.reporting.models import ScanReport
from systemscan.utils.formatting import format_bytes


class ExecutiveTemplate:
    """Renders a clean, executive-level text summary of scan results."""

    @classmethod
    def render(cls, report: ScanReport) -> str:
        """Generate formatted executive report string."""
        s = report.executive_summary
        sev = s.severity_summary

        lines: list[str] = [
            "=" * 60,
            f"{'EXECUTIVE SECURITY SCAN SUMMARY':^60}",
            "=" * 60,
            "",
            f"Report ID        : {report.metadata.report_id}",
            f"Scan ID          : {s.scan_id}",
            f"Scan Type        : {s.scan_type.value}",
            f"Status           : {s.scan_status.value}",
            f"Host System      : {s.system_identifier}",
            f"Operating System : {s.os_description}",
            f"Start Time (UTC) : {s.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"End Time (UTC)   : {s.completion_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration         : {s.duration_seconds:.1f}s",
            f"Completeness     : {s.completeness_percent:.1f}%",
            "",
            "-" * 60,
            f"{'WORKLOAD & THROUGHPUT METRICS':^60}",
            "-" * 60,
            f"Items Analyzed   : {s.items_analyzed:,}",
            f"Data Volume      : {format_bytes(s.data_processed_bytes)}",
            f"Items Skipped    : {s.items_skipped:,}",
            f"Errors / Alerts  : {s.errors_count:,}",
            "",
            "-" * 60,
            f"{'SECURITY FINDINGS BREAKDOWN':^60}",
            "-" * 60,
            f"CRITICAL         : {sev.critical}",
            f"HIGH             : {sev.high}",
            f"MEDIUM           : {sev.medium}",
            f"LOW              : {sev.low}",
            f"INFO             : {sev.info}",
            f"TOTAL FINDINGS   : {sev.total}",
            "",
            f"OVERALL POSTURE  : {s.overall_result.value}",
            "=" * 60,
        ]

        if s.critical_observations:
            lines.append("\nCRITICAL SECURITY OBSERVATIONS:")
            for obs in s.critical_observations:
                lines.append(f" - {obs}")

        if s.high_priority_recommendations:
            lines.append("\nHIGH-PRIORITY RECOMMENDATIONS:")
            for rec in s.high_priority_recommendations:
                lines.append(f" [!] {rec}")

        lines.extend(
            [
                "",
                "SECURITY ADVISORY & DISCLAIMER:",
                "The findings reflect observations collected during this scan session.",
                "A verdict of 'NO_HIGH_PRIORITY_FINDINGS' indicates that no high-severity",
                "signatures or anomalies were matched; it does not constitute a guarantee",
                "that the system is entirely secure or invulnerable to novel threats.",
                "=" * 60,
                "",
            ]
        )

        return "\n".join(lines)
