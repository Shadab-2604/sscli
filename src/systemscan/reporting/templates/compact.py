"""Compact single-screen text report template."""

from __future__ import annotations

from systemscan.reporting.models import ScanReport
from systemscan.utils.formatting import format_bytes


class CompactTemplate:
    """Renders a concise, space-efficient report representation."""

    @classmethod
    def render(cls, report: ScanReport) -> str:
        """Generate compact report string."""
        s = report.executive_summary
        sev = s.severity_summary

        lines: list[str] = [
            f"--- [systemscan] Scan Report: {s.scan_id} ({s.scan_status.value}) ---",
            f"Type: {s.scan_type.value} | Host: {s.system_identifier} ({s.os_description})",
            f"Duration: {s.duration_seconds:.1f}s | Analyzed: {s.items_analyzed:,} items ({format_bytes(s.data_processed_bytes)}) | Skipped: {s.items_skipped:,}",
            f"Findings: CRIT:{sev.critical} HIGH:{sev.high} MED:{sev.medium} LOW:{sev.low} INFO:{sev.info} (Total: {sev.total})",
            f"Verdict: {s.overall_result.value}",
        ]

        if report.findings:
            lines.append("Top Findings:")
            for f in report.findings[:5]:
                lines.append(f" - [{f.severity.value}] {f.title} ({f.target})")
            if len(report.findings) > 5:
                lines.append(f"   ... and {len(report.findings) - 5} more finding(s).")

        return "\n".join(lines)
