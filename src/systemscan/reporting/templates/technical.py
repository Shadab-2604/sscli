"""Comprehensive detailed technical security report template."""

from __future__ import annotations

from systemscan.reporting.models import ScanReport
from systemscan.utils.formatting import format_bytes


class TechnicalTemplate:
    """Renders an exhaustive technical audit report containing all collected evidence."""

    @classmethod
    def render(cls, report: ScanReport) -> str:
        """Generate comprehensive technical report string."""
        s = report.executive_summary
        sys_info = report.system_info
        stats = report.statistics
        sev = s.severity_summary

        lines: list[str] = [
            "=" * 78,
            f"{'UNIVERSAL SYSTEM SECURITY & INTELLIGENCE AUDIT REPORT':^78}",
            "=" * 78,
            "",
            "REPORT METADATA",
            "-" * 78,
            f"Report ID           : {report.metadata.report_id}",
            f"Scan Session ID     : {report.metadata.scan_id}",
            f"Generated At (UTC)  : {report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Generator           : {report.metadata.generator_name} v{report.metadata.generator_version}",
            f"Schema Version      : {report.metadata.schema_version}",
            f"Sanitized / Redacted: {'YES (' + ', '.join(report.metadata.redaction_policy) + ')' if report.metadata.is_redacted else 'NO'}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 78,
            f"Scan Classification : {s.scan_type.value}",
            f"Terminal Status     : {s.scan_status.value}",
            f"Target System       : {s.system_identifier}",
            f"Operating System    : {s.os_description}",
            f"Execution Window    : {s.start_time.strftime('%Y-%m-%d %H:%M:%S')} to {s.completion_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Elapsed Time  : {s.duration_seconds:.2f} seconds",
            f"Workload Completed  : {s.completeness_percent:.1f}%",
            f"Security Verdict    : {s.overall_result.value}",
            "",
            "FINDINGS OVERVIEW",
            "-" * 78,
            f"CRITICAL : {sev.critical:<6} | HIGH   : {sev.high:<6} | MEDIUM : {sev.medium:<6}",
            f"LOW      : {sev.low:<6} | INFO   : {sev.info:<6} | TOTAL  : {sev.total:<6}",
            "",
            "=" * 78,
            "SECTION A: HOST & SYSTEM ENVIRONMENT",
            "=" * 78,
            f"Hostname            : {sys_info.hostname}",
            f"OS Family / Version : {sys_info.os_name} {sys_info.os_version}",
            f"Kernel Version      : {sys_info.kernel}",
            f"Hardware Arch       : {sys_info.architecture}",
            f"Processor Model     : {sys_info.cpu_model}",
            f"CPU Cores (Phys/Log): {sys_info.cpu_physical_cores or 'N/A'} physical / {sys_info.cpu_logical_cores or 'N/A'} logical",
            f"Total Memory (RAM)  : {f'{sys_info.ram_total_mb:.1f} MB' if sys_info.ram_total_mb else 'N/A'}",
            f"Primary IP Address  : {sys_info.primary_ip or 'N/A'}",
            f"Default Gateway     : {sys_info.default_gateway or 'N/A'}",
            "",
            "=" * 78,
            "SECTION B: OPERATIONAL TELEMETRY & PERFORMANCE",
            "=" * 78,
            f"Items Enumerated    : {stats.items_discovered:,}",
            f"Items Processed     : {stats.items_processed:,}",
            f"Items Skipped (Cache: {stats.items_skipped:,}",
            f"Data Volume Scanned : {format_bytes(stats.bytes_processed)}",
            f"Directories Checked : {stats.directories_inspected:,}",
            f"Average Throughput  : {stats.average_throughput_items_sec:.1f} items/sec ({stats.average_throughput_mb_sec:.2f} MB/sec)",
            f"Errors Encountered  : {stats.errors_count:,}",
            "",
            "=" * 78,
            f"SECTION C: DETAILED SECURITY FINDINGS ({len(report.findings)})",
            "=" * 78,
        ]

        if not report.findings:
            lines.append(
                "No security findings or anomalous indicators detected in this scan scope."
            )
            lines.append("")
        else:
            for idx, f in enumerate(report.findings, start=1):
                lines.extend(
                    [
                        f"[{idx:03d}] {f.title}",
                        "-" * 78,
                        f"Finding ID    : {f.finding_id}",
                        f"Category      : {f.category}",
                        f"Severity      : {f.severity.value}",
                        f"Confidence    : {f.confidence.value}",
                        f"Affected Target: {f.target}",
                        f"Detected At   : {f.detected_at.strftime('%Y-%m-%d %H:%M:%S')} (Source: {f.source_module})",
                        f"Description   : {f.description}",
                        f"Evidence      : {f.evidence}",
                    ]
                )
                if f.remediation:
                    lines.append(f"Remediation   : {f.remediation}")
                lines.append("")

        # Section D: Module-Specific Data
        if report.modules_data:
            lines.extend(
                [
                    "=" * 78,
                    "SECTION D: MODULE-SPECIFIC DIAGNOSTIC DATA",
                    "=" * 78,
                ]
            )
            for mod_name, mod_payload in report.modules_data.items():
                lines.append(f"\n--- [Module: {mod_name.upper()}] ---")
                if isinstance(mod_payload, dict):
                    for k, v in mod_payload.items():
                        lines.append(f" - {k}: {v}")
                elif isinstance(mod_payload, list):
                    for item in mod_payload[:15]:
                        lines.append(f" - {item}")
                    if len(mod_payload) > 15:
                        lines.append(
                            f"   ... ({len(mod_payload) - 15} more items omitted for brevity)"
                        )
                else:
                    lines.append(str(mod_payload))
            lines.append("")

        # Section E: Errors & Limitations
        lines.extend(
            [
                "=" * 78,
                f"SECTION E: OPERATIONAL ERRORS & LIMITATIONS ({len(report.errors)})",
                "=" * 78,
            ]
        )
        if not report.errors:
            lines.append("No non-fatal operational errors or permission failures recorded.")
            lines.append("")
        else:
            for e in report.errors:
                target_info = f" (Target: {e.target})" if e.target else ""
                lines.append(
                    f" - [{e.timestamp.strftime('%H:%M:%S')}] [{e.source_module}] {e.error_type}: {e.message}{target_info}"
                )
            lines.append("")

        # Section F: Remediation & Recommendations
        lines.extend(
            [
                "=" * 78,
                "SECTION F: REMEDIATION & ACTION PLAN",
                "=" * 78,
            ]
        )
        if s.high_priority_recommendations:
            for rec in s.high_priority_recommendations:
                lines.append(f" [!] {rec}")
        else:
            lines.append("Maintain baseline monitoring and schedule periodic follow-up scans.")

        lines.extend(
            [
                "",
                "=" * 78,
                "DISCLAIMER:",
                "This technical audit report is generated automatically based on accessible",
                "system telemetry, file signatures, and network observation probes.",
                "Uninspected directories, encrypted volumes, or unsupported hardware were",
                "not evaluated. The absence of findings does not guarantee full immunity.",
                "=" * 78,
                "",
            ]
        )

        return "\n".join(lines)
