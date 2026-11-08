"""Executive summary generation, risk calculation, and recommendation synthesis."""

from __future__ import annotations

from datetime import datetime

from systemscan.engine.models import ScanState, ScanType
from systemscan.reporting.models import (
    ConfidenceSummary,
    ExecutiveSummary,
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    OverallScanResult,
    SeveritySummary,
)


class ExecutiveSummaryBuilder:
    """Computes risk summaries, posture results, and actionable recommendations."""

    @staticmethod
    def build_severity_summary(findings: list[FindingRecord]) -> SeveritySummary:
        """Aggregate finding counts by severity."""
        crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
        low = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
        info = sum(1 for f in findings if f.severity == FindingSeverity.INFO)
        return SeveritySummary(
            critical=crit,
            high=high,
            medium=med,
            low=low,
            info=info,
            total=len(findings),
        )

    @staticmethod
    def build_confidence_summary(findings: list[FindingRecord]) -> ConfidenceSummary:
        """Aggregate finding counts by confidence rating."""
        conf = sum(1 for f in findings if f.confidence == FindingConfidence.CONFIRMED)
        high = sum(1 for f in findings if f.confidence == FindingConfidence.HIGH)
        med = sum(1 for f in findings if f.confidence == FindingConfidence.MEDIUM)
        low = sum(1 for f in findings if f.confidence == FindingConfidence.LOW)
        unk = sum(1 for f in findings if f.confidence == FindingConfidence.UNKNOWN)
        return ConfidenceSummary(
            confirmed=conf,
            high=high,
            medium=med,
            low=low,
            unknown=unk,
        )

    @staticmethod
    def calculate_overall_result(
        status: ScanState,
        sev_summary: SeveritySummary,
    ) -> OverallScanResult:
        """Determine overall scan posture verdict based on state and severity counts."""
        if status == ScanState.FAILED:
            return OverallScanResult.FAILED

        if status in (ScanState.PARTIAL, ScanState.CANCELLED, ScanState.CANCELLING):
            return OverallScanResult.INCOMPLETE

        if sev_summary.critical > 0 or sev_summary.high > 0:
            return OverallScanResult.ACTION_REQUIRED

        if sev_summary.medium > 0 or sev_summary.low > 0:
            return OverallScanResult.REVIEW_REQUIRED

        return OverallScanResult.NO_HIGH_PRIORITY_FINDINGS

    @classmethod
    def build_summary(
        cls,
        scan_id: str,
        scan_type: ScanType,
        scan_status: ScanState,
        system_identifier: str,
        os_description: str,
        start_time: datetime,
        completion_time: datetime,
        duration_seconds: float,
        items_analyzed: int,
        data_processed_bytes: int,
        items_skipped: int,
        errors_count: int,
        findings: list[FindingRecord],
        items_discovered: int | None = None,
    ) -> ExecutiveSummary:
        """Assemble a complete, validated executive summary."""
        sev_summary = cls.build_severity_summary(findings)
        conf_summary = cls.build_confidence_summary(findings)
        overall_result = cls.calculate_overall_result(scan_status, sev_summary)

        # Observations
        observations: list[str] = []
        for f in findings:
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                obs = f"[{f.severity.value}] {f.title} on {f.target}"
                if obs not in observations:
                    observations.append(obs)

        if not observations:
            if sev_summary.medium > 0:
                observations.append(
                    f"{sev_summary.medium} medium-severity configuration or storage warning(s) identified."
                )
            elif overall_result == OverallScanResult.NO_HIGH_PRIORITY_FINDINGS:
                observations.append(
                    "No critical or high-severity security findings detected in the inspected scope."
                )

        # Recommendations
        recommendations: list[str] = []
        seen_recs: set[str] = set()
        for f in findings:
            if f.remediation and f.severity in (
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
                FindingSeverity.MEDIUM,
            ):
                if f.remediation not in seen_recs:
                    seen_recs.add(f.remediation)
                    recommendations.append(f.remediation)

        if not recommendations:
            recommendations.append(
                "Maintain routine security scans, system patching, and monitor network exposures regularly."
            )

        # Completeness calculation
        completeness = 100.0
        if items_discovered and items_discovered > 0:
            total_handled = items_analyzed + items_skipped
            completeness = round(min(100.0, (total_handled / items_discovered) * 100.0), 1)
        elif scan_status in (ScanState.CANCELLED, ScanState.PARTIAL, ScanState.FAILED):
            completeness = 50.0

        return ExecutiveSummary(
            scan_id=scan_id,
            scan_type=scan_type,
            scan_status=scan_status,
            system_identifier=system_identifier,
            os_description=os_description,
            start_time=start_time,
            completion_time=completion_time,
            duration_seconds=duration_seconds,
            items_analyzed=items_analyzed,
            data_processed_bytes=data_processed_bytes,
            items_skipped=items_skipped,
            errors_count=errors_count,
            severity_summary=sev_summary,
            confidence_summary=conf_summary,
            overall_result=overall_result,
            critical_observations=observations,
            high_priority_recommendations=recommendations,
            completeness_percent=completeness,
        )
