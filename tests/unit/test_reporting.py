"""Unit test suite for Phase 09: Centralized Reporting & Export Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from systemscan.engine.models import ScanState, ScanType
from systemscan.reporting.findings import FindingNormalizer
from systemscan.reporting.formats.csv_export import CSVReportExporter
from systemscan.reporting.formats.json_export import JSONReportExporter
from systemscan.reporting.formats.txt_export import TextReportExporter
from systemscan.reporting.models import (
    ErrorRecord,
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
from systemscan.reporting.validator import ReportValidationError, ReportValidator


@pytest.fixture
def sample_report() -> ScanReport:
    """Construct a complete, valid sample ScanReport fixture."""
    now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
    metadata = ReportMetadata(
        report_id="rep-sample-01",
        scan_id="scan-sample-01",
        scan_type=ScanType.FULL,
        scan_status=ScanState.COMPLETED,
        generated_at=now,
    )
    sys_info = SystemSummary(
        hostname="test-workstation",
        os_name="Linux",
        os_version="6.6.0-kali",
        kernel="Linux 6.6.0",
        architecture="x86_64",
        cpu_model="Intel Core i9-14900K",
        cpu_physical_cores=8,
        cpu_logical_cores=16,
        ram_total_mb=32768.0,
        primary_ip="192.168.1.150",
        default_gateway="192.168.1.1",
    )
    findings = [
        FindingRecord(
            finding_id="fnd-01",
            title="EICAR Standard Anti-Virus Test File",
            category="MALWARE",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.CONFIRMED,
            description="Matched known malicious signature hash.",
            evidence="SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            target="/home/alice/downloads/eicar.com",
            detected_at=now,
            source_module="malware",
            remediation="Isolate file in secure quarantine vault.",
        ),
        FindingRecord(
            finding_id="fnd-02",
            title="Global Listening Socket on Insecure Port",
            category="NETWORK",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.HIGH,
            description="Service bound to 0.0.0.0:8080 without TLS.",
            evidence="Socket TCP 0.0.0.0:8080 (PID 1420)",
            target="0.0.0.0:8080",
            detected_at=now,
            source_module="network",
            remediation="Bind service to localhost (127.0.0.1) or enforce TLS.",
        ),
    ]
    errors = [
        ErrorRecord(
            error_id="err-01",
            timestamp=now,
            source_module="filesystem",
            error_type="PermissionDenied",
            message="Access denied to /root/.ssh",
            target="/root/.ssh",
        )
    ]
    stats = ScanStatistics(
        duration_seconds=42.5,
        items_discovered=1500,
        items_processed=1450,
        items_skipped=50,
        bytes_processed=104857600,
        directories_inspected=120,
        errors_count=1,
        findings_count=2,
        average_throughput_items_sec=34.1,
        average_throughput_mb_sec=2.35,
    )
    exec_summary = ExecutiveSummaryBuilder.build_summary(
        scan_id="scan-sample-01",
        scan_type=ScanType.FULL,
        scan_status=ScanState.COMPLETED,
        system_identifier="test-workstation",
        os_description="Linux 6.6.0-kali (x86_64)",
        start_time=now,
        completion_time=now,
        duration_seconds=42.5,
        items_analyzed=1450,
        data_processed_bytes=104857600,
        items_skipped=50,
        errors_count=1,
        findings=findings,
        items_discovered=1500,
    )
    return ScanReport(
        metadata=metadata,
        system_info=sys_info,
        statistics=stats,
        executive_summary=exec_summary,
        findings=findings,
        errors=errors,
        modules_data={"network_open_ports": [8080, 22]},
    )


class TestReportModelsAndValidation:
    """Validate report data structures, schema requirements, and consistency checks."""

    def test_report_schema_validation(self, sample_report: ScanReport) -> None:
        issues = ReportValidator.validate_report(sample_report)
        assert len(issues) == 0

    def test_validator_catches_findings_count_mismatch(self, sample_report: ScanReport) -> None:
        # Deliberately desynchronize summary
        sample_report.executive_summary.severity_summary.total = 999
        issues = ReportValidator.validate_report(sample_report)
        assert any("Severity summary total" in msg for msg in issues)

        with pytest.raises(ReportValidationError):
            ReportValidator.assert_valid(sample_report)

    def test_validator_catches_invalid_timestamp_chronology(
        self, sample_report: ScanReport
    ) -> None:
        sample_report.executive_summary.start_time = datetime(
            2026, 11, 8, 15, 0, tzinfo=timezone.utc
        )
        sample_report.executive_summary.completion_time = datetime(
            2026, 11, 8, 12, 0, tzinfo=timezone.utc
        )
        issues = ReportValidator.validate_report(sample_report)
        assert any("start_time cannot be after completion_time" in msg for msg in issues)


class TestExecutiveSummaryBuilder:
    """Validate posture verdict calculations and recommendation synthesis."""

    def test_overall_result_action_required_for_critical_or_high(self) -> None:
        sev = SeveritySummary(critical=1, high=0, medium=0, low=0, info=0, total=1)
        res = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.COMPLETED, sev)
        assert res == OverallScanResult.ACTION_REQUIRED

        sev_high = SeveritySummary(critical=0, high=2, medium=0, low=0, info=0, total=2)
        res_high = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.COMPLETED, sev_high)
        assert res_high == OverallScanResult.ACTION_REQUIRED

    def test_overall_result_review_required_for_medium(self) -> None:
        sev = SeveritySummary(critical=0, high=0, medium=3, low=1, info=0, total=4)
        res = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.COMPLETED, sev)
        assert res == OverallScanResult.REVIEW_REQUIRED

    def test_overall_result_no_high_priority_findings(self) -> None:
        sev = SeveritySummary(critical=0, high=0, medium=0, low=0, info=5, total=5)
        res = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.COMPLETED, sev)
        assert res == OverallScanResult.NO_HIGH_PRIORITY_FINDINGS

    def test_overall_result_incomplete_for_partial_or_cancelled(self) -> None:
        sev = SeveritySummary(critical=0, high=0, medium=0, low=0, info=0, total=0)
        res_cancelled = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.CANCELLED, sev)
        assert res_cancelled == OverallScanResult.INCOMPLETE

        res_partial = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.PARTIAL, sev)
        assert res_partial == OverallScanResult.INCOMPLETE

    def test_overall_result_failed_for_failed_state(self) -> None:
        sev = SeveritySummary(critical=0, high=0, medium=0, low=0, info=0, total=0)
        res = ExecutiveSummaryBuilder.calculate_overall_result(ScanState.FAILED, sev)
        assert res == OverallScanResult.FAILED


class TestFindingNormalizer:
    """Validate mapping from disparate module finding types to unified FindingRecord."""

    def test_from_malware_finding(self) -> None:
        mock_malware = MagicMock()
        mock_malware.finding_id = "mal-1234"
        mock_malware.threat_name = "Trojan.Win32.Test"
        mock_malware.category = "MALWARE"
        mock_malware.severity = "CRITICAL"
        mock_malware.confidence = "CONFIRMED"
        mock_malware.description = "Identified trojan binary."
        mock_malware.evidence = "MD5: abcde"
        mock_malware.file_path = "/tmp/malicious.bin"
        mock_malware.detected_at = datetime.now(timezone.utc)
        mock_malware.recommended_action = "Quarantine immediately"

        finding = FindingNormalizer.from_malware_finding(mock_malware)
        assert finding.finding_id == "mal-1234"
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.confidence == FindingConfidence.CONFIRMED
        assert finding.source_module == "malware"
        assert finding.target == "/tmp/malicious.bin"

    def test_from_network_finding(self) -> None:
        mock_network = MagicMock()
        mock_network.finding_id = "net-5678"
        mock_network.title = "Unencrypted Insecure Wi-Fi"
        mock_network.category = "NETWORK"
        mock_network.severity = "MEDIUM"
        mock_network.confidence = "HIGH"
        mock_network.description = "Connected to open network."
        mock_network.evidence = "SSID: PublicCafe"
        mock_network.affected_target = "wlan0"
        mock_network.timestamp = datetime.now(timezone.utc)
        mock_network.remediation = "Disconnect and use VPN."
        mock_network.source_module = "network"

        finding = FindingNormalizer.from_network_finding(mock_network)
        assert finding.finding_id == "net-5678"
        assert finding.severity == FindingSeverity.MEDIUM
        assert finding.target == "wlan0"
        assert finding.source_module == "network"


class TestReportRedaction:
    """Validate sensitive data masking and immutability guarantees."""

    def test_redaction_masks_sensitive_data(self, sample_report: ScanReport) -> None:
        redactor = ReportRedactor(
            policy=RedactionPolicy(
                redact_usernames=True,
                redact_user_paths=True,
                redact_internal_ips=True,
                redact_secrets=True,
            )
        )
        redacted = redactor.redact_report(sample_report)

        # 1. Verify sanitized report has is_redacted flag
        assert redacted.metadata.is_redacted is True
        assert "user_paths" in redacted.metadata.redaction_policy

        # 2. Hostname and IP masked
        assert redacted.system_info.hostname == "[REDACTED_HOST]"
        assert redacted.system_info.primary_ip == "[PRIVATE_IP]"

        # 3. Path masked (/home/alice -> /home/[USER])
        assert "/home/[USER]/downloads/eicar.com" in redacted.findings[0].target
        assert "alice" not in redacted.findings[0].target

        # 4. Immutability guarantee: Original report must NOT have been changed!
        assert sample_report.metadata.is_redacted is False
        assert sample_report.system_info.hostname == "test-workstation"
        assert "alice" in sample_report.findings[0].target

    def test_secret_regex_masking(self) -> None:
        redactor = ReportRedactor()
        text = "Database connection: password=supersecret123; token=eyJhbGciOi"
        sanitized = redactor.sanitize_text(text)
        assert "supersecret123" not in sanitized
        assert "password=[REDACTED_SECRET]" in sanitized
        assert "token=[REDACTED_SECRET]" in sanitized


class TestExportFormats:
    """Validate JSON, CSV, and TXT exporters."""

    def test_json_roundtrip_export_and_load(
        self, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        out_file = tmp_path / "report.json"
        saved = JSONReportExporter.export_to_file(sample_report, out_file)
        assert saved.exists()

        # Load back and validate
        loaded = JSONReportExporter.load_from_file(saved)
        assert loaded.metadata.report_id == sample_report.metadata.report_id
        assert len(loaded.findings) == len(sample_report.findings)
        assert (
            loaded.executive_summary.overall_result
            == sample_report.executive_summary.overall_result
        )

    def test_csv_export_format(self, sample_report: ScanReport, tmp_path: Path) -> None:
        out_file = tmp_path / "findings.csv"
        saved = CSVReportExporter.export_to_file(sample_report, out_file)
        assert saved.exists()

        content = out_file.read_text(encoding="utf-8-sig")
        assert "finding_id,scan_id,title,category,severity" in content
        assert "EICAR Standard Anti-Virus Test File" in content
        assert "Global Listening Socket on Insecure Port" in content

    def test_csv_bundle_export(self, sample_report: ScanReport, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "csv_bundle"
        bundle = CSVReportExporter.export_bundle_to_dir(sample_report, bundle_dir)

        assert "summary" in bundle
        assert "findings" in bundle
        assert "errors" in bundle
        assert bundle["summary"].exists()
        assert bundle["findings"].exists()
        assert bundle["errors"].exists()

    def test_text_export_templates(self, sample_report: ScanReport) -> None:
        tech_str = TextReportExporter.export_to_string(sample_report, style="technical")
        assert "UNIVERSAL SYSTEM SECURITY & INTELLIGENCE AUDIT REPORT" in tech_str
        assert "SECTION A: HOST & SYSTEM ENVIRONMENT" in tech_str
        assert "SECTION C: DETAILED SECURITY FINDINGS" in tech_str
        assert "DISCLAIMER:" in tech_str

        exec_str = TextReportExporter.export_to_string(sample_report, style="executive")
        assert "EXECUTIVE SECURITY SCAN SUMMARY" in exec_str
        assert "SECURITY ADVISORY & DISCLAIMER:" in exec_str

        compact_str = TextReportExporter.export_to_string(sample_report, style="compact")
        assert "[systemscan] Scan Report:" in compact_str


class TestReportStorageAndIntegrity:
    """Validate atomic persistence, checksum manifests, and file integrity checks."""

    def test_save_and_verify_checksum(self, sample_report: ScanReport, tmp_path: Path) -> None:
        mgr = ReportStorageManager(storage_dir=tmp_path)
        saved = mgr.save_report(sample_report, fmt=ReportFormat.JSON, generate_checksum=True)

        assert saved.exists()
        manifest = saved.with_suffix(".json.sha256")
        assert manifest.exists()

        # Verify integrity
        is_valid, msg = mgr.verify_report(sample_report.metadata.report_id)
        assert is_valid is True
        assert "matches cryptographic SHA-256" in msg

    def test_tampered_report_fails_verification(
        self, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        mgr = ReportStorageManager(storage_dir=tmp_path)
        saved = mgr.save_report(sample_report, fmt=ReportFormat.JSON, generate_checksum=True)

        # Tamper with file
        saved.write_text('{"tampered": true}', encoding="utf-8")

        is_valid, msg = mgr.verify_report(sample_report.metadata.report_id)
        assert is_valid is False
        assert "MISMATCH" in msg

    def test_refuse_silent_overwrite_without_flag(
        self, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        mgr = ReportStorageManager(storage_dir=tmp_path)
        mgr.save_report(sample_report, fmt=ReportFormat.JSON)

        # Attempt second save without overwrite=True
        with pytest.raises(FileExistsError):
            mgr.save_report(sample_report, fmt=ReportFormat.JSON, overwrite=False)

        # With overwrite=True, succeeds
        mgr.save_report(sample_report, fmt=ReportFormat.JSON, overwrite=True)

    def test_delete_report_requires_confirmation(
        self, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        mgr = ReportStorageManager(storage_dir=tmp_path)
        mgr.save_report(sample_report, fmt=ReportFormat.JSON)

        with pytest.raises(PermissionError):
            mgr.delete_report(sample_report.metadata.report_id, confirm=False)

        deleted = mgr.delete_report(sample_report.metadata.report_id, confirm=True)
        assert deleted is True
        assert mgr.find_report_file(sample_report.metadata.report_id) is None
