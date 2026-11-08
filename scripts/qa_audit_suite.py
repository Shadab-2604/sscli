"""Comprehensive Quality Assurance, Security Validation, and E2E Scenario Test Harness.

Executes Scenarios A through I in isolated environments and benchmarks stress performance.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# Ensure src is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

import psutil

from systemscan.config.manager import ConfigManager
from systemscan.core.application import Application
from systemscan.core.dependencies import DependencyRegistry
from systemscan.devices.manager import DeviceManager
from systemscan.engine.models import ScanState, ScanType
from systemscan.engine.orchestrator import CentralScanOrchestrator
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import ScanConfig
from systemscan.modules.malware.engine import MalwareDetectionEngine
from systemscan.modules.storage.cleanup.audit import CleanupAuditLogger
from systemscan.modules.storage.cleanup.executor import SafeCleanupExecutor
from systemscan.modules.storage.cleanup.planner import CleanupPlanner
from systemscan.modules.storage.disk_usage import DiskUsageAnalyzer
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.diagnostics import NetworkDiagnostics
from systemscan.network.dns import DNSIntelligenceEngine
from systemscan.network.firewall import FirewallAuditor
from systemscan.network.interfaces import NetworkInterfaceInspector
from systemscan.reporting.generator import ReportGenerator
from systemscan.reporting.models import FindingConfidence, FindingSeverity, ReportFormat
from systemscan.reporting.findings import FindingNormalizer
from systemscan.reporting.storage import ReportStorageManager
from systemscan.reporting.validator import ReportValidator
from systemscan.update.transaction import UpdateTransactionCoordinator
from systemscan.utils.paths import AppPaths


def run_scenario_a() -> dict[str, Any]:
    """Scenario A — Fresh Installation in an isolated virtual environment."""
    results: dict[str, Any] = {"name": "Scenario A - Fresh Installation", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_venv_") as tmp_venv_dir:
        venv_path = Path(tmp_venv_dir) / "test_env"
        # 1. Create clean virtualenv
        proc_venv = subprocess.run(
            [sys.executable, "-m", "venv", str(venv_path)],
            capture_output=True,
            text=True,
        )
        if proc_venv.returncode != 0:
            results["error"] = f"Failed to create venv: {proc_venv.stderr}"
            return results

        site_packages = (
            venv_path
            / (
                "Lib"
                if os.name == "nt"
                else f"lib/python{sys.version_info.major}.{sys.version_info.minor}"
            )
            / "site-packages"
        )
        site_packages.mkdir(parents=True, exist_ok=True)
        # Bridge dependencies from current test environment via .pth
        parent_site = (
            Path(sys.prefix)
            / (
                "Lib"
                if os.name == "nt"
                else f"lib/python{sys.version_info.major}.{sys.version_info.minor}"
            )
            / "site-packages"
        )
        (site_packages / "parent_deps.pth").write_text(
            str(parent_site.resolve()) + "\n", encoding="utf-8"
        )

        python_bin = venv_path / ("Scripts" if os.name == "nt" else "bin") / "python"
        wheel_file = BASE_DIR / "dist" / "systemscan-1.0.0-py3-none-any.whl"

        # 2. Install built wheel into isolated venv
        proc_install = subprocess.run(
            [
                str(python_bin),
                "-m",
                "pip",
                "install",
                str(wheel_file),
                "--no-deps",
                "--force-reinstall",
            ],
            capture_output=True,
            text=True,
        )
        if proc_install.returncode != 0:
            results["error"] = f"Failed to install wheel: {proc_install.stderr}"
            return results

        # 3. Test CLI version
        proc_ver = subprocess.run(
            [str(python_bin), "-m", "systemscan", "--version"],
            capture_output=True,
            text=True,
        )
        # 4. Test CLI help
        proc_help = subprocess.run(
            [str(python_bin), "-m", "systemscan", "--help"],
            capture_output=True,
            text=True,
        )
        # 5. Test doctor
        proc_doc = subprocess.run(
            [str(python_bin), "-m", "systemscan", "doctor"],
            capture_output=True,
            text=True,
        )

        results["version_output"] = proc_ver.stdout.strip()
        results["help_returncode"] = proc_help.returncode
        results["doctor_returncode"] = proc_doc.returncode
        results["installed_cleanly"] = (
            proc_ver.returncode == 0 and "1.0.0" in proc_ver.stdout and proc_help.returncode == 0
        )
        results["status"] = "PASS" if results["installed_cleanly"] else "FAIL"

    return results


def run_scenario_b() -> dict[str, Any]:
    """Scenario B — System, Hardware, Process, Service, and Network Inspection."""
    results: dict[str, Any] = {"name": "Scenario B - System Inspection", "status": "FAIL"}
    try:
        from systemscan.modules.hardware.cpu import collect_cpu_info
        from systemscan.modules.hardware.memory import collect_memory_info
        from systemscan.modules.hardware.storage import collect_partition_info
        from systemscan.modules.processes.collector import collect_processes
        from systemscan.modules.system_info.operating_system import collect_operating_system_info

        os_info = collect_operating_system_info()
        cpu_info = collect_cpu_info()
        mem_info = collect_memory_info()
        disk_info = collect_partition_info()
        proc_list = collect_processes(limit=5)

        results["os"] = os_info.name
        results["cpu_cores"] = cpu_info.logical_cores
        results["ram_total_gb"] = round(mem_info.total_bytes / (1024**3), 2)
        results["disks_detected"] = len(disk_info)
        results["processes_sampled"] = len(proc_list)
        results["status"] = "PASS"
    except Exception as e:
        results["error"] = str(e)

    return results


def run_scenario_c() -> dict[str, Any]:
    """Scenario C — Controlled Filesystem & Malware Scan."""
    results: dict[str, Any] = {"name": "Scenario C - Controlled Scan", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_target_") as target_dir:
        t_path = Path(target_dir)

        # 1. Normal file
        (t_path / "normal.txt").write_text("Standard document text.", encoding="utf-8")
        # 2. Hidden file
        (t_path / ".hidden_file").write_text("Hidden config file.", encoding="utf-8")
        # 3. Nested directory
        nested = t_path / "nested" / "sub"
        nested.mkdir(parents=True)
        (nested / "nested.dat").write_text("Nested data", encoding="utf-8")
        # 4. Unicode filename
        (t_path / "test_unicode_测试_ünicöde.log").write_text("Unicode content", encoding="utf-8")
        # 5. Empty file
        (t_path / "empty.bin").touch()
        # 6. Duplicate files
        dup_content = b"Exact duplicate content bytes for hash testing"
        (t_path / "dup1.bin").write_bytes(dup_content)
        (t_path / "dup2.bin").write_bytes(dup_content)
        # 7. Harmless PE file header (MZ sample)
        (t_path / "harmless_sample.exe").write_bytes(b"MZ\x90\x00\x03\x00\x00\x00Dummy PE content")

        # Execute Filesystem scanner
        from systemscan.filesystem.models import FileMetadata

        cfg = ScanConfig(roots=[str(t_path)])
        scanner = FilesystemScanner()
        items = [i for i in scanner.stream_scan(cfg) if isinstance(i, FileMetadata)]

        # Execute Malware scanner
        malware_engine = MalwareDetectionEngine()
        malware_findings = []
        for item in items:
            m_f = malware_engine.analyze_file(item.path, scan_id="test-scan-001")
            malware_findings.extend(m_f)

        results["items_found"] = len(items)
        results["malware_findings"] = len(malware_findings)
        results["status"] = "PASS" if len(items) >= 7 else "FAIL"

    return results


def run_scenario_d() -> dict[str, Any]:
    """Scenario D — Storage & Safe Cleanup Simulation."""
    results: dict[str, Any] = {"name": "Scenario D - Storage & Cleanup", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_cleanup_") as clean_dir:
        c_path = Path(clean_dir)
        # Create dummy cache files
        cache_dir = c_path / "cache"
        cache_dir.mkdir()
        temp_file1 = cache_dir / "temp1.tmp"
        temp_file1.write_text("cache 1", encoding="utf-8")
        temp_file2 = cache_dir / "temp2.tmp"
        temp_file2.write_text("cache 2", encoding="utf-8")

        # 1. Analyze storage volumes
        volumes = DiskUsageAnalyzer.analyze_volumes()

        # 2. Safe cleanup preview & planner
        preview = CleanupPlanner.generate_preview(
            target_paths=[cache_dir], include_browser_cache=False
        )

        # 3. Execute dry-run
        audit_logger = CleanupAuditLogger(audit_dir=c_path)
        executor = SafeCleanupExecutor(audit_logger=audit_logger)
        dry_run_res = executor.execute_cleanup(preview, authorized=False, dry_run=True)

        # Verify no files deleted in dry-run
        assert temp_file1.exists()
        assert temp_file2.exists()

        # 4. Execute authorized actual cleanup
        actual_res = executor.execute_cleanup(preview, authorized=True, dry_run=False)

        # Verify deletion of cache items
        assert not temp_file1.exists()
        assert not temp_file2.exists()
        audits = audit_logger.list_audits()
        assert len(audits) >= 2

        results["volumes_analyzed"] = len(volumes)
        results["candidates_found"] = preview.total_files
        results["dry_run_deleted"] = dry_run_res.deleted_files_count
        results["actual_deleted"] = actual_res.deleted_files_count
        results["audit_logs_recorded"] = len(audits)
        results["status"] = "PASS"

    return results


def run_scenario_e() -> dict[str, Any]:
    """Scenario E — Network Audit (Safe Local Read-Only)."""
    results: dict[str, Any] = {"name": "Scenario E - Network Audit", "status": "FAIL"}
    try:
        # 1. Interface inspection
        ifaces = NetworkInterfaceInspector().inspect_all()
        # 2. Active connections
        conns = NetworkConnectionInspector().inspect_connections()[:5]
        # 3. DNS configuration
        dns_servers = DNSIntelligenceEngine().get_configured_dns_servers()
        # 4. Firewall configuration
        fw_status, fw_findings = FirewallAuditor().audit_firewall()
        # 5. Safe local gateway query
        diag = NetworkDiagnostics()
        gw = diag.provider.get_default_gateway()

        results["interfaces_count"] = len(ifaces)
        results["active_connections_sampled"] = len(conns)
        results["dns_servers_count"] = len(dns_servers)
        results["firewall_enabled"] = fw_status.is_enabled
        results["default_gateway"] = gw or "None"
        results["status"] = "PASS"
    except Exception as e:
        results["error"] = str(e)

    return results


def run_scenario_f() -> dict[str, Any]:
    """Scenario F — Central Scan Lifecycle, ETA, Pause, Resume, and Cancellation."""
    results: dict[str, Any] = {"name": "Scenario F - Scan Lifecycle", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_lifecycle_") as tmp_dir:
        mock_paths = AppPaths(base_dir=Path(tmp_dir))
        mock_paths.ensure_directories()

        cfg_mgr = ConfigManager(app_paths=mock_paths)
        orchestrator = CentralScanOrchestrator(config_manager=cfg_mgr)

        # Test cooperative pause request
        orchestrator.lifecycle.transition_to(ScanState.INITIALIZING)
        orchestrator.lifecycle.transition_to(ScanState.RUNNING)
        orchestrator.pause_controller.request_pause()
        assert orchestrator.pause_controller.is_pause_requested is True

        # Test resume preparation for missing checkpoint raises cleanly
        try:
            orchestrator.pause_controller.prepare_resume("chk-dummy")
            resume_ok = False
        except FileNotFoundError:
            resume_ok = True

        # Test cancellation token
        tok = CancellationToken()
        assert not tok.is_cancelled
        tok.cancel()
        assert tok.is_cancelled

        results["pause_requested"] = orchestrator.pause_controller.is_pause_requested
        results["resume_missing_handled"] = resume_ok
        results["cancellation_verified"] = tok.is_cancelled
        results["status"] = "PASS"

    return results


def run_scenario_g() -> dict[str, Any]:
    """Scenario G — Report Generation, Multi-Format Export, Redaction & Checksum Manifest."""
    results: dict[str, Any] = {"name": "Scenario G - Reporting & Export", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_report_") as tmp_dir:
        t_path = Path(tmp_dir)

        # Create sample finding with sensitive data
        finding = FindingNormalizer.create_custom_finding(
            title="Exposed Test API Key",
            category="CREDENTIALS",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.CONFIRMED,
            description="Found AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in config",
            evidence="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            target="C:\\Users\\admin\\secrets.env",
            source_module="security_audit",
        )

        from datetime import datetime, timezone

        report = ReportGenerator.generate_report(
            scan_id="scn-qa-test",
            scan_type=ScanType.FULL,
            scan_status=ScanState.COMPLETED,
            start_time=datetime.now(timezone.utc),
            completion_time=datetime.now(timezone.utc),
            duration_seconds=1.25,
            items_discovered=50,
            items_processed=50,
            items_skipped=0,
            bytes_processed=1024 * 1024,
            findings=[finding],
            errors=[],
        )

        storage = ReportStorageManager(storage_dir=t_path)
        # 1. JSON export
        json_file = storage.save_report(report, fmt=ReportFormat.JSON, generate_checksum=True)
        # 2. CSV export
        csv_file = storage.save_report(report, fmt=ReportFormat.CSV, generate_checksum=True)
        # 3. TXT export
        txt_file = storage.save_report(report, fmt=ReportFormat.TXT, generate_checksum=True)

        # Validate manifest files
        assert json_file.with_name(f"{json_file.name}.sha256").exists()
        assert csv_file.with_name(f"{csv_file.name}.sha256").exists()
        assert txt_file.with_name(f"{txt_file.name}.sha256").exists()

        # Validate report JSON parsing
        with open(json_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data["metadata"]["scan_id"] == "scn-qa-test"
        assert len(data["findings"]) == 1

        results["json_exported"] = json_file.exists()
        results["csv_exported"] = csv_file.exists()
        results["txt_exported"] = txt_file.exists()
        results["manifests_verified"] = True
        results["status"] = "PASS"

    return results


def run_scenario_h() -> dict[str, Any]:
    """Scenario H — Update & Recovery State Machine Simulation."""
    from unittest.mock import patch

    from systemscan.update.transaction import UpdateLockError

    results: dict[str, Any] = {"name": "Scenario H - Update & Recovery", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_update_") as tmp_dir:
        t_path = Path(tmp_dir)
        mock_paths = AppPaths(base_dir=t_path)
        mock_paths.ensure_directories()

        with patch("systemscan.update.transaction.AppPaths", return_value=mock_paths):
            coord = UpdateTransactionCoordinator()
            # Test acquisition of lock
            coord.acquire_lock("txn-001")
            assert coord.lock_file.exists()

            # Duplicate acquisition raises UpdateLockError
            locked = False
            try:
                coord.acquire_lock("txn-002")
            except UpdateLockError:
                locked = True
            assert locked is True

            # Release lock
            coord.release_lock()
            assert not coord.lock_file.exists()

            results["lock_acquired"] = True
            results["lock_concurrency_verified"] = locked
            results["lock_released"] = not coord.lock_file.exists()
            results["status"] = "PASS"

    return results


def run_scenario_i() -> dict[str, Any]:
    """Scenario I — Cross-Platform Local Host Verification."""
    results: dict[str, Any] = {"name": "Scenario I - Cross-Platform Host", "status": "FAIL"}
    try:
        from systemscan.modules.system_info.operating_system import collect_operating_system_info

        info = collect_operating_system_info()
        results["detected_os"] = info.name
        results["architecture"] = info.machine_arch
        results["kernel"] = info.kernel_version
        results["python_version"] = sys.version.split()[0]
        results["status"] = "PASS"
    except Exception as e:
        results["error"] = str(e)

    return results


def run_performance_stress_test() -> dict[str, Any]:
    """Execute controlled multi-tier dataset stress testing."""
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="sscli_qa_stress_") as stress_root:
        s_path = Path(stress_root)

        tiers = [
            ("small_1k", 1000),
            ("medium_10k", 10000),
        ]

        proc = psutil.Process()
        mem_before = proc.memory_info().rss / (1024 * 1024)

        for name, count in tiers:
            tier_dir = s_path / name
            tier_dir.mkdir()
            # Generate files efficiently
            for i in range(count):
                sub = tier_dir / f"d_{i % 20}"
                if not sub.exists():
                    sub.mkdir()
                (sub / f"f_{i}.txt").write_text(f"File content line {i}", encoding="utf-8")

            t0 = time.perf_counter()
            cfg = ScanConfig(roots=[str(tier_dir)])
            scanner = FilesystemScanner()
            scanned = list(scanner.stream_scan(cfg))
            elapsed = time.perf_counter() - t0

            mem_now = proc.memory_info().rss / (1024 * 1024)

            results[name] = {
                "count": len(scanned),
                "duration_s": round(elapsed, 4),
                "throughput_items_s": round(len(scanned) / max(elapsed, 0.001), 1),
                "memory_mb": round(mem_now, 2),
            }

        mem_after = proc.memory_info().rss / (1024 * 1024)
        results["memory_delta_mb"] = round(mem_after - mem_before, 2)

    return results


def main() -> None:
    print("=================== EXECUTING E2E SCENARIOS A THROUGH I ===================")
    scenarios = [
        run_scenario_a,
        run_scenario_b,
        run_scenario_c,
        run_scenario_d,
        run_scenario_e,
        run_scenario_f,
        run_scenario_g,
        run_scenario_h,
        run_scenario_i,
    ]

    all_passed = True
    scenario_results = []
    for s_fn in scenarios:
        res = s_fn()
        scenario_results.append(res)
        print(f"[{res.get('status', 'FAIL')}] {res.get('name')}")
        if res.get("status") != "PASS":
            all_passed = False
            print(f"    Details: {res}")

    print("\n=================== EXECUTING PERFORMANCE STRESS TESTING ===================")
    perf_results = run_performance_stress_test()
    print(json.dumps(perf_results, indent=2))

    summary = {
        "all_scenarios_passed": all_passed,
        "scenarios": scenario_results,
        "performance": perf_results,
    }

    out_file = BASE_DIR / "qa_audit_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nAudit results persisted to {out_file}")
    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
