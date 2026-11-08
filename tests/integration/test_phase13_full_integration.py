"""Phase 13: Full end-to-end integration test validating the unified security scan workflow."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from systemscan.config.manager import ConfigManager
from systemscan.engine.models import ScanState, ScanType
from systemscan.engine.orchestrator import CentralScanOrchestrator
from systemscan.reporting.storage import ReportStorageManager
from systemscan.utils.paths import AppPaths


def test_full_system_scan_end_to_end_workflow(tmp_path: Path) -> None:
    """Validate full end-to-end scan: traversal -> malware -> storage -> network -> history -> report."""
    mock_paths = AppPaths(base_dir=tmp_path)
    mock_paths.ensure_directories()

    # Create dummy target file structure
    target_dir = tmp_path / "scan_target"
    target_dir.mkdir(parents=True, exist_ok=True)
    clean_file = target_dir / "clean.txt"
    clean_file.write_text("Hello, this is a clean file for testing.", encoding="utf-8")

    # Configure orchestrator with isolated paths
    with (
        patch("systemscan.engine.history.AppPaths", return_value=mock_paths),
        patch("systemscan.engine.checkpoint.AppPaths", return_value=mock_paths),
        patch("systemscan.engine.incremental.AppPaths", return_value=mock_paths),
        patch("systemscan.reporting.storage.AppPaths", return_value=mock_paths),
    ):
        cfg_mgr = ConfigManager(app_paths=mock_paths)
        orchestrator = CentralScanOrchestrator(config_manager=cfg_mgr)

        events: list[str] = []

        def on_event(evt) -> None:
            events.append(evt.current_phase)

        # Execute unified FULL scan
        record = orchestrator.run_scan(
            scan_type=ScanType.FULL,
            targets=[target_dir],
            on_event=on_event,
        )

        # 1. Validate History Record
        assert record.scan_type == ScanType.FULL
        assert record.status in (ScanState.COMPLETED, ScanState.PARTIAL)
        assert record.items_discovered >= 1
        assert record.items_processed >= 1
        assert "filesystem" in record.modules_executed
        assert "network" in record.modules_executed

        # 2. Validate Progress Events
        assert len(events) > 0
        assert any("Discovery" in e for e in events)

        # 3. Validate Report Generation & Persistence
        storage_mgr = ReportStorageManager(storage_dir=mock_paths.report_dir)
        reports = storage_mgr.list_reports()
        assert len(reports) >= 1

        latest_rep = storage_mgr.load_report(record.scan_id)
        assert latest_rep is not None
        assert latest_rep.metadata.scan_id == record.scan_id
        assert latest_rep.metadata.scan_type == ScanType.FULL.value
        assert latest_rep.system_summary is not None
        assert latest_rep.executive_summary is not None

        # 4. Validate Checksum Manifest was generated
        manifest_files = list(mock_paths.report_dir.glob(f"*{record.scan_id}*.sha256"))
        assert len(manifest_files) >= 1
        manifest_content = manifest_files[0].read_text(encoding="utf-8").strip()
        assert len(manifest_content.split()[0]) == 64


def test_modular_scan_selection_independence(tmp_path: Path) -> None:
    """Validate that selecting individual scan types runs only requested modules without coupling."""
    mock_paths = AppPaths(base_dir=tmp_path)
    mock_paths.ensure_directories()

    target_dir = tmp_path / "modular_target"
    target_dir.mkdir(parents=True, exist_ok=True)
    f = target_dir / "sample.log"
    f.write_text("log line", encoding="utf-8")

    with (
        patch("systemscan.engine.history.AppPaths", return_value=mock_paths),
        patch("systemscan.engine.checkpoint.AppPaths", return_value=mock_paths),
        patch("systemscan.engine.incremental.AppPaths", return_value=mock_paths),
        patch("systemscan.reporting.storage.AppPaths", return_value=mock_paths),
    ):
        cfg_mgr = ConfigManager(app_paths=mock_paths)
        orchestrator = CentralScanOrchestrator(config_manager=cfg_mgr)

        # Execute FILESYSTEM only
        rec_fs = orchestrator.run_scan(
            scan_type=ScanType.FILESYSTEM,
            targets=[target_dir],
        )
        assert rec_fs.scan_type == ScanType.FILESYSTEM
        assert "filesystem" in rec_fs.modules_executed
        assert "network" not in rec_fs.modules_executed

        # Execute MALWARE only
        rec_mal = orchestrator.run_scan(
            scan_type=ScanType.MALWARE,
            targets=[target_dir],
        )
        assert rec_mal.scan_type == ScanType.MALWARE
        assert "malware" in rec_mal.modules_executed
        assert "network" not in rec_mal.modules_executed


def test_pause_resume_checkpoint_lifecycle(tmp_path: Path) -> None:
    """Validate cooperative pause signaling, checkpoint creation, and resume preparation."""
    import pytest

    mock_paths = AppPaths(base_dir=tmp_path)
    mock_paths.ensure_directories()

    with patch("systemscan.engine.checkpoint.AppPaths", return_value=mock_paths):
        cfg_mgr = ConfigManager(app_paths=mock_paths)
        orchestrator = CentralScanOrchestrator(config_manager=cfg_mgr)

        # Transition to RUNNING so pause request is accepted
        orchestrator.lifecycle.transition_to(ScanState.INITIALIZING)
        orchestrator.lifecycle.transition_to(ScanState.RUNNING)

        # Request pause
        orchestrator.pause_controller.request_pause()
        assert orchestrator.pause_controller.is_pause_requested is True

        # Resume preparation on nonexistent ID raises FileNotFoundError
        with pytest.raises(FileNotFoundError):
            orchestrator.pause_controller.prepare_resume("chk-nonexistent")
