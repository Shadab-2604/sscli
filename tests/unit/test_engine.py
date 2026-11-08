"""Unit test suite for Phase 08: Scan Intelligence & Performance Engine."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.concurrency import IntelligentConcurrencyManager
from systemscan.engine.deduplication import ScanDeduplicationManager
from systemscan.engine.eta import IntelligentETAEngine
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.incremental import IncrementalScanEngine
from systemscan.engine.lifecycle import (
    InvalidScanStateTransitionError,
    ScanLifecycleCoordinator,
)
from systemscan.engine.models import (
    ConcurrencyMode,
    IncrementalVerificationMode,
    ScanCheckpoint,
    ScanHistoryRecord,
    ScanProgressEvent,
    ScanState,
    ScanType,
)
from systemscan.engine.pause_resume import ScanPauseResumeController
from systemscan.engine.resource_monitor import SystemResourceMonitor


class TestScanLifecycle:
    """Validate scan state transitions, guards, and transition coordinator."""

    def test_valid_state_transitions(self) -> None:
        coordinator = ScanLifecycleCoordinator()
        assert coordinator.state == ScanState.QUEUED

        coordinator.transition_to(ScanState.INITIALIZING)
        assert coordinator.state == ScanState.INITIALIZING

        coordinator.transition_to(ScanState.RUNNING)
        assert coordinator.state == ScanState.RUNNING

        coordinator.transition_to(ScanState.PAUSING)
        assert coordinator.state == ScanState.PAUSING

        coordinator.transition_to(ScanState.PAUSED)
        assert coordinator.state == ScanState.PAUSED

        coordinator.transition_to(ScanState.RESUMING)
        assert coordinator.state == ScanState.RESUMING

        coordinator.transition_to(ScanState.RUNNING)
        assert coordinator.state == ScanState.RUNNING

        coordinator.transition_to(ScanState.COMPLETED)
        assert coordinator.state == ScanState.COMPLETED

    def test_invalid_state_transition_raises_error(self) -> None:
        coordinator = ScanLifecycleCoordinator()
        assert coordinator.state == ScanState.QUEUED

        # Cannot jump from QUEUED directly to COMPLETED or PAUSED
        with pytest.raises(InvalidScanStateTransitionError):
            coordinator.transition_to(ScanState.COMPLETED)

        with pytest.raises(InvalidScanStateTransitionError):
            coordinator.transition_to(ScanState.PAUSED)

    def test_terminal_state_cannot_transition(self) -> None:
        coordinator = ScanLifecycleCoordinator()
        coordinator.transition_to(ScanState.INITIALIZING)
        coordinator.transition_to(ScanState.CANCELLING)
        coordinator.transition_to(ScanState.CANCELLED)

        assert coordinator.state == ScanState.CANCELLED
        with pytest.raises(InvalidScanStateTransitionError):
            coordinator.transition_to(ScanState.RUNNING)

    def test_callbacks_on_transition(self) -> None:
        events: list[tuple[ScanState, ScanState]] = []

        def on_change(old_st: ScanState, new_st: ScanState) -> None:
            events.append((old_st, new_st))

        coordinator = ScanLifecycleCoordinator()
        coordinator.register_callback(on_change)
        coordinator.transition_to(ScanState.INITIALIZING)
        coordinator.transition_to(ScanState.RUNNING)

        assert len(events) == 2
        assert events[0] == (ScanState.QUEUED, ScanState.INITIALIZING)
        assert events[1] == (ScanState.INITIALIZING, ScanState.RUNNING)


class TestConcurrencyManager:
    """Validate concurrency allocation, adaptive throttling, and sequential mode."""

    def test_sequential_mode_uses_one_worker(self) -> None:
        mgr = IntelligentConcurrencyManager(
            mode=ConcurrencyMode.SEQUENTIAL,
            configured_max_workers=8,
        )
        assert mgr.get_optimal_worker_count() == 1

    def test_fixed_mode_clamps_workers(self) -> None:
        mgr = IntelligentConcurrencyManager(
            mode=ConcurrencyMode.FIXED,
            configured_max_workers=4,
        )
        assert mgr.get_optimal_worker_count() == 4

    def test_adaptive_mode_caps_at_configured_max(self) -> None:
        mgr = IntelligentConcurrencyManager(
            mode=ConcurrencyMode.ADAPTIVE,
            configured_max_workers=2,
        )
        assert mgr.get_optimal_worker_count() <= 2

    def test_adaptive_throttles_under_high_load(self) -> None:
        mgr = IntelligentConcurrencyManager(
            mode=ConcurrencyMode.ADAPTIVE,
            configured_max_workers=8,
        )
        mgr.physical_cores = 8
        with patch.object(SystemResourceMonitor, "is_resource_constrained", return_value=True):
            workers = mgr.get_optimal_worker_count()
            assert workers == 4  # 8 // 2 = 4

    def test_adaptive_reduces_to_one_on_low_battery(self) -> None:
        mgr = IntelligentConcurrencyManager(
            mode=ConcurrencyMode.ADAPTIVE,
            configured_max_workers=8,
        )
        with patch.object(SystemResourceMonitor, "is_on_low_battery", return_value=True):
            assert mgr.get_optimal_worker_count() == 1


class TestIntelligentETAEngine:
    """Validate ETA calculations, smoothing, and unknown workload handling."""

    def test_unknown_workload_returns_none(self) -> None:
        eta_engine = IntelligentETAEngine()
        # Discovery not complete or totals unknown
        eta_engine.record_progress(items_delta=10, bytes_delta=1024)

        elapsed, remaining, pct = eta_engine.calculate_eta()
        assert remaining is None
        assert pct is None

    def test_known_workload_progress_percentage(self) -> None:
        eta_engine = IntelligentETAEngine(min_samples_for_eta=10)
        eta_engine.set_discovered_totals(
            total_items=200, total_bytes=20480, discovery_complete=True
        )
        eta_engine.record_progress(items_delta=50, bytes_delta=5120)

        elapsed, remaining, pct = eta_engine.calculate_eta()
        assert pct is not None
        assert abs(pct - 25.0) < 0.1

    def test_eta_calculation_after_min_samples(self) -> None:
        eta_engine = IntelligentETAEngine(min_samples_for_eta=5)
        eta_engine.set_discovered_totals(
            total_items=100, total_bytes=10000, discovery_complete=True
        )
        eta_engine.record_progress(items_delta=10, bytes_delta=1000)

        elapsed, remaining, pct = eta_engine.calculate_eta()
        assert pct == 10.0
        assert remaining is not None
        assert remaining >= 0.0


class TestIncrementalScanning:
    """Validate incremental file skipping, verification modes, and persistence."""

    def test_fast_verification_skips_unchanged_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "sample.txt"
        test_file.write_text("hello world")

        cache_file = tmp_path / "cache.json"
        engine = IncrementalScanEngine(
            cache_path=cache_file,
            verification_mode=IncrementalVerificationMode.FAST,
        )

        stat = test_file.stat()
        # First check: not in cache -> should scan
        should_scan, cached = engine.should_scan_file(
            path=str(test_file),
            size_bytes=stat.st_size,
            modified_time=stat.st_mtime,
        )
        assert should_scan is True
        assert cached is None

        # Record scan
        engine.record_scan_result(
            path=str(test_file),
            size_bytes=stat.st_size,
            modified_time=stat.st_mtime,
            status="CLEAN",
        )
        engine.save_cache()

        # Second check: file unchanged -> should skip
        should_scan_2, cached_2 = engine.should_scan_file(
            path=str(test_file),
            size_bytes=stat.st_size,
            modified_time=stat.st_mtime,
        )
        assert should_scan_2 is False
        assert cached_2 is not None

    def test_thorough_verification_always_rescans(self, tmp_path: Path) -> None:
        test_file = tmp_path / "data.bin"
        test_file.write_text("data")

        cache_file = tmp_path / "cache.json"
        engine = IncrementalScanEngine(
            cache_path=cache_file,
            verification_mode=IncrementalVerificationMode.THOROUGH,
        )

        stat = test_file.stat()
        engine.record_scan_result(
            path=str(test_file),
            size_bytes=stat.st_size,
            modified_time=stat.st_mtime,
            status="CLEAN",
        )

        # In thorough mode, even unchanged files must be scanned
        should_scan, _ = engine.should_scan_file(
            path=str(test_file),
            size_bytes=stat.st_size,
            modified_time=stat.st_mtime,
        )
        assert should_scan is True

    def test_modified_size_forces_rescan(self, tmp_path: Path) -> None:
        test_file = tmp_path / "modified.txt"
        test_file.write_text("initial")

        cache_file = tmp_path / "cache.json"
        engine = IncrementalScanEngine(
            cache_path=cache_file,
            verification_mode=IncrementalVerificationMode.FAST,
        )

        stat = test_file.stat()
        engine.record_scan_result(
            path=str(test_file),
            size_bytes=stat.st_size,
            modified_time=stat.st_mtime,
        )

        # Change size
        should_scan, _ = engine.should_scan_file(
            path=str(test_file),
            size_bytes=stat.st_size + 100,
            modified_time=stat.st_mtime,
        )
        assert should_scan is True


class TestCheckpointManager:
    """Validate atomic saving, loading, corruption recovery, and retention pruning."""

    def test_save_and_load_checkpoint(self, tmp_path: Path) -> None:
        ckpt_dir = tmp_path / "checkpoints"
        mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir)

        progress = ScanProgressEvent(
            scan_id="test-scan-001",
            state=ScanState.RUNNING,
            current_phase="MALWARE",
            items_processed=50,
            bytes_processed=1024,
        )
        ckpt = ScanCheckpoint(
            scan_id="test-scan-001",
            scan_type=ScanType.FILESYSTEM,
            targets=[str(tmp_path)],
            progress=progress,
            current_phase="MALWARE",
        )

        saved_path = mgr.save_checkpoint(ckpt)
        assert saved_path.exists()

        loaded = mgr.load_checkpoint("test-scan-001")
        assert loaded is not None
        assert loaded.scan_id == "test-scan-001"
        assert loaded.progress.items_processed == 50

    def test_corrupted_checkpoint_recovery(self, tmp_path: Path) -> None:
        ckpt_dir = tmp_path / "checkpoints"
        ckpt_dir.mkdir(parents=True, exist_ok=True)
        corrupt_file = ckpt_dir / "corrupt-scan.json"
        corrupt_file.write_text("{bad json")

        mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir)
        loaded = mgr.load_checkpoint("corrupt-scan")
        assert loaded is None
        assert not corrupt_file.exists()
        assert (ckpt_dir / "corrupt-scan.corrupt").exists()

    def test_retention_pruning(self, tmp_path: Path) -> None:
        ckpt_dir = tmp_path / "checkpoints"
        mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir, retention_count=2)

        for i in range(5):
            progress = ScanProgressEvent(
                scan_id=f"scan-{i}",
                state=ScanState.RUNNING,
                current_phase="TRAVERSAL",
            )
            ckpt = ScanCheckpoint(
                scan_id=f"scan-{i}",
                scan_type=ScanType.FILESYSTEM,
                targets=[str(tmp_path)],
                progress=progress,
                current_phase="TRAVERSAL",
            )
            mgr.save_checkpoint(ckpt)
            time.sleep(0.01)

        remaining = mgr.list_checkpoints()
        assert len(remaining) <= 2


class TestPauseResumeController:
    """Validate pause signaling and resume preparations."""

    def test_pause_request_and_confirmation(self, tmp_path: Path) -> None:
        lifecycle = ScanLifecycleCoordinator()
        lifecycle.transition_to(ScanState.INITIALIZING)
        lifecycle.transition_to(ScanState.RUNNING)

        ckpt_mgr = ScanCheckpointManager(checkpoint_dir=tmp_path / "ckpts")
        ctrl = ScanPauseResumeController(lifecycle=lifecycle, checkpoint_manager=ckpt_mgr)

        assert not ctrl.is_pause_requested
        ctrl.request_pause()
        assert ctrl.is_pause_requested
        assert lifecycle.state == ScanState.PAUSING

        progress = ScanProgressEvent(
            scan_id="test-pause", state=ScanState.PAUSED, current_phase="TEST"
        )
        ckpt = ScanCheckpoint(
            scan_id="test-pause",
            scan_type=ScanType.FILESYSTEM,
            targets=[str(tmp_path)],
            progress=progress,
            current_phase="TEST",
        )
        ctrl.confirm_paused(ckpt)
        assert lifecycle.state == ScanState.PAUSED
        assert not ctrl.is_pause_requested

    def test_prepare_resume(self, tmp_path: Path) -> None:
        ckpt_dir = tmp_path / "ckpts"
        ckpt_mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir)

        progress = ScanProgressEvent(scan_id="res-01", state=ScanState.PAUSED, current_phase="TEST")
        ckpt = ScanCheckpoint(
            scan_id="res-01",
            scan_type=ScanType.FILESYSTEM,
            targets=[str(tmp_path)],
            progress=progress,
            current_phase="TEST",
        )
        ckpt_mgr.save_checkpoint(ckpt)

        lifecycle = ScanLifecycleCoordinator(initial_state=ScanState.PAUSED)
        ctrl = ScanPauseResumeController(lifecycle=lifecycle, checkpoint_manager=ckpt_mgr)

        resumed_ckpt = ctrl.prepare_resume("res-01")
        assert resumed_ckpt.scan_id == "res-01"
        assert lifecycle.state == ScanState.RESUMING


class TestScanDeduplication:
    """Validate path normalization and ancestor root pruning."""

    def test_prunes_nested_child_directories(self, tmp_path: Path) -> None:
        parent = tmp_path / "parent"
        parent.mkdir()
        child = parent / "child"
        child.mkdir()
        other = tmp_path / "other"
        other.mkdir()

        pruned = ScanDeduplicationManager.normalize_and_prune_paths(
            [str(parent), str(child), str(other)]
        )
        assert len(pruned) == 2
        assert parent.resolve() in pruned
        assert other.resolve() in pruned
        assert child.resolve() not in pruned


class TestScanHistoryManager:
    """Validate session history recording, querying, and clearing."""

    def test_record_and_query_history(self, tmp_path: Path) -> None:
        hist_file = tmp_path / "history.json"
        mgr = ScanHistoryManager(history_file=hist_file)

        now = datetime.now(timezone.utc)
        record = ScanHistoryRecord(
            scan_id="hist-001",
            scan_type=ScanType.MALWARE,
            targets=[str(tmp_path)],
            status=ScanState.COMPLETED,
            started_at=now,
            completed_at=now,
            duration_seconds=12.5,
            items_discovered=100,
            items_processed=100,
            bytes_processed=50000,
            findings_count=1,
            items_failed=0,
        )
        mgr.record_session(record)

        sessions = mgr.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].scan_id == "hist-001"
        assert sessions[0].findings_count == 1

    def test_clear_history_requires_confirmation(self, tmp_path: Path) -> None:
        hist_file = tmp_path / "history.json"
        mgr = ScanHistoryManager(history_file=hist_file)

        with pytest.raises(PermissionError):
            mgr.clear_history(confirm=False)


class TestSystemResourceMonitor:
    """Validate resource querying and system metric captures."""

    def test_query_snapshot(self) -> None:
        snapshot = SystemResourceMonitor.get_snapshot()
        assert snapshot.cpu_percent >= 0.0
        assert snapshot.memory_percent >= 0.0
        assert snapshot.memory_available_mb >= 0.0
