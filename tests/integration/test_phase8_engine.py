"""Integration tests for Phase 08: Scan Intelligence & Performance CLI commands."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.models import (
    ScanCheckpoint,
    ScanHistoryRecord,
    ScanProgressEvent,
    ScanState,
    ScanType,
)

runner = CliRunner()


class TestPhase8CLIIntegration:
    """Verify performance, history, and scan orchestration CLI subcommands."""

    def test_cli_performance_overview(self) -> None:
        # 1. Text display
        res_text = runner.invoke(app, ["performance"])
        assert res_text.exit_code == 0
        assert "Scan Intelligence & Performance Engine Status" in res_text.output
        assert "Effective Worker Threads:" in res_text.output

        # 2. JSON format
        res_json = runner.invoke(app, ["performance", "--format", "json"])
        assert res_json.exit_code == 0
        data = json.loads(res_json.output)
        assert "resource_snapshot" in data
        assert "concurrency" in data
        assert "effective_workers" in data["concurrency"]

    def test_cli_history_operations(self, tmp_path: Path) -> None:
        hist_file = tmp_path / "scan_history.json"
        mgr = ScanHistoryManager(history_file=hist_file)

        now = datetime.now(timezone.utc)
        record = ScanHistoryRecord(
            scan_id="int-test-01",
            scan_type=ScanType.FILESYSTEM,
            targets=[str(tmp_path)],
            status=ScanState.COMPLETED,
            started_at=now,
            completed_at=now,
            duration_seconds=5.2,
            items_discovered=25,
            items_processed=25,
            bytes_processed=4096,
            findings_count=0,
            items_failed=0,
        )
        mgr.record_session(record)

        # Patch history manager to use temporary path
        from unittest.mock import patch

        with patch("systemscan.cli.commands.history.ScanHistoryManager", return_value=mgr):
            # 1. List text
            res_list = runner.invoke(app, ["history"], env={"COLUMNS": "160"})
            assert res_list.exit_code == 0
            assert "int-test-01" in res_list.output
            assert "COMPLETED" in res_list.output

            # 2. List JSON
            res_json = runner.invoke(app, ["history", "--format", "json"])
            assert res_json.exit_code == 0
            items = json.loads(res_json.output)
            assert len(items) == 1
            assert items[0]["scan_id"] == "int-test-01"

            # 3. Show detail
            res_show = runner.invoke(app, ["history", "show", "int-test-01"])
            assert res_show.exit_code == 0
            assert "int-test-01" in res_show.output

            # 4. Clear confirmation
            res_clear = runner.invoke(app, ["history", "clear", "--yes"])
            assert res_clear.exit_code == 0
            assert "historical scan execution records have been cleared" in res_clear.output

    def test_cli_scan_start_and_status(self, tmp_path: Path) -> None:
        sample_file = tmp_path / "hello.txt"
        sample_file.write_text("sample content for scan")

        # Run orchestrated scan with quiet mode
        res_start = runner.invoke(
            app,
            ["scan", "start", "--type", "filesystem", "--path", str(tmp_path), "--quiet"],
        )
        assert res_start.exit_code == 0

        # Scan status and list
        res_status = runner.invoke(app, ["scan", "status"])
        assert res_status.exit_code == 0

        res_list = runner.invoke(app, ["scan", "list"])
        assert res_list.exit_code == 0

    def test_cli_scan_pause_and_cancel_commands(self, tmp_path: Path) -> None:
        ckpt_dir = tmp_path / "checkpoints"
        ckpt_mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir)

        progress = ScanProgressEvent(
            scan_id="paused-01",
            state=ScanState.PAUSED,
            current_phase="MALWARE",
        )
        ckpt = ScanCheckpoint(
            scan_id="paused-01",
            scan_type=ScanType.MALWARE,
            targets=[str(tmp_path)],
            progress=progress,
            current_phase="MALWARE",
        )
        ckpt_mgr.save_checkpoint(ckpt)

        from unittest.mock import patch

        with patch("systemscan.engine.checkpoint.ScanCheckpointManager", return_value=ckpt_mgr):
            # Pause signal
            res_pause = runner.invoke(app, ["scan", "pause", "--id", "paused-01"])
            assert res_pause.exit_code == 0
            assert "Signal pause sent" in res_pause.output

            # Status check
            res_stat = runner.invoke(app, ["scan", "status", "--id", "paused-01"])
            assert res_stat.exit_code == 0
            assert "paused-01" in res_stat.output

            # Cancel checkpoint
            res_cancel = runner.invoke(app, ["scan", "cancel", "--id", "paused-01"])
            assert res_cancel.exit_code == 0
            assert "cancelled and checkpoint deleted" in res_cancel.output
