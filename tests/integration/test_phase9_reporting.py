"""Integration tests for Phase 09: Report CLI commands and multi-format exports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.models import ScanHistoryRecord, ScanState, ScanType
from systemscan.reporting.storage import ReportStorageManager

runner = CliRunner()


class TestReportCLIIntegration:
    """Verify report subcommands: list, show, generate, export, verify, delete."""

    def test_cli_report_workflow(self, tmp_path: Path) -> None:
        report_dir = tmp_path / "reports"
        hist_file = tmp_path / "history.json"

        storage_mgr = ReportStorageManager(storage_dir=report_dir)
        hist_mgr = ScanHistoryManager(history_file=hist_file)

        # 1. Seed scan history
        now = datetime.now(timezone.utc)
        record = ScanHistoryRecord(
            scan_id="int-scan-01",
            scan_type=ScanType.FULL,
            targets=[str(tmp_path)],
            status=ScanState.COMPLETED,
            started_at=now,
            ended_at=now,
            duration_seconds=15.2,
            items_discovered=100,
            items_processed=100,
            bytes_processed=20480,
            findings_count=0,
            items_failed=0,
        )
        hist_mgr.record_session(record)

        with (
            patch("systemscan.cli.commands.reports.ReportStorageManager", return_value=storage_mgr),
            patch("systemscan.reporting.exporter.ReportStorageManager", return_value=storage_mgr),
            patch("systemscan.cli.commands.reports.ScanHistoryManager", return_value=hist_mgr),
        ):
            # 2. List (initially empty)
            res_init = runner.invoke(app, ["report", "list"])
            assert res_init.exit_code == 0
            assert "No reports found" in res_init.output

            # 3. Generate JSON report
            res_gen = runner.invoke(
                app, ["report", "generate", "--scan-id", "int-scan-01", "--format", "json"]
            )
            assert res_gen.exit_code == 0
            assert "Report successfully generated" in res_gen.output

            # 4. List reports
            res_list = runner.invoke(app, ["report", "list"])
            assert res_list.exit_code == 0
            assert "Saved Scan Reports" in res_list.output
            assert "JSON" in res_list.output

            # Find generated report id
            reports = storage_mgr.list_reports()
            assert len(reports) == 1
            rep_id = reports[0]["report_id"]

            # 5. Show report
            res_show = runner.invoke(app, ["report", "show", rep_id])
            assert res_show.exit_code == 0
            assert "UNIVERSAL SYSTEM SECURITY & INTELLIGENCE AUDIT REPORT" in res_show.output

            # 6. Verify checksum
            res_verify = runner.invoke(app, ["report", "verify", rep_id])
            assert res_verify.exit_code == 0
            assert "matches cryptographic SHA-256" in res_verify.output

            # 7. Export CSV
            csv_target = tmp_path / "custom_export.csv"
            res_csv = runner.invoke(
                app,
                [
                    "report",
                    "export",
                    "--scan-id",
                    "int-scan-01",
                    "--format",
                    "csv",
                    "--output",
                    str(csv_target),
                ],
            )
            assert res_csv.exit_code == 0
            assert csv_target.exists()

            # 8. Export Redacted JSON
            redact_target = tmp_path / "redacted.json"
            res_redact = runner.invoke(
                app,
                [
                    "report",
                    "export",
                    "--scan-id",
                    "int-scan-01",
                    "--format",
                    "json",
                    "--redact",
                    "--output",
                    str(redact_target),
                ],
            )
            assert res_redact.exit_code == 0
            assert redact_target.exists()
            redacted_data = json.loads(redact_target.read_text(encoding="utf-8"))
            assert redacted_data["metadata"]["is_redacted"] is True

            # 9. Delete report
            res_del = runner.invoke(app, ["report", "delete", rep_id, "--yes"])
            assert res_del.exit_code == 0
            assert f"Report '{rep_id}' successfully deleted" in res_del.output
            assert len(storage_mgr.list_reports()) == 0
