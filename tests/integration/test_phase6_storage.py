"""Integration tests for Phase 6: CLI storage, cache, and safe cleanup workflows."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from systemscan.cli import app


def test_cli_storage_analyze() -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["storage", "analyze"])
    assert res.exit_code == 0
    assert "Mounted Storage Volumes" in res.output or "Mount Point" in res.output

    # JSON mode
    res_json = runner.invoke(app, ["storage", "analyze", "--format", "json"])
    assert res_json.exit_code == 0
    assert "mount_point" in res_json.output


def test_cli_cache_scan() -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["cache", "scan"])
    assert res.exit_code == 0
    assert "Standard Cache" in res.output or "Category" in res.output

    res_json = runner.invoke(app, ["cache", "scan", "--format", "json"])
    assert res_json.exit_code == 0
    assert "category" in res_json.output


def test_cli_cleanup_preview_and_dryrun(tmp_path: Path) -> None:
    runner = CliRunner()
    target_dir = tmp_path / "test_cleanup_zone"
    target_dir.mkdir()

    # Create dummy temp file and protected document
    (target_dir / "junk.tmp").write_bytes(b"JUNK_DATA" * 50)
    (target_dir / "protected.docx").write_bytes(b"IMPORTANT_DOC" * 50)

    # 1. Preview
    res_prev = runner.invoke(app, ["cleanup", "preview", "--path", str(target_dir)])
    assert res_prev.exit_code == 0
    assert "CLEANUP PREVIEW DASHBOARD" in res_prev.output
    assert "Reclaimable Space:" in res_prev.output

    # 2. Dry-run execution
    res_dry = runner.invoke(app, ["cleanup", "execute", "--path", str(target_dir), "--dry-run"])
    assert res_dry.exit_code == 0
    assert "DRY-RUN Complete" in res_dry.output
    assert (target_dir / "junk.tmp").exists()  # Not deleted in dry run

    # 3. Real authorized execution with --yes
    res_exec = runner.invoke(app, ["cleanup", "execute", "--path", str(target_dir), "--yes"])
    assert res_exec.exit_code == 0
    assert "Cleanup Completed Successfully" in res_exec.output
    assert not (target_dir / "junk.tmp").exists()  # Deleted
    assert (target_dir / "protected.docx").exists()  # Protected file remains intact!
