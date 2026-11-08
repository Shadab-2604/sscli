"""Unit tests for systemscan uninstall CLI command and data preservation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.utils.paths import AppPaths

runner = CliRunner()


def test_uninstall_plan_preserves_data_by_default(tmp_path: Path) -> None:
    """Verify that default uninstall command preserves user data and does not delete directories."""
    mock_paths = AppPaths(base_dir=tmp_path)
    mock_paths.ensure_directories()
    assert mock_paths.config_dir.exists()
    assert mock_paths.data_dir.exists()

    with patch("systemscan.cli.commands.uninstall.AppPaths", return_value=mock_paths):
        result = runner.invoke(app, ["uninstall", "--dry-run"])
        assert result.exit_code == 0
        assert "USER DATA PRESERVED BY DEFAULT" in result.output
        assert mock_paths.config_dir.exists()
        assert mock_paths.data_dir.exists()


def test_uninstall_remove_data_dry_run(tmp_path: Path) -> None:
    """Verify that --remove-data with --dry-run simulates deletion without modifying filesystem."""
    mock_paths = AppPaths(base_dir=tmp_path)
    mock_paths.ensure_directories()

    with patch("systemscan.cli.commands.uninstall.AppPaths", return_value=mock_paths):
        result = runner.invoke(app, ["uninstall", "--remove-data", "--dry-run"])
        assert result.exit_code == 0
        assert "COMPLETE APPLICATION DATA PURGE REQUESTED" in result.output
        assert "[DRY-RUN]" in result.output
        assert mock_paths.config_dir.exists()


def test_uninstall_remove_data_with_confirmation(tmp_path: Path) -> None:
    """Verify that --remove-data --yes deletes application directories within bounded base directory."""
    mock_paths = AppPaths(base_dir=tmp_path)
    mock_paths.ensure_directories()
    test_file = mock_paths.config_dir / "config.json"
    test_file.write_text("{}", encoding="utf-8")
    assert test_file.exists()

    with patch("systemscan.cli.commands.uninstall.AppPaths", return_value=mock_paths):
        result = runner.invoke(app, ["uninstall", "--remove-data", "--yes"])
        assert result.exit_code == 0
        assert "Application data purged" in result.output
        assert not test_file.exists()
