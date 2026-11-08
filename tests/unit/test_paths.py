"""Unit tests for centralized path management."""

from pathlib import Path

from systemscan.utils.paths import AppPaths


def test_paths_resolution(tmp_path: Path) -> None:
    custom_reports = tmp_path / "my_reports"
    app_paths = AppPaths(custom_report_dir=custom_reports)

    assert app_paths.install_dir.is_dir()
    assert app_paths.report_dir == custom_reports
    assert app_paths.config_file.name == "config.json"

    # Verify directory creation
    app_paths.ensure_directories()
    assert custom_reports.is_dir()
    assert app_paths.config_dir.is_dir()
    assert app_paths.data_dir.is_dir()
    assert app_paths.cache_dir.is_dir()
    assert app_paths.log_dir.is_dir()
    assert app_paths.backup_dir.is_dir()
    assert app_paths.quarantine_dir.is_dir()


def test_paths_as_dict() -> None:
    app_paths = AppPaths()
    d = app_paths.as_dict()
    assert "install_dir" in d
    assert "config_dir" in d
    assert "data_dir" in d
    assert "report_dir" in d
    assert "config_file" in d
