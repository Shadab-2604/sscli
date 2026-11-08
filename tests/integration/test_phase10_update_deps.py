"""Integration tests for Phase 10: Dependency Manager & Application Self-Update System CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.version import __version__

runner = CliRunner()


def test_cli_doctor_command() -> None:
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code in (0, 1)
    assert "SystemScan Environment Doctor" in res.output
    assert "Python Version" in res.output
    assert "Virtual Environment" in res.output
    assert "Package Dependencies" in res.output


def test_cli_doctor_verbose_command() -> None:
    res = runner.invoke(app, ["doctor", "--verbose"])
    assert res.exit_code in (0, 1)
    assert "App Storage Paths & Permissions" in res.output


def test_cli_dependencies_list() -> None:
    res = runner.invoke(app, ["dependencies", "list"])
    assert res.exit_code == 0
    assert "Application Dependency Registry" in res.output
    assert "typer" in res.output
    assert "rich" in res.output


def test_cli_dependencies_check() -> None:
    res = runner.invoke(app, ["dependencies", "check"])
    assert res.exit_code in (0, 1)
    assert "Checking Application Dependencies" in res.output


def test_cli_dependencies_missing() -> None:
    res = runner.invoke(app, ["dependencies", "missing"])
    assert res.exit_code == 0


def test_cli_dependencies_verify() -> None:
    res = runner.invoke(app, ["dependencies", "verify"])
    assert res.exit_code == 0
    assert "Verifying Installed Dependency Runtimes" in res.output


def test_cli_dependencies_install_dry_run() -> None:
    res = runner.invoke(app, ["dependencies", "install", "requests", "--dry-run", "--allow-global"])
    assert res.exit_code == 0
    assert "DRY-RUN" in res.output


def test_cli_update_status() -> None:
    res = runner.invoke(app, ["update", "status"])
    assert res.exit_code == 0
    assert "Application Update Status" in res.output
    assert __version__ in res.output


def test_cli_update_history() -> None:
    res = runner.invoke(app, ["update", "history"])
    assert res.exit_code == 0


def test_cli_update_version() -> None:
    res = runner.invoke(app, ["update", "version"])
    assert res.exit_code == 0
    assert __version__ in res.output


def test_cli_top_level_version() -> None:
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert __version__ in res.output


def test_cli_checkupdate_command() -> None:
    res = runner.invoke(app, ["checkupdate"])
    assert res.exit_code in (0, 1)
    assert "Checking for updates" in res.output


def test_cli_slash_checkupdate_command() -> None:
    res = runner.invoke(app, ["/checkupdate"])
    assert res.exit_code in (0, 1)
    assert "Checking for updates" in res.output
