"""Integration tests for Typer CLI commands."""

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.version import __version__

runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Universal System Security & Intelligence CLI" in result.output
    assert "COMMAND [ARGS]..." in result.output


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_info() -> None:
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "SYSTEM INTELLIGENCE OVERVIEW" in result.output
    assert "SYSTEM" in result.output
    assert "CPU" in result.output


def test_cli_config_commands() -> None:
    # 1. Config show
    res_show = runner.invoke(app, ["config", "show"])
    assert res_show.exit_code == 0
    assert "schema_version" in res_show.output

    # 2. Config path
    res_path = runner.invoke(app, ["config", "path"])
    assert res_path.exit_code == 0
    assert "config.json" in res_path.output

    # 3. Config validate
    res_val = runner.invoke(app, ["config", "validate"])
    assert res_val.exit_code == 0
    assert "valid" in res_val.output

    # 4. Config backup
    res_bak = runner.invoke(app, ["config", "backup"])
    assert res_bak.exit_code == 0
    assert "Backup Created" in res_bak.output

    # 5. Config reset force
    res_reset = runner.invoke(app, ["config", "reset", "--force"])
    assert res_reset.exit_code == 0
    assert "reset to defaults" in res_reset.output


def test_cli_reports() -> None:
    result = runner.invoke(app, ["reports"])
    assert result.exit_code == 0
    assert "Report Storage Location" in result.output


def test_cli_update_status() -> None:
    result = runner.invoke(app, ["update", "status"])
    assert result.exit_code == 0
    assert "Application Update Status" in result.output
    assert "Installed Version" in result.output


def test_cli_scan_command() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Perform universal filesystem discovery" in result.output
