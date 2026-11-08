"""Integration tests for Phase 2 CLI commands and formatting."""

import json

from typer.testing import CliRunner

from systemscan.cli import app

runner = CliRunner()


def test_cli_info_text() -> None:
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "SYSTEM INTELLIGENCE OVERVIEW" in result.output
    assert "CPU" in result.output
    assert "MEMORY" in result.output


def test_cli_info_json() -> None:
    result = runner.invoke(app, ["info", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "os" in data
    assert "cpu" in data
    assert "memory" in data
    assert "storage" in data
    assert "network" in data


def test_cli_hardware_components() -> None:
    # 1. CPU
    res_cpu = runner.invoke(app, ["hardware", "--component", "cpu"])
    assert res_cpu.exit_code == 0
    assert "Processor" in res_cpu.output

    # 2. Memory
    res_mem = runner.invoke(app, ["hardware", "--component", "memory"])
    assert res_mem.exit_code == 0
    assert "Physical RAM" in res_mem.output

    # 3. Storage
    res_storage = runner.invoke(app, ["hardware", "--component", "storage"])
    assert res_storage.exit_code == 0

    # 4. JSON
    res_json = runner.invoke(app, ["hardware", "--component", "cpu", "--format", "json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert "cpu" in data


def test_cli_processes() -> None:
    # 1. Text table
    result = runner.invoke(app, ["processes", "--limit", "5"])
    assert result.exit_code == 0
    assert "Active System Processes" in result.output

    # 2. JSON
    res_json = runner.invoke(
        app, ["processes", "--sort", "mem", "--limit", "3", "--format", "json"]
    )
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert isinstance(data, list)
    assert len(data) <= 3


def test_cli_services() -> None:
    result = runner.invoke(app, ["services"])
    assert result.exit_code == 0
    assert "System Services" in result.output


def test_cli_startup() -> None:
    result = runner.invoke(app, ["startup"])
    assert result.exit_code == 0
    assert "Startup Applications & Persistence" in result.output


def test_cli_monitor_single_iteration() -> None:
    result = runner.invoke(app, ["monitor", "--iterations", "1"])
    assert result.exit_code == 0
    assert "REAL-TIME SYSTEM MONITOR" in result.output
    assert "CPU Usage" in result.output
    assert "RAM Usage" in result.output
