"""Unit tests for the SSCLI Interactive CLI Interface."""

from __future__ import annotations

import io
from pathlib import Path
from unittest import mock

import pytest
from rich.console import Console

from systemscan.cli.interactive import (
    action_check_updates,
    action_custom_scan,
    action_dependency_doctor,
    action_devices_scanner,
    action_malware_scan,
    action_network_audit,
    action_reports_export,
    action_scan_history,
    action_settings,
    action_storage_analyzer,
    action_system_info,
    render_cli_welcome,
    run_compact_live_scan,
    run_interactive_menu,
)


def test_render_cli_welcome():
    """Verify CLI welcome screen displays branded header, system info, and numbered menu."""
    buf = io.StringIO()
    test_console = Console(file=buf, no_color=True, highlight=False)

    with mock.patch("systemscan.cli.interactive.console", test_console):
        render_cli_welcome()

    output = buf.getvalue()
    assert "SSCLI / SYSTEM SECURITY & INTELLIGENCE" in output
    assert "Universal System Security Scanner" in output
    assert "[SYSTEM]" in output
    assert "OS       :" in output
    assert "CPU      :" in output
    assert "RAM      :" in output
    assert "STATUS   :" in output
    assert "READY" in output
    assert "[MAIN MENU]" in output
    assert "1. System Information" in output
    assert "2. Quick Security Scan" in output
    assert "3. Full System Scan" in output
    assert "4. Custom Path Scan" in output
    assert "5. Malware Detection" in output
    assert "6. Storage Analyzer" in output
    assert "7. Network Security Audit" in output
    assert "8. USB / External Device Scanner & Repair" in output
    assert "9. Scan History" in output
    assert "10. Reports & Export" in output
    assert "11. Dependency Doctor" in output
    assert "12. Settings" in output
    assert "13. Check for Updates & Self-Update" in output
    assert "0. Exit" in output


def test_interactive_menu_exit():
    """Verify selecting option 0 exits cleanly."""
    with mock.patch("systemscan.cli.interactive.Prompt.ask", return_value="0"):
        with pytest.raises(SystemExit) as exc_info:
            run_interactive_menu()
        assert exc_info.value.code == 0


def test_action_system_info():
    """Verify System Information action executes and renders OS & CPU/RAM tables."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_system_info()
    output = buf.getvalue()
    assert "SYSTEM INFORMATION" in output
    assert "Operating System" in output
    assert "CPU & Memory" in output


def test_action_storage_analyzer():
    """Verify Storage Analyzer action executes and renders partition table."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_storage_analyzer()
    output = buf.getvalue()
    assert "STORAGE ANALYZER" in output
    assert "Mounted Storage Partitions" in output


def test_action_network_audit():
    """Verify Network Security Audit executes and renders network tables."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_network_audit()
    output = buf.getvalue()
    assert "NETWORK SECURITY AUDIT" in output
    assert "Firewall" in output


def test_action_devices_scanner():
    """Verify USB & External Device scanner executes without error."""
    buf = io.StringIO()
    test_console = Console(file=buf, no_color=True, highlight=False)
    with (
        mock.patch("systemscan.cli.interactive.console", test_console),
        mock.patch("systemscan.cli.interactive.Prompt.ask", return_value="0"),
    ):
        action_devices_scanner()
    output = buf.getvalue()
    assert "USB & EXTERNAL DEVICE SCANNER" in output
    assert "STORAGE / USB RECOVERY & REPAIR TOOLKIT" in output


def test_action_check_updates():
    """Verify Check for Updates executes and displays version and status."""
    buf = io.StringIO()
    test_console = Console(file=buf, no_color=True, highlight=False)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_check_updates()
    output = buf.getvalue()
    assert "CHECK FOR UPDATES & SELF-UPDATE" in output
    assert "Current Version" in output


def test_action_scan_history():
    """Verify Scan History action retrieves and displays records or empty notice."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_scan_history()
    output = buf.getvalue()
    assert "SCAN HISTORY" in output


def test_action_reports_export():
    """Verify Reports action retrieves and displays reports or empty notice."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_reports_export()
    output = buf.getvalue()
    assert "REPORTS & EXPORT" in output


def test_action_dependency_doctor():
    """Verify Dependency Doctor action executes environment diagnosis."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with (
        mock.patch("systemscan.cli.interactive.console", test_console),
        mock.patch("systemscan.cli.interactive.Prompt.ask", return_value="n"),
    ):
        action_dependency_doctor()
    output = buf.getvalue()
    assert "DEPENDENCY DOCTOR" in output
    assert "Environment Health" in output


def test_action_settings():
    """Verify Settings action displays configuration values."""
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with mock.patch("systemscan.cli.interactive.console", test_console):
        action_settings()
    output = buf.getvalue()
    assert "SETTINGS & CONFIGURATION" in output
    assert "Active Scanner Configuration" in output


def test_run_compact_live_scan_lifecycle(tmp_path: Path):
    """Verify compact live scan traverses directories, updates counters, and saves report."""
    test_file1 = tmp_path / "doc1.txt"
    test_file1.write_text("secure document 1")
    test_file2 = tmp_path / "doc2.log"
    test_file2.write_text("application log")

    buf = io.StringIO()
    test_console = Console(file=buf, no_color=True, highlight=False)

    with mock.patch("systemscan.cli.interactive.console", test_console):
        run_compact_live_scan(
            scan_title="Test Unit Scan",
            roots=[str(tmp_path)],
            enable_malware=False,
        )

    output = buf.getvalue()
    assert "Initializing scanner..." in output
    assert "Scan type: Test Unit Scan" in output
    assert "Scan completed in" in output
    assert "Summary:" in output
    assert "Threats detected: 0" in output


def test_action_custom_scan(tmp_path: Path):
    """Verify custom scan prompts for path and executes scan."""
    buf = io.StringIO()
    test_console = Console(file=buf, no_color=True, highlight=False)

    with (
        mock.patch("systemscan.cli.interactive.console", test_console),
        mock.patch("systemscan.cli.interactive.Prompt.ask", return_value=str(tmp_path)),
    ):
        action_custom_scan()

    output = buf.getvalue()
    assert "Initializing scanner..." in output
    assert "Scan completed in" in output


def test_action_malware_scan(tmp_path: Path):
    """Verify malware scan prompts for path and executes inspection."""
    buf = io.StringIO()
    test_console = Console(file=buf, no_color=True, highlight=False)

    with (
        mock.patch("systemscan.cli.interactive.console", test_console),
        mock.patch("systemscan.cli.interactive.Prompt.ask", return_value=str(tmp_path)),
    ):
        action_malware_scan()

    output = buf.getvalue()
    assert "Initializing scanner..." in output
    assert "Scan completed in" in output
