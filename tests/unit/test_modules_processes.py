"""Unit tests for Process, Service, and Startup inspection modules."""

from unittest.mock import MagicMock

import psutil

from systemscan.modules.models import ProcessSummary
from systemscan.modules.processes.collector import (
    collect_process_summary,
    collect_processes,
)
from systemscan.modules.processes.metadata import extract_process_info
from systemscan.modules.processes.services import collect_services
from systemscan.modules.processes.startup import collect_startup_entries


def test_process_summary() -> None:
    summary = collect_process_summary()
    assert isinstance(summary, ProcessSummary)
    assert summary.total_processes > 0
    assert summary.total_threads >= 0


def test_collect_processes_sorting() -> None:
    # 1. Sort by CPU
    by_cpu = collect_processes(sort_by="cpu", limit=10)
    assert len(by_cpu) <= 10
    if len(by_cpu) >= 2:
        assert by_cpu[0].cpu_percent >= by_cpu[1].cpu_percent

    # 2. Sort by memory
    by_mem = collect_processes(sort_by="mem", limit=10)
    assert len(by_mem) <= 10
    if len(by_mem) >= 2:
        assert by_mem[0].memory_mb >= by_mem[1].memory_mb

    # 3. Sort by PID
    by_pid = collect_processes(sort_by="pid", limit=10)
    assert len(by_pid) <= 10
    if len(by_pid) >= 2:
        assert by_pid[0].pid <= by_pid[1].pid


def test_process_disappearance_handling() -> None:
    # Mock a process that raises NoSuchProcess on inspection
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 99999
    mock_proc.as_dict.side_effect = psutil.NoSuchProcess(pid=99999)

    info = extract_process_info(mock_proc)
    assert info is None


def test_process_access_denied_handling() -> None:
    # Mock a process that raises AccessDenied on detailed inspection
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 1234
    mock_proc.as_dict.side_effect = psutil.AccessDenied(pid=1234)

    info = extract_process_info(mock_proc)
    assert info is not None
    assert info.pid == 1234
    assert info.status == "access_denied"


def test_collect_services() -> None:
    services = collect_services(status_filter="all")
    assert isinstance(services, list)
    for s in services:
        assert len(s.name) > 0
        assert s.status in ("running", "stopped", "paused", "unknown")


def test_collect_startup_entries() -> None:
    entries = collect_startup_entries()
    assert isinstance(entries, list)
    for e in entries:
        assert len(e.name) > 0
        assert len(e.source) > 0
        assert len(e.command) > 0
