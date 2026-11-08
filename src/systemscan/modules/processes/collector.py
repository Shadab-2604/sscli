"""Process collection and sorting engine for systemscan."""

from __future__ import annotations

import psutil

from systemscan.logging.logger import get_logger
from systemscan.modules.models import ProcessInformation, ProcessSummary
from systemscan.modules.processes.metadata import extract_process_info

logger = get_logger("processes.collector")


def collect_process_summary() -> ProcessSummary:
    """Collect aggregate process counts and thread totals across the host."""
    total = 0
    running = 0
    sleeping = 0
    threads = 0

    for proc in psutil.process_iter(attrs=["status", "num_threads"]):
        try:
            total += 1
            info = proc.info
            status = info.get("status")
            if status == psutil.STATUS_RUNNING:
                running += 1
            elif status == psutil.STATUS_SLEEPING:
                sleeping += 1

            th = info.get("num_threads")
            if th:
                threads += th
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return ProcessSummary(
        total_processes=total,
        running_processes=running,
        sleeping_processes=sleeping,
        total_threads=threads,
    )


def collect_processes(
    sort_by: str = "cpu",
    limit: int | None = 50,
    include_handles: bool = False,
) -> list[ProcessInformation]:
    """Enumerate running processes, sorted by CPU, memory, name, or PID."""
    results: list[ProcessInformation] = []

    for proc in psutil.process_iter():
        item = extract_process_info(proc, include_handles=include_handles)
        if item is not None:
            results.append(item)

    # Sorting
    key = sort_by.lower()
    if key == "cpu":
        results.sort(key=lambda p: p.cpu_percent, reverse=True)
    elif key in ("mem", "memory", "ram"):
        results.sort(key=lambda p: p.memory_mb, reverse=True)
    elif key == "name":
        results.sort(key=lambda p: p.name.lower())
    elif key == "pid":
        results.sort(key=lambda p: p.pid)
    else:
        results.sort(key=lambda p: p.cpu_percent, reverse=True)

    if limit is not None and limit > 0:
        return results[:limit]
    return results
