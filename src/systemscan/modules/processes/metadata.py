"""Process metadata extraction and defensive attribute reading for systemscan."""

from __future__ import annotations

from datetime import datetime, timezone

import psutil

from systemscan.modules.models import ProcessInformation


def extract_process_info(
    proc: psutil.Process,
    include_handles: bool = False,
) -> ProcessInformation | None:
    """Safely extract metadata for a single process, handling disappearance or access denial."""
    try:
        # Use as_dict with specific attributes to minimize syscalls
        info = proc.as_dict(
            attrs=[
                "pid",
                "name",
                "ppid",
                "exe",
                "username",
                "status",
                "cpu_percent",
                "memory_percent",
                "memory_info",
                "create_time",
                "num_threads",
            ]
        )
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None
    except psutil.AccessDenied:
        # Return partial information accessible without elevated rights
        return ProcessInformation(
            pid=proc.pid,
            name="[Access Denied]",
            status="access_denied",
        )

    pid = info.get("pid") or proc.pid
    name = info.get("name") or "Unknown"
    ppid = info.get("ppid")
    exe = info.get("exe")
    username = info.get("username")
    status = str(info.get("status") or "unknown")
    cpu_pct = float(info.get("cpu_percent") or 0.0)
    mem_pct = float(info.get("memory_percent") or 0.0)

    mem_info = info.get("memory_info")
    mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0

    ctime_raw = info.get("create_time")
    ctime_str = ""
    if ctime_raw:
        try:
            ctime_str = datetime.fromtimestamp(ctime_raw, tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            pass

    threads = info.get("num_threads")

    open_files_cnt: int | None = None
    connections_cnt: int | None = None

    if include_handles:
        try:
            open_files = proc.open_files()
            open_files_cnt = len(open_files)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

        try:
            conns = proc.net_connections(kind="inet")
            connections_cnt = len(conns)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

    return ProcessInformation(
        pid=pid,
        name=name,
        ppid=ppid,
        exe_path=exe,
        username=username,
        status=status,
        cpu_percent=cpu_pct,
        memory_percent=mem_pct,
        memory_mb=round(mem_mb, 2),
        create_time=ctime_str,
        thread_count=threads,
        open_files_count=open_files_cnt,
        connections_count=connections_cnt,
    )
