"""Operating system discovery engine for systemscan."""

from __future__ import annotations

import os
import platform
import sys
import time
from datetime import datetime, timezone

import psutil

from systemscan.modules.models import OperatingSystemModel
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform


def detect_active_shell() -> str | None:
    """Detect current executing shell (bash, zsh, fish, powershell, cmd)."""
    # 1. Check SHELL environment variable (POSIX)
    shell_env = os.environ.get("SHELL")
    if shell_env:
        return os.path.basename(shell_env)

    # 2. Check PowerShell environment or ComSpec (Windows)
    if os.environ.get("PSExecutionPolicyPreference") or os.environ.get("PSModulePath"):
        return "powershell"

    comspec = os.environ.get("COMSPEC")
    if comspec:
        return os.path.basename(comspec).lower()

    return None


def collect_operating_system_info(
    platform_handler: PlatformInterface | None = None,
) -> OperatingSystemModel:
    """Collect comprehensive operating system identification and uptime metrics."""
    handler = platform_handler or detect_platform()

    # System boot time & uptime
    boot_timestamp = psutil.boot_time()
    boot_dt = datetime.fromtimestamp(boot_timestamp, tz=timezone.utc)
    uptime_sec = max(0.0, time.time() - boot_timestamp)

    # Linux distribution details
    distro_name, distro_ver = handler.get_linux_distribution()

    # Kernel & build details
    kernel = platform.release()
    build = platform.version()

    return OperatingSystemModel(
        family=platform.system(),
        name=handler.os_name,
        version=handler.os_version,
        release=platform.release(),
        distro_name=distro_name,
        distro_version=distro_ver,
        kernel_version=kernel,
        build_info=build,
        hostname=platform.node(),
        machine_arch=platform.machine(),
        processor_arch=platform.processor() or platform.machine(),
        python_version=platform.python_version(),
        python_executable=sys.executable,
        shell=detect_active_shell(),
        boot_time=boot_dt.isoformat(),
        uptime_seconds=uptime_sec,
    )
