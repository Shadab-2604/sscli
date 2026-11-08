"""Consolidated system intelligence collector orchestrator for systemscan."""

from __future__ import annotations

import time

from systemscan.logging.logger import get_logger
from systemscan.modules.hardware.cpu import collect_cpu_info
from systemscan.modules.hardware.firmware import collect_firmware_info
from systemscan.modules.hardware.gpu import collect_gpu_info
from systemscan.modules.hardware.memory import collect_memory_info
from systemscan.modules.hardware.storage import collect_storage_info
from systemscan.modules.models import SystemInformation
from systemscan.modules.processes.collector import collect_process_summary
from systemscan.modules.system_info.environment import (
    collect_application_environment,
    collect_execution_environment,
)
from systemscan.modules.system_info.network_interfaces import (
    collect_network_interfaces,
)
from systemscan.modules.system_info.operating_system import (
    collect_operating_system_info,
)
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform
from systemscan.utils.paths import AppPaths, paths

logger = get_logger("system_info.collector")


class SystemInfoCollector:
    """Orchestrates comprehensive, cross-platform host system intelligence collection."""

    def __init__(
        self,
        platform_handler: PlatformInterface | None = None,
        app_paths: AppPaths | None = None,
        include_serials: bool = False,
    ) -> None:
        self.platform = platform_handler or detect_platform()
        self.paths = app_paths or paths
        self.include_serials = include_serials

    def collect(self) -> SystemInformation:
        """Run all inspection subsystems and construct a unified SystemInformation snapshot."""
        start_time = time.perf_counter()
        logger.debug("Starting comprehensive system intelligence inspection...")

        # 1. Operating System
        os_info = collect_operating_system_info(self.platform)

        # 2. Execution & Application Environment
        exec_env = collect_execution_environment(self.platform)
        app_env = collect_application_environment(self.paths)

        # 3. CPU & Memory
        cpu_info = collect_cpu_info(interval=0.05)
        mem_info = collect_memory_info()

        # 4. Storage & Partitions
        partitions, physical_disks = collect_storage_info(self.platform)

        # 5. GPUs & Firmware
        gpus = collect_gpu_info(self.platform)
        firmware = collect_firmware_info(
            include_serials=self.include_serials, platform_handler=self.platform
        )

        # 6. Network Interfaces
        network = collect_network_interfaces()

        # 7. Process Summary
        proc_summary = collect_process_summary()

        duration = time.perf_counter() - start_time
        logger.debug(f"System intelligence collection completed in {duration:.3f}s")

        return SystemInformation(
            os=os_info,
            environment=exec_env,
            application=app_env,
            cpu=cpu_info,
            memory=mem_info,
            storage=partitions,
            physical_disks=physical_disks,
            gpus=gpus,
            firmware=firmware,
            network=network,
            process_summary=proc_summary,
        )


def collect_system_information(
    include_serials: bool = False,
    platform_handler: PlatformInterface | None = None,
    app_paths: AppPaths | None = None,
) -> SystemInformation:
    """Convenience function to inspect host and return SystemInformation."""
    collector = SystemInfoCollector(
        platform_handler=platform_handler,
        app_paths=app_paths,
        include_serials=include_serials,
    )
    return collector.collect()
