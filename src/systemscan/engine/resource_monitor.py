"""System resource consumption and power telemetry monitor for adaptive workload management."""

from __future__ import annotations

import psutil

from systemscan.engine.models import ResourceUsageSnapshot
from systemscan.logging.logger import get_logger

logger = get_logger("engine.resource_monitor")


class SystemResourceMonitor:
    """Monitors live host CPU, memory, and battery status for adaptive workload management."""

    @staticmethod
    def get_snapshot() -> ResourceUsageSnapshot:
        """Capture current resource utilization metrics."""
        # Non-blocking CPU measurement
        try:
            cpu_pct = psutil.cpu_percent(interval=None)
        except Exception:
            cpu_pct = 0.0

        # Memory telemetry
        try:
            mem = psutil.virtual_memory()
            mem_pct = mem.percent
            mem_avail_mb = round(mem.available / (1024 * 1024), 2)
        except Exception:
            mem_pct = 0.0
            mem_avail_mb = 0.0

        # Battery / power status where supported
        battery_pct: float | None = None
        power_plugged: bool | None = None
        try:
            if hasattr(psutil, "sensors_battery"):
                battery = psutil.sensors_battery()
                if battery is not None:
                    battery_pct = round(battery.percent, 1)
                    power_plugged = battery.power_plugged
        except Exception as e:
            logger.debug(f"Battery sensors inspection unavailable: {e}")

        return ResourceUsageSnapshot(
            cpu_percent=cpu_pct,
            memory_percent=mem_pct,
            memory_available_mb=mem_avail_mb,
            battery_percent=battery_pct,
            power_plugged=power_plugged,
        )

    @classmethod
    def is_resource_constrained(
        cls,
        max_cpu_percent: float = 85.0,
        max_memory_percent: float = 75.0,
    ) -> bool:
        """Determine whether current system resource consumption exceeds throttle ceilings."""
        snapshot = cls.get_snapshot()
        return (
            snapshot.cpu_percent >= max_cpu_percent or snapshot.memory_percent >= max_memory_percent
        )

    @classmethod
    def is_on_low_battery(cls, threshold_pct: float = 20.0) -> bool:
        """Determine if system is running on battery below safe operational threshold."""
        snapshot = cls.get_snapshot()
        if snapshot.power_plugged is False and snapshot.battery_percent is not None:
            return snapshot.battery_percent <= threshold_pct
        return False
