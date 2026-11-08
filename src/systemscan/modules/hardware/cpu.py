"""CPU inspection and hardware telemetry module for systemscan."""

from __future__ import annotations

import os
import platform
from typing import Any

import cpuinfo
import psutil

from systemscan.logging.logger import get_logger
from systemscan.modules.models import CPUInformation

logger = get_logger("hardware.cpu")

# Cache static CPU metadata to avoid expensive repeated queries
_CACHED_CPU_STATIC: dict[str, Any] | None = None


def get_static_cpu_info() -> dict[str, Any]:
    """Retrieve and cache static processor specifications using py-cpuinfo."""
    global _CACHED_CPU_STATIC
    if _CACHED_CPU_STATIC is not None:
        return _CACHED_CPU_STATIC

    try:
        info = cpuinfo.get_cpu_info()
    except Exception as e:
        logger.debug(f"py-cpuinfo failed: {e}. Falling back to platform info.")
        info = {}

    brand = info.get("brand_raw") or platform.processor() or "Unknown CPU"
    vendor = info.get("vendor_id_raw") or "Unknown"
    arch = info.get("arch") or platform.machine()

    _CACHED_CPU_STATIC = {
        "vendor": vendor,
        "model": brand,
        "architecture": arch,
    }
    return _CACHED_CPU_STATIC


def collect_cpu_info(interval: float | None = 0.1) -> CPUInformation:
    """Collect comprehensive CPU specifications and real-time utilization telemetry."""
    static = get_static_cpu_info()

    # Physical and logical core counts
    physical_cores = psutil.cpu_count(logical=False)
    logical_cores = psutil.cpu_count(logical=True)

    # CPU Frequencies
    current_freq: float | None = None
    min_freq: float | None = None
    max_freq: float | None = None

    try:
        freq = psutil.cpu_freq()
        if freq:
            current_freq = freq.current
            min_freq = freq.min if freq.min > 0 else None
            max_freq = freq.max if freq.max > 0 else None
    except Exception as e:
        logger.debug(f"Could not retrieve CPU frequency: {e}")

    # Instantaneous or short-sample CPU utilization
    try:
        utilization = float(psutil.cpu_percent(interval=interval))
        per_core = [float(p) for p in psutil.cpu_percent(interval=None, percpu=True)]
    except Exception as e:
        logger.debug(f"Could not calculate CPU utilization: {e}")
        utilization = 0.0
        per_core = []

    # System load averages (Linux/macOS; Windows not natively supported in standard psutil)
    load_avg: tuple[float, float, float] | None = None
    if hasattr(os, "getloadavg"):
        try:
            load_avg = os.getloadavg()
        except OSError:
            pass

    # CPU temperature (where sensors exposed and accessible)
    temperature: float | None = None
    try:
        if hasattr(psutil, "sensors_temperatures"):
            sensors = psutil.sensors_temperatures()
            if sensors:
                for _name, entries in sensors.items():
                    for entry in entries:
                        if entry.current is not None and entry.current > 0:
                            temperature = float(entry.current)
                            break
                    if temperature is not None:
                        break
    except Exception as e:
        logger.debug(f"Could not read CPU temperature sensors: {e}")

    return CPUInformation(
        vendor=static["vendor"],
        model=static["model"],
        architecture=static["architecture"],
        physical_cores=physical_cores,
        logical_cores=logical_cores,
        current_frequency_mhz=current_freq,
        min_frequency_mhz=min_freq,
        max_frequency_mhz=max_freq,
        utilization_percent=utilization,
        per_core_utilization=per_core,
        load_averages=load_avg,
        temperature_celsius=temperature,
    )
