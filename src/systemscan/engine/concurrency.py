"""Intelligent concurrency and adaptive workload management engine."""

from __future__ import annotations

import concurrent.futures
import os

import psutil

from systemscan.engine.models import ConcurrencyMode
from systemscan.engine.resource_monitor import SystemResourceMonitor
from systemscan.logging.logger import get_logger

logger = get_logger("engine.concurrency")


class IntelligentConcurrencyManager:
    """Dynamically scales thread pools and execution concurrency based on host capacity and load."""

    def __init__(
        self,
        mode: ConcurrencyMode = ConcurrencyMode.ADAPTIVE,
        configured_max_workers: int = 4,
        max_cpu_percent: float = 85.0,
        max_memory_percent: float = 75.0,
    ) -> None:
        self.mode = mode
        self.configured_max_workers = max(1, min(configured_max_workers, 64))
        self.max_cpu_percent = max_cpu_percent
        self.max_memory_percent = max_memory_percent
        self.physical_cores = psutil.cpu_count(logical=False) or os.cpu_count() or 2
        self.logical_cores = psutil.cpu_count(logical=True) or os.cpu_count() or 4

    def get_optimal_worker_count(self) -> int:
        """Calculate recommended worker count according to active mode and host load."""
        if self.mode == ConcurrencyMode.SEQUENTIAL:
            return 1

        if self.mode == ConcurrencyMode.FIXED:
            return self.configured_max_workers

        # ADAPTIVE mode:
        # Base capacity derived from physical cores (avoid hyperthread over-subscription for I/O)
        base_workers = max(1, min(self.physical_cores, self.configured_max_workers))

        # Check low battery first (power conservation takes highest priority)
        if SystemResourceMonitor.is_on_low_battery(threshold_pct=20.0):
            logger.debug("Adaptive concurrency reducing workers to 1 due to low battery.")
            return 1

        # Check resource constraints
        if SystemResourceMonitor.is_resource_constrained(
            max_cpu_percent=self.max_cpu_percent,
            max_memory_percent=self.max_memory_percent,
        ):
            # Throttle concurrency by 50%
            throttled = max(1, base_workers // 2)
            logger.debug(
                f"Adaptive concurrency throttling workers from {base_workers} to {throttled} due to system load."
            )
            return throttled

        return base_workers

    def create_thread_pool(
        self, workers: int | None = None
    ) -> concurrent.futures.ThreadPoolExecutor:
        """Create a bounded ThreadPoolExecutor configured with appropriate worker count."""
        effective_workers = workers if workers is not None else self.get_optimal_worker_count()
        return concurrent.futures.ThreadPoolExecutor(
            max_workers=effective_workers,
            thread_name_prefix="syscan_worker",
        )
