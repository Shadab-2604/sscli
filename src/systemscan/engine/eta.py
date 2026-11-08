"""Dynamic scan duration estimation (ETA) and throughput smoothing engine."""

from __future__ import annotations

import time

from systemscan.logging.logger import get_logger

logger = get_logger("engine.eta")


class IntelligentETAEngine:
    """Estimates scan completion time with exponential smoothing and unknown-workload guards."""

    def __init__(self, smoothing_factor: float = 0.20, min_samples_for_eta: int = 25) -> None:
        self.smoothing_factor = smoothing_factor  # Alpha for Exponential Moving Average
        self.min_samples_for_eta = min_samples_for_eta

        self.start_time = time.perf_counter()
        self.last_update_time = self.start_time

        self.total_items_discovered: int | None = None
        self.total_bytes_estimated: int | None = None

        self.items_processed: int = 0
        self.bytes_processed: int = 0

        self.smoothed_items_per_sec: float = 0.0
        self.smoothed_bytes_per_sec: float = 0.0

        self.is_discovery_complete: bool = False

    def set_discovered_totals(
        self,
        total_items: int | None,
        total_bytes: int | None = None,
        discovery_complete: bool = False,
    ) -> None:
        """Update discovery bounds as directory trees and storage volumes are enumerated."""
        self.total_items_discovered = total_items
        self.total_bytes_estimated = total_bytes
        self.is_discovery_complete = discovery_complete

    def record_progress(self, items_delta: int = 1, bytes_delta: int = 0) -> None:
        """Record newly processed units and update smoothed throughput rates."""
        now = time.perf_counter()
        elapsed_since_update = now - self.last_update_time

        self.items_processed += items_delta
        self.bytes_processed += bytes_delta

        if elapsed_since_update >= 0.25:  # Update rates at max 4 Hz
            instant_items_rate = (
                items_delta / elapsed_since_update if elapsed_since_update > 0 else 0.0
            )
            instant_bytes_rate = (
                bytes_delta / elapsed_since_update if elapsed_since_update > 0 else 0.0
            )

            if self.smoothed_items_per_sec == 0.0:
                self.smoothed_items_per_sec = instant_items_rate
                self.smoothed_bytes_per_sec = instant_bytes_rate
            else:
                alpha = self.smoothing_factor
                self.smoothed_items_per_sec = (alpha * instant_items_rate) + (
                    (1.0 - alpha) * self.smoothed_items_per_sec
                )
                self.smoothed_bytes_per_sec = (alpha * instant_bytes_rate) + (
                    (1.0 - alpha) * self.smoothed_bytes_per_sec
                )

            self.last_update_time = now

    def calculate_eta(self) -> tuple[float, float | None, float | None]:
        """Compute (elapsed_seconds, estimated_remaining_seconds, completion_percent).

        Returns:
            elapsed_seconds: Total time elapsed since scan start.
            estimated_remaining_seconds: Estimated seconds remaining, or None if unknown.
            completion_percent: Percentage completed (0.0 - 100.0), or None if total unknown.
        """
        now = time.perf_counter()
        elapsed_seconds = now - self.start_time

        # If discovery is not complete or total items are not known, do NOT fabricate an ETA or percentage
        if (
            not self.is_discovery_complete
            or self.total_items_discovered is None
            or self.total_items_discovered <= 0
        ):
            return elapsed_seconds, None, None

        # If we have insufficient processed samples, ETA is too volatile to display
        if self.items_processed < self.min_samples_for_eta:
            completion_pct = min(
                100.0, (self.items_processed / self.total_items_discovered) * 100.0
            )
            return elapsed_seconds, None, completion_pct

        # Calculate completion percentage
        completion_pct = min(100.0, (self.items_processed / self.total_items_discovered) * 100.0)

        # Fallback to cumulative average if smoothed rate is zero
        effective_rate = self.smoothed_items_per_sec
        if effective_rate <= 0.1:
            effective_rate = self.items_processed / elapsed_seconds if elapsed_seconds > 0 else 0.0

        if effective_rate <= 0.0:
            return elapsed_seconds, None, completion_pct

        remaining_items = max(0, self.total_items_discovered - self.items_processed)
        estimated_remaining_seconds = remaining_items / effective_rate

        return elapsed_seconds, round(estimated_remaining_seconds, 1), round(completion_pct, 2)
