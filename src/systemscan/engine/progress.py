"""Unified progress event dispatching, rate limiting, and Rich rendering system."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from systemscan.engine.models import ScanProgressEvent
from systemscan.logging.logger import get_logger
from systemscan.utils.formatting import format_bytes

logger = get_logger("engine.progress")


class ProgressEventDispatcher:
    """Manages subscription, rate-limiting, and terminal presentation of scan progress events."""

    def __init__(
        self,
        console: Console | None = None,
        refresh_interval: float = 1.0,
        quiet: bool = False,
        json_progress: bool = False,
    ) -> None:
        self.console = console or Console()
        self.refresh_interval = refresh_interval
        self.quiet = quiet
        self.json_progress = json_progress

        self._listeners: list[Callable[[ScanProgressEvent], None]] = []
        self._last_emit_time = 0.0

    def add_listener(self, callback: Callable[[ScanProgressEvent], None]) -> None:
        """Register an external event callback."""
        self._listeners.append(callback)

    def dispatch(self, event: ScanProgressEvent, force: bool = False) -> None:
        """Broadcast progress event to all listeners and render display if interval has elapsed."""
        now = time.perf_counter()
        if not force and (now - self._last_emit_time) < self.refresh_interval:
            return

        self._last_emit_time = now

        # Machine-readable output
        if self.json_progress:
            payload = event.model_dump(mode="json")
            self.console.print(json.dumps(payload))
            return

        # Quiet mode suppresses live presentation
        if not self.quiet:
            self.render_progress(event)

        for callback in self._listeners:
            try:
                callback(event)
            except Exception as e:
                logger.debug(f"Progress listener exception: {e}")

    def render_progress(self, event: ScanProgressEvent) -> None:
        """Render a clean, high-density terminal dashboard panel."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right", width=18)
        grid.add_column(style="bold white")

        pct_str = (
            f"{event.completion_percent:.1f}%"
            if event.completion_percent is not None
            else "[dim]Calculating...[/dim]"
        )
        speed_items = f"{int(event.processing_rate_items_sec):,} items/sec"
        speed_bytes = f"{format_bytes(int(event.processing_rate_bytes_sec))}/sec"

        grid.add_row("Status / Phase:", f"[{event.state.value}] {event.current_phase}")
        if event.current_target:
            grid.add_row("Current Target:", f"[dim]{event.current_target[:60]}[/dim]")
        grid.add_row(
            "Items Processed:",
            f"{event.items_processed:,} / {event.items_discovered:,} ({pct_str})",
        )
        grid.add_row("Data Processed:", f"{format_bytes(event.bytes_processed)}")
        grid.add_row("Processing Speed:", f"{speed_items} ({speed_bytes})")
        grid.add_row("Elapsed Duration:", event.formatted_elapsed)
        grid.add_row("Estimated Remaining:", event.formatted_remaining)

        if event.resource_usage:
            cpu_val = f"{event.resource_usage.cpu_percent:.1f}%"
            mem_val = f"{event.resource_usage.memory_percent:.1f}% ({event.resource_usage.memory_available_mb:.0f} MB free)"
            grid.add_row(
                "Host Load (CPU/RAM):", f"[yellow]{cpu_val}[/yellow] / [magenta]{mem_val}[/magenta]"
            )

        panel = Panel(
            grid,
            title="[bold cyan]SYSTEM SECURITY & INTELLIGENCE SCANNER[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
            expand=False,
        )
        self.console.print(panel)
