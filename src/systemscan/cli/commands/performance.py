"""CLI command for inspecting system resource capacity and concurrency settings."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from systemscan.config.manager import ConfigManager
from systemscan.engine.concurrency import IntelligentConcurrencyManager
from systemscan.engine.models import ConcurrencyMode
from systemscan.engine.resource_monitor import SystemResourceMonitor

console = Console()
app = typer.Typer(
    name="performance",
    help="Inspect host hardware resources, CPU/memory headroom, and concurrency configuration.",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def performance_overview(
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Display real-time host resource utilization and active concurrency limits."""
    cfg = ConfigManager().load_config()
    perf_cfg = getattr(cfg, "performance", None)

    snap = SystemResourceMonitor.get_snapshot()

    mode_val = ConcurrencyMode.ADAPTIVE
    if perf_cfg and hasattr(perf_cfg, "mode"):
        try:
            mode_val = ConcurrencyMode(perf_cfg.mode.upper())
        except ValueError:
            mode_val = ConcurrencyMode.ADAPTIVE

    max_workers = getattr(perf_cfg, "max_workers", 4) if perf_cfg else 4
    max_cpu = getattr(perf_cfg, "max_cpu_percent", 85.0) if perf_cfg else 85.0
    max_mem = getattr(perf_cfg, "max_memory_percent", 75.0) if perf_cfg else 75.0

    mgr = IntelligentConcurrencyManager(
        mode=mode_val,
        configured_max_workers=max_workers,
        max_cpu_percent=max_cpu,
        max_memory_percent=max_mem,
    )
    effective_workers = mgr.get_optimal_worker_count()

    if format.lower() == "json":
        payload = {
            "resource_snapshot": snap.model_dump(mode="json"),
            "concurrency": {
                "mode": mode_val.value,
                "physical_cores": mgr.physical_cores,
                "logical_cores": mgr.logical_cores,
                "configured_max_workers": mgr.configured_max_workers,
                "effective_workers": effective_workers,
                "max_cpu_throttle_percent": max_cpu,
                "max_memory_throttle_percent": max_mem,
            },
        }
        console.print_json(json.dumps(payload, indent=2))
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=26)
    grid.add_column(style="bold white")

    grid.add_row(
        "CPU Physical / Logical Cores:",
        f"{mgr.physical_cores} physical / {mgr.logical_cores} logical",
    )
    grid.add_row(
        "Current CPU Load:", f"[yellow]{snap.cpu_percent:.1f}%[/yellow] (Ceiling: {max_cpu}%)"
    )
    grid.add_row(
        "Current Memory Usage:",
        f"[magenta]{snap.memory_percent:.1f}%[/magenta] ({snap.memory_available_mb:.0f} MB available)",
    )
    grid.add_row(
        "Power & Battery Status:",
        f"Plugged: {snap.power_plugged}, Battery: {snap.battery_percent or 'N/A'}%",
    )
    grid.add_row("Concurrency Mode:", f"[bold green]{mode_val.value}[/bold green]")
    grid.add_row("Configured Max Workers:", str(mgr.configured_max_workers))
    grid.add_row("Effective Worker Threads:", f"[bold cyan]{effective_workers}[/bold cyan]")

    panel = Panel(
        grid,
        title="[bold cyan]Scan Intelligence & Performance Engine Status[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()
