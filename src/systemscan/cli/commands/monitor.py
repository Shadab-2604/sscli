"""Live interactive terminal system monitor command for systemscan."""

from __future__ import annotations

import time
from typing import Annotated

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from systemscan.core.application import app_instance
from systemscan.modules.hardware.cpu import collect_cpu_info
from systemscan.modules.hardware.memory import collect_memory_info
from systemscan.modules.hardware.storage import collect_partition_info
from systemscan.modules.processes.collector import (
    collect_process_summary,
    collect_processes,
)
from systemscan.modules.system_info.operating_system import (
    collect_operating_system_info,
)

app = typer.Typer(
    name="monitor",
    help="Real-time terminal system performance and telemetry monitor.",
    no_args_is_help=False,
)
console = Console()


def build_monitor_dashboard() -> Panel:
    """Construct instantaneous visual telemetry dashboard."""
    # 1. Telemetry samples
    cpu = collect_cpu_info(interval=None)
    mem = collect_memory_info()
    partitions = collect_partition_info()
    proc_summary = collect_process_summary()
    os_info = collect_operating_system_info(app_instance.platform)

    # 2. Header Grid (System & Uptime)
    hdr_table = Table.grid(padding=(0, 3))
    hdr_table.add_column("Key1", style="dim cyan")
    hdr_table.add_column("Val1", style="bold white")
    hdr_table.add_column("Key2", style="dim cyan")
    hdr_table.add_column("Val2", style="bold white")
    hdr_table.add_column("Key3", style="dim cyan")
    hdr_table.add_column("Val3", style="bold white")

    hdr_table.add_row(
        "Host:",
        os_info.hostname,
        "OS:",
        os_info.name,
        "Uptime:",
        os_info.uptime_formatted,
    )
    hdr_table.add_row(
        "Processes:",
        str(proc_summary.total_processes),
        "Threads:",
        str(proc_summary.total_threads),
        "CPU Load:",
        f"{cpu.utilization_percent:.1f}%",
    )

    # 3. CPU & Memory Gauge Grid
    gauge_table = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    gauge_table.add_column("Metric", width=18)
    gauge_table.add_column("Value", width=24)
    gauge_table.add_column("Visual", ratio=1)

    # CPU bar
    cpu_bars = int(cpu.utilization_percent / 5)
    cpu_color = (
        "green"
        if cpu.utilization_percent < 60
        else ("yellow" if cpu.utilization_percent < 85 else "red")
    )
    gauge_table.add_row(
        "[bold cyan]CPU Usage[/bold cyan]",
        f"{cpu.utilization_percent:.1f}% ({cpu.current_freq_formatted})",
        f"[{cpu_color}]{'█' * cpu_bars}{'░' * (20 - cpu_bars)}[/{cpu_color}]",
    )

    # Memory bar
    mem_bars = int(mem.percentage / 5)
    mem_color = "green" if mem.percentage < 70 else ("yellow" if mem.percentage < 90 else "red")
    gauge_table.add_row(
        "[bold cyan]RAM Usage[/bold cyan]",
        f"{mem.used_formatted} / {mem.total_formatted} ({mem.percentage:.1f}%)",
        f"[{mem_color}]{'█' * mem_bars}{'░' * (20 - mem_bars)}[/{mem_color}]",
    )

    # Swap bar
    if mem.swap_total_bytes > 0:
        swp_bars = int(mem.swap_percentage / 5)
        gauge_table.add_row(
            "[bold cyan]Swap Space[/bold cyan]",
            f"{mem.swap_used_formatted} / {mem.swap_total_formatted} ({mem.swap_percentage:.1f}%)",
            f"[dim cyan]{'█' * swp_bars}{'░' * (20 - swp_bars)}[/dim cyan]",
        )

    # 4. Storage volumes mini-table
    storage_table = Table(
        title="Mounted Storage Volumes",
        box=None,
        show_header=True,
        header_style="bold dim cyan",
        padding=(0, 2),
    )
    storage_table.add_column("Mountpoint", style="bold white")
    storage_table.add_column("Filesystem", style="dim")
    storage_table.add_column("Used / Total", justify="right")
    storage_table.add_column("Usage", justify="right")

    for p in partitions[:4]:  # Top 4 volumes to keep compact
        storage_table.add_row(
            p.mountpoint,
            p.filesystem_type,
            f"{p.used_formatted} / {p.total_formatted}",
            f"{p.percentage:.1f}%",
        )

    # 5. Top 5 CPU Processes
    top_cpu = collect_processes(sort_by="cpu", limit=5)
    proc_table = Table(
        title="Top CPU-Consuming Processes",
        box=None,
        show_header=True,
        header_style="bold dim cyan",
        padding=(0, 2),
    )
    proc_table.add_column("PID", style="dim cyan", justify="right")
    proc_table.add_column("Process Name", style="bold white")
    proc_table.add_column("CPU %", justify="right")
    proc_table.add_column("Memory (MB)", justify="right")

    for proc_item in top_cpu:
        proc_table.add_row(
            str(proc_item.pid),
            proc_item.name,
            f"{proc_item.cpu_percent:.1f}%",
            f"{proc_item.memory_mb:.1f}",
        )

    # Assembly into unified Live Panel
    group = Group(
        hdr_table,
        Text("\n" + "─" * 70, style="dim"),
        gauge_table,
        Text("\n" + "─" * 70, style="dim"),
        storage_table,
        Text("\n" + "─" * 70, style="dim"),
        proc_table,
        Text(
            "\n[dim]Press Ctrl+C to stop monitoring and return to shell.[/dim]",
            style="dim",
            justify="center",
        ),
    )

    return Panel(
        group,
        title="[bold cyan]REAL-TIME SYSTEM MONITOR[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
        expand=False,
    )


def run_monitor_loop(
    interval: float = 2.0,
    iterations: int | None = None,
) -> None:
    """Run real-time host performance and resource consumption monitor loop."""
    effective_interval = max(0.2, interval)
    cycles = 0
    try:
        with Live(
            build_monitor_dashboard(),
            console=console,
            refresh_per_second=int(1.0 / effective_interval) or 1,
            transient=False,
        ) as live:
            if iterations == 1:
                return

            while True:
                time.sleep(effective_interval)
                live.update(build_monitor_dashboard())
                cycles += 1
                if iterations is not None and cycles >= iterations:
                    break
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring session stopped by user.[/yellow]")


@app.callback(invoke_without_command=True)
def monitor_command(
    interval: Annotated[
        float,
        typer.Option(
            "--interval",
            "-i",
            help="Telemetry refresh interval in seconds.",
        ),
    ] = 2.0,
    iterations: Annotated[
        int | None,
        typer.Option(
            "--iterations",
            "-n",
            help="Number of telemetry cycles to run before exiting (defaults to continuous).",
        ),
    ] = None,
) -> None:
    """Run real-time host performance and resource consumption monitor."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    run_monitor_loop(interval=interval, iterations=iterations)
