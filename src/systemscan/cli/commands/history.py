"""CLI commands for managing persistent scan session history."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.models import ScanState, ScanType
from systemscan.utils.formatting import format_bytes

console = Console()
app = typer.Typer(
    name="history",
    help="Inspect, filter, and manage historical scan execution records.",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def list_history(
    ctx: typer.Context,
    type: Annotated[
        str | None,
        typer.Option(
            "--type", "-t", help="Filter by scan type (e.g. 'full', 'malware', 'storage')."
        ),
    ] = None,
    status: Annotated[
        str | None,
        typer.Option(
            "--status", "-s", help="Filter by terminal status (e.g. 'COMPLETED', 'FAILED')."
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum records to display."),
    ] = 25,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """List historical scan executions."""
    if ctx.invoked_subcommand is not None:
        return

    mgr = ScanHistoryManager()

    stype: ScanType | None = None
    if type:
        try:
            stype = ScanType[type.upper()]
        except KeyError:
            pass

    sstatus: ScanState | None = None
    if status:
        try:
            sstatus = ScanState[status.upper()]
        except KeyError:
            pass

    sessions = mgr.list_sessions(scan_type=stype, status=sstatus, limit=limit)

    if format.lower() == "json":
        data = [s.model_dump(mode="json") for s in sessions]
        console.print_json(json.dumps(data, indent=2))
        return

    if not sessions:
        console.print("\n[yellow]No scan history records found.[/yellow]\n")
        return

    tbl = Table(
        title="[bold cyan]Scan Execution History[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Scan ID", style="bold white", width=12)
    tbl.add_column("Type", style="yellow")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Duration", justify="right", style="dim")
    tbl.add_column("Items Processed", justify="right", style="green")
    tbl.add_column("Data Volume", justify="right", style="cyan")
    tbl.add_column("Findings", justify="right", style="bold red")
    tbl.add_column("Started At", style="dim")

    for s in sessions:
        st_color = (
            "green"
            if s.status == ScanState.COMPLETED
            else ("yellow" if s.status == ScanState.PAUSED else "red")
        )
        tbl.add_row(
            s.scan_id,
            s.scan_type.value,
            f"[{st_color}]{s.status.value}[/{st_color}]",
            f"{s.duration_seconds:.1f}s",
            f"{s.items_processed:,}",
            format_bytes(s.bytes_processed),
            str(s.findings_count),
            s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print()
    console.print(tbl)
    console.print()


@app.command(name="show")
def show_session(
    scan_id: Annotated[str, typer.Argument(help="Scan ID to display in detail.")],
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Display comprehensive telemetry and execution metadata for a single scan session."""
    mgr = ScanHistoryManager()
    session = mgr.get_session(scan_id)

    if not session:
        console.print(f"[bold red]Error:[/bold red] Scan session '{scan_id}' not found in history.")
        raise typer.Exit(code=1)

    if format.lower() == "json":
        console.print_json(session.model_dump_json(indent=2))
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=22)
    grid.add_column(style="bold white")

    st_color = "green" if session.status == ScanState.COMPLETED else "red"
    grid.add_row("Scan ID:", session.scan_id)
    grid.add_row("Scan Type:", session.scan_type.value)
    grid.add_row("Execution Status:", f"[{st_color}]{session.status.value}[/{st_color}]")
    grid.add_row("Targets:", ", ".join(session.targets) if session.targets else "Default")
    grid.add_row("Started At:", session.started_at.isoformat())
    if session.ended_at:
        grid.add_row("Ended At:", session.ended_at.isoformat())
    grid.add_row("Duration:", f"{session.duration_seconds:.1f} seconds")
    grid.add_row("Items Discovered:", f"{session.items_discovered:,}")
    grid.add_row("Items Processed:", f"{session.items_processed:,}")
    grid.add_row("Items Skipped:", f"{session.items_skipped:,}")
    grid.add_row("Errors Encountered:", f"{session.items_failed}")
    grid.add_row("Data Volume:", format_bytes(session.bytes_processed))
    grid.add_row("Security Findings:", f"[bold red]{session.findings_count}[/bold red]")
    grid.add_row(
        "Modules Executed:",
        ", ".join(session.modules_executed) if session.modules_executed else "None",
    )

    panel = Panel(
        grid,
        title=f"[bold cyan]Scan Session Details: {session.scan_id}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()


@app.command(name="clear")
def clear_history(
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Confirm deletion without interactive prompt."),
    ] = False,
) -> None:
    """Clear all saved scan history records."""
    if not yes:
        confirm = typer.confirm(
            "Are you sure you want to permanently clear all scan execution history?",
            default=False,
        )
        if not confirm:
            console.print("[yellow]History clear cancelled by operator.[/yellow]")
            return

    mgr = ScanHistoryManager()
    mgr.clear_history(confirm=True)
    console.print(
        "[bold green]All historical scan execution records have been cleared.[/bold green]"
    )
