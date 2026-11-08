"""Process inspection commands for systemscan."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import render_processes_table
from systemscan.core.application import app_instance
from systemscan.modules.processes.collector import collect_processes

app = typer.Typer(
    name="processes",
    help="Inspect, list, and sort active host processes.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def processes_command(
    sort: Annotated[
        str,
        typer.Option(
            "--sort",
            "-s",
            help="Sort processes by 'cpu', 'mem', 'name', or 'pid'.",
        ),
    ] = "cpu",
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-l",
            help="Maximum number of processes to display.",
        ),
    ] = 25,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'text' or 'json'.",
        ),
    ] = "text",
) -> None:
    """Enumerate running processes sorted by resource consumption or identifier."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    procs = collect_processes(sort_by=sort, limit=limit)

    if format.lower() == "json":
        data = [p.model_dump(mode="json") for p in procs]
        console.print_json(json.dumps(data, indent=2))
        return

    render_processes_table(procs)
