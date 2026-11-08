"""Startup application and persistence discovery commands for systemscan."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import render_startup_table
from systemscan.core.application import app_instance
from systemscan.modules.processes.startup import collect_startup_entries

app = typer.Typer(
    name="startup",
    help="Discover startup applications, registry persistence, and scheduled autostart entries.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def startup_command(
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output presentation format: 'text' or 'json'.",
        ),
    ] = "text",
) -> None:
    """Discover applications configured to launch on system or user session boot."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    entries = collect_startup_entries(app_instance.platform)

    if format.lower() == "json":
        data = [e.model_dump(mode="json") for e in entries]
        console.print_json(json.dumps(data, indent=2))
        return

    render_startup_table(entries)
