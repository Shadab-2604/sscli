"""Service inspection commands for systemscan."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import render_services_table
from systemscan.core.application import app_instance
from systemscan.modules.processes.services import collect_services

app = typer.Typer(
    name="services",
    help="Inspect, list, and filter host background system services and daemons.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def services_command(
    status: Annotated[
        str,
        typer.Option(
            "--status",
            "-s",
            help="Filter services by status: 'all', 'running', or 'stopped'.",
        ),
    ] = "running",
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output presentation format: 'text' or 'json'.",
        ),
    ] = "text",
) -> None:
    """Enumerate system background services and daemons."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    services = collect_services(status_filter=status, platform_handler=app_instance.platform)

    if format.lower() == "json":
        data = [s.model_dump(mode="json") for s in services]
        console.print_json(json.dumps(data, indent=2))
        return

    render_services_table(services)
