"""Comprehensive system overview and diagnostic command for systemscan."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import (
    create_key_value_table,
    render_network_interfaces,
    render_storage_info,
    render_system_overview,
)
from systemscan.core.application import app_instance
from systemscan.modules.system_info.collector import collect_system_information

app = typer.Typer(
    help="Display comprehensive system overview, host intelligence, and runtime diagnostics.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def info_command(
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output presentation format: 'text' or 'json'.",
        ),
    ] = "text",
    include_serials: Annotated[
        bool,
        typer.Option(
            "--include-serials",
            help="Include sensitive hardware serial numbers in output.",
        ),
    ] = False,
    detailed: Annotated[
        bool,
        typer.Option(
            "--detailed",
            "-d",
            help="Include complete storage partitions, network, and environment breakdown.",
        ),
    ] = False,
) -> None:
    """Inspect and present detailed host system overview and intelligence."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    # Read default from config if not explicitly passed as flag
    allow_serials = include_serials or app_instance.config.preferences.include_hardware_serials

    sys_info = collect_system_information(
        include_serials=allow_serials,
        platform_handler=app_instance.platform,
        app_paths=app_instance.paths,
    )

    if format.lower() == "json":
        console.print_json(sys_info.model_dump_json(indent=2))
        return

    # Visual Rich Presentation
    render_system_overview(sys_info)

    if detailed:
        # Storage
        render_storage_info(sys_info.storage, sys_info.physical_disks)
        # Network
        render_network_interfaces(sys_info.network)
        # Environment
        env_dict = sys_info.environment.model_dump()
        env_dict.pop("safe_environment_vars", None)
        console.print(create_key_value_table("Execution Environment", env_dict))
        console.print()
