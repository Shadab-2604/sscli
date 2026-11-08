"""Configuration management commands for systemscan."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from systemscan.cli.display import print_info
from systemscan.core.application import app_instance

app = typer.Typer(
    name="config",
    help="Manage, inspect, backup, and reset application configuration.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def default_config_command(ctx: typer.Context) -> None:
    """Show current active configuration if no subcommand is passed."""
    if ctx.invoked_subcommand is None:
        show_config()


@app.command("show")
def show_config() -> None:
    """Display active configuration in formatted JSON."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    cfg_dict = app_instance.config_manager.current.model_dump(mode="json")
    json_str = json.dumps(cfg_dict, indent=2)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)

    panel = Panel(
        syntax,
        title=f"[cyan]Configuration: {app_instance.paths.config_file}[/cyan]",
        border_style="cyan",
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()


@app.command("path")
def path_config() -> None:
    """Display the filesystem path of the configuration file."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    print_info("Configuration Path", str(app_instance.paths.config_file))


@app.command("backup")
def backup_config() -> None:
    """Create a timestamped backup of the current configuration file."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    backup_path = app_instance.config_manager.create_backup()
    print_info("Backup Created", f"Configuration safely backed up to:\n{backup_path}")


@app.command("reset")
def reset_config(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Force reset without interactive confirmation")
    ] = False,
) -> None:
    """Reset configuration to defaults with safety backup."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    if not force:
        confirm = typer.confirm(
            "Are you sure you want to reset configuration to defaults? (A backup will be created)",
            default=False,
        )
        if not confirm:
            console.print("[yellow]Reset cancelled by user.[/yellow]")
            return

    app_instance.config_manager.reset(create_backup_first=True)
    console.print(
        "[green]Configuration successfully reset to defaults. Previous config backed up.[/green]"
    )


@app.command("validate")
def validate_config() -> None:
    """Validate current configuration file against schema."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    app_instance.config_manager.load()
    console.print(f"[green]Configuration at {app_instance.paths.config_file} is valid.[/green]")
