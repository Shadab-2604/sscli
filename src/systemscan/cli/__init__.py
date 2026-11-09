"""Main CLI package, Typer application definition, and entry point for systemscan."""

from __future__ import annotations

import sys
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.banner import get_banner_panel, render_banner
from systemscan.cli.commands.cache import app as cache_cmd
from systemscan.cli.commands.cleanup import app as cleanup_cmd
from systemscan.cli.commands.config import app as config_cmd
from systemscan.cli.commands.dependencies import app as dependencies_cmd
from systemscan.cli.commands.devices import app as devices_cmd
from systemscan.cli.commands.doctor import app as doctor_cmd
from systemscan.cli.commands.hardware import app as hardware_cmd
from systemscan.cli.commands.history import app as history_cmd
from systemscan.cli.commands.info import app as info_cmd
from systemscan.cli.commands.malware import app as malware_cmd
from systemscan.cli.commands.monitor import app as monitor_cmd
from systemscan.cli.commands.network import app as network_cmd
from systemscan.cli.commands.network_monitor import app as network_monitor_cmd
from systemscan.cli.commands.performance import app as performance_cmd
from systemscan.cli.commands.processes import app as processes_cmd
from systemscan.cli.commands.reports import app as reports_cmd
from systemscan.cli.commands.scan import app as scan_cmd
from systemscan.cli.commands.services import app as services_cmd
from systemscan.cli.commands.startup import app as startup_cmd
from systemscan.cli.commands.storage import app as storage_cmd
from systemscan.cli.commands.uninstall import app as uninstall_cmd
from systemscan.cli.commands.update import app as update_cmd
from systemscan.cli.display import print_error, print_info, print_warning
from systemscan.cli.menu import run_interactive_menu
from systemscan.core.application import app_instance
from systemscan.version import APP_NAME, __version__

console = Console()

app = typer.Typer(
    name="systemscan",
    help=f"{APP_NAME} - Cross-platform audit, diagnostics, and security scanner.",
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Register modular subcommands
app.add_typer(info_cmd, name="info")
app.add_typer(info_cmd, name="system-info")
app.add_typer(hardware_cmd, name="hardware")
app.add_typer(processes_cmd, name="processes")
app.add_typer(services_cmd, name="services")
app.add_typer(startup_cmd, name="startup")
app.add_typer(monitor_cmd, name="monitor")
app.add_typer(config_cmd, name="config")
app.add_typer(reports_cmd, name="reports")
app.add_typer(reports_cmd, name="report")
app.add_typer(update_cmd, name="update")
app.add_typer(update_cmd, name="/update")
app.add_typer(scan_cmd, name="scan")
app.add_typer(devices_cmd, name="devices")
app.add_typer(malware_cmd, name="malware")
app.add_typer(storage_cmd, name="storage")
app.add_typer(cache_cmd, name="cache")
app.add_typer(cleanup_cmd, name="cleanup")
app.add_typer(network_cmd, name="network")
app.add_typer(network_monitor_cmd, name="network-monitor")
app.add_typer(network_monitor_cmd, name="threat-monitor")
app.add_typer(history_cmd, name="history")
app.add_typer(performance_cmd, name="performance")
app.add_typer(doctor_cmd, name="doctor")
app.add_typer(dependencies_cmd, name="dependencies")
app.add_typer(dependencies_cmd, name="deps")
app.add_typer(uninstall_cmd, name="uninstall")


@app.command("version", help="Display application version information.")
def version_command() -> None:
    """Print application version and exit cleanly."""
    console.print(
        f"[bold cyan]{APP_NAME}[/bold cyan] version [bold white]{__version__}[/bold white]"
    )


@app.command("dashboard", help="Launch the interactive terminal menu.")
def dashboard_command() -> None:
    """Launch the interactive terminal menu."""
    from systemscan.cli.interactive import run_interactive_menu

    run_interactive_menu()
    raise typer.Exit(code=0)


@app.command("checkupdate", help="Check remote repository for updates (alias for 'update check').")
def checkupdate_command(
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Release channel to check (stable, beta, dev)."),
    ] = None,
) -> None:
    """Check remote repository for updates."""
    from systemscan.cli.commands.update import check as update_check

    update_check(channel=channel)


@app.command("/checkupdate", hidden=True)
def slash_checkupdate_command(
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Release channel to check (stable, beta, dev)."),
    ] = None,
) -> None:
    """Check remote repository for updates (slash syntax alias)."""
    from systemscan.cli.commands.update import check as update_check

    update_check(channel=channel)


def version_callback(value: bool) -> None:
    """Print application version and exit cleanly."""
    if value:
        console.print(
            f"[bold cyan]{APP_NAME}[/bold cyan] version [bold white]{__version__}[/bold white]"
        )
        raise typer.Exit(code=0)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the application version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
    debug: Annotated[
        bool,
        typer.Option("--debug", "-d", help="Enable diagnostic debugging mode and full tracebacks."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Enable verbose informational logging."),
    ] = False,
    no_banner: Annotated[
        bool,
        typer.Option("--no-banner", help="Suppress the startup ASCII/Rich banner."),
    ] = False,
    interactive: Annotated[
        bool,
        typer.Option(
            "--interactive",
            "-i",
            help="Launch the interactive terminal menu explicitly.",
        ),
    ] = False,
) -> None:
    """Universal System Security & Intelligence CLI application entry callback."""
    # Bootstrap application container
    app_instance.bootstrap(debug=debug, verbose=verbose)

    # If no subcommand is passed or --interactive was requested:
    if ctx.invoked_subcommand is None:
        if interactive or (
            sys.stdin.isatty() and sys.stdout.isatty() and not debug and not verbose
        ):
            # Launch the clean interactive terminal menu
            from systemscan.cli.interactive import run_interactive_menu

            run_interactive_menu()
            raise typer.Exit(code=0)
        else:
            # Non-interactive without subcommand: show banner and help
            if not no_banner:
                render_banner(console)
            console.print(ctx.get_help())
            raise typer.Exit(code=0)


def main() -> None:
    """Primary console script execution entrypoint."""
    try:
        app(prog_name="systemscan")
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation aborted by user (Ctrl+C).[/yellow]")
        sys.exit(130)
    except typer.Exit as e:
        sys.exit(e.exit_code)
    except Exception as e:
        exit_code = app_instance.error_handler.handle_exception(e)
        sys.exit(exit_code)


__all__ = [
    "app",
    "get_banner_panel",
    "main",
    "print_error",
    "print_info",
    "print_warning",
    "render_banner",
    "run_interactive_menu",
]


if __name__ == "__main__":
    main()
