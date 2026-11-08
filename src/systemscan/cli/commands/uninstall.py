"""Application uninstallation and user data preservation command."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("cli.uninstall")
console = Console(stderr=True)

app = typer.Typer(
    name="uninstall",
    help="Safely uninstall application components and manage application data preservation.",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def uninstall_main(
    remove_data: Annotated[
        bool,
        typer.Option(
            "--remove-data",
            help="Also delete all application data, configuration, scan history, reports, and logs.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Simulate the uninstall procedure and display paths without deleting anything.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Bypass interactive confirmation prompt.",
        ),
    ] = False,
) -> None:
    """Safely uninstall systemscan and manage application data preservation."""
    app_paths = AppPaths()

    console.print("\n[bold cyan]SystemScan Safe Uninstaller[/bold cyan]")
    console.print("=" * 60)

    # 1. Show package environment info
    is_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    env_type = "Isolated Virtual Environment" if is_venv else "Global / User Environment"

    env_table = Table(
        title="Application Installation State", show_header=True, header_style="bold blue"
    )
    env_table.add_column("Property", style="bold", width=25)
    env_table.add_column("Location / Detail")

    env_table.add_row("Execution Prefix", sys.prefix)
    env_table.add_row("Environment Type", env_type)
    env_table.add_row("Module Location", str(app_paths.install_dir))
    console.print(env_table)
    console.print()

    # 2. Show Application Data Paths
    data_table = Table(
        title="Application User Data & Configuration", show_header=True, header_style="bold magenta"
    )
    data_table.add_column("Role", style="bold", width=20)
    data_table.add_column("Filesystem Path")
    data_table.add_column("Action", width=18)

    action_label = "[red]DELETE[/red]" if remove_data else "[green]PRESERVE[/green]"

    tracked_dirs = [
        ("Configuration", app_paths.config_dir),
        ("Scan Data & History", app_paths.data_dir),
        ("Reports Directory", app_paths.report_dir),
        ("Logs Directory", app_paths.log_dir),
        ("Cache Directory", app_paths.cache_dir),
        ("Backups Directory", app_paths.backup_dir),
    ]

    for role, path in tracked_dirs:
        exists_str = " (exists)" if path.exists() else " (absent)"
        data_table.add_row(role, f"{path}{exists_str}", action_label)

    console.print(data_table)
    console.print()

    if not remove_data:
        console.print(
            Panel(
                "[green]USER DATA PRESERVED BY DEFAULT[/green]\n"
                "Your configuration, reports, scan history, baselines, and logs will remain untouched.\n\n"
                "To remove the Python package from this environment, execute:\n"
                f"  [bold cyan]{sys.executable} -m pip uninstall -y systemscan[/bold cyan]\n\n"
                "Or run the automated platform uninstaller script:\n"
                "  Linux/macOS: [bold cyan]bash scripts/uninstall.sh[/bold cyan]\n"
                "  Windows:     [bold cyan]powershell -File scripts/uninstall.ps1[/bold cyan]\n\n"
                "If you also wish to permanently erase all configuration and reports, re-run with:\n"
                "  [bold yellow]systemscan uninstall --remove-data[/bold yellow]",
                title="Uninstallation Plan",
                border_style="green",
            )
        )
        return

    # User requested --remove-data
    console.print(
        Panel(
            "[bold red]WARNING: COMPLETE APPLICATION DATA PURGE REQUESTED[/bold red]\n"
            "This operation will permanently delete:\n"
            f"  • Configuration files ({app_paths.config_file})\n"
            f"  • All generated scan reports ({app_paths.report_dir})\n"
            f"  • Historical scan session ledgers ({app_paths.data_dir})\n"
            f"  • Application operational logs ({app_paths.log_dir})\n\n"
            "This action CANNOT be undone.",
            title="Destructive Action Confirmation",
            border_style="red",
        )
    )

    if dry_run:
        console.print("[yellow][DRY-RUN] No files or directories were deleted.[/yellow]")
        return

    if not yes:
        confirmed = typer.confirm(
            "Are you sure you want to permanently delete all application data?"
        )
        if not confirmed:
            console.print("[yellow]Uninstallation aborted by user. No data was deleted.[/yellow]")
            return

    # Execute safe deletion of application directories
    console.print("\n[bold red]Removing application data directories...[/bold red]")
    deleted_count = 0
    dirs_to_clean = {
        app_paths.cache_dir,
        app_paths.log_dir,
        app_paths.data_dir,
        app_paths.config_dir,
    }

    for target_dir in dirs_to_clean:
        target_path = Path(target_dir).resolve()

        # Path traversal and safety guard: Never delete system root or home root
        home = Path.home().resolve()
        if target_path in (Path("/"), Path("C:\\"), home, target_path.parent == target_path):
            logger.error(f"Refusing to delete unsafe directory boundary: {target_path}")
            continue

        if target_path.exists():
            try:
                shutil.rmtree(target_path)
                console.print(f"  [red]Deleted:[/red] {target_path}")
                deleted_count += 1
            except Exception as e:
                console.print(f"  [yellow]Failed to delete {target_path}: {e}[/yellow]")
                logger.warning(f"Failed to remove directory {target_path}: {e}")

    console.print(
        f"\n[green]Application data purged ({deleted_count} directories removed).[/green]"
    )
    console.print(
        "To finish removing the systemscan binary, execute:\n"
        f"  [bold cyan]{sys.executable} -m pip uninstall -y systemscan[/bold cyan]\n"
    )
