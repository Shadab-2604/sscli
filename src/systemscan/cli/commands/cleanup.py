"""CLI commands for cleanup previews, dry-runs, and authorized execution."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.prompt import Confirm

from systemscan.cli.display import render_cleanup_preview
from systemscan.core.application import app_instance
from systemscan.modules.storage.cleanup.executor import SafeCleanupExecutor
from systemscan.modules.storage.cleanup.planner import CleanupPlanner
from systemscan.modules.storage.models import format_bytes

app = typer.Typer(
    name="cleanup",
    help="Preview and safely clean approved temporary and cache storage.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def default_cleanup(
    ctx: typer.Context,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Simulate cleanup without deleting any files."),
    ] = False,
) -> None:
    """Default entrypoint for `systemscan cleanup` -> previews candidates."""
    if ctx.invoked_subcommand is None:
        if dry_run:
            execute_cleanup(dry_run=True, yes=True)
        else:
            preview_cleanup()


@app.command(name="preview")
def preview_cleanup(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Optional specific directory to preview for cleanup."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Scan and generate a pre-execution cleanup preview without modifying any files."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target_dirs = [Path(path)] if path else None
    preview = CleanupPlanner.generate_preview(target_paths=target_dirs)

    if format.lower() == "json":
        console.print_json(preview.model_dump_json(indent=2))
    else:
        render_cleanup_preview(preview)


@app.command(name="execute")
def execute_cleanup(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Target directory to clean."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Simulate deletion and measure reclaimable space without modifying files.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Bypass interactive confirmation prompt."),
    ] = False,
) -> None:
    """Safely delete explicitly approved cleanup candidates."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target_dirs = [Path(path)] if path else None
    preview = CleanupPlanner.generate_preview(target_paths=target_dirs)

    if preview.total_reclaimable_bytes == 0:
        console.print("[green]No safe cleanup candidates discovered.[/green]")
        return

    render_cleanup_preview(preview)

    if dry_run:
        console.print(
            "[bold yellow]Executing simulated DRY-RUN (no files will be deleted)...[/bold yellow]\n"
        )
        executor = SafeCleanupExecutor()
        audit = executor.execute_cleanup(preview, dry_run=True)
        console.print(
            f"[bold green]DRY-RUN Complete:[/bold green] Simulated deletion of {audit.deleted_files_count} files ({format_bytes(audit.actual_reclaimed_bytes)})."
        )
        return

    # Deletion requires confirmation
    if not yes:
        confirmed = Confirm.ask(
            f"[bold red]Are you sure you want to permanently delete {preview.category_counts.get('temporary_files', 0) + preview.category_counts.get('user_cache', 0)} approved cache/temp files ({preview.total_reclaimable_formatted})?[/bold red]"
        )
        if not confirmed:
            console.print("[yellow]Cleanup aborted by user.[/yellow]")
            return

    console.print("\n[bold green]Proceeding with authorized cleanup...[/bold green]")
    executor = SafeCleanupExecutor()
    audit = executor.execute_cleanup(preview, authorized=True, dry_run=False)

    console.print("[bold green]Cleanup Completed Successfully:[/bold green]")
    console.print(f" - Deleted Files: [green]{audit.deleted_files_count}[/green]")
    console.print(f" - Skipped Files: [yellow]{audit.skipped_files_count}[/yellow]")
    console.print(f" - Failed Files: [red]{audit.failed_files_count}[/red]")
    console.print(
        f" - Actual Space Reclaimed: [bold green]{audit.actual_reclaimed_formatted}[/bold green]"
    )
    console.print(f" - Audit ID: [dim]{audit.operation_id}[/dim]\n")
