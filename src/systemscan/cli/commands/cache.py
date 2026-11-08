"""CLI subcommands for cache inspection and browser cache analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from systemscan.core.application import app_instance
from systemscan.modules.storage.cache.browser_cache import BrowserCacheAnalyzer
from systemscan.modules.storage.cache.discovery import CacheDiscoveryEngine
from systemscan.modules.storage.models import format_bytes

app = typer.Typer(
    name="cache",
    help="Discover, analyze, and measure system, application, and browser cache storage.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def default_cache(ctx: typer.Context) -> None:
    """Default entrypoint for `systemscan cache` -> scans standard cache locations."""
    if ctx.invoked_subcommand is None:
        scan_cache(format="text")


@app.command(name="scan")
def scan_cache(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Optional specific cache directory to scan."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output presentation format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Discover and measure disk consumption across standard cache and temporary directories."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    if path:
        dirs = [("Custom Cache", Path(path))]
    else:
        dirs = CacheDiscoveryEngine.get_standard_cache_directories()

    results = []
    for label, dir_path in dirs:
        total_bytes = 0
        file_count = 0
        try:
            for item in dir_path.glob("**/*"):
                if item.is_file():
                    try:
                        total_bytes += item.stat().st_size
                        file_count += 1
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            pass

        results.append(
            {
                "category": label,
                "path": str(dir_path),
                "file_count": file_count,
                "total_bytes": total_bytes,
                "formatted_size": format_bytes(total_bytes),
            }
        )

    if format.lower() == "json":
        console.print_json(json.dumps(results, indent=2))
    else:
        tbl = Table(
            title="[bold cyan]Standard Cache & Temporary Storage Locations[/bold cyan]",
            border_style="cyan",
            header_style="bold cyan",
            show_lines=True,
        )
        tbl.add_column("Category", style="yellow")
        tbl.add_column("Directory Path", style="bold white")
        tbl.add_column("Files", justify="right", style="cyan")
        tbl.add_column("Storage Consumed", justify="right", style="bold green")

        for r in results:
            tbl.add_row(
                str(r["category"]),
                str(r["path"]),
                f"{r['file_count']:,}",
                str(r["formatted_size"]),
            )

        console.print()
        console.print(tbl)
        console.print()


@app.command(name="browser")
def analyze_browser_cache(
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Inspect cache storage consumed by supported web browsers (Chrome, Edge, Firefox, Brave)."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    records = BrowserCacheAnalyzer.discover_browser_caches()

    if format.lower() == "json":
        data = [r.model_dump(mode="json") for r in records]
        console.print_json(json.dumps(data, indent=2))
    else:
        if not records:
            console.print("[yellow]No supported browser cache installations discovered.[/yellow]")
            return

        tbl = Table(
            title="[bold cyan]Web Browser Cache Storage Overview[/bold cyan]",
            border_style="cyan",
            header_style="bold cyan",
            show_lines=True,
        )
        tbl.add_column("Browser", style="bold white")
        tbl.add_column("Profile", style="yellow")
        tbl.add_column("Cache Path", style="dim white")
        tbl.add_column("Files", justify="right", style="cyan")
        tbl.add_column("Cache Size", justify="right", style="bold green")
        tbl.add_column("Running?", justify="center")

        for r in records:
            running_badge = (
                "[bold red]YES[/bold red]" if r.is_browser_running else "[green]No[/green]"
            )
            tbl.add_row(
                r.browser_name,
                r.profile_name,
                r.cache_path,
                f"{r.file_count:,}",
                r.size_formatted,
                running_badge,
            )

        console.print()
        console.print(tbl)
        console.print(
            "[dim]Note: Browser caches are protected when browser processes are actively running.[/dim]\n"
        )
