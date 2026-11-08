"""CLI commands for disk usage, large files, duplicates, extensions, and age analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import (
    render_disk_volumes_table,
    render_duplicate_groups_table,
    render_extension_stats_table,
    render_large_directories_table,
    render_large_files_table,
)
from systemscan.core.application import app_instance
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import DirectoryMetadata, FileMetadata, ScanConfig
from systemscan.modules.storage.age_analyzer import AgeAnalyzer
from systemscan.modules.storage.directory_analyzer import DirectoryAnalyzer
from systemscan.modules.storage.disk_usage import DiskUsageAnalyzer
from systemscan.modules.storage.duplicate_detector import DuplicateDetector
from systemscan.modules.storage.extension_analyzer import ExtensionAnalyzer
from systemscan.modules.storage.hidden_storage import HiddenStorageAnalyzer
from systemscan.modules.storage.large_files import LargeFileAnalyzer

app = typer.Typer(
    name="storage",
    help="Analyze disk usage, large files, duplicates, extensions, and hidden storage.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def default_storage(ctx: typer.Context) -> None:
    """Default entrypoint for `systemscan storage` -> summarizes mounted volumes."""
    if ctx.invoked_subcommand is None:
        analyze_volumes(format="text")


@app.command(name="analyze")
def analyze_volumes(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Optional specific directory path to evaluate."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Analyze storage capacity, utilization, and free space across mounted volumes."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    if path:
        vol = DiskUsageAnalyzer.get_volume_for_path(path)
        volumes = [vol] if vol else []
    else:
        volumes = DiskUsageAnalyzer.analyze_volumes()

    if format.lower() == "json":
        data = [v.model_dump(mode="json") for v in volumes]
        console.print_json(json.dumps(data, indent=2))
    else:
        render_disk_volumes_table(volumes)


@app.command(name="large-files")
def find_large_files(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Directory path to scan for large files."),
    ] = None,
    min_size_mb: Annotated[
        int,
        typer.Option("--min-size-mb", "-s", help="Minimum file size threshold in Megabytes."),
    ] = 100,
    top: Annotated[
        int,
        typer.Option("--top", "-t", help="Maximum number of largest files to report."),
    ] = 25,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Discover the largest files exceeding configured threshold."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target = path or str(Path.cwd())
    scanner = FilesystemScanner()
    token = CancellationToken()
    large_analyzer = LargeFileAnalyzer(min_size_bytes=min_size_mb * 1024 * 1024, top_limit=top)

    fs_cfg = ScanConfig(roots=[target])

    try:
        for item in scanner.stream_scan(config=fs_cfg, cancellation_token=token):
            if isinstance(item, FileMetadata):
                large_analyzer.inspect_file(item)
    except KeyboardInterrupt:
        token.cancel()

    files = large_analyzer.get_top_large_files()

    if format.lower() == "json":
        data = [f.model_dump(mode="json") for f in files]
        console.print_json(json.dumps(data, indent=2))
    else:
        if not files:
            console.print(
                f"[green]No files exceeding {min_size_mb} MB discovered in '{target}'.[/green]"
            )
        else:
            render_large_files_table(files)


@app.command(name="large-directories")
def find_large_directories(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Directory path to scan."),
    ] = None,
    top: Annotated[
        int,
        typer.Option("--top", "-t", help="Maximum directories to report."),
    ] = 25,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Identify directories consuming the greatest aggregated storage."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target = path or str(Path.cwd())
    scanner = FilesystemScanner()
    token = CancellationToken()
    dir_analyzer = DirectoryAnalyzer(top_limit=top)

    fs_cfg = ScanConfig(roots=[target])

    try:
        for item in scanner.stream_scan(config=fs_cfg, cancellation_token=token):
            if isinstance(item, FileMetadata):
                dir_analyzer.inspect_file(item)
            elif isinstance(item, DirectoryMetadata):
                dir_analyzer.inspect_directory(item)
    except KeyboardInterrupt:
        token.cancel()

    dirs = dir_analyzer.get_top_directories()

    if format.lower() == "json":
        data = [d.model_dump(mode="json") for d in dirs]
        console.print_json(json.dumps(data, indent=2))
    else:
        render_large_directories_table(dirs)


@app.command(name="duplicates")
def find_duplicates(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Directory path to scan for duplicates."),
    ] = None,
    min_size_kb: Annotated[
        int,
        typer.Option("--min-size-kb", help="Ignore files beneath size threshold in KB."),
    ] = 1,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Discover duplicate files via multi-stage size grouping and SHA-256 verification."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target = path or str(Path.cwd())
    console.print(f"[bold cyan]Scanning for duplicate files in:[/bold cyan] {target} ...")

    scanner = FilesystemScanner()
    token = CancellationToken()
    dup_detector = DuplicateDetector(min_size_bytes=min_size_kb * 1024)

    fs_cfg = ScanConfig(roots=[target])

    try:
        for item in scanner.stream_scan(config=fs_cfg, cancellation_token=token):
            if isinstance(item, FileMetadata):
                dup_detector.inspect_file(item)
    except KeyboardInterrupt:
        token.cancel()

    groups = dup_detector.find_duplicates()

    if format.lower() == "json":
        data = [g.model_dump(mode="json") for g in groups]
        console.print_json(json.dumps(data, indent=2))
    else:
        if not groups:
            console.print("[green]No duplicate files detected.[/green]")
        else:
            render_duplicate_groups_table(groups)


@app.command(name="extensions")
def analyze_extensions(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Directory path to analyze."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Analyze file storage distribution by extension."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target = path or str(Path.cwd())
    scanner = FilesystemScanner()
    token = CancellationToken()
    ext_analyzer = ExtensionAnalyzer()

    fs_cfg = ScanConfig(roots=[target])

    try:
        for item in scanner.stream_scan(config=fs_cfg, cancellation_token=token):
            if isinstance(item, FileMetadata):
                ext_analyzer.inspect_file(item)
    except KeyboardInterrupt:
        token.cancel()

    stats = ext_analyzer.get_extension_summary()

    if format.lower() == "json":
        data = [s.model_dump(mode="json") for s in stats]
        console.print_json(json.dumps(data, indent=2))
    else:
        render_extension_stats_table(stats)


@app.command(name="old-files")
def analyze_old_files(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Directory path to analyze."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Analyze dormant file distribution across 30, 90, 180, and 365+ day thresholds."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target = path or str(Path.cwd())
    scanner = FilesystemScanner()
    token = CancellationToken()
    age_analyzer = AgeAnalyzer()

    fs_cfg = ScanConfig(roots=[target])

    try:
        for item in scanner.stream_scan(config=fs_cfg, cancellation_token=token):
            if isinstance(item, FileMetadata):
                age_analyzer.inspect_file(item)
    except KeyboardInterrupt:
        token.cancel()

    brackets = age_analyzer.get_brackets_summary()

    if format.lower() == "json":
        console.print_json(json.dumps(brackets, indent=2))
    else:
        from rich.table import Table

        from systemscan.modules.storage.models import format_bytes

        tbl = Table(
            title=f"[bold cyan]File Dormancy & Age Distribution ({target})[/bold cyan]",
            border_style="cyan",
            header_style="bold cyan",
        )
        tbl.add_column("Age Threshold", style="bold yellow")
        tbl.add_column("File Count", justify="right", style="cyan")
        tbl.add_column("Storage Consumed", justify="right", style="bold green")

        for bracket_name, b_data in brackets.items():
            tbl.add_row(bracket_name, f"{b_data['count']:,}", format_bytes(b_data["total_bytes"]))

        console.print()
        console.print(tbl)
        console.print()


@app.command(name="hidden")
def analyze_hidden(
    path: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Directory path to inspect."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """Analyze storage consumption contributed by hidden files and directories."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target = path or str(Path.cwd())
    scanner = FilesystemScanner()
    token = CancellationToken()
    hidden_analyzer = HiddenStorageAnalyzer()

    fs_cfg = ScanConfig(roots=[target], include_hidden=True)

    try:
        for item in scanner.stream_scan(config=fs_cfg, cancellation_token=token):
            if isinstance(item, FileMetadata):
                hidden_analyzer.inspect_file(item)
            elif isinstance(item, DirectoryMetadata):
                hidden_analyzer.inspect_directory(item)
    except KeyboardInterrupt:
        token.cancel()

    from systemscan.modules.storage.models import format_bytes

    if format.lower() == "json":
        data = {
            "total_hidden_files": hidden_analyzer.total_hidden_files,
            "total_hidden_directories": hidden_analyzer.total_hidden_directories,
            "total_hidden_bytes": hidden_analyzer.total_hidden_bytes,
        }
        console.print_json(json.dumps(data, indent=2))
    else:
        console.print(f"\n[bold cyan]Hidden Storage Usage for:[/bold cyan] {target}")
        console.print(
            f" - Hidden Directories: [yellow]{hidden_analyzer.total_hidden_directories}[/yellow]"
        )
        console.print(f" - Hidden Files: [yellow]{hidden_analyzer.total_hidden_files}[/yellow]")
        console.print(
            f" - Total Space Consumed: [bold green]{format_bytes(hidden_analyzer.total_hidden_bytes)}[/bold green]\n"
        )
