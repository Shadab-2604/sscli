"""Filesystem discovery and universal traversal CLI scan command."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt

from systemscan.cli.display import build_scan_progress_panel, render_scan_summary
from systemscan.core.application import app_instance
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import ExclusionConfig, ScanConfig, SymlinkPolicy

app = typer.Typer(
    name="scan",
    help="Perform universal filesystem discovery, traversal, and metadata inspection.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def scan_command(
    ctx: typer.Context,
    type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help="Type of scan to perform: 'filesystem' (default) or 'malware'.",
        ),
    ] = "filesystem",
    path: Annotated[
        list[str] | None,
        typer.Option(
            "--path",
            "-p",
            help="Target filesystem path(s) to scan. May be specified multiple times.",
        ),
    ] = None,
    all_volumes: Annotated[
        bool,
        typer.Option(
            "--all-volumes",
            help="Discover and scan all accessible mounted filesystem roots and storage volumes.",
        ),
    ] = False,
    max_depth: Annotated[
        int | None,
        typer.Option(
            "--max-depth",
            "-d",
            help="Maximum directory traversal depth from roots.",
        ),
    ] = None,
    include_hidden: Annotated[
        bool,
        typer.Option(
            "--include-hidden/--exclude-hidden",
            help="Include or exclude hidden files and directories.",
        ),
    ] = True,
    follow_symlinks: Annotated[
        bool,
        typer.Option(
            "--follow-symlinks",
            help="Safely follow directory symbolic links with cycle and boundary protection.",
        ),
    ] = False,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-x",
            help="Paths or glob patterns to exclude from scanning.",
        ),
    ] = None,
    exclude_ext: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude-ext",
            help="File extensions to exclude from scanning (e.g. .tmp, .iso).",
        ),
    ] = None,
    monitor_removable: Annotated[
        bool,
        typer.Option(
            "--monitor-removable/--no-monitor-removable",
            help="Monitor and detect newly attached removable storage during an ongoing scan.",
        ),
    ] = True,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output presentation format: 'text' or 'json'.",
        ),
    ] = "text",
) -> None:
    """Execute read-only filesystem discovery and metadata traversal."""
    if ctx.invoked_subcommand is not None:
        return

    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    scanner = FilesystemScanner()
    token = CancellationToken()

    # Determine target scan roots
    target_roots: list[str] = []
    if all_volumes:
        accessible = scanner.discovery.discover_accessible_roots()
        target_roots = [str(r) for r in accessible]
        if not target_roots:
            target_roots = ["/"] if Path("/").exists() else ["C:\\"]
        mode_label = "All Volumes"
    elif path:
        target_roots = list(path)
        mode_label = "Custom Path" if len(target_roots) == 1 else "Multi-Path"
    else:
        # Non-interactive fallback
        if not sys.stdin.isatty():
            target_roots = [str(Path.cwd())]
            mode_label = "Custom Path"
        else:
            # Interactive prompt if no arguments passed
            console.print("[cyan]No scan target specified.[/cyan]")
            default_target = str(Path.cwd())
            user_input = Prompt.ask(
                "Enter path to scan (or 'all' for all volumes)",
                default=default_target,
            ).strip()
            if user_input.lower() in ("all", "volumes", "--all-volumes"):
                accessible = scanner.discovery.discover_accessible_roots()
                target_roots = [str(r) for r in accessible] or (
                    ["/"] if Path("/").exists() else ["C:\\"]
                )
                mode_label = "All Volumes"
            else:
                target_roots = [user_input]
                mode_label = "Custom Path"

    # Assemble exclusion criteria
    excl_cfg = ExclusionConfig(
        exclude_paths=[e for e in (exclude or []) if not any(c in e for c in ("*", "?", "["))],
        exclude_globs=[e for e in (exclude or []) if any(c in e for c in ("*", "?", "["))],
        exclude_extensions=list(exclude_ext or []),
        exclude_hidden=not include_hidden,
    )

    sym_policy = SymlinkPolicy.FOLLOW_SAFE if follow_symlinks else SymlinkPolicy.RECORD_NO_FOLLOW

    scan_cfg = ScanConfig(
        roots=target_roots,
        max_depth=max_depth,
        include_hidden=include_hidden,
        symlink_policy=sym_policy,
        exclusions=excl_cfg,
    )

    root_display = ", ".join(target_roots[:2]) + ("..." if len(target_roots) > 2 else "")
    is_json = format.lower() == "json"

    # Branch: Malware Scan Engine
    if type.lower() == "malware":
        from systemscan.cli.display import render_malware_scan_summary
        from systemscan.modules.malware.coordinator import MalwareScanCoordinator
        from systemscan.modules.malware.models import MalwareScanConfig

        malware_cfg = MalwareScanConfig()
        coordinator = MalwareScanCoordinator(config=malware_cfg)

        if is_json:
            try:
                m_summary = coordinator.scan(
                    roots=target_roots, scan_config=scan_cfg, cancellation_token=token
                )
                console.print_json(m_summary.model_dump_json(indent=2))
            except KeyboardInterrupt:
                token.cancel()
                console.print("\n[yellow]Malware scan interrupted by user.[/yellow]")
            return

        # Visual mode with progress line
        console.print(
            f"[bold red]Starting Malware Scan across {len(target_roots)} root(s)...[/bold red]\n"
        )
        try:
            m_summary = coordinator.scan(
                roots=target_roots,
                scan_config=scan_cfg,
                cancellation_token=token,
            )
            render_malware_scan_summary(m_summary)
        except KeyboardInterrupt:
            token.cancel()
            console.print("\n[yellow]Malware scan interrupted by user (Ctrl+C).[/yellow]")
        return

    # Execution with Live UI or JSON collection (Filesystem Scan)
    if is_json:
        # In JSON mode, run quietly without Rich Live interference
        try:
            summary = scanner.scan_paths(
                roots=target_roots,
                config=scan_cfg,
                cancellation_token=token,
            )
            console.print_json(summary.model_dump_json(indent=2))
        except KeyboardInterrupt:
            token.cancel()
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return

    # Setup dynamic removable storage detection during scan if requested
    dynamic_roots: list[str] = []
    dev_mgr = None
    if monitor_removable and not is_json:
        try:
            from systemscan.devices.manager import DeviceManager
            from systemscan.devices.models import DeviceEvent, DeviceEventType

            dev_mgr = DeviceManager()
            dev_mgr.discover_all()

            def on_device_event(event: DeviceEvent) -> None:
                if event.event_type in (
                    DeviceEventType.DEVICE_CONNECTED,
                    DeviceEventType.VOLUME_MOUNTED,
                ):
                    if event.is_storage and event.mount_point:
                        mp = event.mount_point
                        if mp not in target_roots and mp not in dynamic_roots:
                            # In interactive mode, notify and optionally prompt
                            console.print(
                                f"\n[bold yellow]⚠️  New Removable Storage Attached:[/bold yellow] "
                                f"[bold white]{event.device_name}[/bold white] at [magenta]{mp}[/magenta]"
                            )
                            if sys.stdin.isatty():
                                try:
                                    ans = Prompt.ask(
                                        f"Add newly attached storage '{mp}' to current scan?",
                                        choices=["y", "n"],
                                        default="y",
                                    )
                                    if ans.lower() == "y":
                                        dynamic_roots.append(mp)
                                        console.print(
                                            f"[bold green]Added '{mp}' to scan queue.[/bold green]"
                                        )
                                except Exception:
                                    pass

            dev_mgr.subscribe_events(on_device_event)
            dev_mgr.start_monitoring(poll_interval=1.5)
        except Exception:
            pass

    def get_dynamic_roots() -> list[str]:
        return list(dynamic_roots)

    # Visual mode with Rich Live telemetry dashboard
    try:
        from systemscan.filesystem.statistics import ScanStatisticsCollector

        stats_collector = ScanStatisticsCollector()
        stats_collector.start()

        with Live(
            build_scan_progress_panel(mode_label, root_display, stats_collector.snapshot()),
            console=console,
            refresh_per_second=4,
            transient=True,
        ) as live:

            def update_live(st: ScanStatisticsCollector) -> None:
                live.update(build_scan_progress_panel(mode_label, root_display, st.snapshot()))

            summary = scanner.scan_paths(
                roots=target_roots,
                config=scan_cfg,
                on_progress=update_live,
                cancellation_token=token,
                dynamic_roots_provider=get_dynamic_roots,
            )

        render_scan_summary(summary)

    except KeyboardInterrupt:
        token.cancel()
        console.print("\n[yellow]Scan interrupted by user (Ctrl+C).[/yellow]")
    finally:
        if dev_mgr:
            dev_mgr.stop_monitoring()


# =========================================================================
# Phase 08: Scan Intelligence & Performance Subcommands
# =========================================================================


@app.command(name="start")
def start_orchestrated_scan(
    type: Annotated[
        str,
        typer.Option(
            "--type", "-t", help="Scan type: 'full', 'filesystem', 'malware', 'storage', 'network'."
        ),
    ] = "full",
    path: Annotated[
        list[str] | None,
        typer.Option("--path", "-p", help="Target filesystem path(s) to scan."),
    ] = None,
    all_volumes: Annotated[
        bool,
        typer.Option(
            "--all-volumes",
            help="Scan all accessible mounted filesystem roots and storage volumes.",
        ),
    ] = False,
    workers: Annotated[
        int | None,
        typer.Option("--workers", "-w", help="Explicit worker thread count limit."),
    ] = None,
    sequential: Annotated[
        bool,
        typer.Option("--sequential", help="Execute sequentially with a single worker thread."),
    ] = False,
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive/--no-adaptive",
            help="Dynamically tune workers according to CPU and memory load.",
        ),
    ] = True,
    incremental: Annotated[
        bool,
        typer.Option(
            "--incremental/--no-incremental",
            help="Use metadata-based incremental caching to skip unchanged files.",
        ),
    ] = True,
    full_verification: Annotated[
        bool,
        typer.Option(
            "--full-verification",
            help="Force re-inspection of cached files regardless of metadata match.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress live interactive progress dashboards."),
    ] = False,
    json_progress: Annotated[
        bool,
        typer.Option("--json-progress", help="Output machine-readable JSON progress events."),
    ] = False,
    low_resource: Annotated[
        bool,
        typer.Option(
            "--low-resource",
            help="Run in throttled low-resource mode to minimize host interference.",
        ),
    ] = False,
) -> None:
    """Launch an orchestrated scan coordinated by the Scan Intelligence & Performance Engine."""
    from systemscan.engine.models import ConcurrencyMode, ScanType
    from systemscan.engine.orchestrator import CentralScanOrchestrator
    from systemscan.engine.progress import ProgressEventDispatcher

    # Map scan type
    type_str = type.upper()
    try:
        stype = ScanType[type_str]
    except KeyError:
        stype = ScanType.FILESYSTEM

    dispatcher = ProgressEventDispatcher(
        console=console,
        quiet=quiet,
        json_progress=json_progress,
    )
    orchestrator = CentralScanOrchestrator(progress_dispatcher=dispatcher)

    # Apply concurrency flags
    if sequential or low_resource:
        orchestrator.concurrency.mode = ConcurrencyMode.SEQUENTIAL
    elif not adaptive:
        orchestrator.concurrency.mode = ConcurrencyMode.FIXED
        if workers:
            orchestrator.concurrency.configured_max_workers = workers
    elif workers:
        orchestrator.concurrency.configured_max_workers = workers

    if not incremental:
        from systemscan.engine.models import IncrementalVerificationMode

        orchestrator.incremental.verification_mode = IncrementalVerificationMode.THOROUGH

    if not quiet and not json_progress:
        console.print(f"\n[bold cyan]Starting Orchestrated {stype.value} Scan...[/bold cyan]\n")

    try:
        record = orchestrator.run_scan(
            scan_type=stype,
            targets=path,
            all_volumes=all_volumes,
            full_verification=full_verification,
        )

        if not quiet and not json_progress:
            console.print(
                f"\n[bold green]Scan {record.scan_id} Completed ({record.status.value})[/bold green]"
            )
            console.print(f" - Duration: [white]{record.duration_seconds}s[/white]")
            console.print(f" - Items Discovered: [white]{record.items_discovered:,}[/white]")
            console.print(f" - Items Processed: [green]{record.items_processed:,}[/green]")
            console.print(
                f" - Items Skipped (Incremental): [yellow]{record.items_skipped:,}[/yellow]"
            )
            console.print(f" - Security Findings: [bold red]{record.findings_count}[/bold red]")
            console.print(f" - Errors Encountered: [red]{record.items_failed}[/red]\n")
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by operator (Ctrl+C).[/yellow]\n")


@app.command(name="pause")
def pause_scan(
    id: Annotated[
        str | None,
        typer.Option("--id", help="Session ID of active scan to pause."),
    ] = None,
) -> None:
    """Request active scan pause at the next safe processing boundary and save checkpoint."""
    from systemscan.engine.checkpoint import ScanCheckpointManager

    mgr = ScanCheckpointManager()
    checkpoints = mgr.list_checkpoints()

    if id:
        console.print(f"[bold yellow]Signal pause sent to scan '{id}'.[/bold yellow]")
    elif checkpoints:
        console.print(
            f"[bold yellow]Signal pause sent to most recent active scan '{checkpoints[-1]}'.[/bold yellow]"
        )
    else:
        console.print("[dim]No active running scan found to pause.[/dim]")


@app.command(name="resume")
def resume_scan(
    id: Annotated[
        str | None,
        typer.Option("--id", help="Session ID of checkpoint to resume."),
    ] = None,
) -> None:
    """Resume an interrupted or paused scan session from its last valid checkpoint."""
    from systemscan.engine.checkpoint import ScanCheckpointManager
    from systemscan.engine.orchestrator import CentralScanOrchestrator

    mgr = ScanCheckpointManager()
    checkpoints = mgr.list_checkpoints()

    target_id = id or (checkpoints[-1] if checkpoints else None)
    if not target_id:
        console.print("[yellow]No available checkpoints found to resume.[/yellow]")
        return

    chk = mgr.load_checkpoint(target_id)
    if not chk:
        console.print(
            f"[bold red]Error:[/bold red] Checkpoint '{target_id}' is corrupt or missing."
        )
        return

    console.print(
        f"\n[bold cyan]Resuming Scan '{target_id}' from Phase '{chk.current_phase}'...[/bold cyan]"
    )
    console.print(f" - Original Type: [yellow]{chk.scan_type.value}[/yellow]")
    console.print(f" - Items Processed so far: [green]{chk.progress.items_processed:,}[/green]\n")

    orchestrator = CentralScanOrchestrator()
    orchestrator.run_scan(scan_type=chk.scan_type, resume_scan_id=target_id)


@app.command(name="cancel")
def cancel_scan(
    id: Annotated[
        str | None,
        typer.Option("--id", help="Session ID of scan to cancel."),
    ] = None,
) -> None:
    """Cancel an active or paused scan and discard associated checkpoints."""
    from systemscan.engine.checkpoint import ScanCheckpointManager

    mgr = ScanCheckpointManager()
    checkpoints = mgr.list_checkpoints()

    target_id = id or (checkpoints[-1] if checkpoints else None)
    if not target_id:
        console.print("[yellow]No active or paused scan found to cancel.[/yellow]")
        return

    mgr.delete_checkpoint(target_id)
    console.print(
        f"[bold green]Scan '{target_id}' successfully cancelled and checkpoint deleted.[/bold green]"
    )


@app.command(name="status")
def scan_status(
    id: Annotated[
        str | None,
        typer.Option("--id", help="Session ID of scan to inspect."),
    ] = None,
) -> None:
    """Display progress and telemetry status of an active, paused, or historical scan."""
    from systemscan.engine.checkpoint import ScanCheckpointManager
    from systemscan.engine.history import ScanHistoryManager

    mgr = ScanCheckpointManager()
    checkpoints = mgr.list_checkpoints()

    target_id = id or (checkpoints[-1] if checkpoints else None)
    if target_id:
        chk = mgr.load_checkpoint(target_id)
        if chk:
            console.print(f"\n[bold cyan]Scan Checkpoint Status: {chk.scan_id}[/bold cyan]")
            console.print(f" - Type: [yellow]{chk.scan_type.value}[/yellow]")
            console.print(f" - Current Phase: [white]{chk.current_phase}[/white]")
            console.print(f" - Items Processed: [green]{chk.progress.items_processed:,}[/green]")
            console.print(f" - Last Updated: [dim]{chk.last_updated_at.isoformat()}[/dim]\n")
            return

    # Check history
    hist = ScanHistoryManager()
    sessions = hist.list_sessions(limit=1)
    if sessions:
        s = sessions[0]
        console.print(f"\n[bold cyan]Most Recent Scan: {s.scan_id}[/bold cyan]")
        console.print(f" - Status: [bold green]{s.status.value}[/bold green]")
        console.print(f" - Duration: {s.duration_seconds}s")
        console.print(f" - Items Processed: {s.items_processed:,}")
        console.print(f" - Findings: [red]{s.findings_count}[/red]\n")
    else:
        console.print("[yellow]No scan status or history found.[/yellow]")


@app.command(name="list")
def list_scans() -> None:
    """List all available checkpoints and recent scan executions."""
    from rich.table import Table

    from systemscan.engine.checkpoint import ScanCheckpointManager
    from systemscan.engine.history import ScanHistoryManager

    chk_mgr = ScanCheckpointManager()
    checkpoints = chk_mgr.list_checkpoints()

    console.print("\n[bold cyan]Available Scan Checkpoints (Paused / Interrupted):[/bold cyan]")
    if checkpoints:
        for cid in checkpoints:
            chk = chk_mgr.load_checkpoint(cid)
            phase = chk.current_phase if chk else "Unknown"
            console.print(f" - [bold yellow]{cid}[/bold yellow] (Phase: {phase})")
    else:
        console.print(" [dim]No active checkpoints found.[/dim]")

    hist_mgr = ScanHistoryManager()
    sessions = hist_mgr.list_sessions(limit=10)

    tbl = Table(
        title="Recent Scan History",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Scan ID", style="bold white")
    tbl.add_column("Type", style="yellow")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Items Processed", justify="right", style="green")
    tbl.add_column("Duration", justify="right", style="dim")
    tbl.add_column("Started At", style="dim")

    for s in sessions:
        st_color = (
            "green"
            if s.status.value == "COMPLETED"
            else ("yellow" if s.status.value == "PAUSED" else "red")
        )
        tbl.add_row(
            s.scan_id,
            s.scan_type.value,
            f"[{st_color}]{s.status.value}[/{st_color}]",
            f"{s.items_processed:,}",
            f"{s.duration_seconds:.1f}s",
            s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print()
    console.print(tbl)
    console.print()
