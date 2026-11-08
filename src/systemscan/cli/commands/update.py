"""Application self-update CLI commands for systemscan."""

from __future__ import annotations

import urllib.request
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from systemscan.cli.display import (
    create_key_value_table,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from systemscan.core.application import app_instance
from systemscan.update.backup import UpdateBackupManager
from systemscan.update.checker import UpdateChecker
from systemscan.update.history import UpdateHistoryManager
from systemscan.update.models import ReleaseChannel, UpdateStage
from systemscan.update.rollback import UpdateRollbackManager
from systemscan.update.transaction import UpdateTransactionCoordinator
from systemscan.update.verifier import UpdateVerifier
from systemscan.utils.paths import AppPaths
from systemscan.version import APP_NAME, __version__

app = typer.Typer(
    name="update",
    help="Check, verify, install, and roll back application updates.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def update_default(ctx: typer.Context) -> None:
    """Display update status or help if no subcommand provided."""
    if ctx.invoked_subcommand is None:
        status()


@app.command("status")
def status() -> None:
    """Display current version, channel configuration, and update state."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    update_cfg = app_instance.config.updates
    backup_mgr = UpdateBackupManager(max_backups=update_cfg.max_backups)
    backups = backup_mgr.list_backups()
    history_mgr = UpdateHistoryManager()
    recent_txns = history_mgr.list_transactions(limit=1)

    last_update_str = "None"
    if recent_txns:
        last_update_str = f"{recent_txns[0].target_version} ({recent_txns[0].created_at.strftime('%Y-%m-%d %H:%M')})"

    data = {
        "Application": APP_NAME,
        "Installed Version": __version__,
        "Configured Channel": update_cfg.channel.value,
        "Update Source": update_cfg.update_source,
        "Auto-Check on Startup": update_cfg.auto_check,
        "Cryptographic Verification": "Enforced (SHA-256)",
        "Automated Rollback": "Enabled" if update_cfg.rollback_enabled else "Disabled",
        "Available Backups": f"{len(backups)} snapshot(s)",
        "Last Update Transaction": last_update_str,
    }

    console.print()
    console.print(create_key_value_table("Application Update Status", data))
    console.print()


@app.command("check")
def check(
    channel: str | None = typer.Option(
        None, "--channel", "-c", help="Release channel to check (stable, beta, dev)."
    ),
) -> None:
    """Check remote repository for newer application releases."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target_channel = (
        ReleaseChannel(channel.lower())
        if channel
        else ReleaseChannel(app_instance.config.updates.channel.value)
    )
    console.print(f"\n[cyan]Checking for updates on '{target_channel.value}' channel...[/cyan]")

    checker = UpdateChecker(config=app_instance.config)
    plan = checker.create_update_plan(channel=target_channel)

    if not plan.is_update_available:
        print_success(f"SystemScan is up to date (current version: v{__version__}).")
        return

    release = checker.fetch_latest_release(channel=target_channel)
    if not release:
        print_warning("No release details found matching update criteria.")
        return

    table = Table(
        title=f"New Release Available: v{release.version}",
        show_header=True,
        header_style="bold green",
    )
    table.add_column("Property", style="bold", width=20)
    table.add_column("Details")

    table.add_row("Current Version", __version__)
    table.add_row("Available Version", f"[bold green]{release.version}[/bold green]")
    table.add_row("Release Date", release.release_date.strftime("%Y-%m-%d %H:%M:%S UTC"))
    table.add_row("Channel", release.channel.value)
    table.add_row("Asset Name", release.asset_name)
    table.add_row("Asset Size", f"{release.asset_size_bytes / (1024 * 1024):.2f} MB")
    table.add_row("SHA-256", release.sha256[:16] + "...")
    table.add_row("Min Python", f">={release.min_python_version}")

    console.print()
    console.print(table)
    console.print()

    if release.release_notes:
        console.print(
            Panel(
                release.release_notes.strip(),
                title="Release Notes & Changelog",
                border_style="cyan",
            )
        )
        console.print()

    console.print(
        "[bold cyan]To install this update, run:[/bold cyan] [green]systemscan update install[/green]\n"
    )


@app.command("download")
def download(
    output_dir: str | None = typer.Option(
        None, "--output", "-o", help="Target directory for downloaded artifact."
    ),
    channel: str | None = typer.Option(
        None, "--channel", "-c", help="Release channel (stable, beta, dev)."
    ),
) -> None:
    """Download the latest release archive without installing."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target_channel = (
        ReleaseChannel(channel.lower())
        if channel
        else ReleaseChannel(app_instance.config.updates.channel.value)
    )
    checker = UpdateChecker(config=app_instance.config)
    release = checker.fetch_latest_release(channel=target_channel)

    if not release:
        print_error("Failed to discover release metadata.")
        raise typer.Exit(code=1)

    dest_dir = Path(output_dir) if output_dir else (AppPaths().data_dir / "downloads")
    dest_dir.mkdir(parents=True, exist_ok=True)
    target_path = dest_dir / release.asset_name

    console.print(f"[cyan]Downloading {release.asset_name} from {release.download_url}...[/cyan]")
    try:
        urllib.request.urlretrieve(release.download_url, target_path)  # noqa: S310
    except Exception as e:
        print_error("Download failed", str(e))
        raise typer.Exit(code=1) from e

    # Verify download hash
    verifier = UpdateVerifier()
    ok, msg = verifier.verify_file_hash(target_path, release.sha256)
    if not ok:
        print_error("Cryptographic verification failed for downloaded asset", msg)
        raise typer.Exit(code=1)

    print_success(f"Downloaded and verified release asset at '{target_path}'.")


@app.command("verify")
def verify_archive(
    file_path: str = typer.Argument(..., help="Path to downloaded archive or wheel to verify."),
    sha256: str | None = typer.Option(None, "--sha256", "-s", help="Expected SHA-256 hash."),
) -> None:
    """Verify cryptographic digest and archive safety of an update package."""
    target_path = Path(file_path)
    if not target_path.exists():
        print_error("File not found", str(target_path))
        raise typer.Exit(code=1)

    verifier = UpdateVerifier()
    console.print(f"[cyan]Inspecting archive: {target_path.name}...[/cyan]")

    if sha256:
        h_ok, h_msg = verifier.verify_file_hash(target_path, sha256)
        if not h_ok:
            print_error("SHA-256 verification failed", h_msg)
            raise typer.Exit(code=1)
        console.print("[green]✓ SHA-256 checksum matches expected digest.[/green]")

    safe_ok, safe_msg = verifier.verify_archive_safety(target_path)
    if not safe_ok:
        print_error("Archive safety inspection failed", safe_msg)
        raise typer.Exit(code=1)

    print_success(
        f"Archive '{target_path.name}' passed all security checks (No zip-slip, size safe, safe symlinks)."
    )


@app.command("install")
def install(
    channel: str | None = typer.Option(
        None, "--channel", "-c", help="Release channel (stable, beta, dev)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Simulate update transaction without modifying files."
    ),
    allow_downgrade: bool = typer.Option(
        False, "--allow-downgrade", help="Explicitly authorize installing an older version."
    ),
) -> None:
    """Execute transactional self-update with atomic staging and automated rollback."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    target_channel = (
        ReleaseChannel(channel.lower())
        if channel
        else ReleaseChannel(app_instance.config.updates.channel.value)
    )
    coordinator = UpdateTransactionCoordinator(config=app_instance.config)

    console.print(
        f"\n[bold cyan]Initiating Update Transaction ({target_channel.value} channel)...[/bold cyan]"
    )

    def progress_handler(stage: UpdateStage, pct: float, msg: str) -> None:
        console.print(f"  [{pct:5.1f}%] [bold blue]{stage.value:<12}[/bold blue] {msg}")

    txn = coordinator.execute_update(
        channel=target_channel,
        dry_run=dry_run,
        allow_downgrade=allow_downgrade,
        progress_cb=progress_handler,
    )

    console.print()
    if txn.committed:
        print_success(
            f"Successfully updated SystemScan to v{txn.target_version}!\n"
            f"Transaction ID: {txn.transaction_id}"
        )
    elif txn.rolled_back:
        print_warning(
            f"Update failed ({txn.failure_reason.value if txn.failure_reason else 'Unknown'}): {txn.error_message}\n"
            "Application was safely rolled back to previous state without data loss."
        )
        raise typer.Exit(code=1)
    else:
        print_error(
            f"Update failed ({txn.failure_reason.value if txn.failure_reason else 'Aborted'})",
            txn.error_message or "Unknown error",
        )
        raise typer.Exit(code=1)


@app.command("rollback")
def rollback(
    transaction_id: str | None = typer.Option(
        None, "--transaction", "-t", help="Specific transaction ID snapshot to restore."
    ),
) -> None:
    """Restore previous application version from pre-update backup snapshot."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    console.print("\n[yellow]Executing application rollback from backup snapshot...[/yellow]")
    mgr = UpdateRollbackManager()
    ok, msg = mgr.rollback(transaction_id=transaction_id)

    if ok:
        print_success(msg)
    else:
        print_error("Rollback failed", msg)
        raise typer.Exit(code=1)


@app.command("history")
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum transactions to display."),
) -> None:
    """Display update audit history and past transaction records."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    mgr = UpdateHistoryManager()
    records = mgr.list_transactions(limit=limit)

    if not records:
        print_info("No update transactions recorded yet.")
        return

    table = Table(title="Update Transaction History", show_header=True, header_style="bold cyan")
    table.add_column("Transaction ID", style="bold", width=36)
    table.add_column("Source", width=10)
    table.add_column("Target", width=10)
    table.add_column("Channel", width=10)
    table.add_column("Status", width=14)
    table.add_column("Timestamp", width=20)

    for r in records:
        if r.committed:
            status_str = "[green]COMPLETED[/green]"
        elif r.rolled_back:
            status_str = "[yellow]ROLLED BACK[/yellow]"
        else:
            status_str = f"[red]{r.current_stage.value}[/red]"

        table.add_row(
            r.transaction_id,
            r.source_version,
            r.target_version,
            r.channel.value,
            status_str,
            r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print()
    console.print(table)
    console.print()


@app.command("version")
def version_cmd() -> None:
    """Display application version and architecture details."""
    console.print(
        f"[bold cyan]{APP_NAME}[/bold cyan] version [bold white]{__version__}[/bold white]"
    )
