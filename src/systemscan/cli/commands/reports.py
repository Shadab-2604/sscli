"""Comprehensive report management, generation, and multi-format export CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from systemscan.cli.display import print_error, print_info, print_success
from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.history import ScanHistoryManager
from systemscan.reporting.exporter import ReportExporter
from systemscan.reporting.formats.json_export import JSONReportExporter
from systemscan.reporting.formats.txt_export import TextReportExporter
from systemscan.reporting.generator import ReportGenerator
from systemscan.reporting.models import ReportFormat, ScanReport
from systemscan.reporting.storage import ReportStorageManager
from systemscan.utils.formatting import format_bytes

console = Console()
app = typer.Typer(
    name="report",
    help="Generate, inspect, export, and verify security scan reports.",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def reports_default(ctx: typer.Context) -> None:
    """List generated scan reports or display reporting status."""
    if ctx.invoked_subcommand is not None:
        return

    mgr = ReportStorageManager()
    reports = mgr.list_reports()

    console.print()
    print_info("Report Storage Location", str(mgr.storage_dir))

    if not reports:
        console.print(
            "\n[dim]No scan reports found. Use 'systemscan report generate' or complete a scan to produce a report.[/dim]\n"
        )
        return

    _render_report_table(reports)


def _render_report_table(reports: list[dict[str, Any]]) -> None:
    table = Table(
        title=f"Saved Scan Reports ({len(reports)})",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Report ID", style="bold white", width=18)
    table.add_column("Filename", style="dim")
    table.add_column("Format", justify="center", style="yellow")
    table.add_column("Size", justify="right", style="green")
    table.add_column("Created At (UTC)", style="dim")

    for r in reports:
        table.add_row(
            r["report_id"],
            r["filename"],
            r["format"].upper(),
            format_bytes(r["size_bytes"]),
            r["created_at"].strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print()
    console.print(table)
    console.print()


@app.command(name="list")
def list_reports(
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'json'."),
    ] = "text",
) -> None:
    """List all available scan reports in storage."""
    mgr = ReportStorageManager()
    reports = mgr.list_reports()

    if format.lower() == "json":
        data = [
            {
                "report_id": r["report_id"],
                "filename": r["filename"],
                "format": r["format"],
                "size_bytes": r["size_bytes"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in reports
        ]
        console.print_json(json.dumps(data, indent=2))
        return

    if not reports:
        console.print("\n[dim]No reports found in storage.[/dim]\n")
        return

    _render_report_table(reports)


@app.command(name="show")
def show_report(
    report_id: Annotated[str, typer.Argument(help="Report identifier to display.")],
    style: Annotated[
        str,
        typer.Option(
            "--style",
            "-s",
            help="Display style template: 'technical' (default), 'executive', or 'compact'.",
        ),
    ] = "technical",
) -> None:
    """Display the formatted contents of an existing report."""
    mgr = ReportStorageManager()
    target = mgr.find_report_file(report_id)

    if not target:
        print_error(f"Report '{report_id}' not found in storage.")
        raise typer.Exit(code=1)

    if target.suffix.lower() == ".json":
        try:
            report = JSONReportExporter.load_from_file(target)
            rendered = TextReportExporter.export_to_string(report, style=style)
            console.print(rendered)
            return
        except Exception as e:
            print_error(f"Failed to render JSON report '{report_id}': {e}")
            raise typer.Exit(code=1) from e

    # For text or csv reports, print raw content
    console.print(target.read_text(encoding="utf-8"))


@app.command(name="generate")
def generate_report(
    scan_id: Annotated[
        str | None,
        typer.Option("--scan-id", "-s", help="Scan session ID to generate report for."),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format: json, csv, txt."),
    ] = "json",
    redact: Annotated[
        bool,
        typer.Option("--redact", "-r", help="Redact sensitive data (usernames, IPs, MACs)."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Custom output path or directory."),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Overwrite existing report file if present."),
    ] = False,
) -> None:
    """Generate a formal report from scan session history or active checkpoints."""
    # Find scan record
    hist_mgr = ScanHistoryManager()
    target_scan_id = scan_id

    if not target_scan_id:
        sessions = hist_mgr.list_sessions(limit=1)
        if sessions:
            target_scan_id = sessions[0].scan_id
        else:
            ckpt_mgr = ScanCheckpointManager()
            ckpts = ckpt_mgr.list_checkpoints()
            if ckpts:
                target_scan_id = ckpts[-1]

    if not target_scan_id:
        print_error("No scan sessions or checkpoints found. Execute a scan first.")
        raise typer.Exit(code=1)

    # Load scan history or checkpoint
    session = hist_mgr.get_session(target_scan_id)
    report: ScanReport
    if session:
        report = ReportGenerator.from_history_record(session)
    else:
        ckpt_mgr = ScanCheckpointManager()
        chk = ckpt_mgr.load_checkpoint(target_scan_id)
        if chk:
            report = ReportGenerator.from_checkpoint(chk)
        else:
            print_error(f"No scan history or checkpoint found for scan ID '{target_scan_id}'.")
            raise typer.Exit(code=1)

    # Export report
    fmt = ReportFormat(format.lower().strip())
    out_path = Path(output) if output else None

    storage_mgr = ReportStorageManager()
    exporter = ReportExporter(storage_manager=storage_mgr)
    try:
        saved_path = exporter.export(
            report=report,
            fmt=fmt,
            output_path=out_path,
            overwrite=overwrite,
            redact=redact,
        )
        print_success(f"Report successfully generated and saved to: {saved_path}")
    except FileExistsError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from e
    except Exception as e:
        print_error(f"Report generation failed: {e}")
        raise typer.Exit(code=1) from e


@app.command(name="export")
def export_report(
    scan_id: Annotated[
        str,
        typer.Option("--scan-id", "-s", help="Scan session ID to export."),
    ],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Target export format: json, csv, txt."),
    ] = "json",
    redact: Annotated[
        bool,
        typer.Option("--redact", "-r", help="Redact sensitive data (usernames, IPs, MACs)."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Custom destination file or directory path."),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Overwrite target file if it already exists."),
    ] = False,
    style: Annotated[
        str,
        typer.Option(
            "--style", help="Template style for TXT export (technical, executive, compact)."
        ),
    ] = "technical",
) -> None:
    """Export a scan session report in JSON, CSV, or TXT format."""
    hist_mgr = ScanHistoryManager()
    session = hist_mgr.get_session(scan_id)

    report: ScanReport
    if session:
        report = ReportGenerator.from_history_record(session)
    else:
        ckpt_mgr = ScanCheckpointManager()
        chk = ckpt_mgr.load_checkpoint(scan_id)
        if chk:
            report = ReportGenerator.from_checkpoint(chk)
        else:
            print_error(f"Scan session '{scan_id}' not found in history or checkpoints.")
            raise typer.Exit(code=1)

    try:
        fmt = ReportFormat(format.lower().strip())
    except ValueError as e:
        print_error(f"Unsupported format: '{format}'. Choose from 'json', 'csv', 'txt'.")
        raise typer.Exit(code=1) from e

    out_path = Path(output) if output else None
    storage_mgr = ReportStorageManager()
    exporter = ReportExporter(storage_manager=storage_mgr)

    try:
        saved_path = exporter.export(
            report=report,
            fmt=fmt,
            output_path=out_path,
            overwrite=overwrite,
            redact=redact,
            txt_style=style,
        )
        print_success(f"Report successfully exported: {saved_path}")
    except FileExistsError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from e
    except Exception as e:
        print_error(f"Export failed: {e}")
        raise typer.Exit(code=1) from e


@app.command(name="verify")
def verify_report(
    report_id: Annotated[
        str, typer.Argument(help="Report identifier to cryptographically verify.")
    ],
) -> None:
    """Verify cryptographic SHA-256 integrity manifest for a saved report."""
    mgr = ReportStorageManager()
    is_valid, msg = mgr.verify_report(report_id)

    if is_valid:
        print_success(msg)
    else:
        print_error(msg)
        raise typer.Exit(code=1)


@app.command(name="delete")
def delete_report(
    report_id: Annotated[str, typer.Argument(help="Report identifier to delete.")],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Confirm deletion without interactive prompt."),
    ] = False,
) -> None:
    """Delete a report file and its checksum manifest."""
    if not yes:
        confirm = typer.confirm(
            f"Are you sure you want to permanently delete report '{report_id}'?",
            default=False,
        )
        if not confirm:
            console.print("[yellow]Deletion cancelled by operator.[/yellow]")
            return

    mgr = ReportStorageManager()
    try:
        deleted = mgr.delete_report(report_id, confirm=True)
        if deleted:
            print_success(f"Report '{report_id}' successfully deleted.")
        else:
            print_error(f"Report '{report_id}' not found in storage.")
            raise typer.Exit(code=1)
    except Exception as e:
        print_error(f"Failed to delete report: {e}")
        raise typer.Exit(code=1) from e
