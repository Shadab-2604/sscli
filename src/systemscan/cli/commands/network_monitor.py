"""CLI commands for the Network Threat Monitor module."""

from __future__ import annotations

import time
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from systemscan.network_monitor.configuration import NetworkMonitorConfig, SensitivityLevel
from systemscan.network_monitor.diagnostics.diagnostics import CaptureDiagnostics
from systemscan.network_monitor.manager import NetworkThreatMonitorManager
from systemscan.network_monitor.models import MonitorMode, SensorHealthStatus
from systemscan.network_monitor.storage.database import NetworkAlertDatabase

app = typer.Typer(
    name="network-monitor",
    help="Dual-Mode Local & Network-Wide Nmap / Port Reconnaissance Monitor.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

console = Console()


@app.callback(invoke_without_command=True)
def default_network_monitor_callback(
    ctx: typer.Context,
    local: Annotated[
        bool, typer.Option("--local", help="Monitor local laptop traffic only.")
    ] = False,
    network: Annotated[
        bool,
        typer.Option("--network", help="Monitor network-wide traffic from configured sensor only."),
    ] = False,
    both: Annotated[
        bool, typer.Option("--both", help="Simultaneously monitor local and network-wide traffic.")
    ] = False,
    interface: Annotated[
        str | None, typer.Option("--interface", "-i", help="Explicit network interface to capture.")
    ] = None,
    sensitivity: Annotated[
        str,
        typer.Option("--sensitivity", "-s", help="Detection sensitivity: low, balanced, or high."),
    ] = "balanced",
    duration: Annotated[
        int | None,
        typer.Option(
            "--duration", "-d", help="Monitoring duration in seconds (defaults to continuous)."
        ),
    ] = None,
    status: Annotated[
        bool, typer.Option("--status", help="Show sensor health, operational coverage and exit.")
    ] = False,
    diagnostics: Annotated[
        bool,
        typer.Option(
            "--diagnostics", help="Run packet capture permission and driver pre-flight diagnostics."
        ),
    ] = False,
    devices: Annotated[
        bool, typer.Option("--devices", help="List active tracked network endpoints.")
    ] = False,
    alerts: Annotated[
        bool, typer.Option("--alerts", help="Display recent detected threat alerts.")
    ] = False,
) -> None:
    """Default entry point for `systemscan network-monitor`."""
    if ctx.invoked_subcommand is not None:
        return

    # Handle quick flags
    if diagnostics:
        diagnostics_command()
        return

    if status:
        status_command()
        return

    if devices:
        devices_command()
        return

    if alerts:
        alerts_command()
        return

    # Determine mode
    mode = MonitorMode.BOTH
    if local and not network:
        mode = MonitorMode.LOCAL
    elif network and not local:
        mode = MonitorMode.NETWORK_WIDE

    run_live_monitor(
        mode=mode,
        interface=interface,
        sensitivity=sensitivity,
        duration=duration,
    )


def render_monitor_header() -> None:
    """Print standard cyan and white brand header."""
    console.print()
    console.print("[bold cyan]SSCLI[/bold cyan] / [bold white]NETWORK THREAT MONITOR[/bold white]")
    console.print(
        "[dim white]Passive Behavioral Reconnaissance & Nmap Scan Detection Engine[/dim white]\n"
    )


def run_live_monitor(
    mode: MonitorMode = MonitorMode.BOTH,
    interface: str | None = None,
    sensitivity: str = "balanced",
    duration: int | None = None,
) -> None:
    """Execute live monitoring loop with clean terminal output."""
    render_monitor_header()

    cfg = NetworkMonitorConfig(interface=interface)
    try:
        cfg.apply_sensitivity(sensitivity)
    except Exception:
        cfg.apply_sensitivity(SensitivityLevel.BALANCED)

    manager = NetworkThreatMonitorManager(config=cfg, console=console)
    report = manager.start_monitoring(mode=mode)

    # Initial status readout
    console.print("[bold cyan][LOCAL MONITOR][/bold cyan]")
    loc_color = "green" if report.local_capture_health.value == "HEALTHY" else "yellow"
    console.print(
        f"  [dim]Status    :[/dim] [{loc_color}]{report.local_capture_health.value}[/{loc_color}]"
    )
    console.print(f"  [dim]Interface :[/dim] {report.local_interface}")
    if report.local_details:
        console.print(f"  [dim]Details   :[/dim] [dim]{report.local_details}[/dim]")

    console.print("\n[bold cyan][NETWORK-WIDE MONITOR][/bold cyan]")
    net_color = "green" if report.network_capture_health.value == "HEALTHY" else "yellow"
    console.print(
        f"  [dim]Status    :[/dim] [{net_color}]{report.network_capture_health.value}[/{net_color}]"
    )
    console.print(f"  [dim]Source    :[/dim] {report.network_source_name}")
    console.print(f"  [dim]Details   :[/dim] [dim]{report.network_details}[/dim]")

    console.print("\n[bold cyan][MONITORING COVERAGE][/bold cyan]")
    console.print(f"  [bold white]{report.coverage_summary}[/bold white]")
    console.print(
        f"  [dim]Sensitivity: {cfg.sensitivity.value.upper()} (Threshold: {cfg.thresholds.tcp_port_scan_threshold} ports / {cfg.thresholds.time_window_seconds:.0f}s)[/dim]\n"
    )

    has_active_capture = (
        report.local_capture_health == SensorHealthStatus.HEALTHY
        or report.network_capture_health == SensorHealthStatus.HEALTHY
    )

    if not has_active_capture:
        console.print(
            "[bold red][!] No active packet capture stream is online.[/bold red]\n"
            "  [yellow]• On Windows:[/yellow] Install Npcap driver: [bold cyan]winget install Insecure.Npcap[/bold cyan] (run in Administrator terminal)\n"
            "  [yellow]• On Linux/Kali:[/yellow] Ensure [bold cyan]libpcap[/bold cyan] is installed and run with [bold cyan]sudo[/bold cyan]\n"
            "  [yellow]• Network-Wide:[/yellow] Configure an external router/sensor API in settings.\n"
        )
        console.print(
            "[dim yellow]Capture engine is idling. Press Ctrl+C to stop or return to menu.[/dim yellow]\n"
        )
    else:
        console.print(
            "[bold green][INFO] Detection engine active. Listening for scan patterns... (Press Ctrl+C to stop)[/bold green]\n"
        )

    try:
        start_time = time.time()
        while True:
            time.sleep(0.5)
            if duration and (time.time() - start_time) >= duration:
                console.print(
                    f"\n[bold yellow]Configured monitoring duration ({duration}s) elapsed.[/bold yellow]"
                )
                break
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]Stopping network threat monitor (Ctrl+C pressed)...[/bold yellow]"
        )
    finally:
        manager.stop_monitoring()
        console.print("[bold cyan][INFO] Network Threat Monitor halted cleanly.[/bold cyan]\n")


@app.command("status", help="Display operational sensor health, interfaces, and coverage.")
def status_command() -> None:
    """Print current monitor sensor readiness without starting continuous capture."""
    render_monitor_header()
    manager = NetworkThreatMonitorManager(console=console)
    report = manager.get_status_report()

    s_tbl = Table(title="Sensor Operational Status", header_style="bold cyan", border_style="dim")
    s_tbl.add_column("Subsystem", style="bold white")
    s_tbl.add_column("Health Status", style="cyan")
    s_tbl.add_column("Source / Interface", style="white")
    s_tbl.add_column("Details", style="dim")

    loc_health, loc_msg = manager.local_capture.get_health_status()
    net_health, net_msg = manager.network_capture.get_health_status()

    s_tbl.add_row(
        "Local Laptop Monitor",
        loc_health.value,
        manager.local_capture.get_interface_name(),
        loc_msg,
    )
    s_tbl.add_row(
        "Network-Wide Sensor",
        net_health.value,
        manager.network_capture.get_interface_name(),
        net_msg,
    )
    console.print(s_tbl)
    console.print(f"\n  [bold cyan]Coverage Posture:[/bold cyan] {report.coverage_summary}\n")


@app.command(
    "diagnostics", help="Check packet capture permissions, Npcap/libpcap drivers, and Scapy."
)
def diagnostics_command() -> None:
    """Run capture environment diagnostic checks."""
    render_monitor_header()
    diag = CaptureDiagnostics.run_diagnostics()

    d_tbl = Table(title="Packet Capture Diagnostics", header_style="bold cyan", border_style="dim")
    d_tbl.add_column("Check Dimension", style="cyan")
    d_tbl.add_column("Result", style="bold white")

    d_tbl.add_row("Operating System", f"{diag['os']} ({diag['architecture']})")
    d_tbl.add_row("Python Version", diag["python_version"])
    d_tbl.add_row(
        "Administrative / Root Privilege",
        "[green]YES[/green]" if diag["is_elevated"] else "[yellow]NO (Standard User)[/yellow]",
    )
    d_tbl.add_row(
        "Scapy Library Installed",
        "[green]YES[/green]" if diag["scapy_installed"] else "[red]NO[/red]",
    )
    d_tbl.add_row("Packet Capture Driver", diag["pcap_driver_status"])
    d_tbl.add_row(
        "Local Capture Capability",
        "[green]READY[/green]"
        if diag["can_capture_local"]
        else "[yellow]ATTENTION REQUIRED[/yellow]",
    )
    console.print(d_tbl)
    console.print()


@app.command("alerts", help="List recent network security threat alerts.")
def alerts_command(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Maximum alerts to retrieve.")] = 20,
    export: Annotated[
        str | None, typer.Option("--export", "-e", help="Export format: json, csv, or txt.")
    ] = None,
) -> None:
    """Display or export recorded threat alerts from local SQLite database."""
    db = NetworkAlertDatabase()
    if export:
        content = db.export_alerts(fmt=export, limit=limit)
        console.print(content)
        return

    alerts = db.list_alerts(limit=limit)
    if not alerts:
        console.print("\n[dim]No network threat alerts recorded in history database.[/dim]\n")
        return

    a_tbl = Table(
        title=f"Recorded Network Threat Alerts ({len(alerts)} items)",
        header_style="bold cyan",
        border_style="dim",
    )
    a_tbl.add_column("Event ID", style="dim white")
    a_tbl.add_column("Time", style="dim")
    a_tbl.add_column("Severity", style="bold red")
    a_tbl.add_column("Pattern", style="bold yellow")
    a_tbl.add_column("Source IP", style="cyan")
    a_tbl.add_column("Target IP", style="white")
    a_tbl.add_column("Ports", style="bold white")

    for a in alerts:
        time_str = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        a_tbl.add_row(
            a.alert_id,
            time_str,
            a.severity.value,
            a.pattern.value,
            a.source_ip,
            a.destination_ip,
            str(a.unique_ports),
        )
    console.print(a_tbl)
    console.print()


@app.command("devices", help="List tracked network hosts and identification metadata.")
def devices_command() -> None:
    """Display hosts discovered through active ARP or traffic observations."""
    render_monitor_header()
    manager = NetworkThreatMonitorManager(console=console)
    devs = manager.get_tracked_devices()
    if not devs:
        console.print("[dim]No devices currently observed in memory table.[/dim]\n")
        return

    d_tbl = Table(
        title=f"Observed Network Devices ({len(devs)} tracked)",
        header_style="bold cyan",
        border_style="dim",
    )
    d_tbl.add_column("IP Address", style="bold cyan")
    d_tbl.add_column("MAC Address", style="white")
    d_tbl.add_column("Hostname", style="dim white")
    d_tbl.add_column("Vendor", style="dim")
    d_tbl.add_column("Confidence", style="green")

    for d in devs:
        d_tbl.add_row(
            d.ip_address,
            d.mac_address or "Unknown",
            d.hostname or "Unresolved",
            d.vendor or "Unknown OUI",
            d.confidence.value,
        )
    console.print(d_tbl)
    console.print()
