"""CLI command definitions for the Network Security & Intelligence Engine."""

from __future__ import annotations

import json
from typing import Annotated, Any

import typer
from rich.console import Console

from systemscan.cli.display import (
    render_discovered_hosts_table,
    render_firewall_status_panel,
    render_network_connections_table,
    render_network_diagnostics_panel,
    render_network_findings_table,
    render_network_interfaces_table,
)
from systemscan.network.baseline import NetworkBaselineManager
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.diagnostics import NetworkDiagnostics
from systemscan.network.discovery import LocalNetworkDiscovery
from systemscan.network.dns import DNSIntelligenceEngine
from systemscan.network.findings import NetworkFindingsEvaluator
from systemscan.network.firewall import FirewallAuditor
from systemscan.network.interfaces import NetworkInterfaceInspector
from systemscan.network.models import ConnectionState, DNSRecordType
from systemscan.network.monitor import NetworkMonitor
from systemscan.network.wireless import WirelessSecurityInspector

console = Console()
app = typer.Typer(
    name="network",
    help="Cross-platform Network Security Audit & Network Intelligence Engine.",
    no_args_is_help=True,
)

baseline_app = typer.Typer(
    name="baseline",
    help="Network configuration baseline management and drift comparison.",
    no_args_is_help=True,
)
app.add_typer(baseline_app, name="baseline")


@app.command(name="interfaces")
def inspect_interfaces(
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Discover and display all host network interfaces, addressing, and link speeds."""
    inspector = NetworkInterfaceInspector()
    ifaces = inspector.inspect_all()

    if format.lower() == "json":
        data = [i.model_dump(mode="json") for i in ifaces]
        console.print_json(json.dumps(data, indent=2))
    else:
        render_network_interfaces_table(ifaces)


@app.command(name="connections")
def inspect_connections(
    state: Annotated[
        str,
        typer.Option(
            "--state",
            "-s",
            help="Filter by connection state (e.g. 'ESTABLISHED', 'LISTEN', 'ALL').",
        ),
    ] = "ALL",
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Inspect active TCP/UDP sockets, connection states, and owning processes."""
    inspector = NetworkConnectionInspector()
    conns = inspector.inspect_connections()

    state_filter = state.upper()
    if state_filter != "ALL":
        conns = [c for c in conns if c.state.value == state_filter]

    if format.lower() == "json":
        data = [c.model_dump(mode="json") for c in conns]
        console.print_json(json.dumps(data, indent=2))
    else:
        title = f"Active Network Connections ({state_filter})"
        render_network_connections_table(conns, title=title)


@app.command(name="listening")
def inspect_listening(
    all_interfaces_only: Annotated[
        bool,
        typer.Option(
            "--all-interfaces", "-a", help="Filter only sockets listening on 0.0.0.0 or ::."
        ),
    ] = False,
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Inspect listening network services and exposed incoming ports."""
    inspector = NetworkConnectionInspector()
    conns = inspector.get_listening_ports()

    if all_interfaces_only:
        conns = [c for c in conns if c.is_all_interfaces]

    if format.lower() == "json":
        data = [c.model_dump(mode="json") for c in conns]
        console.print_json(json.dumps(data, indent=2))
    else:
        title = (
            "Globally Exposed Listening Ports (0.0.0.0 / ::)"
            if all_interfaces_only
            else "Listening Ports"
        )
        render_network_connections_table(conns, title=title)


@app.command(name="discover")
def discover_network(
    subnet: Annotated[
        str | None,
        typer.Option(
            "--subnet", "-s", help="Target CIDR subnet (e.g. 192.168.1.0/24). Inferred if omitted."
        ),
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", help="Per-host socket timeout in seconds.")
    ] = 0.35,
    allow_public: Annotated[
        bool,
        typer.Option(
            "--allow-public", help="Explicitly authorize scanning a non-private IP range."
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes", "-y", help="Confirm execution without interactive authorization prompt."
        ),
    ] = False,
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Discover and enumerate reachable hosts on an authorized local subnet."""
    discovery = LocalNetworkDiscovery()
    target_subnet = subnet or discovery.get_default_local_subnet()

    if not target_subnet:
        console.print(
            "[bold red]Error:[/bold red] Could not determine default local subnet. Please specify --subnet."
        )
        raise typer.Exit(code=1)

    try:
        net = discovery.validate_subnet_authorization(target_subnet, allow_public=allow_public)
    except (ValueError, PermissionError) as e:
        console.print(f"[bold red]Validation Error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    console.print(f"\n[bold cyan]Target Subnet:[/bold cyan] {net}")
    console.print(
        f"[bold cyan]Host Scope:[/bold cyan] {net.num_addresses} addresses ({net.network_address} to {net.broadcast_address})"
    )

    if not yes:
        confirm = typer.confirm(
            f"Do you have explicit authorization to audit and discover hosts on '{target_subnet}'?",
            default=True,
        )
        if not confirm:
            console.print("[yellow]Network discovery cancelled by operator.[/yellow]")
            return

    console.print(
        "[dim]Executing safe local host discovery (ARP cache + non-intrusive TCP probes)...[/dim]"
    )
    hosts = discovery.discover(
        subnet_str=str(net), probe_timeout=timeout, allow_public=allow_public
    )

    if format.lower() == "json":
        data = [h.model_dump(mode="json") for h in hosts]
        console.print_json(json.dumps(data, indent=2))
    else:
        render_discovered_hosts_table(hosts, subnet=str(net))


@app.command(name="dns")
def audit_dns(
    domain: Annotated[
        str, typer.Option("--domain", "-d", help="Domain to test resolution for.")
    ] = "example.com",
    record_type: Annotated[
        str, typer.Option("--type", "-t", help="Record type: A, AAAA, PTR, MX, TXT.")
    ] = "A",
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Inspect configured DNS servers and perform test name resolution."""
    engine = DNSIntelligenceEngine()
    servers, _, findings = engine.audit_dns_health()

    try:
        rtype = DNSRecordType[record_type.upper()]
    except KeyError:
        rtype = DNSRecordType.A

    test_res = engine.resolve_domain(domain=domain, record_type=rtype)

    if format.lower() == "json":
        payload = {
            "configured_servers": servers,
            "query_result": test_res.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        console.print_json(json.dumps(payload, indent=2))
    else:
        console.print("\n[bold cyan]Configured DNS Resolver Servers:[/bold cyan]")
        if servers:
            for s in servers:
                console.print(f" - [bold green]{s}[/bold green]")
        else:
            console.print(" [yellow]None detected[/yellow]")

        console.print(f"\n[bold cyan]DNS Resolution Test ({domain} [{rtype.value}]):[/bold cyan]")
        if test_res.success:
            console.print(
                f" - Status: [bold green]SUCCESS[/bold green] ({test_res.resolution_time_ms} ms)"
            )
            console.print(f" - Records: [white]{', '.join(test_res.records)}[/white]")
        else:
            console.print(f" - Status: [bold red]FAILED[/bold red] ({test_res.error})")

        render_network_findings_table(findings)


@app.command(name="firewall")
def inspect_firewall(
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Inspect operating system firewall state, active profiles, and security posture."""
    auditor = FirewallAuditor()
    status, findings = auditor.audit_firewall()

    if format.lower() == "json":
        payload = {
            "firewall_status": status.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        console.print_json(json.dumps(payload, indent=2))
    else:
        render_firewall_status_panel(status)
        render_network_findings_table(findings)


@app.command(name="wifi")
def inspect_wifi(
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Inspect active Wi-Fi connection, encryption protocol, and signal strength."""
    inspector = WirelessSecurityInspector()
    info, findings = inspector.inspect_wifi()

    if format.lower() == "json":
        payload = {
            "wireless_info": info.model_dump(mode="json") if info else None,
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        console.print_json(json.dumps(payload, indent=2))
    else:
        if not info or not info.is_connected or not info.ssid:
            console.print("\n[yellow]No active Wi-Fi connection detected on host.[/yellow]\n")
            return

        console.print("\n[bold cyan]Active Wi-Fi Connection:[/bold cyan]")
        console.print(f" - SSID: [bold white]{info.ssid}[/bold white]")
        console.print(f" - BSSID: [dim]{info.bssid or 'Unknown'}[/dim]")
        sec_color = "red" if info.is_open or info.is_weak else "green"
        console.print(f" - Security: [{sec_color}]{info.security_type or 'Unknown'}[/{sec_color}]")
        console.print(f" - Band: {info.band or 'Unknown'}, Channel: {info.channel or 'Unknown'}")
        if info.signal_strength_pct is not None:
            console.print(f" - Signal Quality: [bold cyan]{info.signal_strength_pct}%[/bold cyan]")

        render_network_findings_table(findings)


@app.command(name="diagnostics")
def run_diagnostics(
    target: Annotated[
        str, typer.Option("--target", "-t", help="Internet target IP to probe.")
    ] = "1.1.1.1",
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Run basic connectivity and reachability diagnostics across Gateway, DNS, and Internet."""
    diag = NetworkDiagnostics()
    console.print(
        f"\n[dim]Executing network reachability diagnostics (Gateway, DNS, {target})...[/dim]"
    )
    res = diag.run_diagnostics(internet_target=target)

    if format.lower() == "json":
        console.print_json(res.model_dump_json(indent=2))
    else:
        render_network_diagnostics_panel(res)


@app.command(name="audit")
def full_network_audit(
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Run a comprehensive network security audit synthesizing all checks and findings."""
    evaluator = NetworkFindingsEvaluator()
    if format.lower() != "json":
        console.print(
            "\n[bold cyan]Executing Comprehensive Host Network Security Audit...[/bold cyan]\n"
        )

    findings = evaluator.run_full_audit()

    if format.lower() == "json":
        data = [f.model_dump(mode="json") for f in findings]
        console.print_json(json.dumps(data, indent=2))
    else:
        render_network_findings_table(findings)


@app.command(name="monitor")
def monitor_connections(
    interval: Annotated[
        float, typer.Option("--interval", "-i", help="Polling interval in seconds.")
    ] = 2.0,
    duration: Annotated[
        float | None,
        typer.Option(
            "--duration", "-d", help="Total monitoring duration in seconds (indefinite if omitted)."
        ),
    ] = None,
) -> None:
    """Monitor active socket connections and newly opened listening ports in real time."""
    monitor_engine = NetworkMonitor()
    console.print(
        f"\n[bold cyan]Starting real-time network connection monitor (Interval: {interval}s)...[/bold cyan]"
    )
    console.print("[dim]Press Ctrl+C to stop monitoring at any time.[/dim]\n")

    cycle = 0

    def on_update(current: list[Any], new_socks: list[Any]) -> None:
        nonlocal cycle
        cycle += 1
        listen_count = len([c for c in current if c.is_listening])
        estab_count = len([c for c in current if c.state == ConnectionState.ESTABLISHED])
        console.print(
            f"[dim]Cycle {cycle}:[/dim] Active Sockets: [bold white]{len(current)}[/bold white] "
            f"(Established: [green]{estab_count}[/green], Listening: [yellow]{listen_count}[/yellow])"
        )
        if new_socks:
            for s in new_socks:
                r_str = f" -> {s.remote_address}:{s.remote_port}" if s.remote_address else ""
                console.print(
                    f"  [bold yellow]+ NEW SOCKET:[/bold yellow] {s.protocol.value} {s.local_address}:{s.local_port}{r_str} "
                    f"[{s.state.value}] ({s.process_name or 'PID ' + str(s.pid)})"
                )

    try:
        monitor_engine.monitor(interval=interval, duration=duration, on_update=on_update)
    except KeyboardInterrupt:
        console.print("\n[yellow]Network monitoring stopped by operator.[/yellow]\n")


# Baseline subcommands
@baseline_app.command(name="create")
def baseline_create(
    name: Annotated[str, typer.Option("--name", "-n", help="Baseline profile name.")] = "default",
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Overwrite existing baseline profile.")
    ] = False,
) -> None:
    """Capture current network configuration as a persistent baseline."""
    mgr = NetworkBaselineManager()
    try:
        baseline = mgr.create_baseline(name=name, overwrite=overwrite)
        console.print(f"\n[bold green]Network baseline '{name}' successfully created.[/bold green]")
        console.print(f" - Interfaces: {len(baseline.known_interfaces)}")
        console.print(f" - Gateways: {baseline.known_gateways}")
        console.print(f" - DNS Servers: {baseline.known_dns_servers}")
        console.print(f" - Listening Ports: {len(baseline.known_listening_ports)}")
    except FileExistsError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


@baseline_app.command(name="compare")
def baseline_compare(
    name: Annotated[str, typer.Option("--name", "-n", help="Baseline profile name.")] = "default",
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: 'text' or 'json'.")
    ] = "text",
) -> None:
    """Compare current network state against a saved baseline."""
    mgr = NetworkBaselineManager()
    try:
        diff = mgr.compare_baseline(name=name)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    if format.lower() == "json":
        console.print_json(diff.model_dump_json(indent=2))
        return

    console.print(f"\n[bold cyan]Network Baseline Drift Comparison ({name}):[/bold cyan]")
    if not diff.has_changes:
        console.print(
            "[bold green]Zero drift detected. System network matches established baseline.[/bold green]\n"
        )
        return

    if diff.added_gateways:
        console.print(f" - [bold red]Added Gateway(s):[/bold red] {diff.added_gateways}")
    if diff.removed_gateways:
        console.print(f" - [bold yellow]Removed Gateway(s):[/bold yellow] {diff.removed_gateways}")
    if diff.added_dns_servers:
        console.print(f" - [bold red]Added DNS Server(s):[/bold red] {diff.added_dns_servers}")
    if diff.removed_dns_servers:
        console.print(
            f" - [bold yellow]Removed DNS Server(s):[/bold yellow] {diff.removed_dns_servers}"
        )
    if diff.added_listening_ports:
        console.print(
            f" - [bold red]New Listening Port(s):[/bold red] {diff.added_listening_ports}"
        )
    if diff.removed_listening_ports:
        console.print(f" - [dim]Closed Listening Port(s):[/dim] {diff.removed_listening_ports}")

    render_network_findings_table(diff.findings)


@baseline_app.command(name="list")
def baseline_list() -> None:
    """List all saved network baseline profiles."""
    mgr = NetworkBaselineManager()
    baselines = mgr.list_baselines()
    console.print("\n[bold cyan]Saved Network Baseline Profiles:[/bold cyan]")
    if baselines:
        for b in baselines:
            console.print(f" - [bold white]{b}[/bold white]")
    else:
        console.print(
            " [dim]No saved baselines found. Run 'systemscan network baseline create' to create one.[/dim]"
        )
    console.print()
