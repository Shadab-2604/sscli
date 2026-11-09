"""Interactive CLI Menu for SSCLI.

Provides a clean, professional, terminal-native interactive command line interface
with subtle colors, compact Rich formatting, and live in-line scan progress.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from systemscan import __version__
from systemscan.core.application import app_instance
from systemscan.core.dependencies import EnvironmentDoctor
from systemscan.devices.manager import DeviceManager
from systemscan.devices.repair import StorageRepairEngine
from systemscan.engine.eta import IntelligentETAEngine
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.models import ScanHistoryRecord, ScanState, ScanType
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import DirectoryMetadata, FileMetadata, ScanConfig
from systemscan.modules.malware.engine import MalwareDetectionEngine
from systemscan.modules.malware.models import ThreatSeverity
from systemscan.modules.storage.cache.discovery import CacheDiscoveryEngine
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.firewall import FirewallAuditor
from systemscan.network.interfaces import NetworkInterfaceInspector
from systemscan.platform.detection import detect_platform_name
from systemscan.reporting.generator import ReportGenerator
from systemscan.reporting.models import (
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    ReportFormat,
)
from systemscan.reporting.storage import ReportStorageManager
from systemscan.utils.formatting import format_bytes, format_duration

console = Console()


def get_cpu_brand() -> str:
    """Retrieve a clean, concise CPU model string."""
    try:
        from systemscan.modules.hardware.cpu import get_static_cpu_info

        brand = get_static_cpu_info().get("brand_raw")
        if brand:
            return str(brand)
    except Exception:
        pass
    proc = platform.processor()
    if proc:
        return proc
    cores = psutil.cpu_count(logical=False) or psutil.cpu_count(logical=True) or 1
    return f"{cores}-Core Processor"


def render_cli_welcome() -> None:
    """Render compact, professional CLI header and host summary."""
    console.print()
    console.print(
        "[bold cyan]SSCLI[/bold cyan] / [bold white]SYSTEM SECURITY & INTELLIGENCE[/bold white]"
    )
    console.print(f"[dim white]Universal System Security Scanner v{__version__}[/dim white]\n")

    os_display = detect_platform_name(detailed=True)
    cpu_display = get_cpu_brand()
    ram_gb = format_bytes(psutil.virtual_memory().total)

    console.print("[bold cyan][SYSTEM][/bold cyan]")
    console.print(f"  [dim]OS       :[/dim] {os_display}")
    console.print(f"  [dim]CPU      :[/dim] {cpu_display}")
    console.print(f"  [dim]RAM      :[/dim] {ram_gb}")
    console.print("  [dim]STATUS   :[/dim] [bold green]READY[/bold green]\n")

    console.print("[bold cyan][MAIN MENU][/bold cyan]\n")
    menu_items = [
        ("1", "System Information"),
        ("2", "Quick Security Scan"),
        ("3", "Full System Scan"),
        ("4", "Custom Path Scan"),
        ("5", "Malware Detection"),
        ("6", "Storage Analyzer"),
        ("7", "Network Security Audit & Threat Monitor"),
        ("8", "USB / External Device Scanner & Repair"),
        ("9", "Scan History"),
        ("10", "Reports & Export"),
        ("11", "Dependency Doctor"),
        ("12", "Settings"),
        ("13", "Check for Updates & Self-Update"),
        ("0", "Exit"),
    ]
    for num, label in menu_items:
        console.print(f"  [bold cyan]{num:>2}.[/bold cyan] {label}")
    console.print()


def pause_prompt() -> None:
    """Wait for user to press enter before returning to the main menu."""
    try:
        Prompt.ask("\n[dim]Press Enter to return to the main menu...[/dim]", default="")
    except (KeyboardInterrupt, EOFError):
        pass


def run_compact_live_scan(
    scan_title: str,
    roots: list[str],
    max_depth: int | None = None,
    enable_malware: bool = True,
) -> None:
    """Execute live scan with clean, compact in-line terminal progress updates."""
    console.print("\n[bold blue][INFO][/bold blue] Initializing scanner...")
    console.print(f"[bold blue][INFO][/bold blue] Scan type: [bold white]{scan_title}[/bold white]")
    root_str = ", ".join(roots[:2]) + ("..." if len(roots) > 2 else "")
    console.print(f"[bold blue][INFO][/bold blue] Target: [cyan]{root_str}[/cyan]")

    scanner = FilesystemScanner()
    token = CancellationToken()
    eta_engine = IntelligentETAEngine()
    malware_engine = MalwareDetectionEngine() if enable_malware else None

    scan_cfg = ScanConfig(
        roots=roots,
        max_depth=max_depth,
        include_hidden=True,
    )

    scan_id = f"scan-{int(time.time())}"
    start_time = time.time()
    files_scanned = 0
    dirs_scanned = 0
    bytes_scanned = 0
    errors_count = 0
    current_path_str = ""
    findings: list[dict[str, Any]] = []

    def make_live_text(is_done: bool = False) -> Text:
        txt = Text()
        txt.append("  [SCAN] ", style="bold blue")
        txt.append(f"Files scanned       : {files_scanned:,}\n")

        txt.append("  [SCAN] ", style="bold blue")
        txt.append(f"Directories scanned : {dirs_scanned:,}\n")

        txt.append("  [SCAN] ", style="bold blue")
        txt.append(f"Data scanned        : {format_bytes(bytes_scanned)}\n")

        # ETA and progress
        _, eta_sec, comp_pct = eta_engine.calculate_eta()
        pct_display = (
            f"{comp_pct:.0f}%" if comp_pct is not None else f"{min(99, files_scanned % 100)}%"
        )
        eta_display = format_duration(eta_sec) if eta_sec is not None else "Calculating..."
        if is_done:
            pct_display = "100%"
            eta_display = "Completed"

        txt.append("  [SCAN] ", style="bold blue")
        txt.append(f"Progress            : {pct_display} (ETA: {eta_display})\n")

        if errors_count > 0:
            txt.append("  [WARN] ", style="bold yellow")
            txt.append(f"Permission errors   : {errors_count}\n", style="yellow")
        else:
            txt.append("  [WARN] ", style="dim")
            txt.append(f"Permission errors   : {errors_count}\n", style="dim")

        if findings:
            txt.append("  [ALERT] ", style="bold red")
            txt.append(f"Threats detected    : {len(findings)}\n", style="bold red")
        else:
            txt.append("  [OK]   ", style="bold green")
            txt.append(f"Threats detected    : {len(findings)}\n", style="green")

        if current_path_str and not is_done:
            trunc_path = current_path_str
            if len(trunc_path) > 60:
                trunc_path = "..." + trunc_path[-57:]
            txt.append(f"  [dim]Current: {trunc_path}[/dim]", style="dim")

        return txt

    last_update = time.time()
    try:
        with Live(make_live_text(), console=console, refresh_per_second=10) as live:
            for item in scanner.stream_scan(config=scan_cfg, cancellation_token=token):
                if token.is_cancelled:
                    break

                if isinstance(item, FileMetadata):
                    files_scanned += 1
                    bytes_scanned += item.size_bytes
                    current_path_str = str(item.path)
                    eta_engine.record_progress(items_delta=1, bytes_delta=item.size_bytes)

                    # Malware inspection
                    if malware_engine:
                        try:
                            verdicts = malware_engine.analyze_file(item.path, scan_id=scan_id)
                            for v in verdicts:
                                if v.severity in (
                                    ThreatSeverity.CRITICAL,
                                    ThreatSeverity.HIGH,
                                    ThreatSeverity.MEDIUM,
                                ):
                                    findings.append(
                                        {
                                            "severity": v.severity.value,
                                            "rule_name": v.threat_name or v.rule_id,
                                            "path": str(item.path),
                                            "evidence": v.evidence,
                                        }
                                    )
                        except Exception:
                            pass

                elif isinstance(item, DirectoryMetadata):
                    dirs_scanned += 1
                    current_path_str = str(item.path)

                now = time.time()
                if now - last_update >= 0.15:
                    live.update(make_live_text())
                    last_update = now

            live.update(make_live_text(is_done=True))

    except KeyboardInterrupt:
        token.cancel()
        console.print("\n[bold yellow][WARN] Scan cancelled by user (Ctrl+C).[/bold yellow]")

    elapsed = max(0.1, time.time() - start_time)
    status = ScanState.CANCELLED if token.is_cancelled else ScanState.COMPLETED

    # Save to history
    try:
        record = ScanHistoryRecord(
            scan_id=scan_id,
            scan_type=ScanType.FULL if "FULL" in scan_title.upper() else ScanType.CUSTOM,
            targets=roots,
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_seconds=elapsed,
            status=status,
            items_processed=files_scanned,
            bytes_processed=bytes_scanned,
            findings_count=len(findings),
            items_failed=errors_count,
        )
        ScanHistoryManager().record_session(record)
    except Exception:
        pass

    # Generate and store report
    report_path_str = ""
    try:
        report_findings: list[FindingRecord] = []
        for idx, f in enumerate(findings):
            sev_str = f.get("severity", "MEDIUM").upper()
            sev_enum = (
                FindingSeverity.HIGH if sev_str in ("HIGH", "CRITICAL") else FindingSeverity.MEDIUM
            )
            report_findings.append(
                FindingRecord(
                    finding_id=f"FIND-{idx + 1:04d}",
                    category=f.get("rule_name", "Malware"),
                    title=f.get("rule_name", "Suspicious Finding"),
                    description=f.get("evidence", "Detection match"),
                    severity=sev_enum,
                    confidence=FindingConfidence.HIGH,
                    evidence=f.get("evidence", ""),
                    target=f.get("path", ""),
                    source_module="malware.engine",
                )
            )

        st_type = ScanType.FULL if "FULL" in scan_title.upper() else ScanType.CUSTOM
        report = ReportGenerator.generate_report(
            scan_id=scan_id,
            scan_type=st_type,
            scan_status=status,
            start_time=datetime.fromtimestamp(start_time, tz=timezone.utc),
            completion_time=datetime.now(timezone.utc),
            duration_seconds=elapsed,
            items_processed=files_scanned,
            bytes_processed=bytes_scanned,
            directories_inspected=dirs_scanned,
            findings=report_findings,
        )
        storage_mgr = ReportStorageManager()
        saved_path = storage_mgr.save_report(report, fmt=ReportFormat.JSON)
        report_path_str = str(saved_path)
    except Exception:
        pass

    # Print summary
    if status == ScanState.COMPLETED:
        console.print(
            f"\n[bold green][OK][/bold green] Scan completed in [bold white]{format_duration(elapsed)}[/bold white]"
        )
        console.print(
            f"[bold cyan][INFO][/bold cyan] Summary: [bold white]{files_scanned:,}[/bold white] files, "
            f"[bold white]{dirs_scanned:,}[/bold white] directories, "
            f"[bold white]{format_bytes(bytes_scanned)}[/bold white] scanned."
        )
        if findings:
            console.print(
                f"[bold red][ALERT][/bold red] Detections: [bold red]{len(findings)} threat(s) detected[/bold red]"
            )
            # Show top findings
            f_table = Table(title="Detected Threats", header_style="bold red", border_style="dim")
            f_table.add_column("Severity", style="bold red")
            f_table.add_column("Rule / Threat", style="yellow")
            f_table.add_column("Path", style="white")
            for f in findings[:10]:
                f_table.add_row(f["severity"], f["rule_name"], f["path"])
            console.print(f_table)
        else:
            console.print(
                "[bold green][OK][/bold green] Threats detected: [bold green]0[/bold green]"
            )

        if report_path_str:
            console.print(
                f"[bold cyan][INFO][/bold cyan] Report saved: [dim]{report_path_str}[/dim]"
            )


def action_system_info() -> None:
    """Action 1: Display comprehensive system & hardware intelligence."""
    console.print(
        "\n[bold cyan]─── SYSTEM INFORMATION ──────────────────────────────────────[/bold cyan]"
    )

    os_tbl = Table(title="Operating System", header_style="bold cyan", border_style="dim")
    os_tbl.add_column("Property", style="dim white")
    os_tbl.add_column("Value", style="bold white")

    os_tbl.add_row("Platform", detect_platform_name(detailed=True))
    os_tbl.add_row("System / Kernel", f"{platform.system()} {platform.release()}")
    os_tbl.add_row("Architecture", platform.machine())
    os_tbl.add_row("Hostname", platform.node())
    os_tbl.add_row("Python", f"{platform.python_version()} ({platform.architecture()[0]})")
    try:
        boot_s = time.time() - psutil.boot_time()
        os_tbl.add_row("Uptime", format_duration(boot_s))
    except Exception:
        pass
    console.print(os_tbl)

    # CPU & Memory table
    perf_tbl = Table(title="CPU & Memory", header_style="bold cyan", border_style="dim")
    perf_tbl.add_column("Resource", style="dim white")
    perf_tbl.add_column("Metric", style="bold white")

    perf_tbl.add_row("Processor Model", get_cpu_brand())
    perf_tbl.add_row("Physical Cores", str(psutil.cpu_count(logical=False)))
    perf_tbl.add_row("Logical Threads", str(psutil.cpu_count(logical=True)))
    perf_tbl.add_row("Current CPU Usage", f"{psutil.cpu_percent(interval=0.1)}%")

    mem = psutil.virtual_memory()
    perf_tbl.add_row("Total RAM", format_bytes(mem.total))
    perf_tbl.add_row("Available RAM", format_bytes(mem.available))
    perf_tbl.add_row("Used RAM", f"{format_bytes(mem.used)} ({mem.percent}%)")
    console.print(perf_tbl)


def action_quick_scan() -> None:
    """Action 2: Fast heuristic scan across user home profile."""
    user_home = str(Path.home())
    run_compact_live_scan(
        "Quick Security Scan", roots=[user_home], max_depth=4, enable_malware=True
    )


def action_full_scan() -> None:
    """Action 3: Comprehensive volume scan across all discovered roots."""
    scanner = FilesystemScanner()
    accessible = scanner.discovery.discover_accessible_roots()
    target_roots = [str(r) for r in accessible] or (["C:\\"] if os.name == "nt" else ["/"])
    run_compact_live_scan("Full System Scan", roots=target_roots, enable_malware=True)


def action_custom_scan() -> None:
    """Action 4: Custom path scan."""
    default_dir = os.getcwd()
    user_path = Prompt.ask("\nEnter directory path to scan", default=default_dir).strip()
    target = Path(user_path).expanduser().resolve()
    if not target.exists():
        console.print(f"[bold red][ERR] Path not found: {target}[/bold red]")
        return
    run_compact_live_scan(f"Custom Scan ({target.name})", roots=[str(target)], enable_malware=True)


def action_malware_scan() -> None:
    """Action 5: Malware & suspicious file inspection sweep."""
    default_dir = os.getcwd()
    user_path = Prompt.ask(
        "\nEnter target path for malware inspection", default=default_dir
    ).strip()
    target = Path(user_path).expanduser().resolve()
    if not target.exists():
        console.print(f"[bold red][ERR] Path not found: {target}[/bold red]")
        return
    run_compact_live_scan(
        f"Malware Sweep ({target.name})", roots=[str(target)], enable_malware=True
    )


def get_directory_size_safe(
    dir_path: Path, max_files: int = 5000, max_time_sec: float = 2.0
) -> int | None:
    """Safely calculate directory size with file limit and timeout to avoid hanging."""
    if not dir_path.exists():
        return None
    total_size = 0
    count = 0
    start_time = time.time()
    try:
        for root, _, files in os.walk(dir_path):
            for f in files:
                count += 1
                if count > max_files or (time.time() - start_time) > max_time_sec:
                    return total_size
                try:
                    p = Path(root) / f
                    if not p.is_symlink():
                        total_size += p.stat().st_size
                except (PermissionError, OSError):
                    continue
        return total_size
    except Exception:
        return None


def action_storage_analyzer() -> None:
    """Action 6: Mounted volume and cache inspection."""
    console.print(
        "\n[bold cyan]─── STORAGE ANALYZER ────────────────────────────────────────[/bold cyan]"
    )

    d_tbl = Table(title="Mounted Storage Partitions", header_style="bold cyan", border_style="dim")
    d_tbl.add_column("Device / Mount", style="white")
    d_tbl.add_column("Fstype", style="dim")
    d_tbl.add_column("Total", style="white")
    d_tbl.add_column("Used", style="white")
    d_tbl.add_column("Free", style="green")
    d_tbl.add_column("Usage", style="yellow")

    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            d_tbl.add_row(
                part.mountpoint,
                part.fstype,
                format_bytes(usage.total),
                format_bytes(usage.used),
                format_bytes(usage.free),
                f"{usage.percent}%",
            )
        except (PermissionError, OSError):
            continue
    console.print(d_tbl)

    # Cache discoveries
    try:
        cache_engine = CacheDiscoveryEngine()
        caches = cache_engine.get_standard_cache_directories()
        c_tbl = Table(
            title="Discovered System / App Caches", header_style="bold cyan", border_style="dim"
        )
        c_tbl.add_column("Category", style="cyan")
        c_tbl.add_column("Path", style="dim white")
        c_tbl.add_column("Size", style="bold yellow")
        for cat, p in caches[:10]:
            p_obj = Path(p)
            sz = get_directory_size_safe(p_obj)
            sz_str = format_bytes(sz) if sz is not None else "Inaccessible"
            c_tbl.add_row(cat, str(p), sz_str)
        console.print(c_tbl)
    except Exception as e:
        console.print(f"[dim]Cache discovery notice: {e}[/dim]")


def action_network_audit() -> None:
    """Action 7: Network security posture inspection."""
    console.print(
        "\n[bold cyan]─── NETWORK SECURITY AUDIT ──────────────────────────────────[/bold cyan]"
    )

    # Firewall
    try:
        fw_status, _ = FirewallAuditor().audit_firewall()
        fw_state = (
            "[bold green]ENABLED[/bold green]"
            if fw_status.is_enabled
            else "[bold red]DISABLED[/bold red]"
        )
        console.print(
            f"  [bold cyan]Firewall Backend :[/bold cyan] {fw_status.backend_name or 'Host Firewall'} ({fw_state})"
        )
        console.print(
            f"  [bold cyan]Default Inbound  :[/bold cyan] {fw_status.default_inbound_action.value}\n"
        )
    except Exception as e:
        console.print(f"  [yellow]Firewall audit note: {e}[/yellow]\n")

    # Interfaces
    try:
        ifaces = NetworkInterfaceInspector().inspect_all()
        if_tbl = Table(title="Network Interfaces", header_style="bold cyan", border_style="dim")
        if_tbl.add_column("Interface", style="bold white")
        if_tbl.add_column("State", style="white")
        if_tbl.add_column("IPv4 Addresses", style="cyan")
        if_tbl.add_column("MAC Address", style="dim")
        for iface in ifaces:
            state = "[green]UP[/green]" if iface.is_up else "[dim]DOWN[/dim]"
            ips = ", ".join(iface.ipv4_addresses) if iface.ipv4_addresses else "No IPv4"
            if_tbl.add_row(iface.name, state, ips, iface.mac_address or "N/A")
        console.print(if_tbl)
    except Exception:
        pass

    # Active Listening Sockets
    try:
        conns = NetworkConnectionInspector().inspect_connections()
        s_tbl = Table(
            title="Active Listening Sockets", header_style="bold cyan", border_style="dim"
        )
        s_tbl.add_column("Proto", style="cyan")
        s_tbl.add_column("Local Address", style="white")
        s_tbl.add_column("Port", style="bold white")
        s_tbl.add_column("PID / Process", style="dim")
        for c in conns[:12]:
            s_tbl.add_row(
                c.protocol.value.upper(),
                c.local_address,
                str(c.local_port),
                f"{c.pid} ({c.process_name})" if c.pid else "System",
            )
        console.print(s_tbl)
    except Exception:
        pass

    # Quick prompt for Network Threat Monitor
    console.print("\n[bold cyan][NETWORK THREAT MONITOR TOOLKIT][/bold cyan]")
    console.print("  [bold cyan]1.[/bold cyan] Launch Live Dual-Mode Network Threat Monitor (systemscan network-monitor)")
    console.print("  [bold cyan]2.[/bold cyan] View Sensor Operational Status & Coverage")
    console.print("  [bold cyan]3.[/bold cyan] Run Capture Diagnostics (Driver & Permissions)")
    console.print("  [bold cyan]4.[/bold cyan] View Detected Network Threat Alerts")
    console.print("  [bold cyan]0.[/bold cyan] Return to Main Menu")

    try:
        sub_ch = Prompt.ask("\nSelect action", default="0").strip()
        if sub_ch == "1":
            from systemscan.cli.commands.network_monitor import run_live_monitor
            dur = Prompt.ask("Enter monitoring duration in seconds (0 for continuous)", default="15").strip()
            duration_int = int(dur) if dur.isdigit() and int(dur) > 0 else None
            run_live_monitor(duration=duration_int)
        elif sub_ch == "2":
            from systemscan.cli.commands.network_monitor import status_command
            status_command()
        elif sub_ch == "3":
            from systemscan.cli.commands.network_monitor import diagnostics_command
            diagnostics_command()
        elif sub_ch == "4":
            from systemscan.cli.commands.network_monitor import alerts_command
            alerts_command()
    except Exception:
        pass


def action_devices_scanner() -> None:
    """Action 8: Connected USB and external devices with corruption diagnostics, repair, and recovery."""
    console.print(
        "\n[bold cyan]─── USB & EXTERNAL DEVICE SCANNER & REPAIR ───────────────────[/bold cyan]"
    )
    try:
        devs = DeviceManager().discover_all()
        if not devs:
            console.print(
                "[dim]No external devices or removable storage controllers detected.[/dim]"
            )
        else:
            d_tbl = Table(
                title="Connected Hardware Devices", header_style="bold cyan", border_style="dim"
            )
            d_tbl.add_column("Device Name", style="bold white")
            d_tbl.add_column("Category / Bus", style="cyan")
            d_tbl.add_column("Vendor / Product", style="white")
            d_tbl.add_column("Removable", style="yellow")
            for d in devs:
                rem = "[green]YES[/green]" if d.is_removable else "NO"
                vp = f"{d.vendor or 'Generic'} {d.product_name or ''}".strip()
                cat = f"{d.category.value.upper()} ({d.bus_type.value.upper()})"
                d_tbl.add_row(d.name or d.device_id, cat, vp, rem)
            console.print(d_tbl)
    except Exception as e:
        console.print(f"[yellow]Device inventory warning: {e}[/yellow]")

    console.print("\n[bold cyan][STORAGE / USB RECOVERY & REPAIR TOOLKIT][/bold cyan]")
    console.print("  [bold cyan]1.[/bold cyan] Check Drive for Filesystem Corruption & Dirty Bit")
    console.print("  [bold cyan]2.[/bold cyan] Repair Corrupted Drive Filesystem (chkdsk / fsck)")
    console.print("  [bold cyan]3.[/bold cyan] Remediate USB Shortcut Virus & Unhide Hidden Files")
    console.print("  [bold cyan]4.[/bold cyan] Data Recovery Scan (File Signature Carving)")
    console.print("  [bold cyan]0.[/bold cyan] Return to Main Menu")

    try:
        sub_choice = Prompt.ask("\nSelect USB action", default="0").strip()
        if sub_choice == "0":
            return

        if sub_choice == "1":
            target = Prompt.ask(
                "Enter drive letter or mount point (e.g. E: or /dev/sdb1)", default=""
            ).strip()
            if not target:
                return
            with console.status(f"[bold cyan]Diagnosing filesystem on {target}...[/bold cyan]"):
                res = StorageRepairEngine.check_filesystem_corruption(target)
            console.print(f"\n[bold white]Diagnostics Result for {res['target']}:[/bold white]")
            status_style = "bold red" if res["is_corrupted"] else "bold green"
            status_text = "CORRUPTED / DIRTY" if res["is_corrupted"] else "CLEAN / HEALTHY"
            console.print(
                f"  [dim]Filesystem State :[/dim] [{status_style}]{status_text}[/{status_style}]"
            )
            for detail in res["details"]:
                console.print(f"  [cyan]•[/cyan] {detail}")
            if res.get("raw_output"):
                console.print(f"\n[dim]{res['raw_output'][:600]}...[/dim]")

        elif sub_choice == "2":
            target = Prompt.ask(
                "Enter drive letter or mount point to repair (e.g. E: or /dev/sdb1)", default=""
            ).strip()
            if not target:
                return
            confirm = (
                Prompt.ask(
                    f"[bold red]WARNING:[/bold red] Filesystem repair modifies disk structures. Proceed with repair on {target}? (y/n)",
                    default="n",
                )
                .strip()
                .lower()
            )
            if confirm not in ("y", "yes"):
                console.print("[yellow]Repair cancelled by user.[/yellow]")
                return
            with console.status(f"[bold cyan]Repairing filesystem on {target}...[/bold cyan]"):
                rep_res = StorageRepairEngine.repair_filesystem(target)
            if rep_res["success"]:
                console.print(f"\n[bold green][OK] {rep_res['message']}[/bold green]")
            else:
                console.print(f"\n[bold yellow][NOTICE] {rep_res['message']}[/bold yellow]")
            if rep_res.get("output"):
                console.print(f"\n[dim]{rep_res['output'][:500]}[/dim]")

        elif sub_choice == "3":
            target = Prompt.ask(
                "Enter infected USB drive path or letter (e.g. E:)", default=""
            ).strip()
            if not target:
                return
            with console.status(
                f"[bold cyan]Remediating shortcut virus and restoring hidden files on {target}...[/bold cyan]"
            ):
                rem_res = StorageRepairEngine.remediate_shortcut_virus_and_unhide(target)
            console.print(
                f"\n[bold green][OK] Attribute unhiding sweep completed on {rem_res['target']}.[/bold green]"
            )
            if rem_res["suspicious_shortcuts"]:
                console.print(
                    f"[bold red]Suspicious Shortcut Droppers Detected ({len(rem_res['suspicious_shortcuts'])}):[/bold red]"
                )
                for sc in rem_res["suspicious_shortcuts"][:10]:
                    console.print(f"  [red]• {sc}[/red]")
            else:
                console.print(
                    "  [dim]No malicious .lnk shortcuts found pointing to script interpreters.[/dim]"
                )
            if rem_res["autorun_droppers"]:
                console.print(
                    f"[bold red]Autorun Droppers Detected ({len(rem_res['autorun_droppers'])}):[/bold red]"
                )
                for ar in rem_res["autorun_droppers"]:
                    console.print(f"  [red]• {ar}[/red]")

        elif sub_choice == "4":
            target = Prompt.ask(
                "Enter drive path or directory to carve for lost files (e.g. E:)", default=""
            ).strip()
            if not target:
                return
            with console.status(
                f"[bold cyan]Carving lost file signatures in {target}...[/bold cyan]"
            ):
                carved = StorageRepairEngine.carve_lost_files(target)
            if not carved:
                console.print(
                    "[dim]No unlinked or corrupt files matching known signatures found.[/dim]"
                )
            else:
                crv_tbl = Table(
                    title=f"Recoverable File Signatures ({len(carved)} found)",
                    header_style="bold cyan",
                    border_style="dim",
                )
                crv_tbl.add_column("File Path", style="dim white")
                crv_tbl.add_column("Detected Signature", style="cyan")
                crv_tbl.add_column("Recommended Ext", style="bold green")
                crv_tbl.add_column("Size", style="yellow")
                for c in carved[:15]:
                    crv_tbl.add_row(
                        c["path"],
                        c["detected_format"],
                        c["recommended_ext"],
                        format_bytes(c["size_bytes"]),
                    )
                console.print(crv_tbl)

    except (KeyboardInterrupt, EOFError):
        pass


def action_scan_history() -> None:
    """Action 9: Scan history records."""
    console.print(
        "\n[bold cyan]─── SCAN HISTORY ────────────────────────────────────────────[/bold cyan]"
    )
    try:
        mgr = ScanHistoryManager()
        sessions = mgr.list_sessions(limit=10)
        if not sessions:
            console.print("[dim]No historical scan sessions recorded yet.[/dim]")
            return
        h_tbl = Table(title="Recent Scan Executions", header_style="bold cyan", border_style="dim")
        h_tbl.add_column("Scan ID", style="cyan")
        h_tbl.add_column("Type", style="white")
        h_tbl.add_column("Timestamp", style="dim")
        h_tbl.add_column("Duration", style="white")
        h_tbl.add_column("Files", style="bold white")
        h_tbl.add_column("Threats", style="red")
        h_tbl.add_column("Status", style="green")

        for s in sessions:
            date_str = s.started_at.strftime("%Y-%m-%d %H:%M")
            h_tbl.add_row(
                s.scan_id,
                s.scan_type.value,
                date_str,
                format_duration(s.duration_seconds),
                f"{s.items_processed:,}",
                str(s.findings_count),
                s.status.value.upper(),
            )
        console.print(h_tbl)
    except Exception as e:
        console.print(f"[yellow]History retrieval notice: {e}[/yellow]")


def action_reports_export() -> None:
    """Action 10: Reports listing and export."""
    console.print(
        "\n[bold cyan]─── REPORTS & EXPORT ────────────────────────────────────────[/bold cyan]"
    )
    try:
        storage = ReportStorageManager()
        reps = storage.list_reports()
        if not reps:
            console.print("[dim]No stored reports found.[/dim]")
            return

        r_tbl = Table(title="Archived Audit Reports", header_style="bold cyan", border_style="dim")
        r_tbl.add_column("Report ID", style="bold cyan")
        r_tbl.add_column("Filename", style="white")
        r_tbl.add_column("Format", style="dim")
        r_tbl.add_column("Size", style="bold white")
        r_tbl.add_column("Saved Path", style="dim")

        for r in reps[:10]:
            r_tbl.add_row(
                str(r["report_id"]),
                str(r["filename"]),
                str(r["format"]).upper(),
                format_bytes(int(r["size_bytes"])),
                str(r["path"]),
            )
        console.print(r_tbl)
    except Exception as e:
        console.print(f"[yellow]Report listing notice: {e}[/yellow]")


def action_dependency_doctor() -> None:
    """Action 11: Dependency and environment doctor."""
    console.print(
        "\n[bold cyan]─── DEPENDENCY DOCTOR & CAPABILITIES ────────────────────────[/bold cyan]"
    )
    try:
        diag = EnvironmentDoctor.diagnose(verbose=True)
        stat_color = "green" if diag.status == "HEALTHY" else "yellow"
        console.print(
            f"  [bold cyan]Environment Health :[/bold cyan] [{stat_color}]{diag.status}[/{stat_color}]"
        )
        console.print(
            f"  [bold cyan]Python Version     :[/bold cyan] {diag.python_version} ({'64-bit' if diag.is_64bit else '32-bit'})\n"
        )

        # Core & optional dependencies
        d_tbl = Table(title="Package Dependencies", header_style="bold cyan", border_style="dim")
        d_tbl.add_column("Package", style="bold white")
        d_tbl.add_column("Category", style="cyan")
        d_tbl.add_column("Status", style="green")
        d_tbl.add_column("Installed Version", style="white")

        for dep in diag.core_dependencies + diag.optional_dependencies:
            status_text = (
                "[green]INSTALLED[/green]"
                if dep.is_installed and dep.is_compatible
                else "[yellow]OPTIONAL[/yellow]"
                if dep.spec.category.value == "optional"
                else "[red]MISSING[/red]"
            )
            d_tbl.add_row(
                dep.name,
                dep.spec.category.value.upper(),
                status_text,
                dep.installed_version or "Not installed",
            )
        console.print(d_tbl)

        # Capabilities matrix
        matrix = app_instance.platform.get_capabilities_matrix()
        c_tbl = Table(
            title="Platform Capabilities (14 Dimensions)",
            header_style="bold cyan",
            border_style="dim",
        )
        c_tbl.add_column("Capability Dimension", style="white")
        c_tbl.add_column("Support Status", style="green")
        for cap, st in sorted(matrix.items()):
            c_tbl.add_row(cap, st.value)
        console.print(c_tbl)

        # Interactive Optional Dependency Installer
        missing_opts = [dep.name for dep in diag.optional_dependencies if not dep.is_installed]
        if missing_opts:
            console.print(
                f"\n[bold yellow]Notice:[/bold yellow] Found {len(missing_opts)} uninstalled optional dependencies ({', '.join(missing_opts)})."
            )
            install_q = (
                Prompt.ask(
                    "Would you like to install these optional dependencies now? (y/n)", default="n"
                )
                .strip()
                .lower()
            )
            if install_q in ("y", "yes"):
                console.print("\n[bold cyan]Installing optional packages via pip...[/bold cyan]")
                cmd = [sys.executable, "-m", "pip", "install", *missing_opts]
                try:
                    proc = subprocess.run(cmd, check=False)
                    if proc.returncode == 0:
                        console.print(
                            "\n[bold green][OK] Dependencies installed successfully![/bold green]"
                        )
                    else:
                        console.print(
                            f"\n[bold yellow][WARN] Pip exited with code {proc.returncode}[/bold yellow]"
                        )
                except Exception as pe:
                    console.print(
                        f"\n[bold red][ERR] Failed to execute pip install: {pe}[/bold red]"
                    )

    except Exception as e:
        console.print(f"[yellow]Doctor diagnostic notice: {e}[/yellow]")


def action_settings() -> None:
    """Action 12: Active configuration view."""
    console.print(
        "\n[bold cyan]─── SETTINGS & CONFIGURATION ────────────────────────────────[/bold cyan]"
    )
    cfg = app_instance.config
    s_tbl = Table(
        title="Active Scanner Configuration", header_style="bold cyan", border_style="dim"
    )
    s_tbl.add_column("Section", style="cyan")
    s_tbl.add_column("Setting", style="white")
    s_tbl.add_column("Value", style="bold white")

    s_tbl.add_row("General", "Log Level", cfg.log_level.value.upper())
    s_tbl.add_row("General", "Debug Mode", str(cfg.preferences.debug))
    s_tbl.add_row("Scanner", "Worker Count", str(cfg.scanner.worker_count))
    s_tbl.add_row("Scanner", "Max File Size", f"{cfg.scanner.max_file_size_mb} MB")
    s_tbl.add_row("Performance", "Mode", cfg.performance.mode.upper())
    s_tbl.add_row("Performance", "Max CPU Load", f"{cfg.performance.max_cpu_percent}%")
    s_tbl.add_row("Reporting", "Default Format", cfg.reporting.default_format.upper())
    s_tbl.add_row("Updates", "Channel", cfg.updates.channel.value.upper())
    s_tbl.add_row("Updates", "Source", cfg.updates.update_source)
    console.print(s_tbl)


def action_check_updates() -> None:
    """Action 13: Check for updates and execute self-update."""
    console.print(
        "\n[bold cyan]─── CHECK FOR UPDATES & SELF-UPDATE ─────────────────────────[/bold cyan]"
    )
    console.print(f"  [bold cyan]Current Version :[/bold cyan] v{__version__}")
    console.print(
        f"  [bold cyan]Update Source   :[/bold cyan] {app_instance.config.updates.update_source}\n"
    )

    from systemscan.update.checker import UpdateChecker
    from systemscan.update.transaction import UpdateTransactionCoordinator

    checker = UpdateChecker(config=app_instance.config)
    with console.status("[bold cyan]Connecting to release server...[/bold cyan]"):
        rel_info, plan = checker.check_for_updates()

    if not plan.is_update_available:
        console.print(
            f"[bold green][OK] Application is up to date (v{__version__}). No new releases found.[/bold green]"
        )
        if plan.compatibility_reason:
            console.print(f"[dim]{plan.compatibility_reason}[/dim]")
        return

    console.print(f"[bold green]New update available: v{plan.target_version}![/bold green]")
    if rel_info:
        console.print(f"  [dim]Released :[/dim] {rel_info.release_date.strftime('%Y-%m-%d')}")
        console.print(f"  [dim]Notes    :[/dim] {rel_info.release_notes[:200]}...")

    confirm = (
        Prompt.ask("\nProceed with download and self-update? (y/n)", default="y").strip().lower()
    )
    if confirm not in ("y", "yes"):
        console.print("[yellow]Update deferred by user.[/yellow]")
        return

    coordinator = UpdateTransactionCoordinator(config=app_instance.config, checker=checker)

    def progress_cb(stage: Any, pct: float, msg: str) -> None:
        console.print(f"  [dim][{pct:>3.0f}%][/dim] {msg}")

    try:
        txn = coordinator.execute_update(
            channel=plan.channel,
            release=rel_info,
            progress_callback=progress_cb,
        )
        if txn.committed:
            console.print(
                "\n[bold green][OK] Update successfully installed! Please restart systemscan.[/bold green]"
            )
        else:
            console.print(f"\n[bold red][ERR] Update failed: {txn.error_message}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red][ERR] Update transaction error: {e}[/bold red]")


def run_interactive_menu() -> None:
    """Main interactive CLI loop."""
    # Ensure application lifecycle is bootstrapped
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    while True:
        try:
            render_cli_welcome()
            choice = Prompt.ask("Select an option", default="0").strip()

            if choice == "0" or choice.lower() in ("exit", "quit", "q"):
                console.print("\n[bold cyan]Exiting SSCLI. Stay secure![/bold cyan]\n")
                sys.exit(0)
            elif choice == "1":
                action_system_info()
                pause_prompt()
            elif choice == "2":
                action_quick_scan()
                pause_prompt()
            elif choice == "3":
                action_full_scan()
                pause_prompt()
            elif choice == "4":
                action_custom_scan()
                pause_prompt()
            elif choice == "5":
                action_malware_scan()
                pause_prompt()
            elif choice == "6":
                action_storage_analyzer()
                pause_prompt()
            elif choice == "7":
                action_network_audit()
                pause_prompt()
            elif choice == "8":
                action_devices_scanner()
                pause_prompt()
            elif choice == "9":
                action_scan_history()
                pause_prompt()
            elif choice == "10":
                action_reports_export()
                pause_prompt()
            elif choice == "11":
                action_dependency_doctor()
                pause_prompt()
            elif choice == "12":
                action_settings()
                pause_prompt()
            elif choice == "13":
                action_check_updates()
                pause_prompt()
            else:
                console.print(
                    f"[bold yellow]Invalid option '{choice}'. Please enter a number between 0 and 13.[/bold yellow]"
                )
                time.sleep(1)
        except (KeyboardInterrupt, EOFError):
            console.print("\n\n[bold cyan]Session closed. Exiting SSCLI.[/bold cyan]\n")
            sys.exit(0)
