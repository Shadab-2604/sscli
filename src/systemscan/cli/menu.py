"""Interactive terminal menu system for systemscan."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from systemscan.cli.banner import render_banner
from systemscan.cli.commands.monitor import run_monitor_loop
from systemscan.cli.display import (
    build_scan_progress_panel,
    render_cpu_info,
    render_device_inventory,
    render_devices_table,
    render_firmware_info,
    render_gpu_info,
    render_memory_info,
    render_network_interfaces,
    render_processes_table,
    render_scan_summary,
    render_services_table,
    render_startup_table,
    render_storage_info,
    render_system_overview,
)
from systemscan.core.application import app_instance
from systemscan.devices.manager import DeviceManager
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import ScanConfig
from systemscan.modules.hardware.cpu import collect_cpu_info
from systemscan.modules.hardware.devices import collect_device_inventory
from systemscan.modules.hardware.firmware import collect_firmware_info
from systemscan.modules.hardware.gpu import collect_gpu_info
from systemscan.modules.hardware.memory import collect_memory_info
from systemscan.modules.hardware.storage import collect_storage_info
from systemscan.modules.processes.collector import collect_processes
from systemscan.modules.processes.services import collect_services
from systemscan.modules.processes.startup import collect_startup_entries
from systemscan.modules.system_info.collector import collect_system_information
from systemscan.modules.system_info.network_interfaces import (
    collect_network_interfaces,
)

console = Console()


def display_menu() -> None:
    """Render the interactive options menu."""
    table = Table(
        title="Main Navigation Menu",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=False,
    )
    table.add_column("Option", style="bold yellow", justify="center", width=8)
    table.add_column("Action / Module", style="bold white", min_width=32)
    table.add_column("Domain", style="dim", min_width=14)

    table.add_row("1", "System Overview", "System Intelligence")
    table.add_row("2", "Hardware Information", "Hardware")
    table.add_row("3", "CPU Information", "Hardware (CPU)")
    table.add_row("4", "Memory Information", "Hardware (RAM)")
    table.add_row("5", "GPU Information", "Hardware (GPU)")
    table.add_row("6", "Storage Information", "Hardware (Storage)")
    table.add_row("7", "Running Processes", "Process Auditing")
    table.add_row("8", "System Services", "Service Auditing")
    table.add_row("9", "Startup Applications", "Persistence")
    table.add_row("10", "Network Interfaces", "Network")
    table.add_row("11", "Live System Monitor", "Live Telemetry")
    table.add_row("12", "Filesystem Scan", "Filesystem Engine")
    table.add_row("13", "Connected Devices & USB", "Device Manager")
    table.add_row("14", "Network Security Audit", "Network Intelligence")
    table.add_row("0", "Exit Application", "—")

    console.print(table)
    console.print()


def run_interactive_menu() -> int:
    """Run interactive menu loop until user exits or interrupts."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    render_banner(console)

    valid_choices = [str(i) for i in range(15)]

    while True:
        try:
            display_menu()
            choice = Prompt.ask(
                "[bold cyan]Select an option[/bold cyan]",
                choices=valid_choices,
                default="1",
            ).strip()

            console.print()

            if choice == "0":
                console.print("[green]Exiting Universal System Scanner. Goodbye![/green]")
                return 0
            elif choice == "1":
                sys_info = collect_system_information(
                    include_serials=False,
                    platform_handler=app_instance.platform,
                    app_paths=app_instance.paths,
                )
                render_system_overview(sys_info)
            elif choice == "2":
                render_cpu_info(collect_cpu_info())
                render_memory_info(collect_memory_info())
                render_gpu_info(collect_gpu_info(app_instance.platform))
                parts, disks = collect_storage_info(app_instance.platform)
                render_storage_info(parts, disks)
                render_firmware_info(
                    collect_firmware_info(
                        include_serials=False, platform_handler=app_instance.platform
                    )
                )
                render_device_inventory(collect_device_inventory(app_instance.platform))
            elif choice == "3":
                render_cpu_info(collect_cpu_info())
            elif choice == "4":
                render_memory_info(collect_memory_info())
            elif choice == "5":
                render_gpu_info(collect_gpu_info(app_instance.platform))
            elif choice == "6":
                parts, disks = collect_storage_info(app_instance.platform)
                render_storage_info(parts, disks)
            elif choice == "7":
                procs = collect_processes(sort_by="cpu", limit=25)
                render_processes_table(procs)
            elif choice == "8":
                services = collect_services(
                    status_filter="running", platform_handler=app_instance.platform
                )
                render_services_table(services)
            elif choice == "9":
                entries = collect_startup_entries(app_instance.platform)
                render_startup_table(entries)
            elif choice == "10":
                render_network_interfaces(collect_network_interfaces())
            elif choice == "11":
                run_monitor_loop(interval=2.0, iterations=None)
            elif choice == "12":
                target_in = Prompt.ask(
                    "[bold cyan]Enter path to scan[/bold cyan] (or 'all' for all volumes)",
                    default=str(Path.cwd()),
                ).strip()
                scanner = FilesystemScanner()
                token = CancellationToken()
                if target_in.lower() in ("all", "volumes"):
                    roots = [str(r) for r in scanner.discovery.discover_accessible_roots()]
                    mode_lbl = "All Volumes"
                else:
                    roots = [target_in]
                    mode_lbl = "Custom Path"

                scan_cfg = ScanConfig(roots=roots)
                root_display = ", ".join(roots[:2]) + ("..." if len(roots) > 2 else "")

                from rich.live import Live

                from systemscan.filesystem.statistics import ScanStatisticsCollector

                init_stats = ScanStatisticsCollector().snapshot()
                with Live(
                    build_scan_progress_panel(mode_lbl, root_display, init_stats),
                    console=console,
                    refresh_per_second=4,
                    transient=True,
                ) as live:

                    def update_progress(
                        st: ScanStatisticsCollector,
                        m: str = mode_lbl,
                        r: str = root_display,
                    ) -> None:
                        live.update(build_scan_progress_panel(m, r, st.snapshot()))

                    summary = scanner.scan_paths(
                        roots=roots,
                        config=scan_cfg,
                        on_progress=update_progress,
                        cancellation_token=token,
                    )

                render_scan_summary(summary)

            elif choice == "13":
                dev_mgr = DeviceManager()
                devs = dev_mgr.discover_all()
                render_devices_table(devs, title="Connected Devices & Storage Inventory")

            elif choice == "14":
                from systemscan.cli.display import render_network_findings_table
                from systemscan.network.findings import NetworkFindingsEvaluator

                console.print(
                    "\n[bold cyan]Running Comprehensive Network Security Audit...[/bold cyan]"
                )
                findings = NetworkFindingsEvaluator().run_full_audit()
                render_network_findings_table(findings)

            console.print()
            Prompt.ask("[dim]Press Enter to return to main menu[/dim]", default="")
            console.print()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Interactive session terminated by user (Ctrl+C).[/yellow]")
            return 130
        except Exception as e:
            console.print(f"[bold red]An error occurred in interactive mode: {e}[/bold red]")
