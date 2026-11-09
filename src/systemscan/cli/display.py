"""Terminal presentation components and formatting helpers for systemscan."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from systemscan.devices.models import DeviceEvent, DeviceMetadata
    from systemscan.filesystem.models import ScanStatistics, ScanSummary
    from systemscan.modules.malware.models import MalwareScanSummary
    from systemscan.modules.models import (
        CPUInformation,
        DeviceInformation,
        DiskInformation,
        FirmwareInformation,
        GPUInformation,
        MemoryInformation,
        NetworkInterface,
        PartitionInformation,
        ProcessInformation,
        ServiceInformation,
        StartupEntry,
        SystemInformation,
    )
    from systemscan.modules.storage.models import (
        CleanupPreview,
        DiskVolumeOverview,
        DuplicateGroup,
        ExtensionStat,
        LargeDirectoryRecord,
        LargeFileRecord,
    )

from systemscan.utils.formatting import format_duration

console = Console()


def print_info(title: str, message: str | None = None) -> None:
    """Display an informational panel or message."""
    if message:
        panel = Panel(message, title=f"[cyan]{title}[/cyan]", border_style="cyan", expand=False)
        console.print(panel)
    else:
        console.print(f"[cyan]{title}[/cyan]")


def print_success(title: str, message: str | None = None) -> None:
    """Display a success panel or message."""
    if message:
        panel = Panel(message, title=f"[green]{title}[/green]", border_style="green", expand=False)
        console.print(panel)
    else:
        console.print(f"[bold green]{title}[/bold green]")


def print_warning(title: str, message: str | None = None) -> None:
    """Display a warning panel or message."""
    if message:
        panel = Panel(
            message, title=f"[yellow]{title}[/yellow]", border_style="yellow", expand=False
        )
        console.print(panel)
    else:
        console.print(f"[bold yellow]{title}[/bold yellow]")


def print_error(title: str, message: str | None = None) -> None:
    """Display an error panel or message."""
    if message:
        panel = Panel(message, title=f"[red]{title}[/red]", border_style="red", expand=False)
        console.print(panel)
    else:
        console.print(f"[bold red]{title}[/bold red]")


def print_future_feature_notice(feature_name: str, scheduled_phase: int, phase_title: str) -> None:
    """Display an explicit notice that a feature is scheduled for a future development phase."""
    content = (
        f"[bold cyan]{feature_name}[/bold cyan] is scheduled for implementation in "
        f"[bold yellow]Phase {scheduled_phase:02d}: {phase_title}[/bold yellow].\n\n"
        "[dim]Future scanning modules are under active roadmap development.[/dim]"
    )
    panel = Panel(
        content,
        title="[bold yellow]Module Not Yet Implemented[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    console.print(panel)


def create_key_value_table(title: str, data: dict[str, Any]) -> Table:
    """Generate a clean, aligned key-value table."""
    table = Table(title=title, show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("Property", style="dim cyan", min_width=22)
    table.add_column("Value", style="bold white")

    for k, v in data.items():
        val_str = str(v) if v is not None else "[dim]N/A[/dim]"
        if isinstance(v, bool):
            val_str = "[green]Yes[/green]" if v else "[dim red]No[/dim red]"
        table.add_row(k, val_str)

    return table


def render_system_overview(sys_info: SystemInformation) -> None:
    """Render unified system overview display matching Section 15 specifications."""
    # Section 1: System
    sys_tbl = Table.grid(padding=(0, 2))
    sys_tbl.add_column("Key", style="dim cyan", justify="right")
    sys_tbl.add_column("Sep", style="dim")
    sys_tbl.add_column("Val", style="bold white")
    sys_tbl.add_row("OS", ":", sys_info.os.name)
    sys_tbl.add_row("Kernel", ":", sys_info.os.kernel_version)
    sys_tbl.add_row("Architecture", ":", sys_info.os.machine_arch)
    sys_tbl.add_row("Hostname", ":", sys_info.os.hostname)
    sys_tbl.add_row("Python", ":", sys_info.os.python_version)
    sys_tbl.add_row("Uptime", ":", sys_info.os.uptime_formatted)

    # Section 2: CPU
    cpu_tbl = Table.grid(padding=(0, 2))
    cpu_tbl.add_column("Key", style="dim cyan", justify="right")
    cpu_tbl.add_column("Sep", style="dim")
    cpu_tbl.add_column("Val", style="bold white")
    cpu_tbl.add_row("Processor", ":", sys_info.cpu.model)
    cpu_tbl.add_row(
        "Physical Cores",
        ":",
        str(sys_info.cpu.physical_cores) if sys_info.cpu.physical_cores else "N/A",
    )
    cpu_tbl.add_row(
        "Logical Cores",
        ":",
        str(sys_info.cpu.logical_cores) if sys_info.cpu.logical_cores else "N/A",
    )
    cpu_tbl.add_row("Usage", ":", sys_info.cpu.utilization_formatted)

    # Section 3: Memory
    mem_tbl = Table.grid(padding=(0, 2))
    mem_tbl.add_column("Key", style="dim cyan", justify="right")
    mem_tbl.add_column("Sep", style="dim")
    mem_tbl.add_column("Val", style="bold white")
    mem_tbl.add_row("Total", ":", sys_info.memory.total_formatted)
    mem_tbl.add_row("Used", ":", sys_info.memory.used_formatted)
    mem_tbl.add_row("Available", ":", sys_info.memory.available_formatted)
    mem_tbl.add_row("Usage", ":", f"{sys_info.memory.percentage:.1f}%")

    # Section 4: Storage
    storage_tbl = Table.grid(padding=(0, 2))
    storage_tbl.add_column("Key", style="dim cyan", justify="right")
    storage_tbl.add_column("Sep", style="dim")
    storage_tbl.add_column("Val", style="bold white")
    root_part = sys_info.storage[0] if sys_info.storage else None
    if root_part:
        storage_tbl.add_row(f"Volume ({root_part.mountpoint})", ":", root_part.total_formatted)
        storage_tbl.add_row("Used", ":", root_part.used_formatted)
        storage_tbl.add_row("Free", ":", root_part.free_formatted)
        storage_tbl.add_row("Usage", ":", f"{root_part.percentage:.1f}%")
    else:
        storage_tbl.add_row("Storage", ":", "No mounted partitions found")

    # Section 5: Processes & Network
    misc_tbl = Table.grid(padding=(0, 2))
    misc_tbl.add_column("Key", style="dim cyan", justify="right")
    misc_tbl.add_column("Sep", style="dim")
    misc_tbl.add_column("Val", style="bold white")
    misc_tbl.add_row("Processes Running", ":", str(sys_info.process_summary.total_processes))
    misc_tbl.add_row("Active Threads", ":", str(sys_info.process_summary.total_threads))
    misc_tbl.add_row("Network Interfaces", ":", str(len(sys_info.network)))
    misc_tbl.add_row("Graphics Adapters", ":", str(len(sys_info.gpus)))

    content = Group(
        Text("SYSTEM", style="bold yellow"),
        sys_tbl,
        Text("\nCPU", style="bold yellow"),
        cpu_tbl,
        Text("\nMEMORY", style="bold yellow"),
        mem_tbl,
        Text("\nSTORAGE", style="bold yellow"),
        storage_tbl,
        Text("\nPROCESSES & NETWORK", style="bold yellow"),
        misc_tbl,
    )

    panel = Panel(
        content,
        title="[bold cyan]SYSTEM INTELLIGENCE OVERVIEW[/bold cyan]",
        border_style="cyan",
        padding=(1, 3),
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()


def render_cpu_info(cpu: CPUInformation) -> None:
    """Render comprehensive CPU specification and telemetry."""
    data: dict[str, Any] = {
        "Processor Model": cpu.model,
        "Vendor": cpu.vendor,
        "Architecture": cpu.architecture,
        "Physical Cores": cpu.physical_cores,
        "Logical Threads": cpu.logical_cores,
        "Current Frequency": cpu.current_freq_formatted,
        "Max Clock Speed": cpu.max_freq_formatted,
        "Min Clock Speed": cpu.min_frequency_mhz or "N/A",
        "Total CPU Utilization": cpu.utilization_formatted,
        "Package Temperature": cpu.temp_formatted,
    }
    if cpu.load_averages:
        data["Load Averages (1, 5, 15m)"] = (
            f"{cpu.load_averages[0]:.2f}, {cpu.load_averages[1]:.2f}, {cpu.load_averages[2]:.2f}"
        )

    console.print()
    console.print(create_key_value_table("Processor (CPU) Specifications", data))

    # Per-core utilization bar table
    if cpu.per_core_utilization:
        table = Table(
            title=f"Per-Core Utilization ({len(cpu.per_core_utilization)} Cores)",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Core", justify="center")
        table.add_column("Usage", justify="right")
        table.add_column("Activity Meter", min_width=25)

        for idx, u in enumerate(cpu.per_core_utilization):
            bars = int(u / 5)
            bar_visual = "█" * bars + "░" * (20 - bars)
            color = "green" if u < 60 else ("yellow" if u < 85 else "red")
            table.add_row(
                f"Core #{idx}",
                f"{u:.1f}%",
                f"[{color}]{bar_visual}[/{color}]",
            )

        console.print()
        console.print(table)
    console.print()


def render_memory_info(mem: MemoryInformation) -> None:
    """Render physical RAM and swap memory telemetry."""
    ram_data = {
        "Total RAM": mem.total_formatted,
        "Used RAM": mem.used_formatted,
        "Available RAM": mem.available_formatted,
        "Free RAM": mem.free_formatted,
        "Cached / Buffers": mem.cached_formatted,
        "RAM Utilization": f"{mem.percentage:.1f}%",
    }
    swap_data = {
        "Total Swap": mem.swap_total_formatted,
        "Used Swap": mem.swap_used_formatted,
        "Free Swap": mem.swap_free_formatted,
        "Swap Utilization": f"{mem.swap_percentage:.1f}%",
    }
    console.print()
    console.print(create_key_value_table("Physical RAM Memory", ram_data))
    console.print()
    console.print(create_key_value_table("Virtual Swap Space", swap_data))
    console.print()


def render_gpu_info(gpus: list[GPUInformation]) -> None:
    """Render graphics adapter inventory."""
    if not gpus:
        print_info("Graphics (GPU)", "No GPU devices detected or accessible.")
        return

    table = Table(
        title=f"Graphics Adapters ({len(gpus)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Vendor", style="bold cyan")
    table.add_column("Device Model", style="bold white")
    table.add_column("Memory (VRAM)")
    table.add_column("Driver Version", style="dim")
    table.add_column("Utilization", justify="right")
    table.add_column("Temperature", justify="right")
    table.add_column("Status", style="dim")

    for g in gpus:
        table.add_row(
            g.vendor,
            g.model,
            g.memory_total_formatted,
            g.driver_version or "[dim]N/A[/dim]",
            g.utilization_formatted,
            g.temp_formatted,
            g.status,
        )

    console.print()
    console.print(table)
    console.print()


def render_storage_info(
    partitions: list[PartitionInformation], disks: list[DiskInformation]
) -> None:
    """Render mounted partitions and physical disk devices."""
    if partitions:
        table = Table(
            title=f"Mounted Partitions & Volumes ({len(partitions)})",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Device", style="dim cyan")
        table.add_column("Mountpoint", style="bold white")
        table.add_column("Filesystem", style="dim")
        table.add_column("Total Size", justify="right")
        table.add_column("Used", justify="right")
        table.add_column("Free", justify="right")
        table.add_column("Usage %", justify="right")
        table.add_column("Read-Only", justify="center")

        for p in partitions:
            color = "green" if p.percentage < 70 else ("yellow" if p.percentage < 90 else "red")
            table.add_row(
                p.device,
                p.mountpoint,
                p.filesystem_type,
                p.total_formatted,
                p.used_formatted,
                p.free_formatted,
                f"[{color}]{p.percentage:.1f}%[/{color}]",
                "[red]Yes[/red]" if p.is_readonly else "[dim]No[/dim]",
            )

        console.print()
        console.print(table)

    if disks:
        disk_tbl = Table(
            title=f"Physical Disk Drives ({len(disks)})",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        disk_tbl.add_column("Identifier", style="bold white")
        disk_tbl.add_column("Model", style="cyan")
        disk_tbl.add_column("Capacity", justify="right")
        disk_tbl.add_column("Removable", justify="center")

        for d in disks:
            disk_tbl.add_row(
                d.name,
                d.model or "[dim]Unknown Model[/dim]",
                d.size_formatted,
                "[yellow]Yes[/yellow]" if d.is_removable else "[dim]No[/dim]",
            )

        console.print()
        console.print(disk_tbl)
    console.print()


def render_processes_table(processes: list[ProcessInformation]) -> None:
    """Render list of running processes."""
    table = Table(
        title=f"Active System Processes ({len(processes)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("PID", style="dim cyan", justify="right")
    table.add_column("Process Name", style="bold white")
    table.add_column("CPU %", justify="right")
    table.add_column("RAM (MB)", justify="right")
    table.add_column("RAM %", justify="right")
    table.add_column("Threads", justify="right", style="dim")
    table.add_column("User", style="dim")
    table.add_column("Status", style="dim")

    for p in processes:
        cpu_color = (
            "bold red" if p.cpu_percent > 50 else ("yellow" if p.cpu_percent > 15 else "white")
        )
        table.add_row(
            str(p.pid),
            p.name,
            f"[{cpu_color}]{p.cpu_percent:.1f}%[/{cpu_color}]",
            f"{p.memory_mb:.1f}",
            f"{p.memory_percent:.1f}%",
            str(p.thread_count) if p.thread_count is not None else "-",
            p.username or "-",
            p.status,
        )

    console.print()
    console.print(table)
    console.print()


def render_services_table(services: list[ServiceInformation]) -> None:
    """Render list of host services."""
    table = Table(
        title=f"System Services ({len(services)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Service Name", style="bold white")
    table.add_column("Display Name", style="dim white")
    table.add_column("Status", justify="center")
    table.add_column("Startup Type", style="dim")

    for s in services:
        status_color = (
            "green" if s.status == "running" else ("yellow" if s.status == "paused" else "dim")
        )
        table.add_row(
            s.name,
            s.display_name or "-",
            f"[{status_color}]{s.status.upper()}[/{status_color}]",
            s.startup_type or "-",
        )

    console.print()
    console.print(table)
    console.print()


def render_startup_table(entries: list[StartupEntry]) -> None:
    """Render startup applications and persistence entries."""
    table = Table(
        title=f"Startup Applications & Persistence ({len(entries)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Entry Name", style="bold white")
    table.add_column("Source", style="cyan")
    table.add_column("Scope", justify="center")
    table.add_column("Command / Executable Path", style="dim white")

    for e in entries:
        table.add_row(e.name, e.source, e.scope, e.command)

    console.print()
    console.print(table)
    console.print()


def render_network_interfaces(interfaces: list[NetworkInterface]) -> None:
    """Render network interface adapters and IP addresses."""
    table = Table(
        title=f"Network Interfaces ({len(interfaces)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Interface", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("MAC Address", style="dim")
    table.add_column("IPv4 Address", style="cyan")
    table.add_column("IPv6 Address", style="dim white")
    table.add_column("Link Speed", justify="right")

    for iface in interfaces:
        status_text = "[green]UP[/green]" if iface.is_up else "[dim red]DOWN[/dim red]"
        ipv4_str = ", ".join(iface.ipv4_addresses) if iface.ipv4_addresses else "-"
        ipv6_str = ", ".join(iface.ipv6_addresses[:2]) if iface.ipv6_addresses else "-"
        speed_str = f"{iface.speed_mbps} Mbps" if iface.speed_mbps else "-"
        table.add_row(
            iface.name,
            status_text,
            iface.mac_address or "-",
            ipv4_str,
            ipv6_str,
            speed_str,
        )

    console.print()
    console.print(table)
    console.print()


def render_firmware_info(fw: FirmwareInformation) -> None:
    """Render motherboard, BIOS, and firmware information."""
    table = create_key_value_table("Motherboard & BIOS Firmware", fw.model_dump())
    console.print()
    console.print(table)
    console.print()


def render_device_inventory(devices: list[DeviceInformation]) -> None:
    """Render hardware device inventory."""
    table = Table(
        title=f"Hardware Device Inventory ({len(devices)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Device Type", style="bold cyan")
    table.add_column("Device Name", style="bold white")
    table.add_column("Description", style="dim white")
    table.add_column("Vendor", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Removable", justify="center")

    for d in devices:
        rem_str = "[yellow]Yes[/yellow]" if d.is_removable else "[dim]No[/dim]"
        table.add_row(
            d.device_type,
            d.name,
            d.description or "-",
            d.vendor or "-",
            d.status,
            rem_str,
        )

    console.print()
    console.print(table)
    console.print()


def build_scan_progress_panel(mode: str, root: str, stats: ScanStatistics) -> Panel:
    """Construct real-time visual progress panel during active filesystem scan."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column("Field", style="dim cyan", min_width=18)
    grid.add_column("Sep", style="dim")
    grid.add_column("Value", style="bold white")

    elapsed_str = format_duration(stats.scan_duration_seconds)

    # Truncate current path if too long
    curr_path = stats.current_path
    if len(curr_path) > 65:
        curr_path = "..." + curr_path[-62:]

    grid.add_row("Mode", ":", mode)
    grid.add_row("Root", ":", root)
    grid.add_row("Current Path", ":", curr_path or "-")
    grid.add_row("Files Discovered", ":", f"{stats.files_discovered:,}")
    grid.add_row("Directories", ":", f"{stats.directories_scanned:,}")
    grid.add_row("Hidden Files", ":", f"{stats.hidden_files:,}")
    grid.add_row("Skipped", ":", f"{stats.skipped_paths:,}")
    grid.add_row("Failed", ":", f"{stats.permission_errors + stats.io_errors:,}")
    grid.add_row("Processed Size", ":", stats.total_size_formatted)
    grid.add_row("Elapsed", ":", elapsed_str)

    return Panel(
        grid,
        title="[bold yellow]SCAN IN PROGRESS[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        expand=False,
    )


def render_scan_summary(summary: ScanSummary) -> None:
    """Render comprehensive end-of-scan summary panel and statistics."""
    stats = summary.statistics
    status_style = (
        "bold green"
        if summary.status.value == "completed"
        else ("bold yellow" if summary.status.value == "cancelled" else "bold red")
    )

    grid = Table.grid(padding=(0, 2))
    grid.add_column("Field", style="dim cyan", min_width=20)
    grid.add_column("Sep", style="dim")
    grid.add_column("Value", style="bold white")

    grid.add_row("Scan ID", ":", summary.scan_id)
    grid.add_row("Scan Mode", ":", summary.scan_mode.replace("_", " ").title())
    grid.add_row("Status", ":", f"[{status_style}]{summary.status.value.upper()}[/{status_style}]")
    grid.add_row("Target Roots", ":", ", ".join(summary.roots))
    grid.add_row("Duration", ":", format_duration(stats.scan_duration_seconds))
    grid.add_row(
        "Throughput",
        ":",
        f"{stats.traversal_speed_files_per_sec:,.1f} files/sec",
    )
    grid.add_row(
        "Files Scanned",
        ":",
        f"{stats.files_scanned:,} ({stats.total_size_formatted})",
    )
    grid.add_row("Directories Scanned", ":", f"{stats.directories_scanned:,}")
    grid.add_row(
        "Hidden Entries",
        ":",
        f"{stats.hidden_files:,} files, {stats.hidden_directories:,} dirs",
    )
    grid.add_row(
        "Symbolic Links",
        ":",
        f"{stats.symlinks_discovered:,} ({stats.broken_links} broken)",
    )
    grid.add_row("Excluded / Skipped", ":", f"{stats.excluded_paths:,} / {stats.skipped_paths:,}")
    grid.add_row("Errors Encountered", ":", f"{len(summary.errors):,}")

    panel = Panel(
        grid,
        title="[bold cyan]FILESYSTEM SCAN SUMMARY[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
        expand=False,
    )

    console.print()
    console.print(panel)
    console.print()

    # If errors were recorded, display error breakdown table
    if summary.errors:
        err_tbl = Table(
            title=f"Encountered Errors ({len(summary.errors)})",
            show_header=True,
            header_style="bold red",
            border_style="dim",
        )
        err_tbl.add_column("Category", style="yellow")
        err_tbl.add_column("Operation", style="cyan")
        err_tbl.add_column("Path", style="dim white")
        err_tbl.add_column("Error Message", style="red")

        for err in summary.errors[:20]:
            err_tbl.add_row(
                err.category.value,
                err.operation,
                err.path,
                err.message,
            )

        if len(summary.errors) > 20:
            err_tbl.caption = f"[dim]Showing first 20 of {len(summary.errors)} total errors.[/dim]"

        console.print(err_tbl)
        console.print()


def render_devices_table(
    devices: list[DeviceMetadata], title: str = "Connected Devices Inventory"
) -> None:
    """Render a structured table of detected hardware devices and storage."""
    tbl = Table(
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Device ID", style="dim cyan", no_wrap=True)
    tbl.add_column("Name", style="bold white")
    tbl.add_column("Category", style="yellow")
    tbl.add_column("Bus", style="blue")
    tbl.add_column("Capacity", justify="right", style="green")
    tbl.add_column("Removable", justify="center")
    tbl.add_column("Mount Point(s)", style="magenta")
    tbl.add_column("Confidence", justify="right", style="dim")

    for dev in devices:
        rem_badge = "[bold yellow]YES[/bold yellow]" if dev.is_removable else "[dim]no[/dim]"
        mounts_str = ", ".join(dev.mount_points) if dev.mount_points else "[dim]--[/dim]"
        conf_str = f"{int(dev.confidence_score * 100)}%"

        tbl.add_row(
            dev.device_id,
            dev.name,
            dev.category.value,
            dev.bus_type.value.upper(),
            dev.capacity_formatted,
            rem_badge,
            mounts_str,
            conf_str,
        )

    console.print()
    console.print(tbl)
    console.print()


def render_device_detail(dev: DeviceMetadata) -> None:
    """Render a detailed inspection card for a single device."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=20)
    grid.add_column(style="white")

    grid.add_row("Device ID:", dev.device_id)
    grid.add_row("Device Name:", dev.name)
    grid.add_row("Category:", dev.category.value)
    grid.add_row("Vendor / Mfg:", f"{dev.vendor} / {dev.manufacturer}")
    grid.add_row("Bus Interconnect:", dev.bus_type.value.upper())
    grid.add_row("Storage Device:", "[green]Yes[/green]" if dev.is_storage else "[dim]No[/dim]")
    grid.add_row(
        "Removable Media:", "[yellow]Yes[/yellow]" if dev.is_removable else "[dim]No[/dim]"
    )
    grid.add_row(
        "Write-Protected:", "[red]Yes[/red]" if dev.is_readonly else "[green]No (Writable)[/green]"
    )
    grid.add_row("Total Capacity:", dev.capacity_formatted)
    grid.add_row("Serial Number:", dev.serial_number or "[dim]Not Available[/dim]")
    if dev.vendor_id and dev.product_id:
        grid.add_row("Hardware VID:PID:", f"{dev.vendor_id}:{dev.product_id}")
    grid.add_row(
        "Active Mounts:", ", ".join(dev.mount_points) if dev.mount_points else "[dim]None[/dim]"
    )
    grid.add_row("Classification Conf:", f"{int(dev.confidence_score * 100)}%")

    panel = Panel(
        grid,
        title=f"[bold cyan]DEVICE INSPECTION: {dev.name}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)

    if dev.partitions:
        p_tbl = Table(
            title="Logical Partitions",
            border_style="dim",
            header_style="bold magenta",
        )
        p_tbl.add_column("Partition ID", style="cyan")
        p_tbl.add_column("Filesystem", style="yellow")
        p_tbl.add_column("Mount Point", style="bold white")
        p_tbl.add_column("Capacity", justify="right", style="green")
        p_tbl.add_column("Status", justify="center")

        for p in dev.partitions:
            cap_str = f"{p.capacity_bytes / (1024**3):.1f} GB" if p.capacity_bytes else "N/A"
            status = "[green]Mounted[/green]" if p.is_mounted else "[dim]Unmounted[/dim]"
            p_tbl.add_row(
                p.partition_id,
                p.filesystem_type,
                p.mount_point or "--",
                cap_str,
                status,
            )

        console.print(p_tbl)
    console.print()


def render_device_event_panel(event: DeviceEvent) -> Panel:
    """Render a visual notification panel for a detected device hardware or mount event."""
    color = "green" if event.event_type.value == "device_connected" else "yellow"
    if "unmount" in event.event_type.value or "disconnect" in event.event_type.value:
        color = "red"

    title = f"[bold {color}]DEVICE EVENT: {event.event_type.value.upper()}[/bold {color}]"
    content = (
        f"[bold white]{event.device_name}[/bold white] ({event.device_id})\n"
        f"Category: [cyan]{event.category.value}[/cyan] | Removable: [yellow]{event.is_removable}[/yellow]\n"
        f"Mount Point: [magenta]{event.mount_point or 'N/A'}[/magenta] | Timestamp: [dim]{event.timestamp.strftime('%H:%M:%S UTC')}[/dim]"
    )
    return Panel(content, title=title, border_style=color, padding=(0, 2), expand=False)


def render_malware_scan_summary(summary: MalwareScanSummary) -> None:
    """Render the standardized MALWARE SCAN SUMMARY table and findings breakdown."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=22)
    grid.add_column(style="bold white")

    status_color = "green" if summary.status == "COMPLETED" else "yellow"
    if summary.status in ("FAILED", "CANCELLED"):
        status_color = "red"

    grid.add_row("Scan Type:", summary.scan_type)
    grid.add_row("Scan ID:", summary.scan_id)
    grid.add_row("Duration:", f"{summary.duration_seconds:.2f}s")
    grid.add_row("Files Scanned:", f"{summary.files_scanned:,}")
    grid.add_row("Files Skipped:", f"{summary.files_skipped:,}")
    grid.add_row("Files Failed:", f"{summary.files_failed:,}")
    grid.add_row("Hash Matches:", f"[bold red]{summary.hash_matches}[/bold red]")
    grid.add_row("Signature Matches:", f"[bold red]{summary.signature_matches}[/bold red]")
    grid.add_row("YARA Matches:", f"[bold yellow]{summary.yara_matches}[/bold yellow]")
    grid.add_row("Heuristic Findings:", f"[bold yellow]{summary.heuristic_findings}[/bold yellow]")
    grid.add_row("Total Detections:", f"[bold red]{summary.total_detections}[/bold red]")
    grid.add_row("Unique Affected Files:", f"[bold red]{summary.unique_affected_files}[/bold red]")
    grid.add_row("Scan Status:", f"[{status_color}]{summary.status}[/{status_color}]")

    sev_text = (
        f"[bold red]CRITICAL: {summary.severity_counts.get('CRITICAL', 0)}[/bold red] | "
        f"[red]HIGH: {summary.severity_counts.get('HIGH', 0)}[/red] | "
        f"[yellow]MEDIUM: {summary.severity_counts.get('MEDIUM', 0)}[/yellow] | "
        f"[cyan]LOW: {summary.severity_counts.get('LOW', 0)}[/cyan] | "
        f"[dim]INFO: {summary.severity_counts.get('INFORMATIONAL', 0)}[/dim]"
    )
    grid.add_row("Severity Breakdown:", sev_text)

    panel = Panel(
        grid,
        title="[bold red]================ MALWARE SCAN SUMMARY ================[/bold red]",
        border_style="red" if summary.total_detections > 0 else "green",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)

    if summary.findings:
        f_tbl = Table(
            title="[bold red]Detected Threats & Suspicious Observations[/bold red]",
            border_style="red",
            header_style="bold red",
            show_lines=True,
        )
        f_tbl.add_column("Sr No", justify="right", style="bold cyan", width=6)
        f_tbl.add_column("Severity", justify="center", width=10)
        f_tbl.add_column("Confidence", justify="center", width=12)
        f_tbl.add_column("Category", style="yellow")
        f_tbl.add_column("Threat / Rule", style="bold white")
        f_tbl.add_column("File Path", style="dim white")
        f_tbl.add_column("Evidence", style="cyan")

        for idx, f in enumerate(summary.findings, start=1):
            sev_style = "bold red" if f.severity.value in ("CRITICAL", "HIGH") else "yellow"
            f_tbl.add_row(
                str(idx),
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.confidence.value,
                f.category.value,
                f.threat_name or f.rule_id,
                f.file_path,
                f.evidence[:60] + ("..." if len(f.evidence) > 60 else ""),
            )

        console.print(f_tbl)

    if summary.suppressed_findings:
        console.print(
            f"[dim]Note: {len(summary.suppressed_findings)} finding(s) were suppressed by active allowlist policies.[/dim]"
        )

    console.print()


def render_disk_volumes_table(volumes: list[DiskVolumeOverview]) -> None:
    """Render a structured overview of mounted storage volumes and capacities."""
    tbl = Table(
        title="[bold cyan]Mounted Storage Volumes & Utilization[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Mount Point", style="bold white")
    tbl.add_column("Device", style="dim")
    tbl.add_column("Filesystem", style="yellow")
    tbl.add_column("Total Size", justify="right", style="cyan")
    tbl.add_column("Used", justify="right", style="magenta")
    tbl.add_column("Free", justify="right", style="green")
    tbl.add_column("Use %", justify="center")
    tbl.add_column("Status", justify="center")

    for v in volumes:
        pct_color = (
            "red" if v.usage_percent >= 90.0 else ("yellow" if v.usage_percent >= 80.0 else "green")
        )
        status_str = (
            "[bold red]LOW SPACE[/bold red]" if v.is_low_space else "[green]HEALTHY[/green]"
        )
        if v.is_readonly:
            status_str += " [dim](RO)[/dim]"
        tbl.add_row(
            v.mount_point,
            v.device,
            v.filesystem_type,
            v.total_formatted,
            v.used_formatted,
            v.free_formatted,
            f"[{pct_color}]{v.usage_percent}%[/{pct_color}]",
            status_str,
        )

    console.print()
    console.print(tbl)
    console.print()


def render_large_files_table(files: list[LargeFileRecord]) -> None:
    """Render a table of largest discovered files."""
    tbl = Table(
        title="[bold cyan]Largest Discovered Files[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Size", justify="right", style="bold green", width=12)
    tbl.add_column("Filename", style="bold white")
    tbl.add_column("Extension", style="yellow")
    tbl.add_column("Path", style="dim white")
    tbl.add_column("Last Modified", style="dim", justify="center")

    for f in files:
        tbl.add_row(
            f.size_formatted,
            f.name,
            f.extension or "(none)",
            f.path,
            f.modified_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print()
    console.print(tbl)
    console.print()


def render_large_directories_table(dirs: list[LargeDirectoryRecord]) -> None:
    """Render a table of largest directories."""
    tbl = Table(
        title="[bold cyan]Largest Aggregated Directories[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Total Size", justify="right", style="bold green", width=12)
    tbl.add_column("Files", justify="right", style="cyan", width=8)
    tbl.add_column("Directory Path", style="bold white")
    tbl.add_column("Hidden", justify="center", width=8)

    for d in dirs:
        tbl.add_row(
            d.size_formatted,
            str(d.file_count),
            d.path,
            "[yellow]Yes[/yellow]" if d.is_hidden else "[dim]No[/dim]",
        )

    console.print()
    console.print(tbl)
    console.print()


def render_duplicate_groups_table(groups: list[DuplicateGroup]) -> None:
    """Render verified duplicate file groups with reclaimable metrics."""
    tot_reclaimable = sum(g.reclaimable_bytes for g in groups)
    tot_copies = sum(g.copy_count for g in groups)

    tbl = Table(
        title=f"[bold yellow]Verified Duplicate Files ({len(groups)} groups, {tot_copies} copies, {tot_reclaimable // (1024 * 1024)} MB Reclaimable)[/bold yellow]",
        border_style="yellow",
        header_style="bold yellow",
        show_lines=True,
    )
    tbl.add_column("SHA-256", style="dim cyan", no_wrap=True)
    tbl.add_column("Copies", justify="center", style="bold white")
    tbl.add_column("File Size", justify="right", style="green")
    tbl.add_column("Reclaimable", justify="right", style="bold green")
    tbl.add_column("Duplicate File Paths", style="dim white")

    for g in groups[:25]:
        paths_str = "\n".join(g.paths)
        tbl.add_row(
            g.sha256[:16] + "...",
            str(g.copy_count),
            g.file_size_formatted,
            g.reclaimable_formatted,
            paths_str,
        )

    if len(groups) > 25:
        tbl.caption = f"[dim]Showing top 25 duplicate groups out of {len(groups)} total.[/dim]"

    console.print()
    console.print(tbl)
    console.print()


def render_extension_stats_table(stats: list[ExtensionStat]) -> None:
    """Render file distribution by extension."""
    tbl = Table(
        title="[bold cyan]Storage Distribution by File Extension[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
    )
    tbl.add_column("Extension", style="bold yellow")
    tbl.add_column("Files", justify="right", style="cyan")
    tbl.add_column("Total Size", justify="right", style="bold green")
    tbl.add_column("Storage Share", justify="right", style="magenta")
    tbl.add_column("Average Size", justify="right", style="dim")

    for s in stats:
        tbl.add_row(
            s.extension,
            f"{s.file_count:,}",
            s.total_formatted,
            f"{s.percentage_of_total}%",
            f"{s.average_bytes // 1024:,} KB"
            if s.average_bytes >= 1024
            else f"{s.average_bytes} B",
        )

    console.print()
    console.print(tbl)
    console.print()


def render_cleanup_preview(preview: CleanupPreview) -> None:
    """Render structured pre-execution cleanup preview dashboard."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=22)
    grid.add_column(style="bold white")

    grid.add_row("Preview ID:", preview.preview_id)
    grid.add_row("Total Evaluated Files:", f"{preview.total_files:,}")
    grid.add_row(
        "Reclaimable Space:", f"[bold green]{preview.total_reclaimable_formatted}[/bold green]"
    )
    grid.add_row(
        "Protected Files:",
        f"[bold yellow]{preview.protected_count}[/bold yellow] ({preview.protected_bytes // (1024 * 1024)} MB) [dim]-- Will NOT be touched[/dim]",
    )
    grid.add_row(
        "Requires Review:",
        f"[yellow]{preview.review_required_count}[/yellow] ({preview.review_required_bytes // (1024 * 1024)} MB) [dim]-- Skipped by default[/dim]",
    )

    panel = Panel(
        grid,
        title="[bold green]================ CLEANUP PREVIEW DASHBOARD ================[/bold green]",
        border_style="green",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)

    if preview.category_counts:
        c_tbl = Table(
            title="Reclaimable Breakdown by Category",
            border_style="dim",
            header_style="bold cyan",
        )
        c_tbl.add_column("Category", style="yellow")
        c_tbl.add_column("Safe Candidate Files", justify="right", style="cyan")
        c_tbl.add_column("Estimated Reclaimable", justify="right", style="bold green")

        for cat_name, count in preview.category_counts.items():
            b_cnt = preview.category_bytes.get(cat_name, 0)
            from systemscan.modules.storage.models import format_bytes

            c_tbl.add_row(cat_name, f"{count:,}", format_bytes(b_cnt))

        console.print(c_tbl)
        console.print()


def render_network_interfaces_table(interfaces: list[Any]) -> None:
    """Render a table of network interfaces and addressing telemetry."""
    tbl = Table(
        title="[bold cyan]Network Interfaces Telemetry[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Interface", style="bold white")
    tbl.add_column("Type", style="yellow")
    tbl.add_column("Status", justify="center")
    tbl.add_column("IPv4 Address", style="green")
    tbl.add_column("Subnet / CIDR", style="dim")
    tbl.add_column("MAC Address", style="dim")
    tbl.add_column("Speed", justify="right", style="cyan")

    for iface in interfaces:
        status_str = "[bold green]UP[/bold green]" if iface.is_up else "[dim red]DOWN[/dim red]"
        ipv4_str = ", ".join(iface.ipv4_addresses) if iface.ipv4_addresses else "[dim]None[/dim]"
        subnets_str = ", ".join(iface.subnets) if iface.subnets else "-"
        mac_str = iface.mac_address or "[dim]N/A[/dim]"
        speed_str = f"{iface.speed_mbps} Mbps" if iface.speed_mbps else "[dim]Unknown[/dim]"

        tbl.add_row(
            iface.name,
            str(
                iface.interface_type.value
                if hasattr(iface.interface_type, "value")
                else iface.interface_type
            ),
            status_str,
            ipv4_str,
            subnets_str,
            mac_str,
            speed_str,
        )

    console.print()
    console.print(tbl)
    console.print()


def render_network_connections_table(
    connections: list[Any], title: str = "Active Network Connections"
) -> None:
    """Render a table of network connections and listening sockets."""
    tbl = Table(
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("Proto", style="yellow", justify="center", width=6)
    tbl.add_column("Local Address", style="bold white")
    tbl.add_column("Port", justify="right", style="cyan", width=7)
    tbl.add_column("Remote Endpoint", style="green")
    tbl.add_column("State", justify="center")
    tbl.add_column("PID", justify="right", style="magenta", width=8)
    tbl.add_column("Process Name", style="bold yellow")

    for conn in connections:
        r_addr = (
            f"{conn.remote_address}:{conn.remote_port}"
            if conn.remote_address
            else "[dim]None[/dim]"
        )
        state_str = str(conn.state.value if hasattr(conn.state, "value") else conn.state)
        state_color = (
            "bold green"
            if state_str == "LISTEN"
            else ("green" if state_str == "ESTABLISHED" else "dim")
        )

        tbl.add_row(
            str(conn.protocol.value if hasattr(conn.protocol, "value") else conn.protocol),
            conn.local_address,
            str(conn.local_port),
            r_addr,
            f"[{state_color}]{state_str}[/{state_color}]",
            str(conn.pid or "-"),
            conn.process_name or "[dim]Unknown[/dim]",
        )

    console.print()
    console.print(tbl)
    console.print()


def render_discovered_hosts_table(hosts: list[Any], subnet: str) -> None:
    """Render a table of reachable hosts discovered on local subnet."""
    tbl = Table(
        title=f"[bold cyan]Local Network Hosts Discovered ({subnet})[/bold cyan]",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    tbl.add_column("IP Address", style="bold green")
    tbl.add_column("MAC Address", style="dim")
    tbl.add_column("Hostname", style="yellow")
    tbl.add_column("Open Ports", style="cyan")
    tbl.add_column("Latency", justify="right", style="magenta")
    tbl.add_column("Role", justify="center")

    for h in hosts:
        role = "[bold cyan]GATEWAY[/bold cyan]" if h.is_gateway else "Host"
        ports_str = ", ".join(str(p) for p in h.open_ports) if h.open_ports else "[dim]None[/dim]"
        lat_str = f"{h.latency_ms:.1f} ms" if h.latency_ms is not None else "[dim]N/A[/dim]"

        tbl.add_row(
            h.ip,
            h.mac or "[dim]Unknown[/dim]",
            h.hostname or "[dim]N/A[/dim]",
            ports_str,
            lat_str,
            role,
        )

    console.print()
    console.print(tbl)
    console.print()


def render_network_findings_table(findings: list[Any]) -> None:
    """Render normalized security findings table."""
    if not findings:
        console.print(
            "\n[bold green]No network security findings or vulnerabilities detected.[/bold green]\n"
        )
        return

    tbl = Table(
        title="[bold red]Network Security Findings & Observations[/bold red]",
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    tbl.add_column("ID", style="dim", width=14)
    tbl.add_column("Severity", justify="center", width=10)
    tbl.add_column("Category", style="yellow")
    tbl.add_column("Title & Description", style="bold white")
    tbl.add_column("Target", style="cyan")
    tbl.add_column("Remediation", style="green")

    for f in findings:
        sev_str = str(f.severity.value if hasattr(f.severity, "value") else f.severity)
        sev_color = (
            "bold red"
            if sev_str in ("CRITICAL", "HIGH")
            else ("yellow" if sev_str == "MEDIUM" else "cyan")
        )
        details = f"{f.title}\n[dim]{f.description}[/dim]"

        tbl.add_row(
            f.finding_id,
            f"[{sev_color}]{sev_str}[/{sev_color}]",
            str(f.category.value if hasattr(f.category, "value") else f.category),
            details,
            f.affected_target,
            f.remediation,
        )

    console.print()
    console.print(tbl)
    console.print()


def render_firewall_status_panel(status: Any) -> None:
    """Render firewall posture and profile status panel."""
    state_color = "bold green" if status.is_enabled else "bold red"
    state_str = "ENABLED" if status.is_enabled else "DISABLED"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=22)
    grid.add_column(style="bold white")

    grid.add_row("Backend Technology:", status.backend_name)
    grid.add_row("Protection Status:", f"[{state_color}]{state_str}[/{state_color}]")
    grid.add_row("Service Running:", "Yes" if status.service_active else "[bold red]NO[/bold red]")
    grid.add_row(
        "Default Inbound:",
        str(
            status.default_inbound_action.value
            if hasattr(status.default_inbound_action, "value")
            else status.default_inbound_action
        ),
    )
    grid.add_row(
        "Default Outbound:",
        str(
            status.default_outbound_action.value
            if hasattr(status.default_outbound_action, "value")
            else status.default_outbound_action
        ),
    )

    if status.profiles:
        profile_strs = [f"{p}: {'ON' if on else 'OFF'}" for p, on in status.profiles.items()]
        grid.add_row("Profiles:", ", ".join(profile_strs))

    panel = Panel(
        grid,
        title="[bold cyan]Host Firewall Security Posture[/bold cyan]",
        border_style="cyan" if status.is_enabled else "red",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()


def render_network_diagnostics_panel(result: Any) -> None:
    """Render network performance and reachability diagnostics panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=24)
    grid.add_column(style="bold white")

    gw_str = (
        f"[bold green]Reachable[/bold green] ({result.gateway_latency_ms} ms)"
        if result.gateway_reachable
        else "[bold red]Unreachable[/bold red]"
    )
    dns_str = (
        f"[bold green]Operational[/bold green] ({result.dns_latency_ms} ms)"
        if result.dns_working
        else "[bold red]Failed[/bold red]"
    )
    inet_str = (
        f"[bold green]Connected[/bold green] ({result.internet_latency_ms} ms)"
        if result.internet_reachable
        else "[bold red]Failed[/bold red]"
    )

    grid.add_row("Default Gateway:", f"{result.gateway_ip or 'None'} -> {gw_str}")
    grid.add_row("DNS Resolution:", dns_str)
    grid.add_row(f"Internet ({result.internet_target}):", inet_str)
    grid.add_row("Packet Loss Rate:", f"{result.packet_loss_percent}%")
    grid.add_row("Diagnostic Summary:", f"[italic]{result.summary}[/italic]")

    panel = Panel(
        grid,
        title="[bold green]Network Connectivity & Reachability Diagnostics[/bold green]",
        border_style="green" if result.internet_reachable else "yellow",
        padding=(1, 2),
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()
