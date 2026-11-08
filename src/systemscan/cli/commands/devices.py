"""CLI subcommands for device discovery, removable storage inspection, and monitoring."""

from __future__ import annotations

import json
import time
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import (
    render_device_detail,
    render_device_event_panel,
    render_devices_table,
)
from systemscan.core.application import app_instance
from systemscan.devices.manager import DeviceManager
from systemscan.devices.models import DeviceEvent

app = typer.Typer(
    name="devices",
    help="Discover, inspect, and monitor connected devices and removable storage.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def default_devices_command(ctx: typer.Context) -> None:
    """Default entry point for `systemscan devices` -> lists connected devices."""
    if ctx.invoked_subcommand is None:
        list_devices(format="text", removable_only=False)


@app.command(name="list")
def list_devices(
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output presentation format: 'text' or 'json'.",
        ),
    ] = "text",
    removable_only: Annotated[
        bool,
        typer.Option(
            "--removable-only",
            "-r",
            help="Filter list to only removable storage devices and external drives.",
        ),
    ] = False,
) -> None:
    """Enumerate and display connected devices and storage volumes."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    manager = DeviceManager()
    devices = manager.discover_all()

    if removable_only:
        devices = [
            d for d in devices if d.is_storage and (d.is_removable or d.bus_type.value == "usb")
        ]

    if format.lower() == "json":
        data = [d.model_dump(mode="json") for d in devices]
        console.print_json(json.dumps(data, indent=2))
    else:
        title = "Removable Storage Devices" if removable_only else "Connected Devices Inventory"
        if not devices:
            console.print("[yellow]No matching devices detected.[/yellow]")
        else:
            render_devices_table(devices, title=title)


@app.command(name="info")
def device_info(
    device_id: Annotated[
        str,
        typer.Argument(help="Identifier or path of the device to inspect (e.g. disk-0, /dev/sdb)."),
    ],
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'text' or 'json'.",
        ),
    ] = "text",
) -> None:
    """Inspect detailed hardware, partition, and mount attributes for a single device."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    manager = DeviceManager()
    dev = manager.get_device_info(device_id)

    if not dev:
        console.print(
            f"[bold red]Error:[/bold red] Device '{device_id}' not found in active inventory."
        )
        raise typer.Exit(code=1)

    if format.lower() == "json":
        console.print_json(dev.model_dump_json(indent=2))
    else:
        render_device_detail(dev)


@app.command(name="monitor")
def monitor_devices(
    interval: Annotated[
        float,
        typer.Option(
            "--interval",
            "-i",
            help="Polling check interval in seconds.",
        ),
    ] = 2.0,
) -> None:
    """Monitor real-time device connections, disconnections, and volume mounts."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    console.print(
        f"[bold cyan]Starting real-time device monitor (interval: {interval}s)... Press Ctrl+C to stop.[/bold cyan]\n"
    )

    manager = DeviceManager()
    # Populate initial inventory
    initial = manager.discover_all()
    console.print(f"[dim]Initial inventory baseline: {len(initial)} devices registered.[/dim]\n")

    def handle_event(event: DeviceEvent) -> None:
        panel = render_device_event_panel(event)
        console.print(panel)

    manager.subscribe_events(handle_event)
    manager.start_monitoring(poll_interval=interval)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping device monitor...[/yellow]")
        manager.stop_monitoring()
        console.print("[green]Device monitor stopped safely.[/green]")
