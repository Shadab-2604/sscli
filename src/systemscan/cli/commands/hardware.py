"""Hardware inspection commands for systemscan."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from systemscan.cli.display import (
    render_cpu_info,
    render_device_inventory,
    render_firmware_info,
    render_gpu_info,
    render_memory_info,
    render_storage_info,
)
from systemscan.core.application import app_instance
from systemscan.modules.hardware.cpu import collect_cpu_info
from systemscan.modules.hardware.devices import collect_device_inventory
from systemscan.modules.hardware.firmware import collect_firmware_info
from systemscan.modules.hardware.gpu import collect_gpu_info
from systemscan.modules.hardware.memory import collect_memory_info
from systemscan.modules.hardware.storage import collect_storage_info

app = typer.Typer(
    name="hardware",
    help="Inspect host hardware components: CPU, memory, GPU, storage, firmware, and devices.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def hardware_command(
    component: Annotated[
        str,
        typer.Option(
            "--component",
            "-c",
            help="Filter specific component: 'all', 'cpu', 'memory', 'gpu', 'storage', 'firmware', or 'devices'.",
        ),
    ] = "all",
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'text' or 'json'.",
        ),
    ] = "text",
    include_serials: Annotated[
        bool,
        typer.Option(
            "--include-serials",
            help="Include sensitive hardware serial numbers in output.",
        ),
    ] = False,
) -> None:
    """Inspect and present detailed physical and logical hardware specifications."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    comp = component.lower()
    is_json = format.lower() == "json"
    allow_serials = include_serials or app_instance.config.preferences.include_hardware_serials

    data_payload: dict[str, object] = {}

    # CPU
    if comp in ("all", "cpu"):
        cpu = collect_cpu_info()
        data_payload["cpu"] = cpu.model_dump(mode="json")
        if not is_json:
            render_cpu_info(cpu)

    # Memory
    if comp in ("all", "memory", "ram"):
        mem = collect_memory_info()
        data_payload["memory"] = mem.model_dump(mode="json")
        if not is_json:
            render_memory_info(mem)

    # GPU
    if comp in ("all", "gpu", "graphics"):
        gpus = collect_gpu_info(app_instance.platform)
        data_payload["gpus"] = [g.model_dump(mode="json") for g in gpus]
        if not is_json:
            render_gpu_info(gpus)

    # Storage
    if comp in ("all", "storage", "disks"):
        partitions, disks = collect_storage_info(app_instance.platform)
        data_payload["partitions"] = [p.model_dump(mode="json") for p in partitions]
        data_payload["disks"] = [d.model_dump(mode="json") for d in disks]
        if not is_json:
            render_storage_info(partitions, disks)

    # Firmware / Motherboard
    if comp in ("all", "firmware", "bios", "motherboard"):
        fw = collect_firmware_info(
            include_serials=allow_serials, platform_handler=app_instance.platform
        )
        data_payload["firmware"] = fw.model_dump(mode="json")
        if not is_json:
            render_firmware_info(fw)

    # Devices
    if comp in ("all", "devices"):
        devices = collect_device_inventory(app_instance.platform)
        data_payload["devices"] = [d.model_dump(mode="json") for d in devices]
        if not is_json and comp == "devices":
            render_device_inventory(devices)

    if is_json:
        console.print_json(json.dumps(data_payload, indent=2))
