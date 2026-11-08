"""Comprehensive typed data models for Phase 2 System Intelligence & Hardware Inspector."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from systemscan.utils.formatting import (
    format_bytes,
    format_celsius,
    format_duration,
    format_mhz,
    format_percentage,
)


class OperatingSystemModel(BaseModel):
    """Detailed operating system identification metadata."""

    family: str = Field(description="OS family: Windows, Linux, Darwin, etc.")
    name: str = Field(description="Friendly operating system name")
    version: str = Field(description="OS version or build string")
    release: str = Field(description="OS release identifier")
    distro_name: str | None = Field(default=None, description="Linux distribution name")
    distro_version: str | None = Field(default=None, description="Linux distribution version")
    kernel_version: str = Field(description="Kernel release string")
    build_info: str | None = Field(default=None, description="OS build or patch details")
    hostname: str = Field(description="Network node hostname")
    machine_arch: str = Field(description="Hardware machine architecture")
    processor_arch: str = Field(description="Processor architecture")
    python_version: str = Field(description="Active Python interpreter version")
    python_executable: str = Field(description="Absolute path to Python executable")
    shell: str | None = Field(default=None, description="Detected login or active shell")
    boot_time: str = Field(description="ISO 8601 boot timestamp")
    uptime_seconds: float = Field(description="System uptime in seconds")

    @property
    def uptime_formatted(self) -> str:
        return format_duration(self.uptime_seconds)


class ExecutionEnvironmentModel(BaseModel):
    """Host execution environment metadata."""

    username: str = Field(description="Current executing username")
    user_id: str | None = Field(default=None, description="User ID / SID where supported")
    is_elevated: bool = Field(description="Administrator or root privilege status")
    virtual_env: str | None = Field(default=None, description="Active virtualenv directory")
    python_executable: str = Field(description="Path to executing python binary")
    working_directory: str = Field(description="Current working directory")
    is_interactive: bool = Field(description="Interactive TTY status")
    terminal_columns: int | None = Field(default=None, description="Terminal width")
    terminal_lines: int | None = Field(default=None, description="Terminal height")
    safe_environment_vars: dict[str, str] = Field(
        default_factory=dict, description="Sanitized platform environment variables"
    )


class ApplicationEnvironmentModel(BaseModel):
    """Systemscan application deployment information."""

    version: str
    install_type: str
    config_dir: str
    data_dir: str
    log_dir: str
    report_dir: str


class CPUInformation(BaseModel):
    """Processor telemetry and hardware specification."""

    vendor: str = Field(description="CPU vendor (e.g. GenuineIntel, AuthenticAMD, Apple)")
    model: str = Field(description="CPU model name and specification")
    architecture: str = Field(description="Instruction set architecture")
    physical_cores: int | None = Field(default=None, description="Physical CPU cores count")
    logical_cores: int | None = Field(default=None, description="Logical CPU threads count")
    current_frequency_mhz: float | None = Field(default=None, description="Current clock speed")
    min_frequency_mhz: float | None = Field(default=None, description="Minimum clock speed")
    max_frequency_mhz: float | None = Field(default=None, description="Maximum clock speed")
    utilization_percent: float = Field(description="Overall instantaneous CPU utilization")
    per_core_utilization: list[float] = Field(
        default_factory=list, description="Per-core utilization percentages"
    )
    load_averages: tuple[float, float, float] | None = Field(
        default=None, description="1, 5, 15 minute system load averages"
    )
    temperature_celsius: float | None = Field(
        default=None, description="Package temperature where exposed"
    )

    @property
    def current_freq_formatted(self) -> str:
        return format_mhz(self.current_frequency_mhz)

    @property
    def max_freq_formatted(self) -> str:
        return format_mhz(self.max_frequency_mhz)

    @property
    def temp_formatted(self) -> str:
        return format_celsius(self.temperature_celsius)

    @property
    def utilization_formatted(self) -> str:
        return format_percentage(self.utilization_percent)


class MemoryInformation(BaseModel):
    """Physical RAM and swap space memory telemetry."""

    total_bytes: int
    available_bytes: int
    used_bytes: int
    free_bytes: int
    percentage: float
    cached_bytes: int | None = None
    swap_total_bytes: int = 0
    swap_used_bytes: int = 0
    swap_free_bytes: int = 0
    swap_percentage: float = 0.0

    @property
    def total_formatted(self) -> str:
        return format_bytes(self.total_bytes)

    @property
    def available_formatted(self) -> str:
        return format_bytes(self.available_bytes)

    @property
    def used_formatted(self) -> str:
        return format_bytes(self.used_bytes)

    @property
    def free_formatted(self) -> str:
        return format_bytes(self.free_bytes)

    @property
    def cached_formatted(self) -> str:
        return format_bytes(self.cached_bytes)

    @property
    def swap_total_formatted(self) -> str:
        return format_bytes(self.swap_total_bytes)

    @property
    def swap_used_formatted(self) -> str:
        return format_bytes(self.swap_used_bytes)

    @property
    def swap_free_formatted(self) -> str:
        return format_bytes(self.swap_free_bytes)


class GPUInformation(BaseModel):
    """Graphics processor specification and operational status."""

    vendor: str = Field(description="GPU vendor (NVIDIA, AMD, Intel, Apple)")
    model: str = Field(description="GPU device model name")
    driver_version: str | None = None
    memory_total_bytes: int | None = None
    memory_used_bytes: int | None = None
    utilization_percent: float | None = None
    temperature_celsius: float | None = None
    architecture: str | None = None
    status: str = Field(default="detected")

    @property
    def memory_total_formatted(self) -> str:
        return format_bytes(self.memory_total_bytes)

    @property
    def memory_used_formatted(self) -> str:
        return format_bytes(self.memory_used_bytes)

    @property
    def temp_formatted(self) -> str:
        return format_celsius(self.temperature_celsius)

    @property
    def utilization_formatted(self) -> str:
        return format_percentage(self.utilization_percent)


class FirmwareInformation(BaseModel):
    """Motherboard, BIOS, and UEFI firmware metadata."""

    manufacturer: str | None = None
    product_model: str | None = None
    serial_number: str | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    bios_release_date: str | None = None
    firmware_type: str | None = None


class PartitionInformation(BaseModel):
    """Filesystem mount point and logical partition specification."""

    device: str
    mountpoint: str
    filesystem_type: str
    options: str = ""
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percentage: float
    is_readonly: bool = False
    is_removable: bool = False

    @property
    def total_formatted(self) -> str:
        return format_bytes(self.total_bytes)

    @property
    def used_formatted(self) -> str:
        return format_bytes(self.used_bytes)

    @property
    def free_formatted(self) -> str:
        return format_bytes(self.free_bytes)


class DiskInformation(BaseModel):
    """Physical or logical storage drive."""

    name: str
    model: str | None = None
    size_bytes: int | None = None
    is_removable: bool = False
    is_physical: bool = True
    partitions: list[PartitionInformation] = Field(default_factory=list)

    @property
    def size_formatted(self) -> str:
        return format_bytes(self.size_bytes)


class DeviceInformation(BaseModel):
    """Hardware device asset inventory entry."""

    device_type: str = Field(description="disk, usb, gpu, network_interface, optical, etc.")
    name: str
    description: str | None = None
    vendor: str | None = None
    status: str = "active"
    is_removable: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkInterface(BaseModel):
    """Network adapter hardware and protocol addressing."""

    name: str
    description: str | None = None
    mac_address: str | None = None
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    netmasks: list[str] = Field(default_factory=list)
    broadcast_addresses: list[str] = Field(default_factory=list)
    is_up: bool = True
    speed_mbps: int | None = None
    interface_type: str | None = None


class ProcessInformation(BaseModel):
    """Individual running process telemetry and metadata."""

    pid: int
    name: str
    ppid: int | None = None
    exe_path: str | None = None
    username: str | None = None
    status: str = "running"
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_mb: float = 0.0
    create_time: str = ""
    thread_count: int | None = None
    open_files_count: int | None = None
    connections_count: int | None = None


class ServiceInformation(BaseModel):
    """System service or daemon status."""

    name: str
    display_name: str | None = None
    status: str = Field(description="running, stopped, paused, unknown")
    startup_type: str | None = None
    description: str | None = None


class StartupEntry(BaseModel):
    """Startup application and persistence mechanism entry."""

    name: str
    source: str = Field(description="Registry, Startup Folder, systemd, LaunchAgent, etc.")
    command: str = Field(description="Command or executable path")
    scope: str = Field(default="system", description="user or system")
    status: str = Field(default="enabled", description="enabled, disabled, unknown")
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProcessSummary(BaseModel):
    """Aggregate statistics for host processes."""

    total_processes: int
    running_processes: int
    sleeping_processes: int
    total_threads: int


class SystemInformation(BaseModel):
    """Root consolidated system intelligence inspection payload."""

    os: OperatingSystemModel
    environment: ExecutionEnvironmentModel
    application: ApplicationEnvironmentModel
    cpu: CPUInformation
    memory: MemoryInformation
    storage: list[PartitionInformation]
    physical_disks: list[DiskInformation] = Field(default_factory=list)
    gpus: list[GPUInformation] = Field(default_factory=list)
    firmware: FirmwareInformation
    network: list[NetworkInterface] = Field(default_factory=list)
    process_summary: ProcessSummary
