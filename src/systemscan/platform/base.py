"""Platform abstraction layer and capability discovery contracts for systemscan."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from systemscan.modules.models import (
        DiskInformation,
        FirmwareInformation,
        GPUInformation,
        ServiceInformation,
        StartupEntry,
    )


class OSType(str, Enum):
    """Enumeration of supported target operating systems."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    UNKNOWN = "unknown"


class CapabilityStatus(str, Enum):
    """Evaluation status of a platform capability."""

    AVAILABLE = "AVAILABLE"
    PARTIALLY_AVAILABLE = "PARTIALLY_AVAILABLE"
    PERMISSION_REQUIRED = "PERMISSION_REQUIRED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class PlatformCapabilities:
    """Declared hardware, kernel, and system inspection capabilities."""

    can_inspect_posix_permissions: bool
    can_inspect_windows_acls: bool
    can_inspect_systemd: bool
    can_inspect_launchd: bool
    can_inspect_windows_services: bool
    can_access_raw_disks: bool
    requires_elevation_for_hardware: bool


class PlatformInterface(ABC):
    """Abstract base contract for OS-specific operations."""

    @property
    @abstractmethod
    def os_type(self) -> OSType:
        """Return the OS category."""

    @property
    @abstractmethod
    def os_name(self) -> str:
        """Friendly name of the operating system."""

    @property
    @abstractmethod
    def os_version(self) -> str:
        """Operating system release or kernel version string."""

    @property
    @abstractmethod
    def architecture(self) -> str:
        """Machine architecture (e.g. x86_64, arm64, AMD64)."""

    @property
    @abstractmethod
    def capabilities(self) -> PlatformCapabilities:
        """Structured capabilities supported on this platform."""

    @abstractmethod
    def is_elevated(self) -> bool:
        """Check if application process runs with administrator / root privileges."""

    @abstractmethod
    def get_system_summary(self) -> dict[str, Any]:
        """Return non-invasive platform diagnostic summary."""

    @abstractmethod
    def get_linux_distribution(self) -> tuple[str | None, str | None]:
        """Return (distro_name, distro_version) if Linux, otherwise (None, None)."""

    @abstractmethod
    def get_firmware_info(self, include_serials: bool = False) -> FirmwareInformation:
        """Retrieve Motherboard, BIOS, or UEFI hardware firmware metadata."""

    @abstractmethod
    def get_gpus(self) -> list[GPUInformation]:
        """Detect and query installed graphics devices."""

    @abstractmethod
    def get_services(self, status_filter: str | None = None) -> list[ServiceInformation]:
        """Query system services/daemons."""

    @abstractmethod
    def get_startup_entries(self) -> list[StartupEntry]:
        """Discover startup and persistence applications."""

    @abstractmethod
    def get_physical_disks(self) -> list[DiskInformation]:
        """Discover physical disk storage devices."""

    @abstractmethod
    def get_capabilities_matrix(self) -> dict[str, CapabilityStatus]:
        """Return the capability evaluation matrix for this platform."""

    def get_capability_status(self, capability: str) -> CapabilityStatus:
        """Query capability status with safe fallback."""
        return self.get_capabilities_matrix().get(capability, CapabilityStatus.UNSUPPORTED)
