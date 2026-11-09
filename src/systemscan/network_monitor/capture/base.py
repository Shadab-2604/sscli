"""Base interfaces and contracts for packet capture engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from systemscan.network_monitor.models import CaptureSourceType, PacketMetadata, SensorHealthStatus


class BaseCaptureProvider(ABC):
    """Abstract contract for platform-specific and remote packet capture sources."""

    @abstractmethod
    def start_capture(self, callback: Callable[[PacketMetadata], None]) -> bool:
        """Initialize and start background packet ingestion. Returns True if successfully bound."""

    @abstractmethod
    def stop_capture(self) -> None:
        """Halt packet capture and release low-level adapter handles."""

    @abstractmethod
    def get_health_status(self) -> tuple[SensorHealthStatus, str]:
        """Return (SensorHealthStatus, details_message)."""

    @abstractmethod
    def get_interface_name(self) -> str:
        """Return canonical bound interface name."""

    @property
    @abstractmethod
    def source_type(self) -> CaptureSourceType:
        """Return origin source classification."""
