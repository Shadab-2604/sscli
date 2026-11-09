"""Local host packet capture controller with platform-adaptive fallback."""

from __future__ import annotations

import logging
from collections.abc import Callable

from systemscan.network_monitor.capture.base import BaseCaptureProvider
from systemscan.network_monitor.capture.pcap_provider import PcapCaptureProvider
from systemscan.network_monitor.models import CaptureSourceType, PacketMetadata, SensorHealthStatus

logger = logging.getLogger("systemscan.network_monitor.local_capture")


class LocalPacketCaptureEngine(BaseCaptureProvider):
    """Manages local machine traffic capture with automated interface selection and permission checks."""

    def __init__(self, interface: str | None = None) -> None:
        self.interface = interface
        self._provider = PcapCaptureProvider(interface=interface)

    @property
    def source_type(self) -> CaptureSourceType:
        return CaptureSourceType.LOCAL

    def get_interface_name(self) -> str:
        return self._provider.get_interface_name()

    def get_health_status(self) -> tuple[SensorHealthStatus, str]:
        return self._provider.get_health_status()

    def start_capture(self, callback: Callable[[PacketMetadata], None]) -> bool:
        return self._provider.start_capture(callback)

    def stop_capture(self) -> None:
        self._provider.stop_capture()
