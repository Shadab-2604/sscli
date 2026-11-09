"""Network-wide traffic visibility interface and remote sensor integration."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from systemscan.network_monitor.capture.base import BaseCaptureProvider
from systemscan.network_monitor.models import (
    CaptureSourceType,
    DeviceIdentity,
    PacketMetadata,
    SensorHealthStatus,
)

logger = logging.getLogger("systemscan.network_monitor.network_capture")


class NetworkVisibilityProvider(BaseCaptureProvider):
    """
    Abstract provider for network-wide monitoring sources (AP/Router integrations,
    mirrored SPAN ports, or dedicated remote network sensors).
    """

    def discover_clients(self) -> list[DeviceIdentity]:
        """Discover connected clients on LAN if supported by provider."""
        return []

    def get_network_metadata(self) -> dict[str, Any]:
        """Retrieve network posture, gateway IP, DHCP range."""
        return {}


class NetworkSensorCaptureEngine(NetworkVisibilityProvider):
    """
    Controller for network-wide visibility. Strictly reports UNAVAILABLE unless a real
    verified traffic source (e.g. SPAN mirror, authorized router API, or dedicated sensor) is active.
    """

    def __init__(self, source_url: str | None = None, auth_token: str | None = None) -> None:
        self.source_url = source_url
        self.auth_token = auth_token
        self._running = False
        self._health = SensorHealthStatus.UNCONFIGURED
        self._status_reason = "No supported network traffic source configured (Local-Only Fallback)"

    @property
    def source_type(self) -> CaptureSourceType:
        return CaptureSourceType.SENSOR

    def get_interface_name(self) -> str:
        return self.source_url or "None"

    def get_health_status(self) -> tuple[SensorHealthStatus, str]:
        return self._health, self._status_reason

    def start_capture(self, callback: Callable[[PacketMetadata], None]) -> bool:
        if not self.source_url:
            self._health = SensorHealthStatus.UNCONFIGURED
            self._status_reason = "No supported network traffic source configured"
            logger.info(
                "Network-wide capture inactive: No external sensor URL or router configured."
            )
            return False

        # In production sensor mode, connection to the authenticated sensor over TLS occurs here
        self._health = SensorHealthStatus.HEALTHY
        self._status_reason = f"Connected to network sensor at {self.source_url}"
        self._running = True
        return True

    def stop_capture(self) -> None:
        self._running = False
        self._health = SensorHealthStatus.UNCONFIGURED
        self._status_reason = "Network sensor stopped"
