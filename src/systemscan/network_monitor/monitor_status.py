"""Status tracking and coverage models for network threat monitoring."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from systemscan.network_monitor.models import MonitorMode, SensorHealthStatus


@dataclass
class MonitorStatusReport:
    """Consolidated operational health and coverage status report."""

    mode: MonitorMode = MonitorMode.BOTH
    timestamp: datetime = datetime.now(timezone.utc)

    # Local monitor
    local_active: bool = False
    local_interface: str = "Unknown"
    local_packets_captured: int = 0
    local_capture_health: SensorHealthStatus = SensorHealthStatus.UNCONFIGURED
    local_details: str = ""

    # Network-wide monitor
    network_active: bool = False
    network_source_name: str = "None"
    network_packets_captured: int = 0
    network_capture_health: SensorHealthStatus = SensorHealthStatus.UNCONFIGURED
    network_details: str = "No supported network traffic source configured"

    # Overall coverage description
    coverage_summary: str = "Local machine traffic only"
    alerts_generated: int = 0
    devices_tracked: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "timestamp": self.timestamp.isoformat(),
            "local_monitor": {
                "active": self.local_active,
                "interface": self.local_interface,
                "packets_captured": self.local_packets_captured,
                "health": self.local_capture_health.value,
                "details": self.local_details,
            },
            "network_wide_monitor": {
                "active": self.network_active,
                "source": self.network_source_name,
                "packets_captured": self.network_packets_captured,
                "health": self.network_capture_health.value,
                "details": self.network_details,
            },
            "coverage_summary": self.coverage_summary,
            "alerts_generated": self.alerts_generated,
            "devices_tracked": self.devices_tracked,
        }
