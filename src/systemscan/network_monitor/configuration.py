"""Configuration models and thresholds for the Network Threat Monitor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SensitivityLevel(str, Enum):
    """Detection sensitivity profile."""

    LOW = "low"
    BALANCED = "balanced"
    HIGH = "high"


@dataclass
class DetectionThresholds:
    """Configurable numerical limits for triggering scanning detection alerts."""

    tcp_port_scan_threshold: int = 20  # unique destination ports / 10s
    udp_port_scan_threshold: int = 15  # unique destination ports / 10s
    host_sweep_threshold: int = 8  # destination IPs / 10s
    syn_anomaly_threshold: int = 20  # SYN probes / 10s
    time_window_seconds: float = 10.0
    multi_stage_threshold: int = 2  # correlated pattern count
    cooldown_seconds: float = 30.0  # deduplication cooldown per (source, pattern)


@dataclass
class NetworkMonitorConfig:
    """Overall settings and baseline parameters for network monitoring."""

    interface: str | None = None
    sensitivity: SensitivityLevel = SensitivityLevel.BALANCED
    duration_seconds: int | None = None
    trusted_ips: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    excluded_ports: list[int] = field(default_factory=list)
    router_api_url: str | None = None
    router_token: str | None = None
    sensor_listen_port: int = 9443
    sensor_auth_token: str | None = None
    max_memory_packets: int = 10000
    alert_retention_days: int = 30
    thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)

    def apply_sensitivity(self, level: SensitivityLevel | str) -> None:
        """Adjust detection thresholds according to chosen sensitivity profile."""
        if isinstance(level, str):
            level = SensitivityLevel(level.lower())
        self.sensitivity = level

        if level == SensitivityLevel.HIGH:
            self.thresholds.tcp_port_scan_threshold = 10
            self.thresholds.udp_port_scan_threshold = 8
            self.thresholds.host_sweep_threshold = 4
            self.thresholds.syn_anomaly_threshold = 10
            self.thresholds.time_window_seconds = 12.0
        elif level == SensitivityLevel.LOW:
            self.thresholds.tcp_port_scan_threshold = 40
            self.thresholds.udp_port_scan_threshold = 30
            self.thresholds.host_sweep_threshold = 15
            self.thresholds.syn_anomaly_threshold = 35
            self.thresholds.time_window_seconds = 8.0
        else:  # BALANCED
            self.thresholds.tcp_port_scan_threshold = 20
            self.thresholds.udp_port_scan_threshold = 15
            self.thresholds.host_sweep_threshold = 8
            self.thresholds.syn_anomaly_threshold = 20
            self.thresholds.time_window_seconds = 10.0
