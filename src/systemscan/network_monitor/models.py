"""Data models for the Network Threat Monitor module."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MonitorMode(str, Enum):
    """Network threat monitoring operating mode."""

    LOCAL = "LOCAL"
    NETWORK_WIDE = "NETWORK_WIDE"
    BOTH = "BOTH"


class ScanProtocol(str, Enum):
    """Network protocol observed in scan activity."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    OTHER = "OTHER"


class ScanPattern(str, Enum):
    """Classified reconnaissance pattern or scan type."""

    TCP_SYN_SCAN = "TCP SYN Scan"
    TCP_CONNECT_SCAN = "TCP Connect Scan"
    UDP_PORT_SCAN = "UDP Port Scan"
    FIN_SCAN = "FIN-Only Scan"
    NULL_SCAN = "NULL-Flag Scan"
    XMAS_SCAN = "Xmas Tree Scan (FIN/PSH/URG)"
    HOST_DISCOVERY = "Host Discovery Sweep"
    NETWORK_SWEEP = "Network Subnet Sweep"
    MULTI_STAGE_RECON = "Multi-Stage Reconnaissance"
    SUSPICIOUS_PROBE = "Suspicious Reconnaissance Probe"
    UNKNOWN_ACTIVITY = "Unknown Scanning Activity"


class AlertSeverity(str, Enum):
    """Threat severity rating for network threat alerts."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionConfidence(str, Enum):
    """Attribution and detection confidence level."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class IdentityConfidence(str, Enum):
    """Confidence level for resolved device identity."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class CaptureSourceType(str, Enum):
    """Origin source of the captured packet stream."""

    LOCAL = "Local Interface"
    ROUTER = "Router Flow / AP Integration"
    MIRRORED = "Mirrored SPAN / TAP"
    SENSOR = "Dedicated Network Sensor"


class SensorHealthStatus(str, Enum):
    """Health state of capture sensors."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    UNCONFIGURED = "UNCONFIGURED"
    ERROR = "ERROR"


@dataclass
class PacketMetadata:
    """Normalized cross-platform network packet representation."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    source_mac: str | None = None
    destination_mac: str | None = None
    protocol: ScanProtocol = ScanProtocol.TCP
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: list[str] = field(default_factory=list)
    packet_length: int = 0
    interface: str = "default"
    direction: str = "incoming"  # incoming, outgoing, transit
    capture_source: CaptureSourceType = CaptureSourceType.LOCAL


@dataclass
class DeviceIdentity:
    """Collected identity and inventory details for an observed host."""

    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str = "Unknown Device"
    interface: str = "default"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_count: int = 0
    is_trusted: bool = False
    confidence: IdentityConfidence = IdentityConfidence.UNKNOWN


@dataclass
class NetworkThreatAlert:
    """Security alert representing detected scanning or reconnaissance behavior."""

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity = AlertSeverity.HIGH
    confidence: DetectionConfidence = DetectionConfidence.HIGH
    alert_type: str = "PORT SCAN DETECTED"
    pattern: ScanPattern = ScanPattern.TCP_SYN_SCAN

    # Actor & target
    source_ip: str = "0.0.0.0"
    source_mac: str | None = None
    source_hostname: str | None = None
    source_vendor: str | None = None

    destination_ip: str = "0.0.0.0"
    destination_hostname: str | None = None

    # Telemetry
    protocol: ScanProtocol = ScanProtocol.TCP
    unique_ports: int = 0
    target_count: int = 1
    time_window_seconds: float = 10.0
    evidence: str = ""
    capture_source: CaptureSourceType = CaptureSourceType.LOCAL
    sample_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "alert_type": self.alert_type,
            "pattern": self.pattern.value,
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "source_hostname": self.source_hostname,
            "source_vendor": self.source_vendor,
            "destination_ip": self.destination_ip,
            "destination_hostname": self.destination_hostname,
            "protocol": self.protocol.value,
            "unique_ports": self.unique_ports,
            "target_count": self.target_count,
            "time_window_seconds": self.time_window_seconds,
            "evidence": self.evidence,
            "capture_source": self.capture_source.value,
            "sample_ports": self.sample_ports,
        }
