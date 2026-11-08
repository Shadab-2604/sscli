"""Data models and enumerations for the Network Security & Intelligence Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class InterfaceType(str, Enum):
    """Categorization of network interface physical or logical type."""

    ETHERNET = "ETHERNET"
    WIFI = "WIFI"
    LOOPBACK = "LOOPBACK"
    VPN = "VPN"
    VIRTUAL = "VIRTUAL"
    BRIDGE = "BRIDGE"
    CELLULAR = "CELLULAR"
    UNKNOWN = "UNKNOWN"


class Protocol(str, Enum):
    """Transport protocol."""

    TCP = "TCP"
    UDP = "UDP"


class ConnectionState(str, Enum):
    """Network connection lifecycle state."""

    ESTABLISHED = "ESTABLISHED"
    LISTEN = "LISTEN"
    TIME_WAIT = "TIME_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    LAST_ACK = "LAST_ACK"
    CLOSING = "CLOSING"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class FindingSeverity(str, Enum):
    """Standardized finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, Enum):
    """Standardized finding confidence levels."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class FindingCategory(str, Enum):
    """Network security finding classifications."""

    NETWORK_CONFIGURATION = "NETWORK_CONFIGURATION"
    OPEN_PORT = "OPEN_PORT"
    EXPOSED_SERVICE = "EXPOSED_SERVICE"
    FIREWALL = "FIREWALL"
    DNS = "DNS"
    WIFI_SECURITY = "WIFI_SECURITY"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    NETWORK_DISCOVERY = "NETWORK_DISCOVERY"
    INTERFACE_CONFIGURATION = "INTERFACE_CONFIGURATION"


class FirewallProfile(str, Enum):
    """Firewall profile contexts."""

    DOMAIN = "DOMAIN"
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"
    GLOBAL = "GLOBAL"
    ALL = "ALL"


class FirewallAction(str, Enum):
    """Firewall filtering action."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REJECT = "REJECT"


class FirewallDirection(str, Enum):
    """Firewall traffic direction."""

    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class HostStatus(str, Enum):
    """Host responsiveness state."""

    UP = "UP"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class DNSRecordType(str, Enum):
    """DNS record query types."""

    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    CNAME = "CNAME"
    PTR = "PTR"


class NetworkInterfaceDetail(BaseModel):
    """Comprehensive details and telemetry for a single network interface."""

    name: str = Field(description="System interface name")
    description: str = Field(default="", description="Adapter description or hardware vendor")
    interface_type: InterfaceType = Field(
        default=InterfaceType.UNKNOWN, description="Classified adapter type"
    )
    mac_address: str | None = Field(default=None, description="Hardware MAC address")
    ipv4_addresses: list[str] = Field(default_factory=list, description="Assigned IPv4 addresses")
    ipv6_addresses: list[str] = Field(default_factory=list, description="Assigned IPv6 addresses")
    subnets: list[str] = Field(
        default_factory=list, description="Configured subnets in CIDR notation"
    )
    gateway: str | None = Field(default=None, description="Default gateway address")
    dns_servers: list[str] = Field(default_factory=list, description="Assigned DNS servers")
    is_up: bool = Field(default=True, description="Whether interface link is operational")
    mtu: int | None = Field(default=None, ge=0, description="Maximum Transmission Unit in bytes")
    speed_mbps: int | None = Field(
        default=None, ge=0, description="Link speed in megabits per second"
    )
    is_dhcp: bool | None = Field(default=None, description="Whether DHCP addressing is active")
    ssid: str | None = Field(default=None, description="Connected Wi-Fi SSID if applicable")
    is_loopback: bool = Field(default=False, description="Whether adapter is a loopback interface")
    is_virtual: bool = Field(
        default=False, description="Whether adapter is a virtual or container interface"
    )
    is_vpn: bool = Field(default=False, description="Whether adapter is a VPN tunnel or tap device")


class NetworkConnection(BaseModel):
    """Observation of an active network connection or listening socket."""

    protocol: Protocol = Field(description="Transport protocol (TCP/UDP)")
    local_address: str = Field(description="Local IP address")
    local_port: int = Field(ge=0, le=65535, description="Local port number")
    remote_address: str | None = Field(default=None, description="Remote IP address if connected")
    remote_port: int | None = Field(
        default=None, ge=0, le=65535, description="Remote port number if connected"
    )
    state: ConnectionState = Field(
        default=ConnectionState.UNKNOWN, description="Connection lifecycle state"
    )
    pid: int | None = Field(default=None, description="Process ID owning this socket")
    process_name: str | None = Field(default=None, description="Process binary name")
    process_path: str | None = Field(default=None, description="Full process executable path")
    is_listening: bool = Field(
        default=False, description="Whether socket is listening for connections"
    )
    is_all_interfaces: bool = Field(
        default=False, description="Whether listening on all interfaces (0.0.0.0 / ::)"
    )
    is_loopback: bool = Field(
        default=False, description="Whether bound to local loopback (127.0.0.1 / ::1)"
    )


class DiscoveredHost(BaseModel):
    """Host discovered on a scanned local subnet."""

    ip: str = Field(description="IPv4 or IPv6 address")
    mac: str | None = Field(default=None, description="Hardware MAC address if resolved")
    hostname: str | None = Field(default=None, description="Host name resolved via reverse DNS")
    status: HostStatus = Field(default=HostStatus.UP, description="Host responsiveness")
    latency_ms: float | None = Field(
        default=None, ge=0.0, description="Round-trip latency in milliseconds"
    )
    open_ports: list[int] = Field(default_factory=list, description="Responsive open TCP ports")
    vendor: str | None = Field(default=None, description="OUI vendor resolved from MAC")
    is_gateway: bool = Field(default=False, description="Whether host is the local default gateway")


class DNSResolutionResult(BaseModel):
    """Result of a DNS resolution diagnostic."""

    query_name: str = Field(description="Queried domain or IP")
    record_type: DNSRecordType = Field(description="Record type queried")
    records: list[str] = Field(default_factory=list, description="Resolved records")
    resolution_time_ms: float = Field(
        default=0.0, ge=0.0, description="Query duration in milliseconds"
    )
    server_used: str | None = Field(default=None, description="DNS server responding to query")
    error: str | None = Field(default=None, description="Error message if resolution failed")
    success: bool = Field(default=True, description="Whether resolution succeeded")


class FirewallRule(BaseModel):
    """Metadata for an active firewall rule."""

    name: str = Field(description="Rule name or identifier")
    direction: FirewallDirection = Field(description="Inbound or outbound direction")
    action: FirewallAction = Field(description="Rule action (ALLOW/BLOCK/REJECT)")
    profile: str = Field(default="ALL", description="Target firewall profile")
    protocol: str = Field(default="ALL", description="Transport protocol")
    local_ports: str = Field(default="ALL", description="Local port filter")
    remote_ports: str = Field(default="ALL", description="Remote port filter")
    remote_addresses: str = Field(default="ALL", description="Remote address filter")
    enabled: bool = Field(default=True, description="Whether rule is active")


class FirewallStatus(BaseModel):
    """Overall status and posture of host firewall system."""

    is_enabled: bool = Field(description="Whether firewall protection is active")
    service_active: bool = Field(
        default=True, description="Whether underlying firewall service is running"
    )
    backend_name: str = Field(
        description="Name of firewall technology (UFW, Windows Defender, etc.)"
    )
    profiles: dict[str, bool] = Field(
        default_factory=dict, description="Status of individual profiles"
    )
    default_inbound_action: FirewallAction = Field(
        default=FirewallAction.BLOCK, description="Default inbound policy"
    )
    default_outbound_action: FirewallAction = Field(
        default=FirewallAction.ALLOW, description="Default outbound policy"
    )
    rules_count: int = Field(default=0, ge=0, description="Total count of active rules")
    rules: list[FirewallRule] = Field(default_factory=list, description="Sample of relevant rules")
    warnings: list[str] = Field(default_factory=list, description="Security warnings or anomalies")


class WirelessConnectionInfo(BaseModel):
    """Telemetry and security metadata for the active Wi-Fi connection."""

    ssid: str | None = Field(default=None, description="Connected Wi-Fi SSID name")
    bssid: str | None = Field(default=None, description="Access point MAC address (BSSID)")
    security_type: str | None = Field(default=None, description="Security/authentication protocol")
    is_open: bool = Field(
        default=False, description="Whether network has no authentication/encryption"
    )
    is_weak: bool = Field(
        default=False, description="Whether network uses deprecated/insecure protocols (WEP, WPA1)"
    )
    band: str | None = Field(default=None, description="Frequency band (2.4 GHz, 5 GHz, 6 GHz)")
    channel: int | None = Field(default=None, ge=1, description="Operating channel")
    signal_strength_pct: int | None = Field(
        default=None, ge=0, le=100, description="Signal quality percentage"
    )
    adapter_name: str | None = Field(default=None, description="Wireless network adapter name")
    is_connected: bool = Field(
        default=False, description="Whether adapter is connected to a wireless network"
    )


class NetworkFinding(BaseModel):
    """Normalized security finding produced during network inspection."""

    finding_id: str = Field(description="Unique identifier for finding")
    category: FindingCategory = Field(description="Functional category")
    title: str = Field(description="Concise finding headline")
    description: str = Field(description="Detailed explanation of finding")
    severity: FindingSeverity = Field(description="Assessed severity level")
    confidence: FindingConfidence = Field(description="Assessment confidence based on evidence")
    evidence: str = Field(description="Supporting evidence and diagnostic context")
    affected_target: str = Field(description="Affected interface, IP, port, or service")
    remediation: str = Field(description="Actionable guidance to remediate the issue")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Detection timestamp"
    )
    source_module: str = Field(default="network", description="Originating inspection module")


class NetworkBaseline(BaseModel):
    """Persistent snapshot of known authorized network state for drift detection."""

    name: str = Field(default="default", description="Baseline configuration profile name")
    version: int = Field(default=1, ge=1, description="Schema version")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Snapshot creation time"
    )
    known_interfaces: list[str] = Field(
        default_factory=list, description="MAC addresses or interface names"
    )
    known_gateways: list[str] = Field(
        default_factory=list, description="Known default gateway IP addresses"
    )
    known_dns_servers: list[str] = Field(
        default_factory=list, description="Known authorized DNS server IPs"
    )
    known_wifi_ssids: list[str] = Field(
        default_factory=list, description="Known authorized Wi-Fi networks"
    )
    known_listening_ports: list[int] = Field(
        default_factory=list, description="Known listening TCP/UDP ports"
    )
    known_local_devices: list[str] = Field(
        default_factory=list, description="Known local IP or MAC addresses"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary baseline metadata"
    )


class BaselineComparisonResult(BaseModel):
    """Differences observed between a saved baseline and the active system state."""

    baseline_name: str = Field(description="Compared baseline profile name")
    compared_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Comparison timestamp"
    )
    added_interfaces: list[str] = Field(
        default_factory=list, description="Newly discovered network interfaces"
    )
    removed_interfaces: list[str] = Field(
        default_factory=list, description="Previously known interfaces missing"
    )
    added_gateways: list[str] = Field(
        default_factory=list, description="New default gateway observed"
    )
    removed_gateways: list[str] = Field(
        default_factory=list, description="Previous default gateway missing"
    )
    added_dns_servers: list[str] = Field(
        default_factory=list, description="New DNS servers configured"
    )
    removed_dns_servers: list[str] = Field(
        default_factory=list, description="Previously configured DNS servers missing"
    )
    added_listening_ports: list[int] = Field(
        default_factory=list, description="New listening ports discovered"
    )
    removed_listening_ports: list[int] = Field(
        default_factory=list, description="Previously listening ports closed"
    )
    new_wifi_ssids: list[str] = Field(default_factory=list, description="New Wi-Fi SSIDs connected")
    new_devices: list[str] = Field(
        default_factory=list, description="New hosts observed on local subnet"
    )
    findings: list[NetworkFinding] = Field(
        default_factory=list, description="Generated security findings"
    )

    @property
    def has_changes(self) -> bool:
        """Return True if any divergence from baseline was detected."""
        return bool(
            self.added_interfaces
            or self.removed_interfaces
            or self.added_gateways
            or self.removed_gateways
            or self.added_dns_servers
            or self.removed_dns_servers
            or self.added_listening_ports
            or self.removed_listening_ports
            or self.new_wifi_ssids
            or self.new_devices
        )


class DiagnosticsResult(BaseModel):
    """Summary of basic network performance and reachability diagnostics."""

    gateway_ip: str | None = Field(default=None, description="Tested default gateway IP")
    gateway_reachable: bool = Field(default=False, description="Whether gateway responded")
    gateway_latency_ms: float | None = Field(
        default=None, ge=0.0, description="Gateway response latency"
    )
    dns_working: bool = Field(default=False, description="Whether DNS resolution succeeded")
    dns_latency_ms: float | None = Field(default=None, ge=0.0, description="DNS resolution latency")
    internet_target: str = Field(
        default="1.1.1.1", description="Target used for internet connectivity check"
    )
    internet_reachable: bool = Field(
        default=False, description="Whether internet target was reachable"
    )
    internet_latency_ms: float | None = Field(
        default=None, ge=0.0, description="Internet response latency"
    )
    packet_loss_percent: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Estimated packet loss"
    )
    summary: str = Field(default="", description="Human-readable diagnostics interpretation")
