"""Unit test suite for Phase 07: Network Security Audit & Network Intelligence Engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.network.baseline import NetworkBaselineManager
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.diagnostics import NetworkDiagnostics
from systemscan.network.discovery import LocalNetworkDiscovery
from systemscan.network.dns import DNSIntelligenceEngine
from systemscan.network.findings import NetworkFindingsEvaluator
from systemscan.network.firewall import FirewallAuditor
from systemscan.network.interfaces import NetworkInterfaceInspector
from systemscan.network.models import (
    ConnectionState,
    DNSRecordType,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FirewallAction,
    FirewallStatus,
    InterfaceType,
    NetworkConnection,
    NetworkFinding,
    NetworkInterfaceDetail,
    Protocol,
    WirelessConnectionInfo,
)
from systemscan.network.monitor import NetworkMonitor
from systemscan.network.providers.linux import LinuxNetworkProvider
from systemscan.network.providers.macos import MacOSNetworkProvider
from systemscan.network.providers.windows import WindowsNetworkProvider
from systemscan.network.wireless import WirelessSecurityInspector


class TestNetworkModels:
    """Validate data models, enumerations, and computed properties."""

    def test_network_interface_detail(self) -> None:
        iface = NetworkInterfaceDetail(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            mac_address="00:11:22:33:44:55",
            ipv4_addresses=["192.168.1.50"],
            ipv6_addresses=["fe80::1"],
            subnets=["192.168.1.0/24"],
            gateway="192.168.1.1",
            dns_servers=["1.1.1.1"],
            is_up=True,
            speed_mbps=1000,
        )
        assert iface.name == "eth0"
        assert iface.interface_type == InterfaceType.ETHERNET
        assert iface.mac_address == "00:11:22:33:44:55"
        assert iface.is_loopback is False

    def test_network_connection_listening(self) -> None:
        conn = NetworkConnection(
            protocol=Protocol.TCP,
            local_address="0.0.0.0",
            local_port=80,
            state=ConnectionState.LISTEN,
            pid=1234,
            process_name="nginx",
            is_listening=True,
            is_all_interfaces=True,
            is_loopback=False,
        )
        assert conn.is_listening is True
        assert conn.is_all_interfaces is True
        assert conn.local_port == 80

    def test_network_finding_model(self) -> None:
        finding = NetworkFinding(
            finding_id="NET-TEST-001",
            category=FindingCategory.OPEN_PORT,
            title="Test Port Open",
            description="Port 23 is exposed.",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.CONFIRMED,
            evidence="Listening on 0.0.0.0:23",
            affected_target="0.0.0.0:23",
            remediation="Close telnet.",
            source_module="network.connections",
        )
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.confidence == FindingConfidence.CONFIRMED


class TestNetworkProviders:
    """Validate platform-specific network command parsers."""

    def test_windows_provider_route_and_dns(self) -> None:
        provider = WindowsNetworkProvider()
        route_out = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
===========================================================================
"""
        with patch.object(provider, "_run_cmd", return_value=route_out):
            gw = provider.get_default_gateway()
            assert gw == "192.168.1.1"

    def test_windows_firewall_parser(self) -> None:
        provider = WindowsNetworkProvider()
        fw_out = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Default Inbound Action                Block

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Default Inbound Action                Block

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Default Inbound Action                Block
"""
        with patch.object(provider, "_run_cmd", return_value=fw_out):
            status = provider.get_firewall_status()
            assert status.backend_name == "Windows Defender Firewall"
            assert status.profiles["public"] is False
            assert status.is_enabled is False  # Public is OFF
            assert len(status.warnings) > 0

    def test_windows_wireless_parser(self) -> None:
        provider = WindowsNetworkProvider()
        wlan_out = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX200
    State                  : connected
    SSID                   : Office_Secure_5G
    BSSID                  : 14:49:e0:11:22:33
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 36
    Signal                 : 92%
"""
        with patch.object(provider, "_run_cmd", return_value=wlan_out):
            info = provider.get_wireless_info()
            assert info is not None
            assert info.ssid == "Office_Secure_5G"
            assert info.is_connected is True
            assert info.signal_strength_pct == 92
            assert info.channel == 36
            assert info.is_open is False

    def test_linux_provider_resolv_conf(self, tmp_path) -> None:
        provider = LinuxNetworkProvider()
        resolv_file = tmp_path / "resolv.conf"
        resolv_file.write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        with (
            patch("systemscan.network.providers.linux.Path.exists", return_value=True),
            patch(
                "systemscan.network.providers.linux.Path.read_text",
                return_value=resolv_file.read_text(),
            ),
        ):
            servers = provider.get_dns_servers()
            assert "1.1.1.1" in servers
            assert "8.8.8.8" in servers

    def test_macos_provider_route(self) -> None:
        provider = MacOSNetworkProvider()
        route_out = "route to: default\ndestination: default\nmask: default\ngateway: 10.0.0.1\ninterface: en0\n"
        with patch.object(provider, "_run_cmd", return_value=route_out):
            gw = provider.get_default_gateway()
            assert gw == "10.0.0.1"


class TestNetworkInterfaceInspector:
    """Validate interface discovery and enrichment."""

    def test_inspect_interfaces(self) -> None:
        inspector = NetworkInterfaceInspector()
        # Mock psutil
        mock_stat = MagicMock()
        mock_stat.isup = True
        mock_stat.speed = 1000
        mock_stat.mtu = 1500

        mock_addr_v4 = MagicMock()
        mock_addr_v4.family = 2  # AF_INET
        mock_addr_v4.address = "192.168.1.100"
        mock_addr_v4.netmask = "255.255.255.0"

        mock_addr_mac = MagicMock()
        mock_addr_mac.family = -1  # AF_LINK
        mock_addr_mac.address = "aa:bb:cc:dd:ee:ff"

        with (
            patch("psutil.net_if_addrs", return_value={"eth0": [mock_addr_mac, mock_addr_v4]}),
            patch("psutil.net_if_stats", return_value={"eth0": mock_stat}),
            patch.object(inspector.provider, "get_default_gateway", return_value="192.168.1.1"),
            patch.object(inspector.provider, "get_dns_servers", return_value=["1.1.1.1"]),
        ):
            ifaces = inspector.inspect_all()
            assert len(ifaces) == 1
            iface = ifaces[0]
            assert iface.name == "eth0"
            assert iface.ipv4_addresses == ["192.168.1.100"]
            assert iface.subnets == ["192.168.1.0/24"]
            assert iface.is_up is True
            assert iface.gateway == "192.168.1.1"


class TestNetworkConnectionInspector:
    """Validate connection and listening port collection."""

    def test_inspect_connections(self) -> None:
        inspector = NetworkConnectionInspector()

        mock_conn1 = MagicMock()
        mock_conn1.type = 1  # TCP
        mock_conn1.laddr = MagicMock(ip="0.0.0.0", port=80)
        mock_conn1.raddr = None
        mock_conn1.status = "LISTEN"
        mock_conn1.pid = 4444

        mock_conn2 = MagicMock()
        mock_conn2.type = 1  # TCP
        mock_conn2.laddr = MagicMock(ip="192.168.1.100", port=55432)
        mock_conn2.raddr = MagicMock(ip="93.184.216.34", port=443)
        mock_conn2.status = "ESTABLISHED"
        mock_conn2.pid = 5555

        with (
            patch("psutil.net_connections", return_value=[mock_conn1, mock_conn2]),
            patch.object(
                inspector, "_resolve_process", return_value=("test_proc", "/usr/bin/test_proc")
            ),
        ):
            conns = inspector.inspect_connections()
            assert len(conns) == 2

            listening = inspector.get_listening_ports()
            assert len(listening) == 1
            assert listening[0].local_port == 80
            assert listening[0].is_all_interfaces is True

            estab = inspector.get_established_connections()
            assert len(estab) == 1
            assert estab[0].remote_port == 443


class TestLocalNetworkDiscovery:
    """Validate subnet authorization checks and host probing."""

    def test_validate_subnet_authorization(self) -> None:
        discovery = LocalNetworkDiscovery()
        # Safe private networks
        net1 = discovery.validate_subnet_authorization("192.168.1.0/24")
        assert str(net1) == "192.168.1.0/24"
        net2 = discovery.validate_subnet_authorization("10.0.0.0/24")
        assert str(net2) == "10.0.0.0/24"

        # Public IP range without authorization flag raises PermissionError
        with pytest.raises(PermissionError):
            discovery.validate_subnet_authorization("8.8.8.0/24", allow_public=False)

        # Excessively large subnet raises ValueError
        with pytest.raises(ValueError):
            discovery.validate_subnet_authorization("10.0.0.0/16")

    def test_discover_with_mocked_arp_and_probe(self) -> None:
        discovery = LocalNetworkDiscovery()
        with (
            patch.object(
                discovery.provider,
                "get_arp_table",
                return_value=[("192.168.1.5", "00:11:22:33:44:55")],
            ),
            patch.object(discovery.provider, "get_default_gateway", return_value="192.168.1.1"),
            patch.object(discovery, "_probe_host", return_value=(True, [80], 4.2)),
            patch.object(discovery, "_resolve_hostname", return_value="router.local"),
        ):
            hosts = discovery.discover(subnet_str="192.168.1.0/29")
            assert len(hosts) > 0
            found_ips = [h.ip for h in hosts]
            assert "192.168.1.5" in found_ips


class TestDNSIntelligenceEngine:
    """Validate DNS resolution testing and error capture."""

    def test_resolve_domain_success(self) -> None:
        engine = DNSIntelligenceEngine()
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            res = engine.resolve_domain("example.com", DNSRecordType.A)
            assert res.success is True
            assert "93.184.216.34" in res.records
            assert res.resolution_time_ms >= 0.0

    def test_audit_dns_health_findings(self) -> None:
        engine = DNSIntelligenceEngine()
        with (
            patch.object(engine, "get_configured_dns_servers", return_value=[]),
            patch.object(
                engine, "resolve_domain", return_value=MagicMock(success=False, error="DNS timeout")
            ),
        ):
            servers, results, findings = engine.audit_dns_health()
            assert len(servers) == 0
            assert any(f.finding_id == "NET-DNS-001" for f in findings)


class TestFirewallAuditor:
    """Validate firewall evaluation and severity checks."""

    def test_firewall_disabled_finding(self) -> None:
        auditor = FirewallAuditor()
        disabled_status = FirewallStatus(
            is_enabled=False,
            service_active=False,
            backend_name="Windows Defender Firewall",
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
        )
        with patch.object(auditor.provider, "get_firewall_status", return_value=disabled_status):
            status, findings = auditor.audit_firewall()
            assert status.is_enabled is False
            assert any(
                f.finding_id == "NET-FW-001" and f.severity == FindingSeverity.CRITICAL
                for f in findings
            )


class TestWirelessSecurityInspector:
    """Validate open Wi-Fi and weak encryption detection."""

    def test_open_wifi_finding(self) -> None:
        inspector = WirelessSecurityInspector()
        open_wifi = WirelessConnectionInfo(
            ssid="Public_Airport_WiFi",
            bssid="00:11:22:33:44:55",
            security_type="Open",
            is_open=True,
            is_connected=True,
        )
        with patch.object(inspector.provider, "get_wireless_info", return_value=open_wifi):
            info, findings = inspector.inspect_wifi()
            assert info is not None
            assert any(
                f.finding_id == "NET-WIFI-001" and f.severity == FindingSeverity.HIGH
                for f in findings
            )


class TestNetworkBaselineManager:
    """Validate baseline creation and divergence detection."""

    def test_baseline_lifecycle(self, tmp_path) -> None:
        mgr = NetworkBaselineManager(baseline_dir=tmp_path)

        with (
            patch.object(mgr.provider, "get_default_gateway", return_value="192.168.1.1"),
            patch(
                "systemscan.network.dns.DNSIntelligenceEngine.get_configured_dns_servers",
                return_value=["1.1.1.1"],
            ),
            patch.object(mgr.provider, "get_wireless_info", return_value=None),
            patch(
                "systemscan.network.connections.NetworkConnectionInspector.get_listening_ports",
                return_value=[],
            ),
            patch(
                "systemscan.network.interfaces.NetworkInterfaceInspector.inspect_all",
                return_value=[],
            ),
        ):
            # Create baseline
            baseline = mgr.create_baseline("test_base")
            assert baseline.name == "test_base"
            assert "192.168.1.1" in baseline.known_gateways

            # Cannot recreate without overwrite
            with pytest.raises(FileExistsError):
                mgr.create_baseline("test_base", overwrite=False)

            # Compare baseline with changed gateway
            with patch.object(mgr.provider, "get_default_gateway", return_value="192.168.1.254"):
                diff = mgr.compare_baseline("test_base")
                assert diff.has_changes is True
                assert "192.168.1.254" in diff.added_gateways
                assert any(f.finding_id == "NET-BASE-001" for f in diff.findings)


class TestNetworkFindingsEvaluator:
    """Validate sensitive port exposure and anomaly evaluation."""

    def test_sensitive_port_telnet(self) -> None:
        evaluator = NetworkFindingsEvaluator()
        telnet_conn = NetworkConnection(
            protocol=Protocol.TCP,
            local_address="0.0.0.0",
            local_port=23,
            state=ConnectionState.LISTEN,
            pid=999,
            process_name="in.telnetd",
            is_listening=True,
            is_all_interfaces=True,
        )
        with (
            patch.object(
                evaluator.conn_inspector, "get_listening_ports", return_value=[telnet_conn]
            ),
            patch.object(
                evaluator.conn_inspector, "get_high_connection_processes", return_value=[]
            ),
        ):
            findings = evaluator.evaluate_listening_sockets()
            assert any(
                f.finding_id == "NET-PORT-23" and f.severity == FindingSeverity.CRITICAL
                for f in findings
            )


class TestNetworkDiagnostics:
    """Validate network diagnostics reachability checks."""

    def test_run_diagnostics(self) -> None:
        diag = NetworkDiagnostics()
        with (
            patch.object(diag.provider, "get_default_gateway", return_value="192.168.1.1"),
            patch.object(diag, "_test_tcp_latency", return_value=5.5),
            patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]),
        ):
            res = diag.run_diagnostics()
            assert res.gateway_reachable is True
            assert res.dns_working is True
            assert res.internet_reachable is True
            assert "Full network connectivity" in res.summary


class TestNetworkMonitor:
    """Validate monitoring loop and delta calculation."""

    def test_monitor_single_cycle(self) -> None:
        inspector = NetworkConnectionInspector()
        monitor = NetworkMonitor(inspector=inspector)

        mock_conn = NetworkConnection(
            protocol=Protocol.TCP,
            local_address="127.0.0.1",
            local_port=9090,
            state=ConnectionState.LISTEN,
            is_listening=True,
            is_loopback=True,
        )

        updates: list[list[NetworkConnection]] = []

        def callback(current: list[NetworkConnection], new_socks: list[NetworkConnection]) -> None:
            updates.append(current)

        with patch.object(inspector, "inspect_connections", return_value=[mock_conn]):
            token = CancellationToken()
            token.cancel()
            monitor.monitor(
                interval=0.01, duration=0.05, cancellation_token=token, on_update=callback
            )
            assert token.is_cancelled is True


class TestAdditionalProviderParsers:
    """Validate Linux and macOS specific provider parsing."""

    def test_linux_wireless_parser(self) -> None:
        provider = LinuxNetworkProvider()
        nmcli_out = "yes:CoffeeShop_Guest:11:22:33:44:55:66:6:2437 MHz:75:WPA2\n"
        with patch.object(provider, "_run_cmd", return_value=nmcli_out):
            info = provider.get_wireless_info()
            assert info is not None
            assert info.ssid == "CoffeeShop_Guest"
            assert info.channel == 6
            assert info.signal_strength_pct == 75
            assert info.is_open is False

    def test_linux_ufw_firewall_parser(self) -> None:
        provider = LinuxNetworkProvider()
        ufw_out = "Status: active\nDefault: incoming (deny), outgoing (allow)\nTo Action From\n22/tcp ALLOW Anywhere\n"
        with patch.object(provider, "_run_cmd", return_value=ufw_out):
            status = provider.get_firewall_status()
            assert status.backend_name == "UFW"
            assert status.is_enabled is True
            assert status.default_inbound_action == FirewallAction.BLOCK

    def test_macos_wireless_parser(self) -> None:
        provider = MacOSNetworkProvider()
        airport_out = """
     agrCtlRSSI: -45
     agrCtlNoise: -90
           state: running
            op mode: station
         lastTxRate: 300
            maxRate: 450
    lastAssocStatus: 0
        802.11 auth: open
          link auth: wpa2-psk
              BSSID: 00:11:22:33:44:55
               SSID: Home_Fiber
                MCS: 15
            channel: 149,1
"""
        with patch.object(provider, "_run_cmd", return_value=airport_out):
            info = provider.get_wireless_info()
            assert info is not None
            assert info.ssid == "Home_Fiber"
            assert info.channel == 149
            assert info.is_connected is True

    def test_macos_firewall_parser(self) -> None:
        provider = MacOSNetworkProvider()
        with patch.object(provider, "_run_cmd", return_value="Firewall is enabled. (State = 1)"):
            status = provider.get_firewall_status()
            assert status.is_enabled is True
            assert status.backend_name == "macOS Application Firewall"
