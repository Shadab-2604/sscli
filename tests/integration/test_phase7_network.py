"""Integration tests for Phase 07: Network Security & Intelligence CLI commands."""

from __future__ import annotations

import json
from unittest.mock import patch

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.network.models import (
    ConnectionState,
    FirewallAction,
    FirewallStatus,
    InterfaceType,
    NetworkConnection,
    NetworkInterfaceDetail,
    Protocol,
    WirelessConnectionInfo,
)

runner = CliRunner()


class TestNetworkCLIIntegration:
    """Verify network commands execute and format properly through Typer runner."""

    def test_cli_network_interfaces(self) -> None:
        mock_iface = NetworkInterfaceDetail(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            mac_address="11:22:33:44:55:66",
            ipv4_addresses=["192.168.1.150"],
            subnets=["192.168.1.0/24"],
            is_up=True,
            speed_mbps=1000,
        )
        with patch(
            "systemscan.network.interfaces.NetworkInterfaceInspector.inspect_all",
            return_value=[mock_iface],
        ):
            # 1. Text format
            res = runner.invoke(app, ["network", "interfaces"], env={"COLUMNS": "160"})
            assert res.exit_code == 0
            assert "eth0" in res.output
            assert "192.168.1.150" in res.output

            # 2. JSON format
            res_json = runner.invoke(app, ["network", "interfaces", "--format", "json"])
            assert res_json.exit_code == 0
            start_idx = res_json.output.find("[")
            assert start_idx != -1
            data = json.loads(res_json.output[start_idx:])
            assert len(data) == 1
            assert data[0]["name"] == "eth0"

    def test_cli_network_connections_and_listening(self) -> None:
        mock_conn = NetworkConnection(
            protocol=Protocol.TCP,
            local_address="0.0.0.0",
            local_port=8080,
            state=ConnectionState.LISTEN,
            pid=123,
            process_name="web_service",
            is_listening=True,
            is_all_interfaces=True,
        )
        with (
            patch(
                "systemscan.network.connections.NetworkConnectionInspector.inspect_connections",
                return_value=[mock_conn],
            ),
            patch(
                "systemscan.network.connections.NetworkConnectionInspector.get_listening_ports",
                return_value=[mock_conn],
            ),
        ):
            res_conn = runner.invoke(app, ["network", "connections"])
            assert res_conn.exit_code == 0
            assert "8080" in res_conn.output

            res_listen = runner.invoke(app, ["network", "listening"])
            assert res_listen.exit_code == 0
            assert "8080" in res_listen.output

    def test_cli_network_firewall(self) -> None:
        mock_fw = FirewallStatus(
            is_enabled=True,
            service_active=True,
            backend_name="Windows Defender Firewall",
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
        )
        with patch(
            "systemscan.network.firewall.FirewallAuditor.audit_firewall", return_value=(mock_fw, [])
        ):
            res = runner.invoke(app, ["network", "firewall"])
            assert res.exit_code == 0
            assert "Windows Defender Firewall" in res.output
            assert "ENABLED" in res.output

    def test_cli_network_wifi(self) -> None:
        mock_wifi = WirelessConnectionInfo(
            ssid="Company_WiFi",
            bssid="11:22:33:44:55:66",
            security_type="WPA2-Personal",
            is_open=False,
            is_weak=False,
            band="5 GHz",
            channel=44,
            signal_strength_pct=88,
            is_connected=True,
        )
        with patch(
            "systemscan.network.wireless.WirelessSecurityInspector.inspect_wifi",
            return_value=(mock_wifi, []),
        ):
            res = runner.invoke(app, ["network", "wifi"])
            assert res.exit_code == 0
            assert "Company_WiFi" in res.output
            assert "WPA2-Personal" in res.output

    def test_cli_network_audit(self) -> None:
        with patch(
            "systemscan.network.findings.NetworkFindingsEvaluator.run_full_audit", return_value=[]
        ):
            res = runner.invoke(app, ["network", "audit"])
            assert res.exit_code == 0
            assert "No network security findings" in res.output
