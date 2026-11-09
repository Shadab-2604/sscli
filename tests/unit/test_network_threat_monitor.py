"""Unit tests for the Network Threat Monitor detection engine, models, and alerts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from systemscan.network_monitor.configuration import NetworkMonitorConfig
from systemscan.network_monitor.detection.engine import NetworkScanDetectionEngine
from systemscan.network_monitor.diagnostics.diagnostics import CaptureDiagnostics
from systemscan.network_monitor.identification.engine import DeviceIdentificationEngine
from systemscan.network_monitor.manager import NetworkThreatMonitorManager
from systemscan.network_monitor.models import (
    AlertSeverity,
    DetectionConfidence,
    NetworkThreatAlert,
    PacketMetadata,
    ScanPattern,
    ScanProtocol,
)
from systemscan.network_monitor.storage.database import NetworkAlertDatabase


def test_tcp_syn_port_scan_detection():
    """Verify detection of Nmap-like TCP SYN scan across multiple destination ports."""
    cfg = NetworkMonitorConfig()
    cfg.thresholds.tcp_port_scan_threshold = 5  # Lower threshold for deterministic unit test
    cfg.thresholds.time_window_seconds = 10.0
    detector = NetworkScanDetectionEngine(config=cfg)

    attacker_ip = "192.168.1.105"
    target_ip = "192.168.1.10"

    alert = None
    for port in range(1, 10):
        pkt = PacketMetadata(
            timestamp=datetime.now(timezone.utc),
            source_ip=attacker_ip,
            destination_ip=target_ip,
            protocol=ScanProtocol.TCP,
            source_port=50000 + port,
            destination_port=port,
            tcp_flags=["SYN"],
        )
        res = detector.process_packet(pkt)
        if res:
            alert = res

    assert alert is not None
    assert alert.pattern == ScanPattern.TCP_SYN_SCAN
    assert alert.source_ip == attacker_ip
    assert alert.destination_ip == target_ip
    assert alert.unique_ports >= 5
    assert alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)


def test_stealth_xmas_scan_detection():
    """Verify detection of TCP Xmas Tree scan (FIN/PSH/URG flags)."""
    cfg = NetworkMonitorConfig()
    detector = NetworkScanDetectionEngine(config=cfg)

    pkt1 = PacketMetadata(
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        protocol=ScanProtocol.TCP,
        destination_port=80,
        tcp_flags=["SYN"],
    )
    pkt2 = PacketMetadata(
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        protocol=ScanProtocol.TCP,
        destination_port=81,
        tcp_flags=["SYN"],
    )
    detector.process_packet(pkt1)
    detector.process_packet(pkt2)

    xmas_pkt = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        protocol=ScanProtocol.TCP,
        source_port=44444,
        destination_port=443,
        tcp_flags=["FIN", "PSH", "URG"],
    )
    alert = detector.process_packet(xmas_pkt)
    assert alert is not None
    assert alert.pattern == ScanPattern.XMAS_SCAN
    assert alert.severity == AlertSeverity.CRITICAL


def test_stealth_null_scan_detection():
    """Verify detection of TCP NULL scan (no control flags set)."""
    cfg = NetworkMonitorConfig()
    detector = NetworkScanDetectionEngine(config=cfg)

    detector.process_packet(
        PacketMetadata(
            source_ip="10.0.0.50",
            destination_ip="10.0.0.1",
            protocol=ScanProtocol.TCP,
            destination_port=80,
            tcp_flags=["SYN"],
        )
    )
    detector.process_packet(
        PacketMetadata(
            source_ip="10.0.0.50",
            destination_ip="10.0.0.1",
            protocol=ScanProtocol.TCP,
            destination_port=81,
            tcp_flags=["SYN"],
        )
    )

    null_pkt = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.50",
        destination_ip="10.0.0.1",
        protocol=ScanProtocol.TCP,
        source_port=33333,
        destination_port=22,
        tcp_flags=[],  # NULL
    )
    alert = detector.process_packet(null_pkt)
    assert alert is not None
    assert alert.pattern == ScanPattern.NULL_SCAN


def test_udp_port_scan_detection():
    """Verify detection of UDP port sweep."""
    cfg = NetworkMonitorConfig()
    cfg.thresholds.udp_port_scan_threshold = 4
    detector = NetworkScanDetectionEngine(config=cfg)

    attacker = "172.16.0.40"
    target = "172.16.0.1"

    alert = None
    for port in [53, 67, 123, 161, 500]:
        pkt = PacketMetadata(
            timestamp=datetime.now(timezone.utc),
            source_ip=attacker,
            destination_ip=target,
            protocol=ScanProtocol.UDP,
            destination_port=port,
        )
        res = detector.process_packet(pkt)
        if res:
            alert = res

    assert alert is not None
    assert alert.pattern == ScanPattern.UDP_PORT_SCAN
    assert alert.unique_ports >= 4


def test_host_discovery_sweep_detection():
    """Verify detection of horizontal subnet host sweep."""
    cfg = NetworkMonitorConfig()
    cfg.thresholds.host_sweep_threshold = 4
    detector = NetworkScanDetectionEngine(config=cfg)

    attacker = "192.168.1.200"
    alert = None
    for host_num in range(1, 8):
        pkt = PacketMetadata(
            timestamp=datetime.now(timezone.utc),
            source_ip=attacker,
            destination_ip=f"192.168.1.{host_num}",
            protocol=ScanProtocol.ICMP,
        )
        res = detector.process_packet(pkt)
        if res:
            alert = res

    assert alert is not None
    assert alert.pattern in (ScanPattern.HOST_DISCOVERY, ScanPattern.NETWORK_SWEEP)
    assert alert.target_count >= 4


def test_alert_sqlite_persistence_and_export(tmp_path: Path):
    """Verify storing alerts in SQLite database and exporting to JSON, CSV, and TXT."""
    db_file = tmp_path / "test_threats.db"
    db = NetworkAlertDatabase(db_path=db_file)

    test_alert = NetworkThreatAlert(
        alert_id="test-001",
        timestamp=datetime.now(timezone.utc),
        severity=AlertSeverity.HIGH,
        confidence=DetectionConfidence.CONFIRMED,
        alert_type="PORT SCAN DETECTED",
        pattern=ScanPattern.TCP_SYN_SCAN,
        source_ip="192.168.1.55",
        source_mac="00:11:22:33:44:55",
        source_hostname="suspicious.lan",
        source_vendor="Acme Security",
        destination_ip="192.168.1.1",
        protocol=ScanProtocol.TCP,
        unique_ports=45,
        evidence="Observed 45 unique destination ports",
    )
    db.save_alert(test_alert)

    loaded = db.list_alerts()
    assert len(loaded) == 1
    assert loaded[0].alert_id == "test-001"
    assert loaded[0].pattern == ScanPattern.TCP_SYN_SCAN

    # Export formats
    json_out = db.export_alerts("json")
    assert "test-001" in json_out
    assert "192.168.1.55" in json_out

    csv_out = db.export_alerts("csv")
    assert "test-001" in csv_out
    assert "TCP SYN Scan" in csv_out

    txt_out = db.export_alerts("txt")
    assert "PORT SCAN DETECTED" in txt_out


def test_device_identification_engine():
    """Verify OUI vendor resolution and device tracking."""
    ident = DeviceIdentificationEngine()
    dev = ident.identify_host(ip="10.0.0.10", mac="08:00:27:12:34:56")
    assert dev.vendor == "Oracle VirtualBox"
    assert dev.mac_address == "08:00:27:12:34:56"
    assert len(ident.get_tracked_devices()) == 1


def test_capture_diagnostics():
    """Verify capture diagnostics runs and returns structured dictionary."""
    diag = CaptureDiagnostics.run_diagnostics()
    assert isinstance(diag, dict)
    assert "os" in diag
    assert "scapy_installed" in diag
    assert "pcap_driver_status" in diag


def test_network_threat_monitor_manager_pipeline(tmp_path: Path):
    """Verify manager orchestrates packet processing, device attribution, and alerts."""
    db_file = tmp_path / "mgr_test.db"
    db = NetworkAlertDatabase(db_path=db_file)
    cfg = NetworkMonitorConfig()
    cfg.thresholds.tcp_port_scan_threshold = 3

    mgr = NetworkThreatMonitorManager(config=cfg, db=db)
    status_report = mgr.get_status_report()
    assert status_report.coverage_summary != ""

    dispatched_alerts = []
    mgr.alert_mgr.register_handler(dispatched_alerts.append)

    # Send packets simulating scan
    for p in range(1, 6):
        pkt = PacketMetadata(
            source_ip="192.168.1.88",
            destination_ip="192.168.1.1",
            source_mac="00:50:56:AA:BB:CC",
            protocol=ScanProtocol.TCP,
            destination_port=p,
            tcp_flags=["SYN"],
        )
        mgr.process_single_packet(pkt)

    assert len(dispatched_alerts) >= 1
    assert dispatched_alerts[0].source_vendor == "VMware"
    assert len(db.list_alerts()) >= 1
