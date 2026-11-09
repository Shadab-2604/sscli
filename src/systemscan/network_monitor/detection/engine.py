"""Multi-protocol sliding-window behavioral scan detection engine."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from systemscan.network_monitor.configuration import NetworkMonitorConfig
from systemscan.network_monitor.models import (
    AlertSeverity,
    DetectionConfidence,
    NetworkThreatAlert,
    PacketMetadata,
    ScanPattern,
    ScanProtocol,
)

logger = logging.getLogger("systemscan.network_monitor.detection")


class NetworkScanDetectionEngine:
    """
    Evaluates packet streams against heuristic behavioral thresholds to detect
    SYN, Connect, UDP, FIN, NULL, Xmas, Host Discovery, and Multi-stage reconnaissance.
    """

    def __init__(self, config: NetworkMonitorConfig | None = None) -> None:
        self.config = config or NetworkMonitorConfig()

        # Sliding window state:
        # src_ip -> list of (timestamp_epoch, dst_ip, dst_port, protocol, flags)
        self._history: dict[str, list[tuple[float, str, int | None, ScanProtocol, list[str]]]] = (
            defaultdict(list)
        )

        # Alert cooldown tracking: (src_ip, pattern_name) -> last_alert_epoch
        self._alert_cooldowns: dict[tuple[str, str], float] = {}

    def process_packet(self, meta: PacketMetadata) -> NetworkThreatAlert | None:
        """Analyze a normalized packet. Returns an alert if a scan threshold is exceeded."""
        src = meta.source_ip
        if not src or src in self.config.trusted_ips or src in ("0.0.0.0", "::"):
            return None

        # Exclude specified ports if configured
        if meta.destination_port and meta.destination_port in self.config.excluded_ports:
            return None

        now = meta.timestamp.timestamp()
        window_sec = self.config.thresholds.time_window_seconds

        # Record packet
        self._history[src].append(
            (now, meta.destination_ip, meta.destination_port, meta.protocol, meta.tcp_flags)
        )

        # Evict records older than sliding window
        cutoff = now - (window_sec * 2.0)
        self._history[src] = [r for r in self._history[src] if r[0] >= cutoff]

        recent = [r for r in self._history[src] if r[0] >= (now - window_sec)]
        if len(recent) < 3:
            return None

        # 1. Check Unusual TCP Flag Probes (FIN, NULL, Xmas)
        flag_alert = self._check_tcp_flag_anomalies(src, recent, meta)
        if flag_alert:
            return flag_alert

        # 2. Check TCP SYN / Connect Port Scan
        tcp_alert = self._check_tcp_port_scan(src, recent, meta)
        if tcp_alert:
            return tcp_alert

        # 3. Check UDP Port Scan
        udp_alert = self._check_udp_port_scan(src, recent, meta)
        if udp_alert:
            return udp_alert

        # 4. Check Host Discovery & Subnet Sweep (ICMP / ARP / Multiple IPs)
        sweep_alert = self._check_host_sweep(src, recent, meta)
        if sweep_alert:
            return sweep_alert

        return None

    def _is_cooling_down(self, src: str, pattern: ScanPattern, now: float) -> bool:
        last = self._alert_cooldowns.get((src, pattern.value), 0.0)
        if now - last < self.config.thresholds.cooldown_seconds:
            return True
        self._alert_cooldowns[(src, pattern.value)] = now
        return False

    def _check_tcp_flag_anomalies(
        self, src: str, recent: list[Any], meta: PacketMetadata
    ) -> NetworkThreatAlert | None:
        now = meta.timestamp.timestamp()
        for _t, dst_ip, port, proto, flags in recent[-5:]:
            if proto != ScanProtocol.TCP:
                continue

            # NULL Scan: no flags set
            if not flags:
                if self._is_cooling_down(src, ScanPattern.NULL_SCAN, now):
                    continue
                return NetworkThreatAlert(
                    severity=AlertSeverity.HIGH,
                    confidence=DetectionConfidence.HIGH,
                    alert_type="STEALTH SCAN DETECTED",
                    pattern=ScanPattern.NULL_SCAN,
                    source_ip=src,
                    source_mac=meta.source_mac,
                    destination_ip=dst_ip,
                    protocol=ScanProtocol.TCP,
                    unique_ports=1,
                    time_window_seconds=self.config.thresholds.time_window_seconds,
                    evidence=f"TCP packet with NULL flags (no control bits) targeting port {port}",
                    capture_source=meta.capture_source,
                    sample_ports=[port] if port else [],
                )

            # FIN Scan: only FIN set
            if flags == ["FIN"]:
                if self._is_cooling_down(src, ScanPattern.FIN_SCAN, now):
                    continue
                return NetworkThreatAlert(
                    severity=AlertSeverity.HIGH,
                    confidence=DetectionConfidence.HIGH,
                    alert_type="STEALTH SCAN DETECTED",
                    pattern=ScanPattern.FIN_SCAN,
                    source_ip=src,
                    source_mac=meta.source_mac,
                    destination_ip=dst_ip,
                    protocol=ScanProtocol.TCP,
                    unique_ports=1,
                    time_window_seconds=self.config.thresholds.time_window_seconds,
                    evidence=f"TCP FIN-only probe without prior connection state targeting port {port}",
                    capture_source=meta.capture_source,
                    sample_ports=[port] if port else [],
                )

            # Xmas Scan: FIN + PSH + URG
            if "FIN" in flags and "PSH" in flags and "URG" in flags:
                if self._is_cooling_down(src, ScanPattern.XMAS_SCAN, now):
                    continue
                return NetworkThreatAlert(
                    severity=AlertSeverity.CRITICAL,
                    confidence=DetectionConfidence.CONFIRMED,
                    alert_type="STEALTH SCAN DETECTED",
                    pattern=ScanPattern.XMAS_SCAN,
                    source_ip=src,
                    source_mac=meta.source_mac,
                    destination_ip=dst_ip,
                    protocol=ScanProtocol.TCP,
                    unique_ports=1,
                    time_window_seconds=self.config.thresholds.time_window_seconds,
                    evidence=f"TCP Xmas Tree probe (FIN+PSH+URG control flags) targeting port {port}",
                    capture_source=meta.capture_source,
                    sample_ports=[port] if port else [],
                )

        return None

    def _check_tcp_port_scan(
        self, src: str, recent: list[Any], meta: PacketMetadata
    ) -> NetworkThreatAlert | None:
        tcp_records = [r for r in recent if r[3] == ScanProtocol.TCP]
        ports = {r[2] for r in tcp_records if r[2] is not None}
        syn_count = sum(1 for r in tcp_records if "SYN" in r[4] and "ACK" not in r[4])

        now = meta.timestamp.timestamp()
        th = self.config.thresholds.tcp_port_scan_threshold

        if len(ports) >= th or syn_count >= self.config.thresholds.syn_anomaly_threshold:
            pattern = (
                ScanPattern.TCP_SYN_SCAN
                if syn_count >= (len(tcp_records) * 0.7)
                else ScanPattern.TCP_CONNECT_SCAN
            )
            if self._is_cooling_down(src, pattern, now):
                return None

            sev = AlertSeverity.CRITICAL if len(ports) >= (th * 2) else AlertSeverity.HIGH
            return NetworkThreatAlert(
                severity=sev,
                confidence=DetectionConfidence.HIGH,
                alert_type="NMAP-LIKE SCAN DETECTED" if syn_count >= th else "PORT SCAN DETECTED",
                pattern=pattern,
                source_ip=src,
                source_mac=meta.source_mac,
                destination_ip=meta.destination_ip,
                protocol=ScanProtocol.TCP,
                unique_ports=len(ports),
                target_count=len({r[1] for r in tcp_records}),
                time_window_seconds=self.config.thresholds.time_window_seconds,
                evidence=f"Observed {len(ports)} unique destination ports probed via {pattern.value} within {self.config.thresholds.time_window_seconds:.0f}s",
                capture_source=meta.capture_source,
                sample_ports=sorted(ports)[:10],
            )
        return None

    def _check_udp_port_scan(
        self, src: str, recent: list[Any], meta: PacketMetadata
    ) -> NetworkThreatAlert | None:
        udp_records = [r for r in recent if r[3] == ScanProtocol.UDP]
        ports = {r[2] for r in udp_records if r[2] is not None}
        now = meta.timestamp.timestamp()
        th = self.config.thresholds.udp_port_scan_threshold

        if len(ports) >= th:
            if self._is_cooling_down(src, ScanPattern.UDP_PORT_SCAN, now):
                return None
            return NetworkThreatAlert(
                severity=AlertSeverity.HIGH,
                confidence=DetectionConfidence.HIGH,
                alert_type="PORT SCAN DETECTED",
                pattern=ScanPattern.UDP_PORT_SCAN,
                source_ip=src,
                source_mac=meta.source_mac,
                destination_ip=meta.destination_ip,
                protocol=ScanProtocol.UDP,
                unique_ports=len(ports),
                target_count=len({r[1] for r in udp_records}),
                time_window_seconds=self.config.thresholds.time_window_seconds,
                evidence=f"Observed {len(ports)} unique UDP destination ports probed within {self.config.thresholds.time_window_seconds:.0f}s",
                capture_source=meta.capture_source,
                sample_ports=sorted(ports)[:10],
            )
        return None

    def _check_host_sweep(
        self, src: str, recent: list[Any], meta: PacketMetadata
    ) -> NetworkThreatAlert | None:
        targets = {r[1] for r in recent if r[1] != src}
        now = meta.timestamp.timestamp()
        th = self.config.thresholds.host_sweep_threshold

        if len(targets) >= th:
            pattern = (
                ScanPattern.NETWORK_SWEEP
                if len(targets) >= (th * 2)
                else ScanPattern.HOST_DISCOVERY
            )
            if self._is_cooling_down(src, pattern, now):
                return None

            proto_summary = meta.protocol
            return NetworkThreatAlert(
                severity=AlertSeverity.HIGH
                if pattern == ScanPattern.NETWORK_SWEEP
                else AlertSeverity.MEDIUM,
                confidence=DetectionConfidence.HIGH,
                alert_type="HOST DISCOVERY DETECTED",
                pattern=pattern,
                source_ip=src,
                source_mac=meta.source_mac,
                destination_ip=f"{len(targets)} subnet hosts",
                protocol=proto_summary,
                unique_ports=len({r[2] for r in recent if r[2] is not None}),
                target_count=len(targets),
                time_window_seconds=self.config.thresholds.time_window_seconds,
                evidence=f"Source host contacted {len(targets)} distinct destination IPs in reconnaissance sweep",
                capture_source=meta.capture_source,
                sample_ports=[],
            )
        return None
