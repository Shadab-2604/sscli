"""Scapy and libpcap / Npcap packet capture provider."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from threading import Event, Thread
from typing import Any

from systemscan.network_monitor.capture.base import BaseCaptureProvider
from systemscan.network_monitor.models import (
    CaptureSourceType,
    PacketMetadata,
    ScanProtocol,
    SensorHealthStatus,
)

logger = logging.getLogger("systemscan.network_monitor.pcap")


class PcapCaptureProvider(BaseCaptureProvider):
    """Captures and normalizes packets via Scapy/libpcap/Npcap."""

    def __init__(self, interface: str | None = None) -> None:
        self.interface = interface
        self._running = False
        self._stop_event = Event()
        self._worker_thread: Thread | None = None
        self._callback: Callable[[PacketMetadata], None] | None = None
        self._packet_count = 0
        self._error_msg = ""
        self._health = SensorHealthStatus.UNCONFIGURED

    @property
    def source_type(self) -> CaptureSourceType:
        return CaptureSourceType.LOCAL

    def get_interface_name(self) -> str:
        return self.interface or "Auto-selected interface"

    def get_health_status(self) -> tuple[SensorHealthStatus, str]:
        if self._running:
            return (
                SensorHealthStatus.HEALTHY,
                f"Active capturing on {self.get_interface_name()} ({self._packet_count} packets processed)",
            )
        if self._error_msg:
            return SensorHealthStatus.ERROR, self._error_msg
        return SensorHealthStatus.UNCONFIGURED, "Capture provider stopped or uninitialized"

    def start_capture(self, callback: Callable[[PacketMetadata], None]) -> bool:
        self._callback = callback
        self._stop_event.clear()
        self._error_msg = ""

        try:
            from scapy.all import sniff
        except ImportError:
            self._error_msg = "Scapy dependency missing. Install with 'pip install scapy'."
            self._health = SensorHealthStatus.ERROR
            logger.warning(self._error_msg)
            return False

        def _sniff_target() -> None:
            self._running = True
            self._health = SensorHealthStatus.HEALTHY
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_scapy_packet,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    store=False,
                )
            except Exception as e:
                err_str = str(e)
                if (
                    "winpcap is not installed" in err_str.lower()
                    or "no libpcap provider" in err_str.lower()
                ):
                    err_str = (
                        "Npcap packet capture driver is not installed on Windows. "
                        "Install Npcap via 'winget install Insecure.Npcap' or from https://npcap.com "
                        "(select 'Install Npcap in WinPcap API-compatible Mode')."
                    )
                self._error_msg = err_str
                self._health = SensorHealthStatus.ERROR
                logger.debug(f"Pcap sniffing encountered error: {e}")
            finally:
                self._running = False

        self._worker_thread = Thread(target=_sniff_target, daemon=True, name="ScapyCaptureWorker")
        self._worker_thread.start()
        return True

    def stop_capture(self) -> None:
        self._stop_event.set()
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)
            self._worker_thread = None

    def _process_scapy_packet(self, pkt: Any) -> None:
        if not self._callback:
            return

        self._packet_count += 1
        meta = PacketMetadata(
            timestamp=datetime.now(timezone.utc),
            interface=self.get_interface_name(),
            capture_source=CaptureSourceType.LOCAL,
            packet_length=len(pkt),
        )

        # Link Layer
        if pkt.haslayer("Ether"):
            eth = pkt.getlayer("Ether")
            meta.source_mac = getattr(eth, "src", None)
            meta.destination_mac = getattr(eth, "dst", None)

        # Network Layer
        if pkt.haslayer("IP"):
            ip = pkt.getlayer("IP")
            meta.source_ip = ip.src
            meta.destination_ip = ip.dst
        elif pkt.haslayer("IPv6"):
            ip6 = pkt.getlayer("IPv6")
            meta.source_ip = ip6.src
            meta.destination_ip = ip6.dst
        elif pkt.haslayer("ARP"):
            arp = pkt.getlayer("ARP")
            meta.protocol = ScanProtocol.ARP
            meta.source_ip = arp.psrc
            meta.destination_ip = arp.pdst
            meta.source_mac = arp.hwsrc
            meta.destination_mac = arp.hwdst
            self._callback(meta)
            return
        else:
            return

        # Transport Layer
        if pkt.haslayer("TCP"):
            tcp = pkt.getlayer("TCP")
            meta.protocol = ScanProtocol.TCP
            meta.source_port = tcp.sport
            meta.destination_port = tcp.dport
            # Flags (S, A, F, R, P, U)
            flags_str = str(tcp.flags)
            flags_list = []
            if "S" in flags_str:
                flags_list.append("SYN")
            if "A" in flags_str:
                flags_list.append("ACK")
            if "F" in flags_str:
                flags_list.append("FIN")
            if "R" in flags_str:
                flags_list.append("RST")
            if "P" in flags_str:
                flags_list.append("PSH")
            if "U" in flags_str:
                flags_list.append("URG")
            meta.tcp_flags = flags_list

        elif pkt.haslayer("UDP"):
            udp = pkt.getlayer("UDP")
            meta.protocol = ScanProtocol.UDP
            meta.source_port = udp.sport
            meta.destination_port = udp.dport

        elif (
            pkt.haslayer("ICMP")
            or pkt.haslayer("ICMPv6EchoRequest")
            or pkt.haslayer("ICMPv6EchoReply")
        ):
            meta.protocol = ScanProtocol.ICMP

        self._callback(meta)
