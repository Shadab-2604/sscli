# SSCLI Network Threat Monitor System Architecture

## Architecture Overview

The **Network Threat Monitor** follows an asynchronous event-driven, producer-consumer architecture. It separates packet ingestion, protocol decoding, behavioral correlation, attribution enrichment, and alert dispatching into decoupled modules.

```mermaid
flowchart TD
    subgraph Ingestion ["1. Packet Ingestion Layer"]
        A1["Local PCAP Provider (Scapy / Npcap / libpcap)"]
        A2["Network Sensor Provider (Remote Mirror / Router API)"]
    end

    subgraph Broker ["2. Event Bus Broker"]
        B1["Thread-Safe Bounded Queue"]
        B2["Topic: packet.observed"]
        B3["Topic: threat.alert"]
    end

    subgraph Correlation ["3. Behavioral Detection Engine"]
        C1["Sliding Time Window Manager"]
        C2["TCP Flag & Protocol Analyzers"]
        C3["Port & Host Sweep Trackers"]
        C4["Alert Cooldown Suppressor"]
    end

    subgraph Attribution ["4. Device Attribution Engine"]
        D1["ARP Cache Inspector"]
        D2["Reverse DNS Resolver"]
        D3["IEEE MAC OUI Vendor Resolver"]
    end

    subgraph Presentation ["5. Alerts & Persistence Layer"]
        E1["Rich Terminal Cyber Alert Formatter"]
        E2["SQLite Database Engine (threat_alerts)"]
        E3["Export Utilities (JSON / CSV / TXT)"]
    end

    A1 -->|Normalized PacketMetadata| B1
    A2 -->|Normalized PacketMetadata| B1
    B1 --> B2
    B2 --> C1
    C1 --> C2
    C2 --> C3
    C3 --> C4
    C4 -->|New Threat Detected| D1
    D1 --> D2
    D2 --> D3
    D3 -->|Enriched Alert| B3
    B3 --> E1
    B3 --> E2
    E2 --> E3
```

---

## Component Specifications

### 1. Ingestion Layer (`systemscan.network_monitor.capture`)
- **`BaseCaptureProvider`:** Abstract base class defining lifecycle methods (`start_capture()`, `stop_capture()`, `get_health_status()`).
- **`PcapCaptureProvider`:** Wraps Scapy/libpcap/Npcap. Extracts layer 2/3/4 fields and encapsulates into a strongly-typed `PacketMetadata` data class.
- **`NetworkSensorCaptureEngine`:** Manages external sensors, mirrored interfaces, or router APIs. Truthfully degrades to `SensorHealthStatus.UNCONFIGURED` if no remote endpoint is provided.

### 2. Event Bus Broker (`systemscan.network_monitor.event_bus`)
- Decouples capture threads from detection and I/O.
- Implements thread-safe pub/sub with a bounded queue (`maxsize=10000`) to prevent memory exhaustion under high-throughput traffic spikes.

### 3. Behavioral Detection Engine (`systemscan.network_monitor.detection`)
- **`NetworkScanDetectionEngine`:** Maintains per-source sliding time windows.
- Tracks unique destination ports contacted per IP.
- Detects stealth patterns:
  - Null scans (flags `0x00`)
  - FIN scans (only `FIN`)
  - Xmas scans (`FIN + PSH + URG`)
- Suppresses repetitive alert notifications via `_alert_cooldowns` dictionary.

### 4. Device Attribution Engine (`systemscan.network_monitor.identification`)
- **`DeviceIdentificationEngine`:** Resolves hardware identities for IP addresses.
- Correlates IP to MAC using local OS ARP tables (`arp -a` / `/proc/net/arp` / `ip neighbor`).
- Resolves hostnames via local DNS / reverse DNS lookup.
- Maps MAC prefixes to hardware manufacturer vendors using IEEE OUI databases.

### 5. Persistence Layer (`systemscan.network_monitor.storage`)
- **`NetworkAlertDatabase`:** Persists alerts to an SQLite database located in the user's application data directory (`threat_alerts` table).
- Provides filtering, listing, and structured export to JSON, CSV, and formatted text.

