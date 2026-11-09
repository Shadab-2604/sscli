# SSCLI Network Threat Monitor

## Overview

The **Network Threat Monitor** (`systemscan network-monitor` / `systemscan threat-monitor`) is a dual-mode, passive behavioral reconnaissance detection engine built into the Universal System Security & Intelligence Scanner (`sscli`).

It is engineered to detect adversarial reconnaissance campaigns, such as Nmap port scans, connect scans, UDP sweeps, FIN/NULL/Xmas stealth probes, and horizontal host discovery scans targeting or originating from the monitored host.

```
+-----------------------------------------------------------------------------+
|                               SSCLI ENGINE                                  |
|                                                                             |
|  +----------------------+                      +-------------------------+  |
|  |     Mode A (Local)   |                      | Mode B (Network-Wide)   |  |
|  |   Laptop Traffic     |                      | Dedicated LAN Sensor    |  |
|  +----------+-----------+                      +------------+------------+  |
|             |                                               |               |
|             +-----------------------+-----------------------+               |
|                                     |                                       |
|                                     v                                       |
|                         [ Normalized Event Bus ]                            |
|                                     |                                       |
|                                     v                                       |
|                        [ Behavioral Scan Detector ]                         |
|                     (Sliding Window & Cooldown Engine)                      |
|                                     |                                       |
|                                     v                                       |
|                       [ Device Attribution Engine ]                         |
|                    (ARP Cache + Reverse DNS + IEEE OUI)                     |
|                                     |                                       |
|                                     v                                       |
|                            [ Threat Dispatcher ]                            |
|                       +-------------+-------------+                         |
|                       v                           v                         |
|               Rich Terminal Alert         SQLite Storage Engine             |
+-----------------------------------------------------------------------------+
```

---

## Operating Modes

### Mode A: Local Laptop Monitor
- **Target:** Traffic visible to the host running SSCLI.
- **Capabilities:**
  - Detects incoming port scans targeting host network interfaces.
  - Detects outbound scanning activities originating from local processes.
  - Inspects TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`) and UDP datagrams.
  - Extracts source IP, destination IP, target ports, and timestamps.
  - Identifies stealth techniques (NULL scans, FIN scans, Xmas Tree scans).

### Mode B: Network-Wide LAN Sensor
- **Target:** Broad subnet visibility via dedicated hardware sensors or router integration.
- **Capabilities:**
  - Ingests traffic mirrored from managed switches (SPAN/port mirroring) or gateway router APIs.
  - Monitors inter-device reconnaissance and lateral movement attempts.
  - Reports coverage truthfully: if no remote sensor URL or router is configured, it falls back to **Local-Only** and transparently reports that network-wide visibility is inactive.

### Mode C: Combined Dual-Mode (Default)
- Concurrently runs local interface capture alongside configured network sensors, normalizing packets into the unified event bus.

---

## Command Reference

### 1. Interactive Submenu
Navigate to **Option 7** in the interactive menu or run:
```bash
systemscan dashboard
```

### 2. Standalone CLI Commands

#### Start Live Threat Monitor
```bash
# Continuous monitoring on default interface
systemscan network-monitor

# Monitor for 60 seconds with High sensitivity
systemscan network-monitor --duration 60 --sensitivity high

# Bind to a specific network interface
systemscan network-monitor --interface "Wi-Fi" --mode local
```

#### Sensor Operational Status & Coverage
Inspect driver availability, active interfaces, and truthful coverage posture:
```bash
systemscan network-monitor status
```

#### Driver & Permission Diagnostics
Audit packet capture dependencies, admin privileges, and Npcap/libpcap health:
```bash
systemscan network-monitor diagnostics
```

#### Historical Threat Alerts
Inspect previously logged threat alerts stored in SQLite:
```bash
# View last 20 detected alerts
systemscan network-monitor alerts --limit 20

# Export detected threats to JSON
systemscan network-monitor alerts --export-json threats.json

# Export detected threats to CSV
systemscan network-monitor alerts --export-csv threats.csv
```

#### Known Devices & Hardware Attribution
Display all observed devices with resolved MAC vendors and hostnames:
```bash
systemscan network-monitor devices
```

---

## Threat Classification Matrix

| Pattern | Detection Criteria | Default Severity |
| :--- | :--- | :--- |
| **TCP SYN Stealth Scan** | Repeated SYN packets to distinct destination ports without ACK completion | `HIGH` |
| **TCP Full Connect Scan** | Rapid full TCP handshakes targeting closed/open ports across threshold | `HIGH` |
| **UDP Port Sweep** | Multiple zero-payload UDP probes to uncommon service ports | `MEDIUM` |
| **NULL Stealth Scan** | TCP packets with zero flags (`0x00`) designed to bypass stateful firewalls | `CRITICAL` |
| **FIN Stealth Scan** | TCP packets with only the `FIN` flag set without an established connection | `CRITICAL` |
| **Xmas Tree Probe** | TCP packets with `FIN + PSH + URG` flags lit like a Christmas tree | `CRITICAL` |
| **Horizontal Subnet Sweep** | Single source querying identical ports across multiple destination hosts | `HIGH` |

