# Network Security Audit & Intelligence Architecture

## 1. Overview & Operational Principles

The Network Security Audit & Network Intelligence Engine provides non-invasive, cross-platform network security auditing and telemetry collection. It operates under strict security boundaries:

- **100% Read-Only Safety**: The engine never modifies firewall rules, DNS resolvers, routing tables, Wi-Fi connections, or adapter configurations.
- **Strict Authorization for Host Discovery**: Local network discovery is confined to RFC 1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or link-local subnets by default. Scanning public IP ranges is prohibited unless explicitly authorized (`--allow-public` and `--yes`).
- **No Exploitation or Brute Forcing**: Probes are limited to standard, non-intrusive TCP handshakes (`connect_ex`) and ARP cache lookups. No vulnerability exploitation, fuzzing, or password cracking is attempted.
- **Credential Protection**: Wi-Fi passwords, pre-shared keys, and sensitive network credentials are never extracted, logged, or exposed.

---

## 2. Platform Architecture & Providers

Operating-system-specific queries are decoupled behind `NetworkPlatformProvider`:

```
                           ┌───────────────────────────┐
                           │  NetworkPlatformProvider  │
                           │     (Abstract Base)       │
                           └─────────────┬─────────────┘
                                         │
            ┌────────────────────────────┼───────────────────────────┐
            │                            │                           │
┌───────────▼────────────┐  ┌────────────▼───────────┐  ┌────────────▼───────────┐
│ WindowsNetworkProvider │  │  LinuxNetworkProvider  │  │  MacOSNetworkProvider  │
│ - netsh advfirewall    │  │ - /proc/net/route, arp │  │ - route, scutil        │
│ - netsh wlan           │  │ - /etc/resolv.conf     │  │ - airport framework    │
│ - route print, arp     │  │ - UFW, nftables        │  │ - socketfilterfw       │
└────────────────────────┘  └────────────────────────┘  └────────────────────────┘
```

---

## 3. Subsystem Breakdown

### 3.1. Interface Telemetry (`interfaces.py`)
- Discovers physical and logical adapters via `psutil.net_if_addrs()` and `psutil.net_if_stats()`.
- Enriches adapters with gateway IP, DNS servers, Wi-Fi SSID, link speeds (Mbps), and MTU.
- Categorizes interfaces into `ETHERNET`, `WIFI`, `LOOPBACK`, `VPN`, `VIRTUAL`, and `BRIDGE`.
- Computes CIDR subnets using Python's standard `ipaddress` library.

### 3.2. Active Connection & Socket Inspection (`connections.py`)
- Enumerates active sockets via `psutil.net_connections(kind="inet")`.
- Identifies listening ports bound to all interfaces (`0.0.0.0` or `::`) vs local loopback (`127.0.0.1` or `::1`).
- Resolves owning process ID, binary name, and executable path with memory caching.
- Flags connection count anomalies (processes holding >60 active sockets).

### 3.3. Local Network Discovery (`discovery.py`)
- Automatically infers the local subnet from the active default gateway interface.
- Queries kernel ARP cache (`arp -a` / `/proc/net/arp`) for passive discovery.
- Executes bounded TCP connect probes across standard safe ports (80, 443, 22, 445, 139, 53) using a worker pool (`ThreadPoolExecutor`).
- Conducts reverse DNS hostname lookups.

### 3.4. DNS Intelligence (`dns.py`)
- Discovers configured DNS resolver servers.
- Resolves `A`, `AAAA`, and `PTR` records with latency measurement.
- Supports optional `dnspython` integration for `MX`, `NS`, `TXT`, and `CNAME` records.
- Identifies unconfigured DNS, resolution failures, and high-latency resolvers (>1500ms).

### 3.5. Firewall Security Posture (`firewall.py`)
- Inspects Windows Defender Firewall profiles (Domain, Private, Public).
- Inspects Linux UFW, firewalld, nftables, and packet filter status.
- Inspects macOS Application Firewall (`socketfilterfw`).
- Flags disabled protection, inactive profiles, or permissive default inbound policies.

### 3.6. Wi-Fi Security Assessment (`wireless.py`)
- Inspects active Wi-Fi connection parameters (SSID, BSSID, authentication protocol, channel, band, signal strength).
- Detects unencrypted open networks and deprecated weak protocols (WEP, WPA-TKIP).
- Never captures or stores Wi-Fi keys.

### 3.7. Baseline & Drift Detection (`baseline.py`)
- Captures snapshots of known authorized interfaces, default gateways, DNS servers, Wi-Fi SSIDs, and listening ports.
- Persists versioned JSON baselines in `AppPaths.data_dir / "network_baselines"`.
- Performs drift comparisons to flag unexpected gateway switches (rogue DHCP/ARP spoofing) or unauthorized listening ports.

