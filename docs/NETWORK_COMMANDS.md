# Network Module CLI Command Reference

This document provides complete syntax, arguments, options, and sample execution outputs for the `systemscan network` command group.

---

## 1. Subcommands Overview

| Command | Purpose | Key Flags |
| :--- | :--- | :--- |
| `systemscan network interfaces` | Inspect network interfaces, addressing, and link speeds | `--format text\|json` |
| `systemscan network connections` | Inspect active TCP/UDP sockets and owning processes | `--state`, `--format text\|json` |
| `systemscan network listening` | Audit incoming listening ports and global exposures | `--all-interfaces`, `--format text\|json` |
| `systemscan network discover` | Discover reachable hosts on local authorized subnet | `--subnet`, `--timeout`, `--allow-public`, `--yes` |
| `systemscan network dns` | Audit DNS server configuration and test resolution | `--domain`, `--type`, `--format text\|json` |
| `systemscan network firewall` | Inspect host firewall posture, profiles, and rules | `--format text\|json` |
| `systemscan network wifi` | Inspect active Wi-Fi connection and security protocols | `--format text\|json` |
| `systemscan network diagnostics` | Measure gateway, DNS, and internet connectivity | `--target`, `--format text\|json` |
| `systemscan network audit` | Execute full comprehensive network security audit | `--format text\|json` |
| `systemscan network monitor` | Monitor socket transitions and new ports in real time | `--interval`, `--duration` |
| `systemscan network baseline create` | Save current network state as a persistent baseline | `--name`, `--overwrite` |
| `systemscan network baseline compare` | Compare active network state against baseline | `--name`, `--format text\|json` |
| `systemscan network baseline list` | List all saved network baseline profiles | None |

---

## 2. Command Details & Examples

### 2.1. Inspect Network Interfaces
```bash
# Terminal table output
systemscan network interfaces

# Structured JSON output
systemscan network interfaces --format json
```

### 2.2. Inspect Active Connections & Listening Sockets
```bash
# All active sockets
systemscan network connections

# Filter by state
systemscan network connections --state ESTABLISHED
systemscan network connections --state LISTEN

# Listening ports bound to all interfaces (0.0.0.0 / ::)
systemscan network listening --all-interfaces
```

### 2.3. Safe Local Subnet Discovery
```bash
# Inferred local subnet
systemscan network discover

# Explicit private CIDR subnet
systemscan network discover --subnet 192.168.1.0/24 --timeout 0.25 --yes
```

### 2.4. DNS Intelligence & Resolution Testing
```bash
# Default resolution test
systemscan network dns

# Custom domain and record type
systemscan network dns --domain cloudflare.com --type A
```

### 2.5. Firewall Posture Inspection
```bash
systemscan network firewall
```

### 2.6. Wi-Fi Security Inspection
```bash
systemscan network wifi
```

### 2.7. Network Connectivity Diagnostics
```bash
systemscan network diagnostics --target 1.1.1.1
```

### 2.8. Comprehensive Network Security Audit
```bash
# Synthesize all checks and findings
systemscan network audit
```

### 2.9. Real-Time Socket Monitor
```bash
# Monitor for 30 seconds with 2-second polling intervals
systemscan network monitor --interval 2.0 --duration 30
```

### 2.10. Network Baseline Management
```bash
# Create baseline snapshot
systemscan network baseline create --name office-lan

# Compare active state to establish baseline drift
systemscan network baseline compare --name office-lan

# List saved baseline profiles
systemscan network baseline list
```

