# SSCLI Network Threat Monitor Troubleshooting Guide

This guide addresses common errors encountered when configuring or running the **Network Threat Monitor**.

---

## 1. Windows: "Sniffing and sending packets is not available at layer 2: winpcap is not installed"

### Cause
On Windows, Scapy requires the **Npcap** packet capture driver to capture packets at Layer 2 (Ethernet). Without Npcap, Windows does not allow user-space applications to intercept raw network traffic.

### Solution
1. Open PowerShell or Command Prompt as **Administrator**.
2. Run:
   ```powershell
   winget install Insecure.Npcap
   ```
   *Or download the installer from [npcap.com](https://npcap.com/#download).*
3. In the installer, ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked.
4. Re-run SSCLI diagnostics to confirm:
   ```bash
   systemscan network-monitor diagnostics
   ```

---

## 2. Linux: "Permission denied" or "Operation not permitted"

### Cause
Raw socket creation on Linux requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities, which are restricted to `root` or specially privileged binaries.

### Solution
Either execute SSCLI with `sudo`:
```bash
sudo systemscan network-monitor
```
Or grant the Python binary non-root raw capture capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

---

## 3. macOS: "Operation not permitted" on `/dev/bpf*`

### Cause
On macOS, Berkeley Packet Filters (`/dev/bpf0`, `/dev/bpf1`, etc.) are protected system devices accessible only by `root` or members of the `access_bpf` group.

### Solution
Run with `sudo`:
```bash
sudo systemscan network-monitor
```

---

## 4. No Packets Captured on Multi-Interface Systems

### Cause
When the host has multiple physical or virtual network adapters (e.g. Wi-Fi, Ethernet, WSL virtual switch, VPN adapters), auto-selection may bind to an inactive adapter.

### Solution
List active network interfaces using SSCLI:
```bash
systemscan network status
```
Then explicitly bind the Threat Monitor to your active adapter:
```bash
systemscan network-monitor --interface "Wi-Fi"
```
Or in Linux:
```bash
sudo systemscan network-monitor --interface eth0
```

---

## 5. False Positives During High-Throughput Web Browsing or Torrenting

### Cause
Torrent clients or aggressive browser prefetching can open dozens of simultaneous outgoing TCP connections, triggering low threshold limits.

### Solution
Switch the detection engine to `LOW` sensitivity:
```bash
systemscan network-monitor --sensitivity low
```
Or adjust thresholds in your configuration:
```bash
systemscan config set network_monitor.sensitivity low
```

