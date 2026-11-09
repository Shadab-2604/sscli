# SSCLI Network Threat Monitor Installation & Driver Setup Guide

This guide details how to configure raw packet capture dependencies across all supported operating systems for SSCLI's **Network Threat Monitor**.

---

## 1. Windows 10 & 11

On Windows, user-space raw packet sniffing requires the **Npcap** kernel driver.

### Quick Install via winget (Recommended)
Open an **Administrator PowerShell** prompt and execute:
```powershell
winget install Insecure.Npcap
```

### Manual Install via Installer
1. Download the official installer from [npcap.com](https://npcap.com/#download).
2. Run the installer with administrative privileges.
3. During setup, **ensure the following options are checked**:
   - [x] **Install Npcap in WinPcap API-compatible Mode** *(Required for Scapy integration)*
   - [x] **Support raw 802.11 traffic (and monitor mode) for wireless adapters** *(Optional)*
4. Complete installation. No system reboot is typically required.

### Verification
Run SSCLI diagnostic tool:
```bash
systemscan network-monitor diagnostics
```
You should see:
```
Packet Capture Driver: Installed (Npcap / WinPcap)
Local Capture Capability: READY
```

---

## 2. Linux (Kali, Ubuntu, Debian, Fedora, Arch)

On Linux distributions, SSCLI relies on standard `libpcap` and Linux raw socket capabilities.

### Kali Linux, Debian, Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev python3-scapy
```

### Fedora, RHEL
```bash
sudo dnf install -y libpcap-devel python3-scapy
```

### Arch Linux
```bash
sudo pacman -S libpcap python-scapy
```

### Non-Root Packet Capture Capabilities
To allow SSCLI to sniff packets without executing as `root`:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```
Alternatively, execute with `sudo`:
```bash
sudo systemscan network-monitor
```

---

## 3. macOS (Intel & Apple Silicon)

macOS uses Berkeley Packet Filters (`/dev/bpf*`) for packet capture.

### Prerequisites
1. Ensure Xcode Command Line Tools are installed:
   ```bash
   xcode-select --install
   ```
2. Verify BPF device access:
   ```bash
   ls -l /dev/bpf*
   ```
3. Execute SSCLI with superuser permissions to access `/dev/bpf`:
   ```bash
   sudo systemscan network-monitor
   ```

---

## 4. Android (Termux & Kali NetHunter)

### Termux (Rooted)
Raw packet capture requires root access on Android:
```bash
# Switch to root
su

# Ensure libpcap and python dependencies are installed
pkg update && pkg install -y libpcap python tsu
pip install scapy

# Start SSCLI threat monitor
tsu -c "systemscan network-monitor"
```

### Kali NetHunter
In the NetHunter Chroot environment:
```bash
sudo apt update && sudo apt install -y libpcap-dev python3-scapy
sudo systemscan network-monitor
```

