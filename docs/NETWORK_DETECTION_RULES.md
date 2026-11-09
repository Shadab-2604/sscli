# SSCLI Network Threat Monitor Detection Rules & Behavioral Analysis

## Detection Philosophy

Traditional intrusion detection tools often flood terminal consoles with noise or log every single packet. SSCLI's **Network Threat Monitor** is designed with the following principles:

1. **Passive Observation Only:** No active probes, ARP spoofing, DNS poisoning, or packet injection.
2. **Behavior-Based Correlation:** Scans are identified across temporal sliding windows rather than single isolated packets.
3. **Threshold Calibration:** Legitimate network traffic (such as web browsing across multiple connections) is filtered through connection state tracking and frequency thresholds.
4. **Alert Cooldowns:** Duplicate alerts from continuous scans are suppressed by a configurable cooldown period (default: 60s per attacker IP / pattern pair).

---

## Sensitivity Profiles

SSCLI provides three pre-tuned sensitivity profiles:

| Profile | TCP Port Threshold | UDP Port Threshold | Time Window | Host Sweep Threshold | Best Used For |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`LOW`** | 50 ports | 60 ports | 15.0s | 15 hosts | High-traffic office networks, download stations |
| **`BALANCED`** *(Default)* | 20 ports | 25 ports | 10.0s | 8 hosts | Daily laptop workstations, home networks |
| **`HIGH`** | 8 ports | 10 ports | 5.0s | 4 hosts | High-security servers, lab testing, CTFs |

---

## Rule Definitions

### 1. `RULE-SCAN-01`: TCP SYN Stealth Scan (Nmap `-sS`)
- **Trigger:** A single remote IP transmits TCP packets with only the `SYN` flag enabled to multiple destination ports on a host within the active time window.
- **Severity:** `HIGH`
- **Confidence:** `HIGH`
- **Mitigation Advice:** Verify host firewall rules. Drop unsolicited incoming SYN packets on unmapped ports.

### 2. `RULE-SCAN-02`: TCP Full Connect Scan (Nmap `-sT`)
- **Trigger:** Rapid sequential TCP handshakes across non-consecutive destination ports from a single IP.
- **Severity:** `HIGH`
- **Confidence:** `HIGH`
- **Mitigation Advice:** Check application logs for connection attempts from source IP.

### 3. `RULE-SCAN-03`: UDP Port Sweep (Nmap `-sU`)
- **Trigger:** Multiple UDP datagrams sent across distinct target ports within the sliding window.
- **Severity:** `MEDIUM`
- **Confidence:** `MEDIUM`
- **Mitigation Advice:** Verify if benign multicast/broadcast discovery services (mDNS, SSDP) are active.

### 4. `RULE-SCAN-04`: TCP NULL Scan (Nmap `-sN`)
- **Trigger:** A TCP packet received with flags set to `0x00` (no flags set).
- **Severity:** `CRITICAL`
- **Confidence:** `CONFIRMED`
- **Rationale:** Legitimate TCP stacks never send zero-flag packets; this pattern specifically exploits RFC 793 handling in Unix kernels.

### 5. `RULE-SCAN-05`: TCP FIN Scan (Nmap `-sF`)
- **Trigger:** A TCP packet containing only the `FIN` flag sent to a closed or untracked port.
- **Severity:** `CRITICAL`
- **Confidence:** `CONFIRMED`
- **Rationale:** Used to bypass stateless firewalls and packet filters that only check for SYN packets.

### 6. `RULE-SCAN-06`: TCP Xmas Tree Scan (Nmap `-sX`)
- **Trigger:** A TCP packet containing `FIN`, `PSH`, and `URG` flags set simultaneously.
- **Severity:** `CRITICAL`
- **Confidence:** `CONFIRMED`
- **Rationale:** Classic reconnaissance signature designed to elicit RST responses from open/closed ports.

### 7. `RULE-SCAN-07`: Horizontal Subnet Sweep (Nmap `-sn` / Ping Sweeps)
- **Trigger:** A single IP sending probe packets to identical ports across multiple destination hosts in the local subnet.
- **Severity:** `HIGH`
- **Confidence:** `HIGH`
- **Mitigation Advice:** Isolate the source host from the VLAN; host is actively mapping network topology.

