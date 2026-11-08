# Network Security Findings Catalog & Rules Reference

The Network Security Audit Engine classifies observations into standardized, evidence-based findings. Each finding includes a unique identifier, category, calibrated severity, confidence rating, evidence string, affected target, and actionable remediation guidance.

---

## 1. Findings Taxonomy

### Severity Levels
- **`CRITICAL`**: Immediate threat of unauthorized access or critical exposure (e.g. host firewall disabled, cleartext remote administration exposed globally).
- **`HIGH`**: Significant vulnerability or insecure protocol (e.g. connected to open Wi-Fi, default inbound firewall rule set to ALLOW, default gateway divergence).
- **`MEDIUM`**: Potential configuration weakness or anomaly (e.g. DNS resolution failure, socket connection count anomaly, new listening ports).
- **`LOW`**: Informational concern or degraded performance (e.g. degraded Wi-Fi signal, high DNS resolution latency).
- **`INFO`**: Diagnostic observation.

### Confidence Levels
- **`CONFIRMED`**: Direct, unambiguous factual verification from operating system APIs or kernel state.
- **`HIGH`**: Reliable programmatic observation backed by multiple corroborating data points.
- **`MEDIUM`**: Heuristic or threshold-based observation.
- **`LOW`**: Inconclusive telemetry requiring administrator confirmation.

---

## 2. Standard Network Finding Rules

| Rule ID | Category | Severity | Confidence | Title & Description | Remediation |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **`NET-FW-001`** | `FIREWALL` | `CRITICAL` | `CONFIRMED` | **Host Firewall is Disabled**: Host firewall protection is turned off or inactive across profiles. | Enable host firewall protection immediately. |
| **`NET-FW-002`** | `FIREWALL` | `HIGH` | `HIGH` | **Permissive Default Inbound Firewall Policy**: Firewall default inbound action allows unsolicited traffic. | Configure default inbound policy to BLOCK/DROP. |
| **`NET-FW-003`** | `FIREWALL` | `HIGH` | `HIGH` | **Firewall Profile Inactive**: A specific profile (Domain, Private, Public) is disabled. | Enable all active profiles. |
| **`NET-WIFI-001`** | `WIFI_SECURITY` | `HIGH` | `CONFIRMED` | **Connected to Open Unencrypted Wi-Fi**: Active connection transmits data without encryption. | Disconnect or use a trusted VPN tunnel. |
| **`NET-WIFI-002`** | `WIFI_SECURITY` | `HIGH` | `CONFIRMED` | **Deprecated Wi-Fi Encryption Protocol**: Access point uses vulnerable WEP or WPA-TKIP. | Upgrade access point to WPA2-AES or WPA3. |
| **`NET-WIFI-003`** | `WIFI_SECURITY` | `LOW` | `HIGH` | **Degraded Wireless Signal Strength**: Signal strength < 25%, risking packet loss. | Relocate closer to access point. |
| **`NET-DNS-001`** | `DNS` | `HIGH` | `CONFIRMED` | **No DNS Servers Configured**: Host interfaces have no active DNS resolvers assigned. | Assign valid internal or trusted public resolvers. |
| **`NET-DNS-002`** | `DNS` | `MEDIUM` | `HIGH` | **DNS Resolution Failure**: Standard domain lookups fail to resolve. | Verify network and DNS reachability. |
| **`NET-DNS-003`** | `DNS` | `LOW` | `MEDIUM` | **Degraded DNS Resolution Latency**: Resolution latency exceeds 1500ms. | Switch to closer or lower-latency resolvers. |
| **`NET-PORT-23`** | `EXPOSED_SERVICE` | `CRITICAL` | `CONFIRMED` | **Telnet Exposed Globally**: Cleartext remote administration protocol listening on 0.0.0.0. | Replace Telnet with SSH (Port 22). |
| **`NET-PORT-3389`** | `EXPOSED_SERVICE` | `HIGH` | `CONFIRMED` | **RDP Exposed Globally**: Remote Desktop Protocol listening on all network interfaces. | Bind to local subnet or restrict via firewall. |
| **`NET-PORT-5900`** | `EXPOSED_SERVICE` | `HIGH` | `CONFIRMED` | **VNC Exposed Globally**: Remote framebuffer service exposed without interface restriction. | Restrict to VPN or SSH tunneling. |
| **`NET-PORT-445`** | `EXPOSED_SERVICE` | `HIGH` | `CONFIRMED` | **SMB Exposed Globally**: Direct SMB file sharing service listening on all interfaces. | Restrict SMB to trusted internal subnets. |
| **`NET-PORT-6379`** | `EXPOSED_SERVICE` | `HIGH` | `CONFIRMED` | **Redis Database Exposed Globally**: In-memory database listening on 0.0.0.0 without boundary. | Bind Redis to 127.0.0.1 and enable auth. |
| **`NET-ANOM-PROC`** | `CONNECTION_ANOMALY` | `MEDIUM` | `HIGH` | **High Connection Count Anomaly**: Process holds unusually large socket count (>60). | Investigate application for socket leaks. |
| **`NET-BASE-001`** | `NETWORK_CONFIGURATION` | `HIGH` | `HIGH` | **Default Gateway Divergence**: Gateway changed compared to baseline. | Verify whether rogue DHCP or ARP spoofing occurred. |
| **`NET-BASE-002`** | `DNS` | `HIGH` | `HIGH` | **DNS Resolver Configuration Divergence**: Unrecognized DNS servers configured since baseline. | Verify host DNS settings against unauthorized redirection. |
| **`NET-BASE-003`** | `OPEN_PORT` | `MEDIUM` | `HIGH` | **New Listening Ports Discovered**: New listening sockets detected since baseline. | Identify owning application and verify exposure. |

