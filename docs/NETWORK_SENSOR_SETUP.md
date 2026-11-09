# SSCLI Network Threat Monitor Sensor Setup Guide

This guide describes how to deploy and integrate dedicated network sensors or router traffic mirrors into SSCLI for **Mode B (Network-Wide Monitoring)**.

---

## 1. Concept & Scope

While **Mode A (Local Monitor)** inspects packets arriving at or leaving your individual machine, **Mode B (Network-Wide Monitor)** extends visibility across your entire subnet (e.g. detecting attacker scans between two other IoT devices on your Wi-Fi).

```
                      +-------------------+
                      |   Default Gateway |
                      |    (Router / AP)  |
                      +---------+---------+
                                |
             +------------------+------------------+
             |                  |                  |
      +------v-------+   +------v-------+   +------v-------+
      | Smart Device |   | Local Laptop |   | Remote Host  |
      |   (Victim)   |   |   (SSCLI)    |   |  (Attacker)  |
      +--------------+   +--------------+   +--------------+
```

Due to switch and Wi-Fi isolation, network-wide monitoring requires one of two configurations:
1. **Managed Switch SPAN Port / Port Mirroring**
2. **Gateway Router Traffic Mirror or Sensor API**

> **Note on Truthful Coverage:** If no sensor or mirror is configured, SSCLI automatically operates in **Local-Only** mode and clearly reports `Inactive` or `Local machine traffic only`. It will never display false network-wide coverage.

---

## 2. Option A: Port Mirroring / SPAN Port

If you have a managed network switch or dedicated hardware tap:
1. Configure a SPAN (Switched Port Analyzer) / monitor session on your switch to mirror traffic from your LAN ports to a dedicated network interface on the SSCLI host.
2. Bind SSCLI to that dedicated monitoring interface:
   ```bash
   systemscan network-monitor --interface "Ethernet 2" --mode network-wide
   ```

---

## 3. Option B: Router Syslog / NetFlow Sensor API

If your router runs pfSense, OPNsense, OpenWrt, or OpenNDS:
1. Configure your router firewall to log port scan attempts to a central HTTP endpoint or syslog daemon.
2. Provide your sensor API endpoint to SSCLI:
   ```bash
   systemscan network-monitor --mode both
   ```
   Or set via configuration:
   ```bash
   systemscan config set network_monitor.router_api_url "http://192.168.1.1:8080/api/v1/sensor"
   systemscan config set network_monitor.router_token "secret_sensor_key"
   ```

When configured, SSCLI seamlessly merges incoming sensor alerts with local detections on the unified terminal dashboard.

