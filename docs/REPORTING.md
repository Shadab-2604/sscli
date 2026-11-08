# Centralized Reporting & Export Engine

The **Reporting & Export Engine** provides consistent, structured, and auditable reporting across all scanner modules in `systemscan` (**Filesystem**, **Malware**, **Storage**, **Cache**, **USB Removable Media**, and **Network Security Audit**).

---

## 1. Architecture Overview

```
              +-------------------------------------+
              |      CentralScanOrchestrator        |
              +------------------+------------------+
                                 |
                                 v
                     +-----------------------+
                     |    ReportGenerator    |
                     +-----------+-----------+
                                 |
     +---------------------------+---------------------------+
     |                           |                           |
+----v----+                 +----v----+                 +----v----+
| Summary |                 | Findings|                 | System  |
| Builder |                 | Normaliz|                 | Snapshot|
+----+----+                 +----+----+                 +----+----+
     |                           |                           |
     +---------------------------+---------------------------+
                                 |
                                 v
                       +-------------------+
                       |    ScanReport     |
                       | (Pydantic Model)  |
                       +---------+---------+
                                 |
                     +-----------+-----------+
                     |                       |
            [Redaction Requested?]           |
                /          \                 |
              YES           NO               |
              /              \               |
      +------v-------+        v              |
      |ReportRedactor| (Unmodified Original) |
      +------+-------+        |              |
             \               /               |
              v             v                |
          +-----------------------+          |
          |    ReportExporter     | <--------+
          +-----------+-----------+
                      |
    +-----------------+-----------------+
    |                 |                 |
+---v----+       +----v---+        +----v---+
|  JSON  |       |  CSV   |        |  TXT   |
| Exporter       | Bundle |        |Exporter|
+---+----+       +----+---+        +----+---+
    |                 |                 |
    +-----------------+-----------------+
                      |
                      v
          +-----------------------+
          | ReportStorageManager  |
          |  - Atomic writes      |
          |  - SHA-256 manifests  |
          |  - Retention pruning  |
          +-----------------------+
```

---

## 2. Standardized Overall Posture Results

The reporting engine calculates a deterministic overall status:

| Status | Trigger Condition | Meaning |
| :--- | :--- | :--- |
| `ACTION_REQUIRED` | Count of `CRITICAL` > 0 or `HIGH` > 0 | High-risk malware, listening services on 0.0.0.0, or dangerous exposures requiring immediate action. |
| `REVIEW_REQUIRED` | Count of `MEDIUM` > 0 or `LOW` > 0 | Unencrypted Wi-Fi, high disk usage, duplicate files, or policy warnings. |
| `NO_HIGH_PRIORITY_FINDINGS` | Zero critical, high, medium, or low findings | No high-risk threats detected within the inspected scope. *(Includes explicit disclaimer that this is not a guarantee of total immunity).* |
| `INCOMPLETE` | Scan state is `PARTIAL`, `CANCELLED`, or `CANCELLING` | Scan was halted or interrupted before completing all targets. |
| `FAILED` | Scan state is `FAILED` | Critical runtime or platform failure prevented inspection. |

---

## 3. CLI Command Reference

### Generate Reports
```bash
# Generate report from most recent scan
systemscan report generate

# Generate report for a specific scan ID in JSON format
systemscan report generate --scan-id scan-1a2b3c4d --format json

# Generate sanitized report with sensitive data masked
systemscan report generate --scan-id scan-1a2b3c4d --format json --redact

# Export to custom path with explicit overwrite permission
systemscan report generate --scan-id scan-1a2b3c4d --format txt --output /tmp/audit.txt --overwrite
```

### Export Existing Sessions
```bash
# Export to CSV spreadsheet tables
systemscan report export --scan-id scan-1a2b3c4d --format csv --output /tmp/findings.csv

# Export with compact template style
systemscan report export --scan-id scan-1a2b3c4d --format txt --style compact
```

### Manage & Verify Reports
```bash
# List all saved reports in storage
systemscan report list

# View formatted report in terminal
systemscan report show rep-9a8b7c6d --style technical
systemscan report show rep-9a8b7c6d --style executive

# Cryptographically verify report integrity against SHA-256 manifest
systemscan report verify rep-9a8b7c6d

# Delete report with confirmation
systemscan report delete rep-9a8b7c6d --yes
```

