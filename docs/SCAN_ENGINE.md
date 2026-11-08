# Scan Intelligence & Central Orchestration Engine

The **Central Scan Orchestrator** coordinates multi-module security scans, resource monitoring, dynamic ETA estimation, incremental file skipping, persistent checkpointing, and session history management across Linux, Windows, and macOS.

---

## 1. Architecture Overview

```
                      +-----------------------------+
                      |   CentralScanOrchestrator   |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
+--------v--------+         +--------v--------+         +--------v--------+
| ScanLifecycle   |         | ConcurrencyMgr  |         | ETA Engine      |
| Coordinator     |         | (Adaptive/CPU)  |         | (EMA Smoothing) |
+-----------------+         +-----------------+         +-----------------+
         |                           |                           |
+--------v--------+         +--------v--------+         +--------v--------+
| IncrementalScan |         | CheckpointMgr   |         | HistoryManager  |
| Engine (Cache)  |         | (Atomic Writes) |         | (JSON Ledger)   |
+-----------------+         +-----------------+         +-----------------+
```

---

## 2. Standardized Lifecycle States

Every scan session follows deterministic state transitions validated by `ScanLifecycleCoordinator`:

| State | Description | Permitted Next States |
| :--- | :--- | :--- |
| `QUEUED` | Scan registered in workload queue | `INITIALIZING`, `CANCELLING`, `CANCELLED` |
| `INITIALIZING` | Loading config, resolving roots, checking checkpoints | `RUNNING`, `CANCELLING`, `CANCELLED`, `FAILED` |
| `RUNNING` | Active scanning across files, network, or storage | `PAUSING`, `CANCELLING`, `COMPLETED`, `PARTIAL`, `FAILED` |
| `PAUSING` | Cooperative pause requested; waiting at boundary | `PAUSED`, `CANCELLING`, `FAILED` |
| `PAUSED` | Scan frozen at safe boundary; checkpoint saved | `RESUMING`, `CANCELLING`, `CANCELLED` |
| `RESUMING` | Checkpoint verified and memory state restored | `RUNNING`, `CANCELLING`, `FAILED` |
| `CANCELLING` | Operator cancellation in progress | `CANCELLED`, `FAILED` |
| `CANCELLED` | Terminal state: scan aborted by user | *None* |
| `COMPLETED` | Terminal state: all targets fully inspected | *None* |
| `PARTIAL` | Terminal state: partially completed due to partial errors | *None* |
| `FAILED` | Terminal state: aborted due to fatal system error | *None* |

Attempting an illegal transition (such as jumping directly from `QUEUED` to `COMPLETED`) raises `InvalidScanStateTransitionError`.

---

## 3. Supported Scan Classifications

`CentralScanOrchestrator` unifies multiple scan dimensions into a single interface:

- **`FULL`**: Exhaustive scan across filesystem traversal, malware signatures, heuristic storage analysis, and network security audit.
- **`FILESYSTEM`**: Traversal of directory hierarchies, hidden objects, symlinks, and file attributes.
- **`MALWARE`**: Hashes, byte signatures, entropy analysis, and suspicious extensions.
- **`STORAGE`**: Disk usage distribution, duplicate detection, and file aging.
- **`CACHE`**: Temporary and application cache discovery.
- **`REMOVABLE`**: USB and external storage monitoring.
- **`NETWORK`**: Active connections, open ports, DNS servers, and firewall posture.
- **`CUSTOM`**: User-specified targeted paths with custom inspection modules.

---

## 4. CLI Execution Commands

### Launch Orchestrated Scan
```bash
# Start an adaptive filesystem scan
systemscan scan start --type filesystem --path /data

# Start a sequential scan with specific worker constraints
systemscan scan start --type malware --path /home/user --workers 2

# Force full verification (bypassing incremental skipping)
systemscan scan start --type full --full-verification

# Machine-readable JSON progress streaming
systemscan scan start --type filesystem --json-progress
```

### Inspect & Control Active Scans
```bash
# View real-time status of active or recent scan
systemscan scan status

# List active checkpoints and recent execution runs
systemscan scan list

# Signal cooperative pause at next safe boundary
systemscan scan pause --id <scan_id>

# Resume paused scan from checkpoint
systemscan scan resume --id <scan_id>

# Cancel scan and purge checkpoint
systemscan scan cancel --id <scan_id>
```

