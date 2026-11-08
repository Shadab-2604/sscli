# Scan Checkpoint Management & Fault-Tolerant Resumption

The **Scan Checkpoint Engine** provides fault-tolerant pause, resume, and crash recovery capabilities for long-running scans across massive storage volumes or deep directory trees.

---

## 1. Checkpoint Architecture

```
Scan in Progress
       |
       +--> Periodic Save / Pause Signal
       |         |
       |    [Atomic Write to .tmp]
       |         |
       |    [Atomic Rename to .json]
       |         |
       |    [Enforce Retention Pruning (Default: 10)]
       v
Interruption / System Reboot
       |
       v
Operator runs: systemscan scan resume --id <scan_id>
       |
  [Load JSON]
       |
  Valid? -- NO --> [Move to .corrupt, log error, cleanly abort]
       |
      YES
       |
  [Revalidate Target Paths (ensure mounts still exist)]
       |
  [Restore Traversal Cursor & Processed List]
       |
  [Resume Scan from Last Recorded Phase]
```

---

## 2. Checkpoint Data Structure

Each checkpoint record is serialized with strict schema validation:

```json
{
  "checkpoint_id": "c1f7a268-2c35-46f9-b883-9366dfef024e",
  "scan_id": "scan-9a8b7c6d",
  "schema_version": 1,
  "scan_type": "FILESYSTEM",
  "targets": ["/var/log", "/opt/data"],
  "completed_phases": ["DISCOVERY"],
  "current_phase": "METADATA_INSPECTION",
  "traversal_cursor": "/opt/data/archive_2024",
  "processed_paths": [
    "/var/log/syslog",
    "/var/log/auth.log"
  ],
  "progress": {
    "scan_id": "scan-9a8b7c6d",
    "state": "PAUSED",
    "current_phase": "METADATA_INSPECTION",
    "items_processed": 1420,
    "bytes_processed": 58392100,
    "elapsed_seconds": 45.2
  },
  "error_count": 0,
  "created_at": "2026-11-08T16:05:00Z",
  "last_updated_at": "2026-11-08T16:05:45Z",
  "scan_config": {}
}
```

---

## 3. Corruption Recovery

If a system crashes mid-write or a checkpoint file becomes corrupted:
1. `load_checkpoint` catches the `json.JSONDecodeError` or validation exception.
2. The damaged file is automatically renamed to `<scan_id>.json.corrupt` to isolate it and prevent scan loops.
3. A descriptive error log is generated, informing the operator that the checkpoint cannot be restored.

---

## 4. Retention Management

To prevent unbounded disk consumption, `ScanCheckpointManager` enforces a retention limit (default: 10 checkpoints). Checkpoint directories are pruned by `mtime` upon every save operation, purging the oldest records.

