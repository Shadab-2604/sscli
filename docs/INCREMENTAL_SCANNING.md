# Incremental Scanning & Metadata Verification

The **Incremental Scan Engine** enables `systemscan` to achieve dramatic speedups on repeated scans by validating whether files have changed since their previous inspection.

---

## 1. Metadata Verification Modes

| Mode | Verification Checks | Typical Speedup | Use Case |
| :--- | :--- | :--- | :--- |
| `FAST` | File size + modification time (`mtime` within 1.0s) + inode check | **90% - 98%** | Routine daily/scheduled scans on large repositories |
| `BALANCED` | `FAST` checks + periodic SHA-256 rehash after 30 days | **80% - 92%** | Default production setting balancing speed and security |
| `THOROUGH` | Ignores cache; forces full file hashing and content analysis | **0%** (Baseline) | High-security audits, malware incident response |

---

## 2. Invalidation Rules

A cached file record is invalidated and re-scanned if:
1. File size in bytes changes.
2. File modification time (`st_mtime`) deviates by $\ge 1.0$ second.
3. Inode number changes (indicating file replacement or atomic rename).
4. The file was previously flagged as `SUSPICIOUS`, `MALWARE`, or `ERROR`.
5. The record age exceeds `rehash_age_days` (in `BALANCED` mode).
6. The user specifies `--full-verification` or `--no-incremental` via the CLI.

---

## 3. Persistent Cache Storage

Cache records are persisted atomically in `~/.config/systemscan/incremental_cache.json` (or OS equivalent) using a write-to-temp-then-rename strategy:

```json
{
  "/usr/bin/python3.12": {
    "path": "/usr/bin/python3.12",
    "size_bytes": 7128368,
    "modified_time": 1729481234.0,
    "inode": 142857,
    "device_id": 2049,
    "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "last_scanned": "2026-11-08T16:00:00Z",
    "status": "CLEAN",
    "findings_count": 0
  }
}
```

