# Application Rollback Architecture & Recovery

## 1. Overview
The rollback subsystem ensures continuous operational availability. If any update transaction fails during installation, configuration migration, or post-update validation, the system automatically triggers an immediate, atomic rollback to restore the previous application state.

## 2. Pre-Update Backup Snapshots (`UpdateBackupManager`)

Before touching any application files, the update coordinator creates an isolated snapshot under:
`<backup_dir>/update_backups/<transaction_id>/`

Each snapshot contains:
1. Complete installed package tree (`systemscan/`).
2. Snapshot manifest (`manifest.json`):
   ```json
   {
     "transaction_id": "upd-a1b2c3d4e5",
     "created_at": "2026-11-08T17:00:00Z",
     "source_dir": "/path/to/venv/lib/python3.12/site-packages/systemscan",
     "files_backed_up": 215,
     "metadata": {
       "source_version": "1.0.0",
       "target_version": "1.1.0"
     }
   }
   ```
3. **Retention Management**: Automatically prunes historical snapshots exceeding `max_backups` (default: 3), preserving disk storage.

## 3. Preservation of User Data

The rollback engine strictly adheres to data boundary guarantees:

> [!IMPORTANT]
> Update backups and rollbacks ONLY operate on application binary and package files (`systemscan/`).
> Under NO circumstance are user directories ever modified, overwritten, or deleted:
> - User configuration (`config.json`)
> - Scan history (`scan_history.json`)
> - Incremental cache (`incremental_cache.json`)
> - Scan reports (`reports/`)
> - Checkpoints (`checkpoints/`)
> - Network baselines (`network_baselines/`)
> - Application logs (`logs/`)

## 4. Automated & Manual Recovery Flows

### Automated Recovery
When an update transaction encounters an error during `APPLYING`, `MIGRATING`, or `VALIDATING`:
1. The coordinator catches the exception and logs an emergency alert.
2. `UpdateRollbackManager.rollback(transaction_id)` is invoked automatically.
3. The failed installation files are removed.
4. The pre-update package files from the snapshot are restored into place.
5. The transaction record in `update_history.json` is updated with `rolled_back = True`, `failure_reason`, and `error_message`.

### Manual Recovery
If an operator chooses to revert to a previous version after a successful update:
```bash
# Roll back to the most recent pre-update snapshot
systemscan update rollback

# Roll back to a specific past transaction snapshot
systemscan update rollback --transaction upd-a1b2c3d4e5
```

