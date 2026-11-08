# Application Self-Update System

## 1. Overview
The Universal System Security & Intelligence CLI (`systemscan`) incorporates a robust, atomic self-update subsystem that discovers, verifies, stages, applies, migrates, and rolls back application updates across Linux, macOS, and Windows.

## 2. Release Channels

Releases are distributed through explicit, configurable channels:
- **`stable`**: Production-tested, fully signed and verified releases. Default channel for end-user deployments.
- **`beta`**: Pre-release builds containing upcoming features for early testing.
- **`dev`**: Bleeding-edge nightlies and developmental iterations.

## 3. Transactional Update State Machine

Update execution is orchestrated by `UpdateTransactionCoordinator` across 10 deterministic lifecycle stages:

```
[CHECKING] ──> [DOWNLOADING] ──> [VERIFYING] ──> [PREPARING] ──> [BACKING_UP]
                                                                        │
[COMPLETED] <── [COMMITTING] <── [VALIDATING] <── [MIGRATING] <── [APPLYING]
       │                                                                │
       └────────────────── Failure / Rollback Path <────────────────────┘
```

1. **`CHECKING`**: Inspects remote release metadata over HTTPS, parses semantic versioning, and validates Python version requirements.
2. **`DOWNLOADING`**: Fetches the verified distribution archive into an isolated, temporary workspace directory.
3. **`VERIFYING`**: Computes SHA-256 digest, checks file size limits, ensures member count boundaries, and verifies path safety (zip-slip defense).
4. **`PREPARING`**: Acquires exclusive file lock (`update.lock`), verifies write permissions, and stages temporary extraction folders.
5. **`BACKING_UP`**: Takes an isolated snapshot of the installed application package directory via `UpdateBackupManager`.
6. **`APPLYING`**: Atomically extracts and unpacks verified application files into the target package location.
7. **`MIGRATING`**: Runs `ConfigMigrationManager` to migrate existing configuration files to the target version schema.
8. **`VALIDATING`**: Performs post-installation smoke tests, package integrity checks, and module import validations.
9. **`COMMITTING`**: Finalizes transaction ledger in `update_history.json`, purges temporary staging assets, and releases file locks.
10. **`COMPLETED`**: Final success state.

## 4. CLI Commands & Aliases

```bash
# View update status and configuration
systemscan update status
systemscan /update status

# Query remote releases for newer versions
systemscan update check
systemscan checkupdate
systemscan /checkupdate

# Download release without installing
systemscan update download --output ./downloads

# Verify archive security without installing
systemscan update verify ./downloads/systemscan-1.1.0.zip --sha256 <expected-hash>

# Perform dry-run update simulation
systemscan update install --dry-run

# Execute full transactional update
systemscan update install --channel stable

# Roll back to previous version from snapshot
systemscan update rollback

# Audit past update transactions
systemscan update history
```

