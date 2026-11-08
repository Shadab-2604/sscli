# Configuration & Schema Migration Engine

## 1. Overview
The Configuration Migration Subsystem (`ConfigMigrationManager`) ensures seamless compatibility when updating `systemscan` across versions with modified or extended schema definitions.

## 2. Migration Principles

1. **Pre-Migration Safety Snapshot**: Before modifying `config.json`, the migration manager creates a timestamped backup in `<backup_dir>/config_migrations/config_pre_migration_<timestamp>.json`.
2. **User Preference Preservation**: Existing custom user settings (e.g., custom paths, log levels, concurrency limits, reporting redaction preferences) are strictly preserved and never overwritten by defaults.
3. **Additive Schema Extension**: Newly introduced sections (e.g. `[updates]`, `[dependencies]`) and keys are added with sensible, secure defaults.
4. **Graceful Deprecation**: Obsolete keys are safely ignored or pruned without causing application crashes.
5. **Schema Validation**: The migrated dictionary is validated against the active Pydantic `SystemScanConfig` model.
6. **Atomic Rollback on Error**: If schema validation fails, the pre-migration snapshot is immediately restored to the original location, and the error is returned to the update coordinator.

## 3. Schema Versioning

Configuration files store a top-level `schema_version` integer:
```json
{
  "schema_version": 1,
  "preferences": {
    "color_enabled": true,
    "interactive_mode": true
  },
  "log_level": "INFO",
  "dependencies": {
    "auto_install": false,
    "allow_global_install": false
  },
  "updates": {
    "enabled": true,
    "channel": "stable",
    "verify_signatures": true,
    "rollback_enabled": true,
    "max_backups": 3
  }
}
```

## 4. Programmatic & Dry-Run Usage

```python
from systemscan.update.migrations import ConfigMigrationManager

mgr = ConfigMigrationManager()

# Simulate schema migration
dry_ok, msg, planned_changes = mgr.migrate(dry_run=True)
print(f"Planned changes: {len(planned_changes)}")

# Execute atomic migration
ok, msg, applied_changes = mgr.migrate(dry_run=False)
```

