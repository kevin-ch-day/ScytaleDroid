# DEV MariaDB Rollback (mysqldump) — quick guide

Purpose: return to a known-good state in minutes if a schema change or run corrupts DEV.

## Pre-change backup
```bash
mysqldump -u scytale_cli -p'SCYTALE_PASS' scytaledroid_droid_intel_db_dev > /tmp/scytaledroid_dev_backup.sql
```

## Restore
```bash
mysql -u scytale_cli -p'SCYTALE_PASS' scytaledroid_droid_intel_db_dev < /tmp/scytaledroid_dev_backup.sql
```

Notes:
- Run from Fedora host where MariaDB is local.
- Replace `SCYTALE_PASS` with the actual password (Password123! in DEV).
- Ensure no processes are writing during restore.
- After restore, re-run `python -m scytaledroid.Database.tools.db_status` to confirm schema_version and connectivity.

Scope:
- DEV only. For PROD, use a separate backup/restore workflow and credentials.
