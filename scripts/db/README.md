# Operational database scripts (web read models)

These tools support **recovery**, **governance**, and **smoke verification** after the operational MariaDB/MySQL schema has drifted from the Python-defined DDL (`scytaledroid/Database/db_queries/`).

Full narrative for project leads: **`docs/maintenance/database_governance_runbook.md`**.

## Environment

Python scripts use **`pymysql`** and expect:

| Variable | Purpose |
| --- | --- |
| `SCYTALEDROID_DB_HOST` | default `localhost` |
| `SCYTALEDROID_DB_PORT` | default `3306` |
| `SCYTALEDROID_DB_USER` | required |
| `SCYTALEDROID_DB_PASS` | optional in dev, empty string allowed |
| `SCYTALEDROID_DB_NAME` | required |

Run from repo root so imports resolve:

```bash
cd /path/to/ScytaleDroid
export SCYTALEDROID_DB_USER=… SCYTALEDROID_DB_NAME=… SCYTALEDROID_DB_PASS=…
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts
```

## Command sequence (operator runbook shorthand)

1. **Backup** the database (logical dump or snapshot).
2. **Posture**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture`  
   Optionally: `mariadb … < scripts/db/check_schema_posture.sql`
3. **Safe alters**: add nullable columns if missing (`--apply-safe-alters` on recreate).
4. **Drop stubs** only after review: conflicting `BASE TABLE` / stray objects under **`v_*` / `vw_*`** web consumer names (`--drop-conflicting-tables --confirm`).
5. **Recreate views**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate --apply-safe-alters --drop-conflicting-tables --confirm`
6. **PHP smoke** (requires ScytaleDroid-Web):  
   `SCYTALEDROID_WEB_ROOT=/path/to/ScytaleDroid-Web ./scripts/db/smoke_web_db.sh`
7. **Counts**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts`

## Files

| File | Role |
| --- | --- |
| `check_schema_posture.sql` | Read-only SQL checks (portable to any SQL client). |
| `recreate_web_consumer_views.py` | Posture report, counts, guarded view recreation chain from repo DDL. |
| `smoke_web_db.sh` | Wraps **`ScytaleDroid-Web/scripts/sd_web_db_smoke.php`** (PDO read smoke). |

## Naming contract

**Do not create physical tables whose names start with `v_` or `vw_`** in the operational analytics DB. Those prefixes are reserved for **SQL VIEW** definitions that layer over canonical tables (`static_analysis_*`, `apps`, `dynamic_*`, etc.).
