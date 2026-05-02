# Operational database scripts (web read models)

These tools support **recovery**, **governance**, and **smoke verification** after the operational MariaDB/MySQL schema has drifted from the Python-defined DDL (`scytaledroid/Database/db_queries/`).

Full narrative for project leads: **`docs/maintenance/database_governance_runbook.md`**.

## One-shot operator doctor

From repo root (same env as static analysis), run:

```bash
chmod +x scripts/db/scytaledroid_doctor.sh   # once
./scripts/db/scytaledroid_doctor.sh
```

This executes: primary DB ping → view **posture** → **semantic** checks → `check_permission_intel.py` → optional Web DB smoke when `SCYTALEDROID_WEB_ROOT` points at your ScytaleDroid-Web checkout.

Skip flags (environment):

| Variable | Effect |
| --- | --- |
| `SCYTALEDROID_DOCTOR_QUICK=1` | Only Primary DB + Permission Intel (skips posture, semantic, web). |
| `SCYTALEDROID_DOCTOR_SKIP_POSTURE=1` | Skip posture step. |
| `SCYTALEDROID_DOCTOR_SKIP_SEMANTIC=1` | Skip semantic step. |
| `SCYTALEDROID_DOCTOR_SKIP_INTEL=1` | Skip Permission Intel doctor. |
| `SCYTALEDROID_DOCTOR_SKIP_WEB=1` | Skip Web smoke even if `SCYTALEDROID_WEB_ROOT` is set. |

## Environment

Python scripts use **`pymysql`** and expect:

| Variable | Purpose |
| --- | --- |
| `SCYTALEDROID_DB_HOST` | default `localhost` |
| `SCYTALEDROID_DB_PORT` | default `3306` |
| `SCYTALEDROID_DB_USER` | required |
| `SCYTALEDROID_DB_PASSWD` | optional in dev, empty string allowed (matches app `db_config`; **`SCYTALEDROID_DB_PASS` accepted as legacy**) |
| `SCYTALEDROID_DB_NAME` | required |

Run from repo root so imports resolve:

```bash
cd /path/to/ScytaleDroid
export SCYTALEDROID_DB_USER=… SCYTALEDROID_DB_NAME=… SCYTALEDROID_DB_PASSWD=…
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts
```

## Command sequence (operator runbook shorthand)

1. **Backup** the database (logical dump or snapshot).
2. **Posture**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture`  
   Optionally: `mariadb … < scripts/db/check_schema_posture.sql`
3. **Semantic smoke** (empty-dashboard detector): `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic`
4. **Dry-run view order**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate --dry-run [--layer full|manifest|web]`
5. **Safe alters**: add nullable columns if missing (`--apply-safe-alters` on recreate).
6. **Drop stubs** only after review: any conflicting `BASE TABLE` whose name matches **`^v_.*` / `^vw_.*`** (`--drop-conflicting-tables --confirm`). Non-empty stubs need **`--allow-drop-nonempty-tables --confirm`**.
7. **Recreate views**: default **`full`** (bootstrap manifest chain + supplementary + web extensions). Narrow with **`--layer manifest`** (DDL from `ordered_schema_statements()` only) or **`--layer web`** (web-consumer extensions only):

   ```bash
   PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate \
     --layer full \
     --apply-safe-alters --drop-conflicting-tables --confirm
   ```

8. **PHP smoke** (requires ScytaleDroid-Web):  
   `SCYTALEDROID_WEB_ROOT=/path/to/ScytaleDroid-Web ./scripts/db/smoke_web_db.sh`
9. **Counts**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts`
10. **Permission Intel** (dedicated `android_permission_intel` DB + paper-grade governance):  
   `PYTHONPATH=. python scripts/db/check_permission_intel.py`  
   Use **`SCYTALEDROID_PERMISSION_INTEL_DB_PASSWD`** (or `…_URL`), not `…_PASS` — see script header.

## Cohort static session audit

After a profile/cohort static run, verify canonical row counts and Web/read views for one `session_stamp`:

```bash
PYTHONPATH=. python scripts/db/audit_static_session.py --session 20260502-rda-canonical-only
```

Canonical writers only (empty historical legacy-table rows are **not** treated as failure):

```bash
PYTHONPATH=. python scripts/db/audit_static_session.py --session 20260502-rda-canonical-only
```

## Files

| File | Role |
| --- | --- |
| `check_schema_posture.sql` | Read-only SQL checks (portable to any SQL client). |
| `recreate_web_consumer_views.py` | Posture / semantic smoke / counts; guarded **`recreate`** (`--layer` full, manifest, or web). |
| `view_repair_support.py` | Helpers; ordered DDL for full vs manifest vs web-only sequences (scripts package). |
| `check_permission_intel.py` | Env/connectivity + governance row counts for **`SCYTALEDROID_PERMISSION_INTEL_DB_*`**. |
| `audit_static_session.py` | Cohort audit: canonical tables + `v_web_*` + handoff + legacy-table counts (informational); prints copyable SQL. |
| `smoke_web_db.sh` | Wraps **`ScytaleDroid-Web/scripts/sd_web_db_smoke.php`** (PDO read smoke). |

## Naming contract

**Do not create physical tables whose names start with `v_` or `vw_`** in the operational analytics DB. Those prefixes are reserved for **SQL VIEW** definitions that layer over canonical tables (`static_analysis_*`, `apps`, `dynamic_*`, etc.), including non-Web reporting views (`v_run_overview`, `v_static_handoff_v1`, artifact registry views, cohort views, etc.).
