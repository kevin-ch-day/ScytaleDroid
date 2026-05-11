# Workspace housekeeping & logs

Keeping local workspaces tidy ensures repeatable scans and prevents stale
artifacts from confusing follow-up investigations. This guide summarises the
built-in maintenance helpers and documents where the CLI writes log files and
reports.

## Workspace & Evidence (menu)

The CLI provides a **Workspace & Evidence** menu for collection operations and
safe cleanup. Typical actions include:

- Workspace disk usage (APK storage, evidence packs, logs, caches).
- Dynamic evidence pack verification (overview, deep checks).
- Dataset freeze manifest writing and immutability verification.
- Deleting INVALID dataset runs locally (evidence-pack cleanup).
- Pruning derived DB orphans (safe; DB is not authoritative).

Important:
- Evidence packs are authoritative.
- The DB is derived/rebuildable and may drift if runs are deleted locally.
- Historical paper export/repro docs were removed during doc cleanup; use the
  active runbook and contracts instead.

## Static analysis caches & retention

Static analysis may use caches under:
- `data/static_analysis/cache/`
- `output/cache/` (if used)

Retention settings (if enabled by the CLI) should be treated as housekeeping
only. Do not rely on retention as a correctness mechanism for paper-grade runs.

## Where logs live

`Utils → Show log directories` prints the resolved paths for each subsystem. By
default logs live under `./logs/` with paired human-readable and JSONL streams
(where configured) so you can tail text locally or feed structured events to tooling.

**Source of truth:** `scytaledroid/Utils/LoggingUtils/logging_engine.py` (`LOG_CONFIGS`). If this table disagrees with code, code wins — see `docs/maintenance/logs_operator_hygiene_plan.md`.

| Category         | Human readable          | Structured JSONL               |
|------------------|-------------------------|--------------------------------|
| Application      | `app.log`               | `app.jsonl`                    |
| Database         | `db.log`                | `db.jsonl`                     |
| Device analysis  | `device_analysis.log`   | `device_analysis.jsonl`        |
| Harvest (global) | `harvest.log`           | `harvest.jsonl`                |
| Static analysis  | `static_analysis.log`   | `static_analysis.jsonl`        |
| Dynamic analysis | `dynamic_analysis.log`  | `dynamic_analysis.jsonl`       |
| Metrics          | —                       | `metrics.jsonl` *(logger category “metrics”; not legacy SQL `metrics` table)* |
| Error funnel     | `error.log`             | —                              |
| Audit trail      | `audit.log`             | `audit.jsonl`                  |

**Rotation:** handlers use size-based rotation with **gzip** on rollover — expect sibling **`*.gz`** files next to active logs (default **10 MiB** per file, **14** backups per category unless changed in code).

**Harvest per-run files** (in addition to global `harvest.log` / `harvest.jsonl`): under `logs/harvest/`, files named `<timestamp>_run-<slug>.jsonl` **and** paired `<timestamp>_run-<slug>.log` (see `create_harvest_run_logger`).

**Third-party debug:** androguard deep logs may land under `logs/third_party/` (e.g. `androguard.<run_id>.log`) when verbosity demands it — not the same channels as the table above.

**Script vocabulary:** some operator scripts glob `logs/harvest_runs/` — treat **`logs/harvest/`** as the canonical per-run directory; path aliases vary by script age.

The same helper also reminds operators where device state and static-analysis
report directories live so they can inspect or archive them manually when
needed.

## Recommended cadence

* Use Workspace & Evidence verification checks during collection to avoid silent drift.
* Run prune-orphans only when DB drift is observed (ad-hoc; derived index).
* Keep ML runs offline and evidence-pack-only; do not depend on DB state.
* Keep the log directory under version control ignores (e.g. `.gitignore`)
  so logs never end up in commits.

For additional operational notes see the [workflow entrypoint
map](../maintenance/workflow_entrypoint_map.md).

## Lab MariaDB rollback

Use this only for the local dev/lab MariaDB environment when a schema change or
bad run leaves the database in a state you want to replace quickly.

Pre-change backup:

```bash
mysqldump -u scytale_cli -p'SCYTALE_PASS' scytaledroid_droid_intel_db_dev > /tmp/scytaledroid_dev_backup.sql
```

Restore:

```bash
mysql -u scytale_cli -p'SCYTALE_PASS' scytaledroid_droid_intel_db_dev < /tmp/scytaledroid_dev_backup.sql
```

Notes:

- run from the Fedora host where MariaDB is local
- replace `SCYTALE_PASS` with the real password for the current environment
- ensure no processes are writing during restore
- after restore, rerun:

```bash
python -m scytaledroid.Database.tools.db_status
```

Recommended runtime mode during this workflow:

- `SCYTALEDROID_DEBUG_MODE=True`
- `SCYTALEDROID_EXECUTION_MODE=DEV`
- `SCYTALEDROID_SYS_ENV=PHYSICAL` or `VIRTUAL`

Scope:

- current lab environment only
- if a future production environment appears, keep a separate restore workflow
  and separate credentials for it
