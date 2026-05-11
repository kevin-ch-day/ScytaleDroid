# Legacy mirror helper wiring report (`legacy_static_mirror_diagnostics`)

**Date:** 2026-05-09  
**Scope:** Lane 2 planning — which call sites can share helpers **without** changing semantics. **Do not** use for `metrics.run_id` ambiguity zones without per-query review.

## Helpers today

| Helper | SQL / role |
| --- | --- |
| `legacy_mirror_table_presence_audit()` | `runs`, `metrics`, `buckets`, `findings` presence |
| `legacy_mirror_runs_findings_presence()` | `runs` + `findings` presence |
| `legacy_runs_count_by_session_stamp()` | `SELECT COUNT(*) FROM runs WHERE session_stamp=%s` |
| `legacy_findings_count_via_runs_session_stamp()` | Legacy `findings` ⋈ `runs` on `session_stamp` |
| `legacy_findings_count_via_static_run_id()` | Legacy `findings.static_run_id` ∈ SAR ids for `session_stamp` |

## Wired in this repo

- `scripts/db/audit_static_session.py` — presence + all three count shapes where applicable (`runs` row uses `legacy_runs_count_by_session_stamp`).
- `scripts/db/session_static_health.py` — runs/findings presence + runs-join findings count.

## `scripts/db/audit_static_session.py` — metrics / buckets

**Stay local:** joined queries `metrics` ⋈ `runs`, `buckets` ⋈ `runs` differ from helper SQL; no shared helper until a parameterized `legacy_mirror_count_via_runs(table, ...)` is designed and tested.

## `scytaledroid/StaticAnalysis/cli/execution/db_verification.py`

**Stay local:**

- Legacy totals use `_legacy_mirror_catalog_total` + `SELECT COUNT(*) FROM \`table\`` (full catalog), **not** session-scoped mirror counts.
- Session-scoped legacy row counts use `_count_by_run("findings"|"metrics"|…)` with **dynamic** table/column choice (`static_run_id` vs legacy `run_id`) — different semantics from both findings helpers.
- **Do not** route `metrics` through new helpers without classifying **`metrics.run_id`** space per `legacy_static_reader_dependency_map.md` §6.

## `scytaledroid/Database/db_utils/menus/query_runner.py`

**Stay local (for now):**

- `_session_downstream_counts` uses `_run_read_only(...)` with a different call signature than `core_q.run_sql`; SQL for `runs` matches **`legacy_runs_count_by_session_stamp`** text but wiring would need a thin adapter (`lambda sql, params, **_: _run_read_only(sql, params, fetch="one")`) — **defer** to avoid coupling scripts helpers to menu DB session layer in the same batch.
- Digest SQL for legacy **`findings`** (if any) uses **session-scoped keys** tied to digest contract — compare line-by-line before deduping.

## Safe future additions (bounded)

- `legacy_metrics_count_via_runs_session_stamp` **only** if the SQL is **identical** to audit’s metrics block and call sites agree on **`runs.run_id`** join semantics (not `metrics.run_id` = SAR id paths).

## Related

- `docs/maintenance/legacy_static_reader_dependency_map.md` §2.1, §6
- `docs/maintenance/fast_implementation_backlog_lanes.md`
