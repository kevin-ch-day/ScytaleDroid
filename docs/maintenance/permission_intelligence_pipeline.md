# Permission intelligence pipeline (operator / developer)

This note frames how ScytaleDroid separates **run evidence** (core DB) from **dictionary and classification knowledge** (Permission Intel DB). When docs disagree with code, treat Python as authoritative.

## Core ideas

- **ScytaleDroid core DB** stores **observed run/app evidence**: what was scanned, what the pipeline extracted, what was persisted for this `static_run_id` / session.
- **Permission Intel DB** (`android_permission_intel`) stores **dictionary and governance knowledge**: AOSP/OEM/custom/unknown reference data, protection metadata, governance snapshots — not static-analysis *results* rows.
- **`static_permission_matrix`** is **evidence-oriented**: per observed permission (after dedupe), profile flags, `source`, `declared_in`, etc., for that run.
- **`static_permission_risk_vnext`** is **canonicalized risk/profile-oriented**: one **lowercase** permission key per logical permission, coarse risk class / rationale from the same profile map used for the matrix.

**Erebus** uses its own configuration (`EREBUS_*`) and databases. It does **not** configure ScytaleDroid Permission Intel; do not point operators at `EREBUS_*` for ScytaleDroid Intel.

## Two databases (summary)

| Concern | Database | Env namespace | Purpose |
| --- | --- | --- | --- |
| **Core (operational static)** | Analyst catalog (e.g. `scytaledroid_core_prod`) | `SCYTALEDROID_DB_*` / `SCYTALEDROID_DB_URL` | Runs, findings, `static_permission_matrix`, `static_permission_risk_vnext`, audit snapshots, persistence failures. |
| **Permission Intel** | `android_permission_intel` (expected) | `SCYTALEDROID_PERMISSION_INTEL_DB_*` or `_URL` | Dictionary + governance tables/views (not static scan results). |

### Core DB: `risk_scores` vs static schema gate

- **`static_permission_matrix`** and **`static_permission_risk_vnext`** are canonical **run evidence** for permissions (facts + per-permission risk detail).
- **`risk_scores`** is a **persisted rollup** (session/package summary) on the **same analyst core** catalog. It supports menus, health checks, and reporting; it is **not** part of `schema_gate.static_schema_gate()`. Treat **empty or missing `risk_scores`** as a **rollup / deployment signal**, not as proof that canonical findings or matrix persistence violated the gate.
- **Legacy `metrics` / `buckets` / `contributors`** remain **mirror / reconcile** surfaces only (`AGENTS.md`, `legacy_static_reader_dependency_map.md`).

## Deduplication (matrix + vnext)

**Rule:** **first-seen spelling wins** for the matrix; later keys that match the same **lowercase** canonical name are skipped. **`static_permission_risk_vnext`** uses the same logical dedupe (one lowercase row per permission).

- **Duplicate permissions** produce structured **`persistence_warnings`** (`duplicate_permission_skipped`, `canonical_permission_name`, `duplicates_skipped_count`, `duplicate_examples`) — they are **warnings**, not persistence failures, and must not cause transaction rollback or DB unique-key collisions.
- Matrix dedupe is logged at **debug**; vnext emits **batched** warnings (one per canonical permission, not one line per duplicate).

## Persistence errors (matrix vs vnext)

Both stages run inside the same DB transaction. **`permission_matrix.write`** failures must **abort** the transaction (same as **`permission_risk.write`**), so operators do not end up with **vnext rows without matrix rows** because matrix errors were swallowed. Historical sessions may still show that skew from older behavior.

## `apk_id` on `static_permission_matrix`

Rows use **`apk_id` only when** report/metadata provides a real APK repository id (`apk_id` / `apkId` / `android_apk_id`). **`static_run_id` and `run_id` are not substituted** for `apk_id` — they are different keys and break linkage semantics.

## Permission Intel availability

- **Readiness** (menu or `scripts/db/permission_intel_readiness.py`): DSN resolution, **resolved database name** vs `android_permission_intel`, connectivity, required tables/views, dictionary read probe, governance gate. Writes are **not** auto-probed.
- **Wrong catalog name** (DSN points at another database): **ERROR** in **paper-grade** mode; **EXPERIMENTAL** in non–paper-grade mode (early exit so mispointed DSN is not confused with “Intel tables missing on the right catalog”).
- **Missing / unreachable Intel** downgrades **governance** (paper-grade expectations) but **must not** crash core matrix/vnext persistence.

## Persistence audit JSON (historical runs)

Audits captured **before** `persistence_warnings` existed will show **no** duplicate-skip rollup — that is normal; **do not rewrite** historical JSON. The post-run / insights tools call this out when the artifact has rows but no warning payloads.

## Operator commands

- **Post-run summary** (includes permission insights when DB enabled):  
  `PYTHONPATH=. python scripts/static_analysis/post_run_session_summary.py <session_stamp>`
- **Permission insights only**:  
  `PYTHONPATH=. python scripts/static_analysis/permission_session_insights.py <session_stamp>`
- **Per-app permission drilldown** (matrix / vnext / audit / optional report JSON):  
  `PYTHONPATH=. python scripts/static_analysis/permission_app_drilldown.py --session-stamp <stamp> --package <pkg>`  
  or `--static-run-id <id> [--report path/to/report.json]`
- **Replay persistence from a saved report** (default dry-run; add `--live` for real writes):  
  `PYTHONPATH=. python scripts/static_analysis/replay_persist_run_summary.py --report <path> [--live --session-stamp …]`
- **Permission name casing audit** (read-only; core + optional Intel):  
  `PYTHONPATH=. python scripts/db/audit_permission_name_casing.py [--intel] [--probe-json] [--discover]`
- **`--skip-db`** on the post-run script skips DB-backed sections (including insights).
- **Intel readiness**:  
  `PYTHONPATH=. python scripts/db/permission_intel_readiness.py`  
  `PYTHONPATH=. python scripts/db/permission_intel_readiness.py --paper-grade`

## Matrix ↔ vnext skew (session insights)

For a session, skew between matrix row counts and vnext row counts is classified heuristically:

- **EXPECTED_A** — Non-`COMPLETED` status (e.g. `FAILED` after partial persistence) or other runs where skew is common.
- **SUSPICIOUS_B** — `COMPLETED` with matrix rows but **no** vnext rows.
- **SUSPICIOUS_C** — `COMPLETED` with vnext rows but **no** matrix rows.

Per-app drilldown is implemented via `scripts/static_analysis/permission_app_drilldown.py` (raw counts from optional report JSON; canonical rows from `static_permission_matrix` / `static_permission_risk_vnext`).

## Gaps / TODO (explicit)

Not fully modeled as first-class per-permission columns in core tables today:

- `permission_name_original` vs canonical everywhere (matrix keeps first spelling; vnext stores lowercase).
- Per-run **AOSP / OEM / custom / unknown** rollups with Intel row citations in SQL (flags exist on profiles when detector + Intel supplied them).
- **Confidence scores** — do not invent; use Intel dictionary + governance snapshots when present.

Extend this document when adding persistence fields or session rollups.
