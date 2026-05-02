# Canonical MASVS / static risk SQL surfaces

Canonical views live in `scytaledroid/Database/db_queries/views_static.py` and are registered in `ordered_schema_statements()` (see manifest for exact order). `CREATE_V_STATIC_RISK_SURFACES_V1` is applied **before** `CREATE_VW_STATIC_RISK_SURFACES_LATEST`. MASVS matrix/findings/session views are registered after `CREATE_V_STATIC_HANDOFF_V1`:

| View | Role |
| --- | --- |
| `v_static_masvs_findings_v1` | Row-level `static_analysis_findings` + normalised `masvs_area_bucket`, `is_masvs_mapped`. |
| `v_static_masvs_matrix_v1` | One row per `static_analysis_runs.id`: severity counts and `masvs_{network,platform,privacy,storage}_status` (`FAIL` / `WARN` / `PASS` / `NO DATA`). |
| `v_static_masvs_session_summary_v1` | Session rollup over `v_static_masvs_matrix_v1` (`GROUP BY session_stamp`). |
| `v_static_risk_surfaces_v1` | Latest static run per package + `risk_scores` + `permission_audit_*` — **no** `runs`, `buckets`, or `metrics`. |

**NO DATA** means no MASVS-mapped findings in that area (non-empty `masvs_area`, `masvs_control`, or `masvs_control_id` required), consistent with `fetch_masvs_matrix()` in `masvs_summary_report.py`.

Session validation helper:

```bash
PYTHONPATH=. python scripts/db/validate_canonical_masvs_session.py --session 20260502-rda-full
```

## Compatibility names (same object names; canonical underneath)

These views keep **stable names** for existing SQL and tooling; definitions no longer touch legacy `runs`, `buckets`, or `masvs_control_coverage`.

| Name | Definition |
| --- | --- |
| `vw_static_risk_surfaces_latest` | `SELECT … FROM v_static_risk_surfaces_v1` plus NULL legacy bucket columns and `composite_static_surface_state = 'canonical_static_latest'`. |
| `v_masvs_matrix` | Maps `v_static_masvs_matrix_v1` into the historic column layout; **`run_id` is `static_analysis_runs.id`** (not legacy `runs.run_id`). Fail bits follow canonical severity statuses; inconclusive columns are `0`. |

### Consumers still referencing these names

**References:**

- `scytaledroid/Database/db_queries/schema_manifest.py` (bootstrap order)
- `scytaledroid/Database/db_queries/views_web.py` — `v_web_app_directory`, cohort UNION branches
- `scytaledroid/Database/db_utils/menus/runs_dashboard.py` — `_fetch_latest_risk_surfaces`
- `scytaledroid/Database/db_utils/menus/query_runner.py` — `prompt_latest_static_risk_surfaces`
- `scytaledroid/Database/db_utils/health_checks/analysis_integrity.py`
- `tests/database/test_runs_dashboard_cross_view.py`, `tests/unit/test_analysis_integrity_summary.py`
- `scripts/db/check_schema_posture.sql`
- Docs: `docs/risk_scoring_contract.md`, `docs/database/view_contract_v_web_static_dynamic_app_summary.md`, `docs/maintenance/phase5c_task_list.md`, `docs/maintenance/cli_web_db_filesystem_boundary.md`

### `masvs_control_coverage` table

Legacy mirror keyed by legacy `runs.run_id` when present. Long-term source is `static_analysis_findings.masvs_*`. SQL view `v_masvs_matrix` no longer reads this table.

### Python branches still using legacy `findings` / `runs`

`fetch_db_masvs_summary()` uses latest `static_analysis_runs` when `run_id` is omitted; legacy `runs` / `findings` remain only as a fallback when no canonical rows exist.

## Safe retirement order

1. Validate cohort sessions (`validate_canonical_masvs_session.py`). **`vw_static_risk_surfaces_latest`** / **`v_masvs_matrix`** are already thin wrappers over canonical views.
2. Optionally repoint call sites to **`v_static_risk_surfaces_v1`** / **`v_static_masvs_matrix_v1`** directly and drop compatibility column names when convenient.
3. Remove legacy **`fetch_db_masvs_summary`** fallback and **`persist_masvs_controls`** / **`masvs_control_coverage`** after parity checks.

---

## Prioritized backlog (ROI-focused)

Use this as the working queue; tick items in PRs when done.

### Tier A — High ROI / bounded effort

| # | Task | Outcome |
| --- | --- | --- |
| A1 | **`audit_static_session.py`** prints canonical MASVS session rollup + matrix row count | **Done** — matrix row count + `v_static_masvs_session_summary_v1` block. |
| A2 | **DB menu** (`query_runner`) exposes **`v_static_masvs_session_summary_v1`** by `session_stamp` | **Done** — curated queries option **12**. |
| A3 | Gate **`fetch_db_masvs_summary`** legacy path behind **`SCYTALEDROID_ALLOW_LEGACY_MASVS_FALLBACK=1`** (default off in CI smoke optional) | **Done** — `None` uses latest `static_analysis_runs` first; `runs`/`findings` only with env or explicit `run_id`. |
| A4 | **`prompt_masvs_by_package`** stops listing “recent packages” from **`runs`**; use **`static_analysis_runs`** | **Done** — recent list uses canonical runs + `static_run_id` label. |

### Tier B — Medium ROI / more moving parts

| # | Task | Outcome |
| --- | --- | --- |
| B1 | Repoint **`views_web.py`** (`v_web_app_directory`, etc.) from **`vw_static_risk_surfaces_latest`** to **`v_static_risk_surfaces_v1`** where SQL is owned here | Clearer plans; wrapper already canonical — optional. |
| B2 | **`analysis_integrity`** health SQL: assert **`composite_static_surface_state`** semantics doc vs NULL buckets | Avoid silent drift when legacy columns are NULL. |
| B3 | **`persist_masvs_controls`** keyed by **`static_run_id`** or retire **writes** after parity | Drops **`masvs_control_coverage`** dependency entirely. |
| B4 | Publication / Table 5 pipelines read **`v_static_masvs_matrix_v1`** or exported rollup CSV | Research exports align with DB truth. |

### Tier C — Larger / cross-repo

| # | Task | Outcome |
| --- | --- | --- |
| C1 | **ScytaleDroid-Web** PHP consumers switch to canonical column contracts | End-user dashboards match CLI DB. |
| C2 | Drop **`runs`/`buckets`** reads from **`static_reconcile`** once unused | Smaller operational confusion. |
