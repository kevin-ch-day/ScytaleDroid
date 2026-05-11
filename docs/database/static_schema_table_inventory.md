# Static-analysis table inventory

Operator reference: how persistent static-analysis objects are classified in this repo. **Runtime code is authoritative**; this file tracks intent for pruning legacy paths.

| Table / object | Class | Notes |
| --- | --- | --- |
| `static_analysis_runs` | **canonical** | Primary static-run ledger; FK hub for SAR rows. |
| `static_analysis_findings` | **canonical** | Per-finding store keyed by SAR `run_id`. |
| `static_permission_matrix` | **canonical** | Permission facts for the run. |
| `static_string_summary` | **canonical** | String analysis rollup for the run. |
| `static_string_samples` | **canonical** | String samples for the run. |
| `static_session_run_links` | **canonical** | Maps session stamp + package → `static_run_id`. |
| `static_session_rollups` | **canonical** | Per-session aggregates (completed/failed/etc.). |
| `v_static_handoff_v1` | **view** | Operational read-model over static pipeline outputs. |
| `apps`, `app_versions`, `schema_version`, … | **reference** | Shared catalogs; not static-only but required for SAR FKs. |
| `runs` | **legacy candidate** | Older run registry (`package`, …). Static analysis **no longer writes** this table; rows are historical or from older toolchains. Diagnostic readers and reset/admin paths may still touch it. |
| `metrics`, `buckets`, `findings`, `contributors` | **legacy mirror / bridge** | Legacy mirror family keyed by legacy `runs` / compat paths; reconcile, diagnostics, optional dep views (`legacy_static_reader_dependency_map.md`, **`metrics.run_id` duality**). **Canonical static persistence** uses `static_analysis_*` only; empty or stale mirror tables are normal when only canonical writers are in use. |
| `static_findings`, `static_findings_summary` | **legacy candidate** | Superseded by `static_analysis_findings` for canonical SAR persistence. |
| `static_permission_risk_vnext` | **canonical** | Run-scoped permission risk detail (one deduped permission key per row); written with the matrix in the static transaction. |
| `risk_scores` | **canonical (rollup)** | Session/package **rollup** persisted on the analyst core catalog for menus, audits, and reporting. **Not** part of `schema_gate.static_schema_gate()`; empty or missing rollups do **not** imply the static schema gate failed. May still appear in **DB schema snapshot** `required_tables.static` as a deployment completeness signal—see `docs/maintenance/session_identity_contract.md` and the archived slice notes in `docs/maintenance/archive/next_pass_docs_policy_implementation_plan.md`. |
| `static_correlation_results`, … | **derived / bridge** | Other analytics surfaces; classify per `docs/database/schema_domain_inventory.md`. |

Preflight for **persisted full static runs** uses `schema_gate.static_schema_gate()` (**canonical tables + `v_static_handoff_v1` + required columns**)—see `scytaledroid/Database/db_utils/schema_gate.py`. That gate is **orthogonal** to whether `risk_scores` rows exist for the session.

**Session scope:** canonical child tables join through `static_analysis_runs.id`; do not filter child tables by nonexistent `session_label` / `session_stamp` columns—see `docs/maintenance/session_identity_contract.md`.
