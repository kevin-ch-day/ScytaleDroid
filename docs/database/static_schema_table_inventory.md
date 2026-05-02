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
| `runs` | **legacy candidate** | Older run registry (`package`, …); **not** mirrored from static ledger for new writes. Optional compat INSERTs may exist elsewhere (`Persistence/db_writer`) until removed. |
| `metrics`, `buckets`, `findings` | **legacy candidate** | Legacy metric/finding buckets keyed by legacy `runs.id`; may still receive writes when compat `run_id` path is active—treat as **removable** once that path is dropped. |
| `static_findings`, `static_findings_summary` | **legacy candidate** | Superseded by `static_analysis_findings` for canonical SAR persistence. |
| `static_permission_risk_vnext`, `risk_scores`, `static_correlation_results`, … | **derived / bridge** | Analytics and correlation surfaces; classify per `docs/database/schema_domain_inventory.md`. |

Preflight for **persisted full static runs** uses `schema_gate.static_schema_gate()` (**canonical tables + `v_static_handoff_v1` + required columns**)—see `scytaledroid/Database/db_utils/schema_gate.py`.
