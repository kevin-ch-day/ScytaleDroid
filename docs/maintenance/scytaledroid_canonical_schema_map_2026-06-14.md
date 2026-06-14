# ScytaleDroid Canonical Schema Map (2026-06-14)

This is a read-only schema-mapping pass for `scytaledroid_core_prod`.

Scope of this pass:

- no destructive changes
- no new foreign keys
- no legacy-column drops
- no Permission Intel modifications
- repo-specific classification of current live tables and key columns

Machine-readable outputs for this pass were written under:

- `output/audit/canonical_schema_map/20260614T154650Z/`

Primary bundle files:

- `summary.json`
- `table_role_inventory.csv`
- `column_role_inventory.csv`
- `collation_drift.csv`
- `id_type_drift.csv`
- `timestamp_debt.csv`
- `status_domain_drift.csv`
- `json_signal.csv`
- `permission_interface_points.csv`

## What `scytaledroid_core_prod` Should Prove

The database should be able to prove:

1. Which package, version, APK set, and split set were analyzed.
2. Which static or dynamic run produced the result.
3. Which device, profile, scenario, tool version, and schema state applied.
4. Which evidence rows support each finding, posture surface, or research claim.
5. Whether the result is reproducible from manifests, receipts, and stored artifacts.

That produces the repo-specific spine below.

## Live Inventory Snapshot

Live inventory from `output/audit/canonical_schema_map/20260614T154650Z/summary.json`:

- Base tables: `73`
- Views: `49`
- Role counts:
  - `canonical_source`: `37`
  - `derived_read_model`: `67`
  - `ledger_audit`: `12`
  - `legacy_compatibility`: `6`
- Join-key collation drift families: `3`
- ID type/signedness drift rows: `116`
- Timestamp debt rows: `88`
- Status-domain rows: `44`
- JSON/LONGTEXT signal rows: `75`
- Permission/authority/intel interface rows: `118`

## Canonical Spine

### Identity spine

Canonical source tables:

- `apps`
- `app_versions`
- `android_apk_repository`
- `apk_sets`
- `apk_set_members`
- `apk_split_groups`
- `android_app_categories`
- `android_app_profiles`
- `android_app_publishers`
- `android_publisher_prefix_rules`
- `app_display_aliases`
- `app_display_orderings`

Important clarification:

- `artifact_registry` is a ledger of produced artifacts and link states.
- `artifact_registry` is not the canonical app/APK identity source.

### Execution spine

Canonical source tables:

- `static_analysis_sessions`
- `static_analysis_runs`
- `dynamic_sessions`
- `static_session_run_links`

Execution-adjacent ledger tables:

- `dynamic_session_issues`
- `static_session_disposition_history`
- `static_persistence_failures`
- `harvest_sessions`

### Evidence / fact tables

Static evidence/fact tables:

- `static_analysis_findings`
- `static_permission_matrix`
- `static_string_summary`
- `static_string_samples`
- `static_string_sample_sets`
- `static_string_selected_samples`
- `static_finding_evidence_payloads`
- `static_fileproviders`
- `static_provider_acl`
- `static_dynload_events`
- `static_reflection_calls`

Dynamic evidence/fact tables discovered from live schema:

- `dynamic_telemetry_network`
- `dynamic_telemetry_process`

Dynamic derived/secondary tables:

- `dynamic_network_features`
- `dynamic_network_indicators`

### Authority overlays

Current local authority overlay tables:

- `permission_audit_snapshots`
- `permission_audit_apps`
- `permission_signal_observations`
- `perm_groups`
- `doc_hosts`

Authority policy for this repo:

- Permission Intel is an external authority source.
- ScytaleDroid should snapshot or reference Permission Intel semantics.
- ScytaleDroid should not write into the Permission Intel database.

### Read models

All `v_*` and `vw_*` surfaces are classified as `derived_read_model`.

Important read-model families:

- `v_run_identity`
- `v_run_overview`
- `v_static_handoff_v1`
- `v_static_session_health_v2`
- `v_static_session_cleanup_candidates_v2`
- `v_web_runtime_run_index`
- `v_web_runtime_run_detail`
- `v_web_app_*`
- `vw_latest_permission_risk`
- `vw_permission_audit_latest`
- `vw_static_*`

### Governance

Current governance / ledger surfaces:

- `schema_migrations`
- `schema_version`
- `artifact_registry`
- `analysis_derivation_receipts`
- `db_ops_log`
- typed-linkage and parity receipt outputs under `data/state/schema_migrations/`
- prune and integrity receipts in repo-owned audit/report scripts

## Table Role Classification

Exhaustive per-table metadata is in:

- `output/audit/canonical_schema_map/20260614T154650Z/table_role_inventory.csv`

Grouped table-role classification:

### `canonical_source`

- `android_apk_repository`
- `android_app_categories`
- `android_app_profiles`
- `android_app_publishers`
- `android_publisher_prefix_rules`
- `apk_sets`
- `apk_set_members`
- `apk_split_groups`
- `apps`
- `app_display_aliases`
- `app_display_orderings`
- `app_versions`
- `device_inventory`
- `device_inventory_snapshots`
- `doc_hosts`
- `dynamic_sessions`
- `dynamic_telemetry_network`
- `dynamic_telemetry_process`
- `harvest_apk_observations`
- `permission_audit_apps`
- `permission_audit_snapshots`
- `permission_signal_observations`
- `perm_groups`
- `static_analysis_findings`
- `static_analysis_runs`
- `static_analysis_sessions`
- `static_dynload_events`
- `static_fileproviders`
- `static_finding_evidence_payloads`
- `static_permission_matrix`
- `static_provider_acl`
- `static_reflection_calls`
- `static_session_run_links`
- `static_string_samples`
- `static_string_sample_sets`
- `static_string_selected_samples`
- `static_string_summary`

### `derived_read_model`

- `analysis_cohorts`
- `analysis_cohort_runs`
- `analysis_dynamic_cohort_status`
- `analysis_ml_app_phase_model_metrics`
- `analysis_risk_regime_summary`
- `analysis_signature_deltas`
- `analysis_static_exposure`
- `dynamic_network_features`
- `dynamic_network_indicators`
- `masvs_control_coverage`
- `ml_feature_windows`
- `ml_scores`
- `risk_scores`
- `static_correlation_results`
- `static_findings_summary`
- `static_permission_risk_vnext`
- `static_session_rollups`
- `web_static_dynamic_app_summary_cache`
- all `v_*` and `vw_*` views

### `ledger_audit`

- `analysis_derivation_receipts`
- `artifact_registry`
- `db_ops_log`
- `dynamic_session_issues`
- `harvest_artifact_paths`
- `harvest_sessions`
- `harvest_source_paths`
- `harvest_storage_roots`
- `schema_migrations`
- `schema_version`
- `static_persistence_failures`
- `static_session_disposition_history`

### `legacy_compatibility`

- `buckets`
- `contributors`
- `findings`
- `metrics`
- `runs`
- `static_findings`

## Key Column Family Classification

Exhaustive column-role output is in:

- `output/audit/canonical_schema_map/20260614T154650Z/column_role_inventory.csv`

Key family interpretation:

### `session_stamp`

Canonical:

- `static_analysis_runs.session_stamp`
- `static_analysis_sessions.session_stamp`

Canonical but debt-heavy child surfaces:

- `static_session_run_links.session_stamp`
- `static_session_rollups.session_stamp`
- `static_string_summary.session_stamp`
- `static_findings_summary.session_stamp`
- `static_dynload_events.session_stamp`
- `static_fileproviders.session_stamp`
- `static_provider_acl.session_stamp`
- `static_reflection_calls.session_stamp`
- `risk_scores.session_stamp`

Legacy:

- `runs.session_stamp`

Major debt:

- `static_session_run_links.session_stamp` is `latin1_swedish_ci`
- `static_string_summary.session_stamp` and `static_findings_summary.session_stamp` are still `varchar(64)`
- several evidence child tables still use `varchar(32)` session-stamp fields

### `static_session_id`

Canonical:

- `static_analysis_sessions.static_session_id`
- `static_analysis_runs.static_session_id`
- `static_session_disposition_history.static_session_id`

Derived:

- `v_static_session_*`
- `v_web_static_*`

### `static_run_id` and `static_run_id_u`

Canonical:

- `artifact_registry.static_run_id`
- `static_session_run_links.static_run_id`
- `static_string_* .static_run_id`
- `permission_audit_* .static_run_id`
- `static_findings_summary.static_run_id`

Legacy compatibility:

- `dynamic_sessions.static_run_id`

Typed replacement:

- `dynamic_sessions.static_run_id_u`

Important debt:

- `dynamic_sessions.static_run_id` is signed `bigint(20)`
- `static_analysis_runs.id` is unsigned `bigint(20) unsigned`
- this blocks clean FK enforcement until cutover

### `dynamic_run_id` and `dynamic_run_uuid`

Canonical:

- `dynamic_sessions.dynamic_run_id`
- `dynamic_telemetry_* .dynamic_run_id`

Legacy compatibility:

- `artifact_registry.dynamic_run_id`

Typed replacement:

- `artifact_registry.dynamic_run_uuid`

Current live state:

- `artifact_registry.dynamic_run_id` and `dynamic_run_uuid` are both populated for all current dynamic rows

### `package_name` and `package_name_lc`

Canonical:

- `apps.package_name`
- most canonical evidence/execution tables still use `package_name`

Derived:

- current `package_name_lc` fields only appear in derived/view surfaces such as `v_static_handoff_v1`

Missing new:

- `apps.package_name_lc`

Interpretation:

- lowercase package identity is not yet explicit in the canonical identity spine

### `profile_key`

Canonical:

- `android_app_profiles.profile_key`
- `apps.profile_key`
- `dynamic_sessions.profile_key`
- `static_analysis_runs.profile_key`

Major debt:

- mixed collations across dictionary and execution tables

### Status columns

Current authoritative status domains that matter operationally:

- `dynamic_sessions.status`
- `static_analysis_runs.status`
- `static_analysis_sessions.session_status`
- `static_analysis_sessions.session_disposition`
- `harvest_sessions.status`
- `schema_migrations.status`
- `analysis_dynamic_cohort_status.status`

Status enforcement does not yet exist at a canonical schema-contract level.

### Timestamp columns

Typed replacement complete but not cut over:

- `static_analysis_runs.run_started_at_utc`

Legacy timestamp debt:

- `static_analysis_runs.run_started_utc`
- `schema_version.applied_at_utc`

Current live state:

- `static_analysis_runs.run_started_utc` is fully parseable and fully backfilled into `run_started_at_utc`

### JSON / LONGTEXT columns

Cold receipt / evidence payload examples:

- `artifact_registry.device_path`
- `artifact_registry.host_path`
- `schema_migrations.payload_json`
- `static_analysis_findings.evidence`
- `static_finding_evidence_payloads.evidence_json`
- `dynamic_sessions.grade_reasons_json`

Zero-signal columns right now:

- `artifact_registry.meta_json`
- `static_analysis_runs.detector_metrics`
- `static_analysis_runs.repro_bundle`
- `static_analysis_runs.analysis_matrices`
- `static_analysis_runs.analysis_indicators`

Interpretation:

- these are current deprecation candidates unless writers are intentionally restored

### Permission / authority / intel-related columns

Current interface points are inventory-only in this pass and are listed in:

- `output/audit/canonical_schema_map/20260614T154650Z/permission_interface_points.csv`

Current local overlay tables:

- `permission_audit_snapshots`
- `permission_audit_apps`
- `permission_signal_observations`
- `static_permission_matrix`
- `static_permission_risk_vnext`
- `risk_scores`
- permission-oriented views such as `v_web_permission_intel_current`

Missing new candidate columns:

- `permission_audit_snapshots.permission_intel_snapshot_id`
- `permission_audit_snapshots.permission_authority_hash`
- `static_analysis_runs.permission_authority_hash`

## Live SQL Findings

### 1. Join-key collation drift

Live drift families from `collation_drift.csv`:

- `package_name`
- `profile_key`
- `session_stamp`

Important hotspots:

- `static_session_run_links.session_stamp` is `latin1_swedish_ci`
- `apk_sets.package_name` and `harvest_apk_observations.package_name` are not aligned with most canonical package tables
- `dynamic_sessions.profile_key` and `static_analysis_runs.profile_key` are not aligned with `android_app_profiles.profile_key`

### 2. ID type / signedness drift

Most important operational mismatch:

- `dynamic_sessions.static_run_id` = `bigint(20)`
- `static_analysis_runs.id` = `bigint(20) unsigned`

This is the FK-readiness blocker.

### 3. Timestamp debt

Live string timestamp debt:

- `static_analysis_runs.run_started_utc` (`varchar(64)`)
- `schema_version.applied_at_utc` (`text`)

Live typed replacement already present:

- `static_analysis_runs.run_started_at_utc` (`datetime`)

### 4. Status-domain drift

Observed high-value live domains:

- `dynamic_sessions.status`: `success`, `degraded`
- `static_analysis_runs.status`: `COMPLETED`, `FAILED`
- `static_analysis_sessions.session_status`: `COMPLETED`, `INTERRUPTED`, `PARTIAL`
- `static_analysis_sessions.session_disposition`: `completed_profile_session`, `completed_full_session`, `interrupted_partial_session`, `mixed_completed_failed_session`

The domains are already small enough to enforce after cleanup.

### 5. JSON / LONGTEXT signal

Important live finding:

- several JSON/LONGTEXT columns are carrying real receipt/evidence payloads
- a smaller set are fully zero-signal and should move to retirement review

Zero-signal set in this pass:

- `artifact_registry.meta_json`
- `static_analysis_runs.detector_metrics`
- `static_analysis_runs.repro_bundle`
- `static_analysis_runs.analysis_matrices`
- `static_analysis_runs.analysis_indicators`

### 6. Permission Intel interface points

ScytaleDroid currently interfaces with permission authority through local overlay tables and permission-focused views.

This pass did not modify Permission Intel and did not assume the authority DB was writable.

## Phase B Migration Plan

### Phase B1: canonical join-key collation and width normalization

Exact tables / columns:

- `static_session_run_links.session_stamp`
- `static_analysis_runs.session_stamp`
- `static_analysis_sessions.session_stamp`
- `static_session_rollups.session_stamp`
- `static_findings_summary.session_stamp`
- `static_string_summary.session_stamp`
- `static_dynload_events.session_stamp`
- `static_fileproviders.session_stamp`
- `static_provider_acl.session_stamp`
- `static_reflection_calls.session_stamp`
- `apps.package_name`
- `apk_sets.package_name`
- `harvest_apk_observations.package_name`
- `android_app_profiles.profile_key`
- `apps.profile_key`
- `dynamic_sessions.profile_key`
- `static_analysis_runs.profile_key`

Why it matters:

- these are the canonical join keys that connect identity, execution, and evidence tables
- current mixed collations and short widths force brittle views and soft joins

Preflight checks:

- rerun `report_canonical_schema_map.py`
- verify no unparseable/truncated `session_stamp` values
- verify row-count parity for joined session views before/after staging

Rollback / compatibility:

- additive rehearsal on a clone first
- keep legacy read-models until view parity is proven

Tests needed:

- static session health/read-model tests
- runtime run index/detail view tests
- grain integrity and session rollout tests

Downtime:

- likely online/in-place on MariaDB for many ALTERs, but large-text/indexed join-key changes should be treated as migration-window work

Runtime writer touch:

- no writer semantic change expected, but any writer that assumes shorter `session_stamp` child widths must be checked

### Phase B2: typed-column read cutover

Exact tables / columns:

- `artifact_registry.dynamic_run_uuid` preferred over `artifact_registry.dynamic_run_id`
- `dynamic_sessions.static_run_id_u` preferred over `dynamic_sessions.static_run_id`
- `static_analysis_runs.run_started_at_utc` preferred over `static_analysis_runs.run_started_utc`

Why it matters:

- typed columns are already populated
- legacy columns are now debt, not missing data

Preflight checks:

- rerun typed-read parity report
- confirm zero mismatches for dynamic linkage, static linkage, and started-at parity

Rollback / compatibility:

- keep dual-write
- keep legacy columns readable behind fallback helpers during parity window

Tests needed:

- `report_phase_a_typed_read_parity.py`
- dynamic/static alignment report tests
- runtime health/report view tests

Downtime:

- additive/read-path change only

Runtime writer touch:

- yes; writers remain dual-write until retirement phase

### Phase B3: selective FK hardening on clean canonical relationships only

Exact tables / columns:

- `app_versions.app_id -> apps.id`
- `static_analysis_runs.static_session_id -> static_analysis_sessions.static_session_id`
- `static_analysis_runs.app_version_id -> app_versions.id`
- `static_analysis_runs.apk_set_id -> apk_sets.apk_set_id`
- `dynamic_sessions.static_run_id_u -> static_analysis_runs.id`
- `static_analysis_findings.run_id -> static_analysis_runs.id`
- `static_permission_matrix.run_id -> static_analysis_runs.id`
- `static_string_summary.run_id -> static_analysis_runs.id`
- `static_string_samples.summary_id -> static_string_summary.id`

Why it matters:

- these are canonical source relationships that should never silently drift

Preflight checks:

- confirm zero orphan rows for candidate relationships
- verify signedness/collation compatibility first

Rollback / compatibility:

- stage one FK family at a time
- leave ledger tables out of hardening

Tests needed:

- persistence tests
- static session integrity tests
- dynamic/static linkage audits

Downtime:

- depends on index creation and table size; treat as migration-window work if table rebuild is required

Runtime writer touch:

- yes; writers must satisfy stricter FK order and transactional behavior

### Phase B4: status-domain enforcement

Exact tables / columns:

- `dynamic_sessions.status`
- `static_analysis_runs.status`
- `static_analysis_sessions.session_status`
- `static_analysis_sessions.session_disposition`
- `harvest_sessions.status`
- `schema_migrations.status`
- `analysis_dynamic_cohort_status.status`

Why it matters:

- current domains are small and stable enough to enforce
- status drift currently remains a code-contract rather than a schema-contract

Preflight checks:

- rerun `status_domain_drift.csv`
- identify all observed values and map any aliases

Rollback / compatibility:

- begin with read-only audits and optional `CHECK`-style staging
- delay strict enforcement until all writers are normalized

Tests needed:

- run-health tests
- harvest summary/tests
- migration registry tests

Downtime:

- additive / low if implemented as constraint staging

Runtime writer touch:

- yes; writers must stop emitting non-canonical variants

### Phase B5: legacy / deprecated column retirement plan

Exact tables / columns:

Legacy tables:

- `runs`
- `metrics`
- `findings`
- `buckets`
- `contributors`
- `static_findings`

Deprecated / zero-signal columns:

- `artifact_registry.meta_json`
- `static_analysis_runs.detector_metrics`
- `static_analysis_runs.repro_bundle`
- `static_analysis_runs.analysis_matrices`
- `static_analysis_runs.analysis_indicators`

Also candidate legacy columns after cutover:

- `dynamic_sessions.static_run_id`
- `artifact_registry.dynamic_run_id`
- `static_analysis_runs.run_started_utc`

Why it matters:

- these surfaces confuse canonical truth with compatibility debt

Preflight checks:

- confirm no runtime code still depends on legacy-only paths
- confirm old-vs-new report/view parity

Rollback / compatibility:

- deprecate first
- remove only after one or more clean release windows and receipt-backed audits

Tests needed:

- persistence and reporting regression tests
- artifact integrity and rollout audits

Downtime:

- none for deprecation planning; actual retirement depends on later change set

Runtime writer touch:

- yes for final retirement; no for the planning phase

### Phase B6: read-model / view rebuilds after canonical cutover

Exact surfaces:

- `v_run_identity`
- `v_run_overview`
- `v_static_handoff_v1`
- `v_static_session_health_v2`
- `v_static_session_cleanup_candidates_v2`
- `v_web_runtime_run_index`
- `v_web_runtime_run_detail`
- `v_web_app_*`
- `vw_latest_permission_risk`
- `vw_permission_audit_latest`
- `vw_static_*`
- `web_static_dynamic_app_summary_cache`

Why it matters:

- current views contain type/collation workarounds that should disappear after canonical cleanup

Preflight checks:

- prove typed-read parity
- prove join-key normalization
- compare old/new result counts and selected sample rows

Rollback / compatibility:

- keep repo-owned view DDL under version control
- rebuild views from repo, not by hand in production

Tests needed:

- web/read-model tests
- static handoff view contract tests
- runtime run detail/index tests

Downtime:

- typically low; view replacement is lighter than base-table rewrite

Runtime writer touch:

- indirect only; view consumers change more than writers

## Final Recommendation

The next DB work should stay staged:

1. Freeze the canonical schema contract from this map.
2. Execute B1 before any new FK hardening.
3. Execute B2 only after parity remains clean.
4. Use B3 only for clean canonical relationships.
5. Treat B5 as a separate cleanup program, not a drive-by migration.
6. Rebuild views last, after canonical source contracts are stable.

Most important separation:

- canonical source tables store identity, execution, evidence, and local authority overlays
- derived/read-model tables and views exist to summarize, score, or serve the web/reporting surfaces
- ledger/audit tables preserve receipts and detached history and should stay FK-loose by policy
- legacy compatibility tables should not regain primary-writer status
