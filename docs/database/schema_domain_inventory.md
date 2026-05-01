# Schema Domain Inventory

This document translates the current ScytaleDroid database into logical domains.
It is intended to answer four project-management questions before any physical
database split is considered:

1. What tables/views exist right now?
2. Which objects are core and should stay?
3. Which objects are paper/export/temporary/derived?
4. Which objects feed the CLI and Web app directly?

## Current posture

ScytaleDroid already has an authoritative bootstrap manifest in
[`scytaledroid/Database/db_queries/schema_manifest.py`](../../scytaledroid/Database/db_queries/schema_manifest.py)
plus a documented "DB as derived index" posture in
[`docs/database/derived_index.md`](./derived_index.md).

This document now combines two sources of truth:

- repo-declared schema objects discovered from `db_queries/`, migrations, and
  schema gates
- observed live-database objects reported from the current
  `scytaledroid_db_dev` inventory analysis

The important complication is that the live schema is not one clean layer:

- A canonical manifest defines the newer app/static/dynamic/analysis tables.
- Web-facing read models are explicitly created as views.
- Some CLI and reporting paths still rely on older compatibility tables such as
  `android_apk_repository`, `runs`, `buckets`, and `masvs_control_coverage`.
- Inventory schema gates also expect harvest-path tables that are documented but
  not part of the current bootstrap manifest.
- The live DB contains additional important objects that do not read as first
  class in the bootstrap manifest, including permission dictionary tables,
  harvest-path tables, and web-side state tables.

So the first database task is logical classification and compatibility mapping,
not a physical split.

## Working rules

For cleanup purposes, treat each object as one of:

- `CORE_KEEP`: long-term write/read contract
- `CORE_REVIEW`: likely core, but shape or ownership is still contested
- `DERIVED_KEEP`: rebuildable but intentionally retained
- `WEB_VIEW_KEEP`: stable read contract for the Web app
- `REFERENCE_KEEP`: dictionary/governance/reference data
- `LEGACY_ACTIVE_BRIDGE`: compatibility object still on an active write path
- `LEGACY_FREEZE`: compatibility object kept read-only during migration
- `EMPTY_REVIEW`: low-confidence object, empty or superseded, verify before drop
- `DROP_LATER`: removable only after write/read paths are retired

## Domain map

### 1. Reference / dictionaries

Core lookup and governance objects that should remain stable.

Tables:

- `android_app_categories`
- `android_app_profiles`
- `android_app_publishers`
- `android_publisher_prefix_rules`
- `android_permission_dict_aosp`
- `android_permission_dict_oem`
- `android_permission_dict_unknown`
- `android_permission_dict_queue`
- `android_permission_meta_oem_prefix`
- `android_permission_meta_oem_vendor`
- `perm_groups`
- `permission_signal_catalog`
- `permission_signal_mappings`
- `permission_cohort_expectations`
- `permission_governance_snapshots`
- `permission_governance_snapshot_rows`
- `aosp_permission_baseline`

Notes:

- These are foundational inputs for classification, governance, and scoring.
- They are now the planned first-wave move candidates for a shared permission
  intelligence database (`android_permission_intel`).
- ScytaleDroid should consume their meaning through a dedicated
  permission-intel boundary rather than permanently owning these tables inside
  the operational DB.
- Classification: mostly `REFERENCE_KEEP`, with `perm_groups` marked
  `EMPTY_REVIEW` until its active role is confirmed.

### 2. App identity / package catalog

Canonical app/build identity and display metadata.

Tables:

- `apps`
- `app_versions`
- `android_apk_repository`
- `apk_split_groups`
- `device_inventory`
- `device_inventory_snapshots`
- `app_display_orderings`
- `app_display_aliases`

Notes:

- This is the newer identity model and should be treated as the canonical
  replacement for ad-hoc package naming scattered across older tables.
- In practice, the live system still depends on `apps`, `android_apk_repository`,
  and a narrower `app_versions` table that is not yet a complete harvested-version
  ledger.
- Anything web-facing should eventually resolve package identity through this
  layer.
- Classification:
  - `CORE_KEEP`: `apps`, `android_apk_repository`, `device_inventory`,
    `device_inventory_snapshots`, `apk_split_groups`
  - `CORE_REVIEW`: `app_versions`

### 3. Static analysis

Manifest, findings, permissions, strings, storage surface, and static scoring.

Tables:

- `static_analysis_runs`
- `static_analysis_findings`
- `static_session_rollups`
- `static_session_run_links`
- `static_correlation_results`
- `findings`
- `risk_scores`
- `static_findings`
- `static_findings_summary`
- `static_permission_matrix`
- `static_permission_risk`
- `static_permission_risk_vnext`
- `static_string_summary`
- `static_string_samples`
- `static_string_selected_samples`
- `static_string_sample_sets`
- `doc_hosts`
- `static_fileproviders`
- `static_provider_acl`
- `static_dynload_events`
- `static_reflection_calls`
- `permission_audit_snapshots`
- `permission_audit_apps`
- `permission_signal_observations`
- `static_persistence_failures`

Views:

- `v_static_handoff_v1`
- `vw_latest_permission_risk`
- `vw_permission_audit_latest`
- `vw_static_module_coverage`
- `vw_storage_surface_risk`
- `vw_dynload_hotspots`
- `v_provider_exposure`
- `v_static_run_category_summary`
- `v_session_string_samples`
- `v_strings_normalized`
- `v_strings_effective`
- `v_string_findings_enriched`
- `v_doc_policy_drift`

Notes:

- `static_analysis_runs` is the core canonical run ledger.
- `static_analysis_findings`, `static_findings`, and `findings` currently form
  an overlapping family and need an explicit canonical decision.
- `risk_scores`, `static_permission_risk`, `static_permission_risk_vnext`,
  `permission_audit_apps`, and `analysis_risk_regime_summary` form another
  overlapping scoring family.
- `static_permission_risk` vs `static_permission_risk_vnext` is a migration seam
  and should be tracked as compatibility debt until one contract is retired.
- `static_permission_matrix`, `static_permission_risk_vnext`,
  `permission_audit_snapshots`, `permission_audit_apps`, and
  `permission_signal_observations` remain ScytaleDroid-local run-output
  surfaces even if permission meaning/governance moves into a shared DB.
- Working classification:
  - `CORE_KEEP`: `static_analysis_runs`, `static_analysis_findings`,
    `static_permission_matrix`, `static_fileproviders`, `static_provider_acl`,
    `static_string_summary`, `static_string_samples`,
    `static_string_selected_samples`, `static_correlation_results`,
    `static_persistence_failures`
  - `CORE_REVIEW`: `static_findings`, `static_findings_summary`,
    `static_permission_risk_vnext`, `permission_audit_apps`,
    `permission_audit_snapshots`
  - `LEGACY_FREEZE`: `findings`, `risk_scores`, `static_permission_risk`
  - `EMPTY_REVIEW`: `doc_hosts` if still empty in the live DB

### 4. Dynamic analysis

Dynamic session metadata, telemetry, and derived per-run features.

Tables:

- `dynamic_sessions`
- `dynamic_session_issues`
- `dynamic_telemetry_process`
- `dynamic_telemetry_network`
- `dynamic_network_indicators`
- `dynamic_network_features`
- `ml_feature_windows`
- `ml_scores`

Notes:

- `dynamic_sessions` is the canonical dynamic run ledger.
- `dynamic_network_features` is explicitly derived and rebuildable, but it is a
  core operational index for reporting and analysis.
- Classification:
  - `CORE_KEEP`: `dynamic_sessions`, `dynamic_telemetry_network`,
    `dynamic_telemetry_process`, `dynamic_network_features`,
    `dynamic_network_indicators`, `dynamic_session_issues`
  - `EMPTY_REVIEW`: `ml_feature_windows`, `ml_scores` when empty and superseded
    by higher-level `analysis_*` summary tables

### 5. Evidence / artifacts

File-level lineage and host/device artifact tracking.

Tables:

- `artifact_registry`
- `harvest_artifact_paths`
- `harvest_source_paths`
- `harvest_storage_roots`

Views:

- `v_artifact_registry_integrity`
- `v_current_artifact_registry`

Notes:

- This is a good candidate for its own clear "artifact contract" because both
  static and dynamic workflows produce consumable outputs here.
- Classification:
  - `CORE_KEEP`: `artifact_registry`, `harvest_artifact_paths`,
    `harvest_source_paths`, `harvest_storage_roots`
  - `DERIVED_KEEP`: `v_artifact_registry_integrity`,
    `v_current_artifact_registry`

### 6. Reporting / Web read models

Stable read-only views that should shield the Web app from underlying schema
churn.

Views:

- `v_web_app_directory`
- `v_web_static_dynamic_app_summary`
- `v_web_runtime_run_index`
- `v_web_runtime_run_detail`
- `v_run_identity`
- `vw_latest_apk_per_package`

Observed live DB tables:

- `web_annotations`
- `web_user_prefs`

Notes:

- The `v_web_*` views are the clearest existing Web contract.
- `v_web_static_dynamic_app_summary` is now the preferred package-level
  cross-analysis summary surface for staged reader migration.
- If the PHP/LAMP layer remains read-only, it should consume views like these
  rather than binding directly to write tables.
- Classification:
  - `WEB_VIEW_KEEP`: `v_web_app_directory`, `v_web_runtime_run_index`,
    `v_web_runtime_run_detail`
  - `CORE_REVIEW`: `v_run_identity`, `vw_latest_apk_per_package`
  - `CORE_REVIEW`: `web_annotations`, `web_user_prefs` if the live Web app
    writes them

### 7. Research / publication / derived cohort analysis

Post-paper analysis registry and publication-facing cohort derivations.

Tables:

- `analysis_cohorts`
- `analysis_derivation_receipts`
- `analysis_cohort_runs`
- `analysis_ml_app_phase_model_metrics`
- `analysis_signature_deltas`
- `analysis_static_exposure`
- `analysis_risk_regime_summary`
- `analysis_dynamic_cohort_status`

Views:

- `v_runtime_dynamic_cohort_status_v1`
- `v_paper_dynamic_cohort_v1`

Notes:

- These are not "temporary" in the sense of being throwaway; they are derived
  research products with provenance.
- They should be isolated from operator-critical ingestion flows, but they are
  valid long-lived schema domains.
- Classification: `DERIVED_KEEP`

### 8. Operational / schema control

Tables:

- `schema_version`

Ad hoc / utility tables outside the main manifest:

- `db_ops_log` is created from database utility actions rather than from the
  canonical bootstrap manifest.

Notes:

- This domain should stay small and explicit.

## Live DB objects that need explicit classification

The PM-supplied live DB inventory surfaces several objects that deserve
first-class treatment in the schema audit even where they are not central in
the bootstrap manifest.

### Legacy static scoring / generic persistence family

Observed objects:

- `runs`
- `findings`
- `metrics`
- `risk_scores`
- `buckets`
- `contributors`
- `correlations`
- `masvs_control_coverage`
- `findings_base002`

Interpretation:

- This looks like an older static-analysis persistence layer that still has
  active readers and, in some cases, active writers.
- The current CLI persistence still references `metrics`, `buckets`,
  `contributors`, and `correlations`.
- New work should not expand this family.

Working classification:

- `LEGACY_FREEZE`: `runs`, `findings`, `metrics`, `risk_scores`, `buckets`,
  `contributors`, `correlations`
- `EMPTY_REVIEW`: `findings_base002`, `masvs_control_coverage` if they remain
  empty or near-empty in the live DB

## Legacy or compatibility seam objects

These objects are active in docs and code paths, but they are not cleanly
represented in the newer canonical bootstrap manifest.

### Legacy harvest / repository seam

Referenced heavily by CLI/docs:

- `android_apk_repository`
- `apk_split_groups`
- `harvest_artifact_paths`
- `harvest_source_paths`
- `harvest_storage_roots`

Why this matters:

- Inventory/harvest schema gates still require them.
- Query docs for the future PHP portal still describe reads over
  `android_apk_repository`.
- Some newer canonical identity flows center on `apps`, while `app_versions`
  behaves today as an analysis-owned version-parent table rather than a
  complete harvested-version ledger.

Interpretation:

- These are not dead tables. They are active compatibility objects and should be
  explicitly classified as such until they are either pulled into the canonical
  manifest or hidden behind replacement views.
- The PM-supplied inventory suggests several of them should probably be treated
  as `CORE_KEEP` or `CORE_REVIEW`, not merely as temporary leftovers.

### Legacy static-reporting seam

Referenced by older reporting and CLI helpers:

- `runs`
- `buckets`
- `masvs_control_coverage`

Why this matters:

- Several DB menus, reports, audits, and views still query them directly.
- Some newer views already mix old and new contracts (`v_run_overview`,
  `v_masvs_matrix`).

Interpretation:

- These are the main static-side compatibility tables that need a retirement or
  adapter strategy.

## What should stay

Treat these as the durable center contract of the project:

- Reference dictionaries and governance tables
- `apps`
- `app_versions` as `CORE_REVIEW`, not yet universal version truth
- `static_analysis_runs` and its canonical companion tables
- `dynamic_sessions` and `dynamic_network_features`
- `artifact_registry`
- `analysis_*` derived-cohort tables
- Web-facing `v_web_*` read models

More explicit first-pass classification:

- `CORE_KEEP`
  - `apps`
  - `android_apk_repository`
  - `apk_split_groups`
  - `device_inventory`
  - `device_inventory_snapshots`
  - `static_analysis_runs`
  - `static_analysis_findings`
  - `static_permission_matrix`
  - `static_fileproviders`
  - `static_provider_acl`
  - `static_string_summary`
  - `static_string_samples`
  - `dynamic_sessions`
  - `dynamic_telemetry_network`
  - `dynamic_telemetry_process`
  - `dynamic_network_features`
  - `dynamic_network_indicators`
  - `artifact_registry`
  - `harvest_artifact_paths`
  - `harvest_source_paths`
  - `harvest_storage_roots`
- `CORE_REVIEW`
  - `app_versions`
- `DERIVED_KEEP`
  - `analysis_cohorts`
  - `analysis_cohort_runs`
  - `analysis_derivation_receipts`
  - `analysis_static_exposure`
  - `analysis_ml_app_phase_model_metrics`
  - `analysis_signature_deltas`
  - `analysis_risk_regime_summary`
  - `analysis_dynamic_cohort_status`
- `WEB_VIEW_KEEP`
  - `v_web_app_directory`
  - `v_web_runtime_run_index`
  - `v_web_runtime_run_detail`
- `REFERENCE_KEEP`
  - all `android_permission_dict_*`
  - all `permission_governance_*`
  - all `permission_signal_*`
  - `android_app_categories`
  - `android_app_profiles`
  - `android_app_publishers`

## What should be treated as derived or publication-facing

Derived but still important:

- `dynamic_network_features`
- `ml_feature_windows`
- `ml_scores`
- `analysis_*`
- `v_runtime_dynamic_cohort_status_v1`
- `v_paper_dynamic_cohort_v1`
- `v_artifact_registry_integrity`
- `v_current_artifact_registry`

These should remain rebuildable and should not own dataset truth.

## What should be tagged as compatibility debt

- `android_apk_repository` family
- `runs`
- `buckets`
- `masvs_control_coverage`
- `static_permission_risk` when `static_permission_risk_vnext` is the intended
  successor

The key point is not to delete these immediately. First classify who writes
them, who reads them, and whether a view can preserve the contract while the
write side is modernized.

Refined first-pass freeze list:

- `LEGACY_FREEZE`
  - `runs`
  - `findings`
  - `metrics`
  - `risk_scores`
  - `buckets`
  - `contributors`
  - `correlations`
- `EMPTY_REVIEW`
  - `findings_base002`
  - `static_correlation_results` when unused
  - `ml_feature_windows`
  - `ml_scores`
  - `masvs_control_coverage`
  - `perm_groups`
  - `doc_hosts`

## Direct consumers

### CLI-facing contracts

Directly important to the CLI today:

- Inventory/harvest gates depend on `device_inventory*` plus legacy harvest
  objects such as `android_apk_repository` and related path tables.
- Static-analysis gates depend on `static_analysis_runs`,
  `static_session_run_links`, `static_session_rollups`,
  `static_permission_risk_vnext`, string tables, and `v_static_handoff_v1`.
- Dynamic workflows depend on `dynamic_sessions` and analysis cohort views such
  as `v_runtime_dynamic_cohort_status_v1`.
- Older DB menus and reports still depend on `runs`, `buckets`, and
  `masvs_control_coverage`.

### Web-facing contracts

The clearest Web-facing contract objects are:

- `v_web_app_directory`
- `v_web_runtime_run_index`
- `v_web_runtime_run_detail`
- `vw_latest_permission_risk`
- `vw_permission_audit_latest`
- `vw_latest_apk_per_package`

These should be treated as read-only compatibility views whose column shape is
deliberately stable.

## Target operating model

This is the contract direction the schema cleanup should enforce:

- CLI writes to core tables.
- Analysis derivation jobs write to `analysis_*` tables.
- Web app reads from `v_web_*` views and only writes narrowly scoped web-state
  tables such as annotations/preferences if needed.
- Paper exports read from frozen `analysis_*` tables and cohort views.
- Legacy tables remain read-only until replacement is complete.

The missing bridge object is a first-class static-dynamic summary view, likely
named `v_web_static_dynamic_app_summary`.

## Recommended next step

Before any schema split or large migration, create a single audit matrix with
one row per table/view and at least these columns:

- object_name
- object_type (`table` or `view`)
- logical_domain
- status (`core`, `derived`, `publication`, `compatibility`, `unclear`)
- bootstrap_source
- write_owner
- read_consumers (`cli`, `web`, `reports`, `tests`)
- replacement_target (if legacy)

That matrix will let ScytaleDroid separate:

- canonical write schema
- stable read contracts
- derived research schema
- legacy compatibility seams

without breaking the CLI or the Web app.

The next useful evidence pull is:

- foreign-key map from `information_schema.key_column_usage`
- PK/index map from `information_schema.statistics`
- `SHOW CREATE VIEW` for the `v_web_*` views

That will answer:

- which tables the Web app truly depends on
- which legacy tables still have structural importance
- whether compatibility views can replace direct reads cleanly
