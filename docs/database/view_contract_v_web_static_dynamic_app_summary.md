# View Contract: `v_web_static_dynamic_app_summary`

Status: implemented transitional v1

## Purpose

This view is the cross-analysis read model for the Web app and
dashboard-style reporting.

It should answer one row per package:

- who is the app
- what is the latest static posture
- what is the latest dynamic posture
- what is the current static/dynamic relationship summary

This is the missing bridge between:

- static analysis
- dynamic analysis
- derived regime analysis
- package identity/display metadata

## Design goals

- Read-only contract for the Web app
- One row per `package_name`
- No direct dependency on legacy static tables such as `runs`, `findings`,
  `metrics`, or `buckets`
- Use canonical or intentionally supported summary sources only
- Stable enough that the Web app can depend on it without understanding the
  underlying schema

## Row grain

- one row per package
- package-level latest-state summary only

Important limitation:

- this is **not** an artifact-exact lineage view
- it joins by `package_name`
- it selects the latest static and latest dynamic posture per package
- it does not prove that static and dynamic rows share the same
  `base_apk_sha256`
- it is suitable for Web/dashboard posture summaries, not per-version forensic
  comparison

Primary key candidate:

- `package_name`

## Recommended source layers

### Identity layer

Use:

- `apps`
- `android_app_categories`
- `android_app_profiles`
- `vw_latest_apk_per_package`

These provide:

- package name
- display label
- category
- profile label
- latest APK/version/hash context

### Static posture layer

Implemented v1 transitional source:

- `static_findings_summary`
- `vw_permission_audit_latest`
- `static_permission_risk_vnext` aggregated per latest static run when needed

Recommended v2 target:

- canonical aggregation over `static_analysis_findings`
- canonical join to `static_analysis_runs`
- supporting contract readers should prefer:
  - `vw_static_finding_surfaces_latest`
  - `vw_static_risk_surfaces_latest`

Reason for transitional v1:

- `v_web_app_directory` still depends on `static_findings_summary`
- the project has not yet decided whether `static_findings_summary` remains a
  long-term summary table or is replaced by a canonical derived view

### Dynamic posture layer

Use:

- `dynamic_sessions`
- `dynamic_network_features`
- latest valid row logic equivalent to `v_web_runtime_run_index`

These provide:

- latest dynamic run id
- run profile
- interaction level
- runtime grade
- feature availability
- low-signal flags
- selected throughput/packet metrics

### Derived regime layer

Use:

- `analysis_risk_regime_summary`

This provides:

- static regime grade
- dynamic regime grade
- dynamic score
- final regime label

## Proposed columns

### Identity and display

- `package_name`
- `app_label`
- `category`
- `profile_label`
- `publisher_key`

### Latest APK/build identity

- `latest_apk_id`
- `latest_apk_sha256`
- `latest_version_name`
- `latest_version_code`
- `latest_harvested_at`

### Static posture summary

- `latest_static_run_id`
- `latest_static_session_stamp`
- `static_source_state`
- `static_high`
- `static_med`
- `static_low`
- `static_info`
- `permission_audit_grade`
- `permission_audit_score_capped`
- `permission_risk_rows`

### Dynamic posture summary

- `latest_dynamic_run_id`
- `latest_dynamic_started_at_utc`
- `latest_dynamic_status`
- `latest_dynamic_grade`
- `dynamic_run_profile`
- `dynamic_interaction_level`
- `dynamic_valid_dataset_run`
- `dynamic_invalid_reason_code`
- `dynamic_feature_state`
- `dynamic_low_signal`
- `dynamic_packet_count`
- `dynamic_bytes_per_sec`
- `dynamic_packets_per_sec`

### Cross-analysis / regime summary

- `regime_static_grade`
- `regime_dynamic_grade`
- `regime_dynamic_score`
- `regime_final_label`
- `regime_created_at_utc`

### Contract/debug indicators

- `has_static_data`
- `has_dynamic_data`
- `has_regime_data`
- `summary_state`

`summary_state` examples:

- `static+dynamic+regime`
- `static+dynamic`
- `static_only`
- `dynamic_only`
- `catalog_only`

## Transitional implementation guidance

### v1 should avoid these direct sources

- `runs`
- `findings`
- `metrics`
- `buckets`
- `contributors`
- `correlations`

### v1 may temporarily depend on these supported summary sources

- `static_findings_summary`
- `vw_permission_audit_latest`
- `vw_latest_apk_per_package`

Supporting contract readers now available:

- `vw_static_finding_surfaces_latest`
- `vw_static_risk_surfaces_latest`

Reason:

- they are already active read contracts in the current system
- replacing them should be a staged migration, not a prerequisite for the view

## Null and freshness semantics

- if no static data exists, static columns are `NULL` and `has_static_data=0`
- if no dynamic data exists, dynamic columns are `NULL` and `has_dynamic_data=0`
- if no derived regime exists, regime columns are `NULL` and `has_regime_data=0`
- the view must not suppress catalog rows just because one analysis axis is
  missing

## Recommended ordering and filters

Default ordering:

- `app_label ASC`

Useful filters:

- category
- profile
- has static data
- has dynamic data
- regime final label
- permission audit grade
- low signal

## Migration note

This view should be introduced as a new contract.

It should not replace `v_web_app_directory` immediately.

Recommended rollout:

1. create `v_web_static_dynamic_app_summary`
2. build one web screen against it
3. compare row coverage with existing directory/runtime pages
4. only then consider refactoring `v_web_app_directory`
