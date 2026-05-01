# Operator Acceptance Matrix

Date: 2026-04-27

This matrix is the current operator-facing source of truth for ScytaleDroid
workflow review. It is intentionally use-case-first so CLI, DB, and Web changes
can be judged against actual operator outcomes instead of internal subsystem
boundaries.

Status terms:

- `Aligned`: current behavior matches the intended operator contract closely.
- `Usable with debt`: current behavior is workable but still carries design or
  data-quality debt.
- `Blocked by current workspace`: behavior is structurally present, but this
  workspace currently lacks the local evidence or artifacts needed for a clean
  demo.

| Use case | User action | Expected behavior | Actual current behavior | Tables written | Views read | Known issues | Priority | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1. Device inventory refresh | Device Inventory & Harvest → Refresh inventory | Attach device, collect package state, create one retained snapshot header plus package rows, sync app identity | `Aligned`. Full refresh on `ZY22JK89DR` creates `device_inventory_snapshots` + `device_inventory` rows and refreshes `apps`; scoped refresh is intentionally filesystem-only | `device_inventory_snapshots`, `device_inventory`, `apps` | none required for capture path | Non-root full inventory remains slow by design; scoped refresh does not update DB | High | DeviceAnalysis |
| 2. Harvest APKs | Device Inventory & Harvest → Execute harvest | Filter readable APK paths, pull artifacts, hash them, persist artifact lineage | `Aligned`. Non-root harvest writes readable `/data/app` APKs and records lineage cleanly; blocked system packages are reported as policy-blocked | `android_apk_repository`, `harvest_source_paths`, `harvest_artifact_paths`, `harvest_storage_roots`, `apk_split_groups` | `vw_latest_apk_per_package` for downstream consumers | Non-root policy intentionally blocks many system packages; current DB still mixes latest-capture and historical library counts in some read paths | High | DeviceAnalysis |
| 3. APK library browsing/search/selection | APK library menu | Browse/search harvested packages by package/device/capture and choose actionable APK groups | `Usable with debt`. Device grouping now resolves `ZY22JK89DR`; current library still includes historical capture groups by design | none | `vw_latest_apk_per_package` plus receipt-backed library projections | Historical library groups vs latest actionable package set still needs clearer secondary UX in detail screens | High | DeviceAnalysis |
| 4. Static analysis: all apps | Static Analysis → Analyze all harvested apps | Analyze the latest usable harvested APK set for every package, then persist one session-scoped batch | `Usable with debt`. Scope-first menu now targets latest capture per package and enters real scan flow | `apps`, `app_versions`, `static_analysis_runs`, `static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, `static_fileproviders`, `static_provider_acl`, `static_string_summary`, `static_string_samples`, `static_string_selected_samples`, `static_string_sample_sets`, `permission_audit_snapshots`, `permission_audit_apps`, `permission_signal_observations`, `static_session_rollups`, `static_session_run_links`, `static_persistence_failures` plus legacy bridge writes | `v_static_handoff_v1`, `vw_permission_audit_latest`, `v_static_run_category_summary`, downstream `v_web_app_directory`, `v_web_static_dynamic_app_summary` | Static persistence still dual-writes into legacy tables and older summary surfaces | High | StaticAnalysis |
| 5. Static analysis: profile/category | Static Analysis → Analyze by profile/category | Let operator choose a profile/category scope first, then analyze only those packages | `Usable with debt`. Scope-first menu supports grouped profile selection and then launches scan flow | Same as use case 4 for selected scope | Same as use case 4 | Profile labels come from current app metadata and still include `UNCLASSIFIED`; summary semantics remain package-level, not cohort-version-level | High | StaticAnalysis |
| 6. Static analysis: one app | Static Analysis → Analyze one app | Search by package/app label, select one app, choose Full/Fast, then scan that target | `Aligned`. Live Signal flow now reaches scan confirmation and runs analysis instead of opening drilldown | Same as use case 4 for one package | Same as use case 4 | Older versions/builds are not chosen from the landing flow; version-specific work stays in compare/review paths | High | StaticAnalysis |
| 7. Static analysis: version diff | Static Analysis → Compare two app versions | Compare the latest two distinct analyzed versions/builds for one package | `Aligned`. Diff logic now skips duplicate latest reports and uses distinct analyzed builds | none | Static diff/report readers over `static_analysis_runs`, `app_versions`, `static_analysis_findings` | Standalone script/snippet access to the diff stack still exposes a circular-import seam; CLI path works | High | StaticAnalysis |
| 8. Static prior-run review | Static Analysis → View previous runs / Re-analyze last / Drilldown | Review prior results, re-run a target, or inspect a single APK in read-only mode | `Usable with debt`. Prior-run review now opens a canonical run-history browser and canonical+legacy lineage view; re-analyze and drilldown work | Re-analyze writes same family as use case 4; read-only review writes none | Static report readers, diagnostics queries, `v_static_run_category_summary`, `v_dep_static_profile` | Review UX is materially better, but some lower-level diagnostics still expose compatibility-era semantics and interrupted runs remain verbose | Medium | StaticAnalysis |
| 9. Dynamic capture | Dynamic Analysis menu | Resolve static baseline, capture a dynamic run, emit evidence pack, persist canonical session metadata | `Blocked by current workspace`. Contract is present, but current workspace has no local evidence packs after cleanup | `dynamic_sessions`, `dynamic_session_issues`, `dynamic_telemetry_network`, `dynamic_telemetry_process`, `artifact_registry` when runs occur | `v_web_runtime_run_index`, `v_web_runtime_run_detail`, analysis cohort views later | Current workspace has `0` local evidence packs; freeze/readiness is blocked until fresh capture occurs | High | DynamicAnalysis |
| 10. Dynamic feature extraction/indexing | Dynamic processing and DB maintenance paths | Re-index evidence packs into feature rows and derived indicators without re-running the app | `Blocked by current workspace`. DB has historical sessions but current local evidence is gone, so rebuildability is low | `dynamic_network_features`, `dynamic_network_indicators`, `artifact_registry` maintenance helpers | `v_web_runtime_run_index`, `v_web_static_dynamic_app_summary`, `analysis_*` readers | `103` runs still missing features; `0` are currently buildable from local evidence in this workspace | High | DynamicAnalysis |
| 11. Reporting / Web views | Reporting & Exports and Web read models | Show stable app/runtime summaries without exposing raw table churn | `Usable with debt`. `v_web_static_dynamic_app_summary` works and CLI reporting now renders a compact terminal summary; runtime views are cleaner than static directory views | none | `v_web_app_directory`, `v_web_runtime_run_index`, `v_web_runtime_run_detail`, `v_web_static_dynamic_app_summary`, `analysis_*` views | Web and some CLI readers still depend on older static summary surfaces in places; broad reads on `v_web_static_dynamic_app_summary` are relatively expensive | High | Reporting + Database |
| 12. Governance / readiness | Governance & Readiness menu | Manage governance snapshot inputs, verify readiness, and anchor reproducible permission-governed runs | `Usable with debt`. Filesystem-canonical bundle flow works, DB mirrors governance state, and readiness reflects current snapshot presence | `permission_governance_snapshots`, `permission_governance_snapshot_rows` via importer | Governance status queries, reporting/readiness summaries | Permission meaning/governance still lives in the main DB today and is the next split target | Very high | Governance + Database |
| 13. Evidence / workspace | Evidence & Workspace menu | Inspect local artifacts, maintain workspace health, and support rebuildability | `Usable with debt`. Maintenance helpers exist and integrity checks are valuable | `artifact_registry` maintenance writes when invoked; dynamic/static maintenance helpers may null/repair references | `v_artifact_registry_integrity`, `v_current_artifact_registry`, health summaries | Current workspace cleanup removed local evidence and logs, which is valid locally but blocks some dynamic rebuild paths | Medium | DynamicAnalysis + Database |
| 14. Database tools | Database tools menu | Inspect health, query contract state, run safe maintenance, and verify schema/read models | `Aligned`. Health checks, dashboards, and repair helpers are useful and reflect live issues | Maintenance actions may touch `dynamic_sessions`, `artifact_registry`, static maintenance tables, schema bootstrap views | `v_web_static_dynamic_app_summary`, `v_web_runtime_run_index`, `v_web_app_directory`, health-check queries | Package-name collation drift is still unresolved; some helper screens still depend on compatibility summaries | High | Database |

## Current acceptance focus

The next acceptance pass should prioritize:

1. operator workflow clarity from inventory → harvest → static
2. permission-intelligence split design without breaking run outputs
3. static compatibility-bridge containment
4. dynamic rebuildability and evidence retention

## Major open issues that can change priorities

- package-name collation drift still threatens new joins and view work
- static dual-write bridge is still active and still leaks into some reader
  paths
- dynamic feature rebuildability is still limited by missing local evidence in
  this workspace
- interrupted static runs are better contained now, but still produce a long
  partial summary before the final failed-run footer

## Review rule

Any future CLI, DB, or Web change that alters one of the workflows above should
update this matrix in the same change set.
