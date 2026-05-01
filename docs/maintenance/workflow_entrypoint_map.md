# Workflow Entrypoint Map

Round 2A only. This is a CLI/main-repo workflow routing map for the core
DB-backed path:

`device/app acquisition → harvested APK library → static analysis selection → static scan execution → persistence/finalization → DB/read-model/artifact outputs`

This document is intentionally concise. It is a workflow router, not a full
architecture doc.

Additional static review/menu paths are summarized at the end so static
operator routing does not require a second overlapping workflow doc.

## Device inventory

### Purpose

- Refresh the installed-package view for a connected device.
- Persist one retained inventory snapshot plus per-package inventory rows for DB-backed flows.

### Operator entrypoint

- `./run.sh`
- `Main Menu → Device Inventory & Harvest → Refresh inventory`

### Primary modules

- `scytaledroid/DeviceAnalysis/workflows/inventory_workflow.py`
- `scytaledroid/DeviceAnalysis/services/inventory_service.py`
- `scytaledroid/DeviceAnalysis/inventory/runner.py`
- `scytaledroid/DeviceAnalysis/inventory/db_sync.py`

### DB surfaces touched

- Canonical writes:
  - `device_inventory_snapshots`
  - `device_inventory`
  - `apps`
- Supporting identity/reference reads:
  - app/profile/category tables as needed by sync

### Generated artifacts

- Inventory JSON/state under `data/`
- Operator logs under `logs/`

### Downstream consumers

- APK harvest planning
- static scope resolution
- package identity used by static and Web app directory/read models

### Validation / smoke checks

- Narrow:
  - `tests/device_analysis/test_inventory_state.py`
  - `tests/device_analysis/test_inventory_sync_menu.py`
- Expanded:
  - `tests/inventory/*`
  - run the inventory refresh from the CLI and confirm new snapshot rows

### Common Codex risk

- Starting in `StaticAnalysis` or Web for an inventory problem.
- Treating filesystem inventory artifacts as the architecture truth instead of checking whether DB snapshot rows were written.

## APK harvest

### Purpose

- Pull APK artifacts from the device, hash them, dedupe them, and persist artifact lineage.
- Create the harvested APK library that static analysis actually consumes.

### Operator entrypoint

- `./run.sh`
- `Main Menu → Device Inventory & Harvest → Execute harvest`

### Primary modules

- `scytaledroid/DeviceAnalysis/harvest/runner.py`
- `scytaledroid/DeviceAnalysis/harvest/planner.py`
- `scytaledroid/DeviceAnalysis/harvest/scope.py`
- `scytaledroid/DeviceAnalysis/services/artifact_store.py`
- `scytaledroid/Database/db_func/harvest/*` indirectly via runner

### DB surfaces touched

- Canonical writes:
  - `android_apk_repository`
  - `harvest_source_paths`
  - `harvest_artifact_paths`
  - `harvest_storage_roots`
  - `apk_split_groups`
- Identity linkage:
  - `apps`

### Generated artifacts

- Harvested APK files under local storage roots / `data`
- Metadata sidecars
- Operator logs and harvest summaries

### Downstream consumers

- APK library review
- static analysis selection workflows
- version comparison and package/artifact identity checks

### Validation / smoke checks

- Narrow:
  - `tests/device_analysis/test_harvest_runner.py`
  - `tests/device_analysis/test_harvest_scope.py`
- Expanded:
  - `tests/harvest/*`
  - run harvest and confirm new rows in `android_apk_repository`

### Common Codex risk

- Debugging static-analysis selection before confirming harvest actually produced actionable APK rows.
- Treating harvest DB mirror failures as static-analysis failures.

## APK library review

### Purpose

- Browse/search harvested APK groups and choose actionable packages or artifacts for follow-on analysis.
- Keep “library review” separate from “run static analysis now.”

### Operator entrypoint

- `./run.sh`
- `Main Menu → APK library`
- also indirectly used by static selection flows

### Primary modules

- `scytaledroid/DeviceAnalysis/apk_library_menu.py`
- `scytaledroid/DeviceAnalysis/services/apk_library_service.py`
- `scytaledroid/DeviceAnalysis/services/static_scope_service.py`
- `scytaledroid/StaticAnalysis/core/repository.py`

### DB surfaces touched

- Primary reads:
  - `android_apk_repository`
  - `harvest_artifact_paths`
  - `apk_split_groups`
  - `apps`
- Selection persistence:
  - local manifest under `data/static_analysis/library_selection.json`

### Generated artifacts

- Local selection manifest
- CLI-only selection state

### Downstream consumers

- static analysis one-app flow
- static analysis by profile/category
- compare/review flows that need artifact grouping

### Validation / smoke checks

- Narrow:
  - `tests/device_analysis/test_apk_library_receipts.py`
  - `tests/device_analysis/test_static_scope_service.py`
- Expanded:
  - manual CLI browse/mark/unmark flow

### Common Codex risk

- Editing static scan code when the real problem is library grouping or selection persistence.
- Confusing latest actionable package selection with historical library review.

## Static analysis all apps

### Purpose

- Analyze the latest usable harvested APK set for every package in scope.
- Launch one session-scoped batch and persist canonical results.

### Operator entrypoint

- `./run.sh`
- `Main Menu → Static Analysis Pipeline → Analyze all harvested apps`

### Primary modules

- `scytaledroid/StaticAnalysis/cli/run.py`
- `scytaledroid/StaticAnalysis/cli/execution/scan_flow.py`
- `scytaledroid/StaticAnalysis/cli/flows/run_dispatch.py`
- `scytaledroid/DeviceAnalysis/services/static_scope_service.py`

### DB surfaces touched

- Canonical reads:
  - harvested APK/library identity surfaces via repository/service layers
- Canonical writes:
  - `static_analysis_runs`
  - `static_analysis_findings`
  - `static_permission_matrix`
  - `static_permission_risk_vnext`
  - `static_fileproviders`
  - `static_provider_acl`
  - `static_string_summary`
  - `static_string_samples`
  - `static_string_selected_samples`
  - `static_string_sample_sets`
  - `permission_audit_snapshots`
  - `permission_audit_apps`
  - `permission_signal_observations`
  - `static_session_rollups`
  - `static_session_run_links`
  - `static_persistence_failures`
- Legacy/compat bridge writes still touched during finalization:
  - `runs`
  - `findings`
  - `metrics`
  - `buckets`
  - `contributors`
  - `risk_scores`

### Generated artifacts

- Static reports and evidence under `output/` and `evidence/`
- Persistence audit JSON
- Permission parity snapshot output
- CLI logs (`logs/static_analysis.log`, `logs/error.log`, optional `logs/third_party/`)
- Operator log scan (session-scoped tails + audit JSON headline): `python -m scytaledroid.StaticAnalysis.audit` — see `docs/maintenance/static_analysis_audit_runbook.md`
- Workflow / health audit (design-first): `docs/maintenance/static_analysis_workflow_audit_v1.md`

### Downstream consumers

- Web app summary/detail pages
- reporting/export services
- Run Health and DB diagnostics
- static/dynamic handoff and comparison workflows

### Validation / smoke checks

- Narrow:
  - `tests/static_analysis/test_run_dispatch_linkage_order.py`
  - `tests/static_analysis/test_results_persistence.py`
- Expanded:
  - full static run via CLI
  - DB verification digest
  - persistence audit output

### Common Codex risk

- Starting in `Database` or Web before confirming whether the scan actually wrote canonical rows.
- Treating legacy bridge tables as the primary output model for new work.

## Static analysis by profile/category

### Purpose

- Analyze a scoped subset of harvested apps by operator profile/category while keeping the same underlying static execution contract.

### Operator entrypoint

- `./run.sh`
- `Main Menu → Static Analysis Pipeline → Analyze by profile/category`

### Primary modules

- `scytaledroid/StaticAnalysis/cli/run.py`
- `scytaledroid/DeviceAnalysis/services/static_scope_service.py`
- `scytaledroid/DeviceAnalysis/package_profiles.py`
- `scytaledroid/StaticAnalysis/cli/execution/scan_flow.py`

### DB surfaces touched

- Same static canonical and bridge persistence families as “all apps”
- Additional scope/profile metadata reads from:
  - `apps`
  - `android_app_profiles`
  - category/profile metadata surfaces

### Generated artifacts

- Same as “all apps,” but for the selected scope/session only

### Downstream consumers

- Same as “all apps”
- profile-scoped reporting and research dataset review

### Validation / smoke checks

- Narrow:
  - `tests/device_analysis/test_static_scope_service.py`
  - `tests/static_analysis/test_view_options_prompt.py`
- Expanded:
  - run one profile-scoped static session and verify session-linked rows

### Common Codex risk

- Starting in detector code when the issue is scope/profile resolution.
- Assuming profile selection changes the persistence contract; it should not.

## Static analysis one app

### Purpose

- Search/select a single package and run one explicit static session for that app.
- This is the focused triage entrypoint, not the read-only drilldown path.

### Operator entrypoint

- `./run.sh`
- `Main Menu → Static Analysis Pipeline → Analyze one app`

### Primary modules

- `scytaledroid/StaticAnalysis/cli/run.py`
- `scytaledroid/StaticAnalysis/cli/execution/scan_flow.py`
- `scytaledroid/StaticAnalysis/cli/flows/run_dispatch.py`
- `scytaledroid/StaticAnalysis/core/repository.py`

### DB surfaces touched

- Same canonical and bridge persistence families as the other static scan flows
- Narrower package/artifact lookup reads through repository/library surfaces

### Generated artifacts

- Same static report/evidence/persistence outputs, but for one package

### Downstream consumers

- App-level triage in downstream readers
- version compare and follow-on dynamic targeting

### Validation / smoke checks

- Narrow:
  - `tests/integration/test_persist_run_summary.py`
  - `tests/static_analysis/test_run_postprocessing.py`
- Expanded:
  - run one-app static flow and verify canonical run plus audit output

### Common Codex risk

- Confusing this path with read-only APK drilldown.
- Debugging page-level app triage when the issue is that one-app scan never entered the real run flow.

## Static persistence / finalization

### Purpose

- Convert finished static scan results into canonical DB rows, evidence artifacts, session links, and verification outputs.
- This is the core transition from “scan execution” to “trusted downstream data.”

### Operator entrypoint

- Implicit inside the static scan workflows above
- Not a separate user-facing workflow, but visible in CLI stages:
  - rendering run summary
  - finalizing persistence and evidence
  - writing persistence audit
  - permission snapshot parity
  - refreshing canonical session views

### Primary modules

- `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py`
- `scytaledroid/StaticAnalysis/cli/execution/results_persistence.py`
- `scytaledroid/StaticAnalysis/cli/flows/run_dispatch.py`
- `scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py`
- `scytaledroid/Database/db_utils/static_reconcile.py`
- `scytaledroid/Database/summary_surfaces.py`

### DB surfaces touched

- Canonical writes:
  - `static_analysis_runs`
  - `static_analysis_findings`
  - `static_findings_summary`
  - `static_findings`
  - `static_permission_matrix`
  - `static_permission_risk_vnext`
  - `static_fileproviders`
  - `static_provider_acl`
  - `static_string_summary`
  - `static_string_samples`
  - `static_string_selected_samples`
  - `static_string_sample_sets`
  - `permission_audit_snapshots`
  - `permission_audit_apps`
  - `permission_signal_observations`
  - `static_session_rollups`
  - `static_session_run_links`
  - `static_persistence_failures`
- Derived/read-model refreshes:
  - `v_web_*` consumers indirectly
  - summary cache refresh surfaces
- Legacy/compatibility surfaces still touched:
  - `runs`
  - `findings`
  - `metrics`
  - `buckets`
  - `contributors`
  - `risk_scores`

### Generated artifacts

- evidence packs / manifests / DEP JSON where applicable
- persistence audit JSON
- permission parity snapshots
- verification digest and reconciliation output
- logs under `logs/`

### Downstream consumers

- Web app pages and read models
- reporting/export generation
- Run Health and DB health tooling
- evidence/audit review
- future static/dynamic comparison

### Validation / smoke checks

- Narrow:
  - `tests/persistence/test_persistence_contracts.py`
  - `tests/persistence/test_static_sections_persistence.py`
  - `tests/static_analysis/test_results_persistence.py`
- Expanded:
  - full static run
  - inspect persistence audit artifact
  - verify DB digest and session health summary

### Common Codex risk

- Starting in Web or report readers before confirming canonical finalization succeeded.
- Fixing bridge tables first instead of checking whether canonical rows and audit artifacts are correct.
- Treating generated output files as architecture truth instead of verifying the canonical DB surfaces they summarize.

## Routing rules summary

- Inventory and harvest issues start in `DeviceAnalysis`.
- APK library/selection issues start in `DeviceAnalysis` services plus repository helpers, not in Web pages.
- Static scan execution issues start in `StaticAnalysis`.
- DB/read-model issues should start in `scytaledroid/Database` only after verifying that the source workflow wrote the expected canonical rows.
- Generated logs, `output/`, and `evidence/` are validation surfaces, not the primary ownership layer.
- Legacy bridge tables/views should be named when touched, but they are not the primary model for new work.

## Related static review paths

These are important static-analysis menu paths, but they do not create a
separate persistence contract.

### Re-analyze last app

- Purpose:
  - rerun the most recent one-app target without repeating search/selection
- Operator entrypoint:
  - `./run.sh`
  - `Main Menu → Static Analysis Pipeline → Re-analyze last app`
- Primary modules:
  - same family as one-app static flow
- DB surfaces touched:
  - same canonical and compat persistence families as one-app static analysis
- Common Codex risk:
  - treating this as a special persistence path; it is only a convenience launcher

### Compare two app versions

- Purpose:
  - compare two distinct analyzed versions/builds of one package
- Operator entrypoint:
  - `./run.sh`
  - `Main Menu → Static Analysis Pipeline → Compare two app versions`
- Primary modules:
  - static review/diff stack over analyzed run history
- DB surfaces touched:
  - primary reads from `static_analysis_runs`, `app_versions`,
    `static_analysis_findings`
- Downstream consumers:
  - app triage, version review, later research/drift analysis
- Common Codex risk:
  - confusing historical library groups with distinct analyzed versions/builds

### Single APK drilldown / previous-run review

- Purpose:
  - inspect an APK target or prior run without launching a new analysis session
- Operator entrypoint:
  - `./run.sh`
  - `Main Menu → Static Analysis Pipeline → Single APK drilldown`
  - `Main Menu → Static Analysis Pipeline → View previous static runs`
- Primary modules:
  - static review/browser flows and canonical run history readers
- DB surfaces touched:
  - primary canonical reads from `static_analysis_runs`
  - some compatibility context may still appear through legacy lineage helpers
- Downstream consumers:
  - operator review, diagnostics, bridge-aware troubleshooting
- Common Codex risk:
  - starting in scan execution code when the problem is review-only routing
