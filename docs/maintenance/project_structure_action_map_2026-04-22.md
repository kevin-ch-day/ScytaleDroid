# Project Structure Action Map (2026-04-22)

## Goal

Reduce maintenance cost without weakening the active contracts around static
exposure, runtime deviation, evidence integrity, reporting/output, and operator
UI behavior.

This is not a broad delete pass. The safe path is to move active behavior out of
ad hoc scripts, keep scripts as thin wrappers where needed, then prune wrappers
and compatibility seams after their replacements are established.

## Current Snapshot

- Python test files: about 210.
- Tracked `scripts/` files: 63 after the unsupported wrapper prune.
- Local workspace size is dominated by ignored runtime data under `data/`,
  especially APK/evidence storage. This is not a tracked code-size problem.
- Generated caches were present across the tree and were removed in this pass.
- `.pytest_cache/` is now ignored explicitly.
- The stray `tests/deviceanalysis/` folder has been collapsed into
  `tests/device_analysis/`.

## Largest Active Maintenance Hotspots

| Area | File | Lines | Recommended action |
|---|---:|---:|---|
| Dynamic ML orchestration | `scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py` | 2770 | Split by phase: selection, cohort state, scoring, artifact writes |
| Dynamic ML artifact writing | `scytaledroid/DynamicAnalysis/ml/artifact_bundle_writer.py` | 2336 | Split writer contracts from per-format emitters |
| Static persistence | `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py` | 2126 | Split prepare/write/finalize pipeline |
| Dynamic menu/controller surface | `scytaledroid/DynamicAnalysis/menu.py` | 2087 | Move profile/status script calls into services |
| Static results flow | `scytaledroid/StaticAnalysis/cli/execution/results.py` | 1721 | Continue renderer/result/persistence follow-up split |
| Guided run controller | `scytaledroid/DynamicAnalysis/controllers/guided_run.py` | 1563 | Split state transitions from prompt/render flow |
| Reporting exports | `scytaledroid/Reporting/services/publication_exports_service.py` | 1479 | Keep as service first; split output builders next |
| Reporting menu | `scytaledroid/Reporting/menu_actions.py` | 1461 | Remove remaining script `runpy` calls |

## Script Boundary Findings

Remaining app-to-script coupling is concentrated:

- `scytaledroid/Reporting/menu_actions.py` no longer runs reporting scripts via
  `runpy`; profile/export menu actions now call app services.
- `scytaledroid/DynamicAnalysis/menu.py` now calls profile v3 capture-status and
  manifest-build services directly.
- `scripts/publication/export_profile.py` is still a script dispatcher.
- Exploratory risk scoring has been moved behind
  `scytaledroid.Reporting.services.risk_scoring_artifacts_service`; unsupported
  script wrappers were removed.
- Profile v3 integrity gates have been moved behind
  `scytaledroid.Reporting.services.profile_v3_integrity_gates_service`; the
  script entrypoint is a wrapper.
- Profile v3 phase 2 exports have been moved behind
  `scytaledroid.Reporting.services.profile_v3_phase2_exports_service`;
  unsupported script wrappers were removed.
- Profile v3 exports have been moved behind
  `scytaledroid.Reporting.services.profile_v3_exports_service`; the script
  entrypoint is a wrapper.
- Profile v3 capture status and manifest build have been moved behind
  `scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service` and
  `scytaledroid.DynamicAnalysis.services.profile_v3_manifest_build_service`; the
  script entrypoints are wrappers.

These should be treated as migration targets, not permanent architecture.

## Prune And Consolidation Classification

### Safe Now

- Generated caches: `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`,
  `.ruff_cache/`. Removed locally; regenerate as needed.
- Test namespace cleanup: `tests/deviceanalysis/` was a duplicate folder shape.
  The tests now live under `tests/device_analysis/`.

### Move Behind App Services Before Pruning

- `scripts/static_analysis/static_baseline_tables.py`
- `scripts/static_analysis/static_baseline_tables_impl.py`

These still represent useful behavior, but the application should call
`scytaledroid/` service modules directly. The scripts can remain temporary
wrappers after the move.

### Migration-Only, Prune After Milestone

- `scripts/device_analysis/migrate_legacy_harvest_storage.py`
- `scripts/device_analysis/replay_harvest_db_mirror.py`
- `scytaledroid/DeviceAnalysis/services/legacy_harvest_migration.py`
- `tests/device_analysis/test_legacy_harvest_migration.py`

Keep until the legacy harvest migration milestone is closed. Then remove the
script, service, and retire-with-code tests together.

### Likely Prune Candidates After Replacement Check

- `scripts/operator/log_device_history.py`: removed. JSON-log history should be
  replaced by DB-backed inventory/history views.
- `scripts/dev/dump_harvest_plan.py`: depends on private harvest scope helpers
  and is developer-only.
- `scripts/profile_tools/profile_v3_ml_derive.py`: removed. The active derive
  logic remains in `scytaledroid.DynamicAnalysis.ml.profile_v3_ml_derive`.
- `scripts/static_analysis/headless_all_apps.py`: likely superseded by static
  run flows and gates, but needs operator-runbook reference check.

### Keep, But Classify As Operator Or Gate Tooling

- `scripts/device_analysis/audit_apk_storage_retention.py`
- `scripts/device_analysis/inventory_determinism_gate.py`
- `scripts/static_analysis/verify_persistence_audit.py`
- `scripts/static_analysis/determinism_gate.py`
- `scripts/operator/measure_inventory_latency.py`
- `scripts/stress_static_postcheck.py`

These are useful validation tools. They should either remain explicitly
best-effort scripts or move behind service APIs if menus/cloud workflows need
them.

## Test-Suite Actions

### Completed In This Pass

- Moved ADB tests from `tests/deviceanalysis/` to `tests/device_analysis/`.
- Verified the moved ADB tests: `7 passed`.

### Next Low-Risk Test Cleanup

- Keep `tests/ui/test_global_menu_rollout.py` as a UI contract test, but reduce
  it to smoke/assertion coverage that protects menu archetypes rather than every
  formatting detail.
- Continue formatting-noise cleanup in:
  - `tests/harvest/test_harvest_views.py`
  - `tests/static_analysis/test_results_helpers.py`
- Keep large persistence and dynamic tests unless they are consolidated into
  smaller authoritative contract tests.

## Recommended Next Implementation Order

1. Finish the current publication export-service move and run full verification.
2. Extract the remaining Reporting `runpy` handlers into app services.
3. Extract Dynamic profile capture-status and manifest-build calls into app
   services.
4. Decide whether static baseline table scripts are still active reporting
   functionality or historical paper support.
5. Consolidate profile v3 preflight scripts into one service-backed command.
6. Start legacy harvest migration retirement only after the migration completion
   milestone is explicit.

## Stop Lines

- Do not delete ignored `data/` evidence/APK trees as part of code cleanup.
- Do not remove tests protecting blocked/non-root semantics, state-service
  boundaries, report/persistence contracts, or evidence meaning.
- Do not prune legacy migration code until its migration milestone and rollback
  story are documented.
- Do not keep adding application behavior to `scripts/`; new logic belongs under
  `scytaledroid/` with scripts as wrappers only when needed.
