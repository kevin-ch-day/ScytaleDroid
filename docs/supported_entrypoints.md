# Supported Entry Points

This project has both supported operator interfaces and internal helper scripts.
Application behavior should live under `scytaledroid/`; scripts are repo-local
automation wrappers, migration helpers, or ad hoc operator utilities. Only the
entry points listed as **Supported (stable)** are considered part of the public
interface and are expected to remain compatible across minor releases.

## Supported (stable)

### TUI (primary)

- `./run.sh` (launches the interactive menus)

### App-owned service entry points

These are the preferred non-interactive boundaries for reporting/output logic.
Scripts may call these services, but menu code should not depend on script
implementation details.

- `scytaledroid.Reporting.services.paper2_results_v2_service`
- `scytaledroid.Reporting.services.publication_status`
- `scytaledroid.Reporting.services.profile_v3_integrity_gates_service`
- `scytaledroid.Reporting.services.profile_v3_phase2_exports_service`
- `scytaledroid.Reporting.services.profile_v3_exports_service`
- `scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service`
- `scytaledroid.DynamicAnalysis.services.profile_v3_manifest_build_service`

### Repo-run wrappers (transitional)

These remain callable for automation compatibility, but they are wrappers or
operator conveniences rather than application-owned logic:

- `scripts/publication/export_profile.py` (preferred dispatcher; requires `--profile v2|v3`)
- `scripts/publication/generate_paper2_results_v2.py`
- `scripts/publication/validate_paper2_results_v2.py`
- `scripts/publication/publication_ml_audit_report.py`
- `scripts/publication/profile_v3_exports.py`
- `scripts/operator/run_profile_v2_demo.sh` (prints `EXPORT PASS` / `LINT PASS`)
- `scripts/operator/run_profile_v3_demo.sh` (prints `EXPORT PASS` / `LINT PASS`)
- `scripts/profile_tools/profile_v3_integrity_gates.py` (one-screen PASS/FAIL summary; v3 paper gate runner)
- `scripts/static_analysis/run_artifact_map.py` (read-only static session artifact audit; contract in `docs/maintenance/static_run_artifact_lifecycle.md`)
- `scripts/operator/report_system_migration_readiness.py` (read-only workspace, DB, corpus, and paper-freeze transfer preflight)

## Not supported (best-effort)

- Any `scripts/` implementation detail that is not listed above.
- Developer-only or exploratory utilities under `scripts/experimental/`.
