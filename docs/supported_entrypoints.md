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

- `scytaledroid.Reporting.services.publication_exports_service`
- `scytaledroid.Reporting.services.publication_results_numbers_service`
- `scytaledroid.Reporting.services.publication_scientific_qa_service`
- `scytaledroid.Reporting.services.publication_pipeline_audit_service`
- `scytaledroid.Reporting.services.publication_status`
- `scytaledroid.Reporting.services.risk_scoring_artifacts_service`
- `scytaledroid.Reporting.services.profile_v3_integrity_gates_service`
- `scytaledroid.Reporting.services.profile_v3_phase2_exports_service`
- `scytaledroid.Reporting.services.profile_v3_exports_service`
- `scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service`
- `scytaledroid.DynamicAnalysis.services.profile_v3_manifest_build_service`

### Repo-run wrappers (transitional)

These remain callable for automation compatibility, but they are wrappers or
operator conveniences rather than application-owned logic:

- `scripts/publication/export_profile.py` (preferred dispatcher; requires `--profile v2|v3`)
- `scripts/publication/publication_exports.py`
- `scripts/publication/publication_results_numbers.py`
- `scripts/publication/publication_scientific_qa.py`
- `scripts/publication/publication_pipeline_audit.py`
- `scripts/publication/publication_ml_audit_report.py`
- `scripts/publication/ingest_publication_bundle.py` (optional; DB mirror ingest)
- `scripts/publication/profile_v3_exports.py`
- `scripts/operator/run_profile_v2_demo.sh` (prints `EXPORT PASS` / `LINT PASS`)
- `scripts/operator/run_profile_v3_demo.sh` (prints `EXPORT PASS` / `LINT PASS`)
- `scripts/profile_tools/profile_v3_integrity_gates.py` (one-screen PASS/FAIL summary; v3 paper gate runner)

## Not supported (best-effort)

- Any `scripts/` implementation detail that is not listed above.
- Developer-only or exploratory utilities under `scripts/experimental/`.
