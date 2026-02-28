# Profile v3 Phase 2 Capture Checklist (Operator Runbook)

This is the Phase 2 execution checklist for Paper #3 (Profile v3 STRUCTURAL).
It exists to prevent redo work by making the strict manifest/export gates true
*by construction*.

## Before You Capture (Daily Start)

- Pause Play auto-updates for the capture window.
- Run v3 scoped inventory sync (Paper #3 dataset scope).
- Re-pull APKs for Paper #3 dataset (full refresh).
- Re-run Phase 1 gates (catalog + freshness + static ready). Freshness must PASS.

## During Capture (Per-App)

For each of the 21 catalog apps, capture:

- `baseline_idle`
- `interaction_scripted`

Run must satisfy (per-run hard minima):

- windows >= 20
- PCAP bytes >= 50,000
- ML artifacts exist:
  - `analysis/ml/v1/window_scores.csv`
  - `analysis/ml/v1/baseline_threshold.json`

Per-app pooled requirement (export math constraint):

- pooled idle windows >= 2 (ddof=1 requirement for sigma_idle)

## After Each Capture Session (Fast Feedback)

- Run the dashboard:
  - `python3 scripts/profile_tools/profile_v3_capture_status.py --write-audit`
- Do not start new apps until blockers are understood (missing phase vs under minima vs mixed versions).

## Version Drift (Recovery)

Policy: mixed versions are not allowed for paper-grade v3.

If an app updates mid-capture (version_code drift):

- Stop capturing that app.
- Decide one of:
  - re-harvest + recapture the affected app phases at the new version_code, OR
  - roll back by reinstalling the harvested APK version (only if your protocol allows).

Do not build the strict v3 manifest until the mixed-version condition is resolved.

## End-of-Day (Phase 2 Completion Criteria)

Phase 2 is complete when the dashboard reports:

- catalog_packages = 21
- blockers = 0

Then proceed to Phase 3:

- Build strict v3 manifest (`profile_v3_manifest_build.py --strict`)

