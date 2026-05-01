# Phase 5C Task List

Date: 2026-04-29

## Purpose

Phase 5C is the cleanup and trust-stability lane that must finish before Phase 6
becomes the main execution lane.

This phase is not about adding more research surfaces yet. It is about reducing
database/read-model complexity so new research pages do not inherit old bridge
and mixed-contract behavior.

Locked product decisions:

- `app_report.php` is the official app landing page.
- `view_app.php` and `android_permissions.php` remain legacy redirects only.
- App report must stay summary-only.
- Detail pages own findings, permissions, components, strings, dynamic, and run
  health.
- Run Health is the default explanation target for missing or partial data.
- Provider-first component coverage is acceptable in Phase 5C if clearly
  labeled.
- Permission Intelligence remains fleet/pattern-oriented in Phase 5C.
- Score work in Phase 5C is audit/explanation first, not aggressive
  recalibration.
- Bridge tables remain available for audit/comparison during Phase 5C, but no
  new dependency growth is allowed.

## Acceptance Bar

Phase 5C is complete when:

- remaining direct-table Web reads are inventoried and classified
- `app_report.php` is strictly summary-only
- provider-first component scope is clearly labeled
- score-model audit exists with concrete recommendations
- bridge freeze/deprecation targets are identified and documented
- Run Health can explain missing/incomplete data clearly
- no new code adds bridge reads unless marked compatibility/diagnostics
- Findings Explorer has source context and group drilldown

## Work Lanes

### 1. Web Read-Model Hardening

Goal:

- keep analyst-facing pages on approved `v_web_*` surfaces wherever possible

Tasks:

- inventory every remaining direct/internal Web read
- classify each direct read as:
  - `diagnostics_only`
  - `temporary`
  - `needs_view`
- create follow-up view work only where the page is a primary analyst surface
- keep new page work off raw canonical/bridge tables unless explicitly
  diagnostic

Current direct-read inventory from `database/db_lib/db_queries.php`:

#### Diagnostics / intentional internal reads

- `static_analysis_runs`
  - run/session quality counts
  - static run recency checks
- `runs`
  - DB health totals only
- `permission_audit_snapshots`
  - DB health totals only
- `apps`
  - catalog totals / category joins
- `dynamic_sessions`
  - runtime dashboard/run counts
- `dynamic_network_features`
  - runtime health totals
- `dynamic_network_indicators`
  - runtime run detail
- `dynamic_session_issues`
  - runtime run detail
- `analysis_cohorts`
  - runtime dashboard totals
- `analysis_cohort_runs`
  - runtime cohort detail
- `analysis_ml_app_phase_model_metrics`
  - runtime cohort detail
- `analysis_risk_regime_summary`
  - runtime dashboard/cohort detail

#### Temporary analyst-surface reads that still need cleanup

- `vw_static_finding_surfaces_latest`
  - still used by fleet component exposure helpers
  - classification: `temporary`
- `vw_static_risk_surfaces_latest`
  - still used in directory/dashboard summary joins
  - classification: `temporary`
- `static_findings_summary`
  - still used in some app summary joins
  - classification: `temporary`
- `static_string_summary`
  - still used in some app summary joins
  - classification: `temporary`
- `static_fileproviders`
  - still used for provider-first fleet and app component exposure
  - classification: `temporary`

#### Needs explicit view decision

- dynamic surfaces currently rely on runtime tables directly
  - classification: `needs_view_decision`
  - note: acceptable if `dynamic.php` and `dynamic_run.php` stay older-style
    operational pages during Phase 5C

### 2. Bridge Freeze / Deprecation

Goal:

- keep `static_reconcile.py` parity-focused and stop bridge-era reporting growth

Tasks:

- continue shrinking `static_reconcile.py` public summary payload
- keep detailed compat information in artifacts, not in normal operator
  summaries
- freeze low-risk bridge surfaces first
- prevent new first-class readers from depending on:
  - `runs`
  - `findings`
  - `metrics`
  - `buckets`
  - `contributors`
  - `risk_scores`

Current bridge posture:

- `runs` → `compat_only_keep`
- `findings` → `compat_mirror_review`
- `metrics` → `compat_mirror_review`
- `buckets` → `compat_mirror_review`
- `contributors` → `compat_mirror_review`
- `risk_scores` → `derived_review`
- `correlations` → `freeze_candidate`

Immediate bridge tasks:

- make `correlations` the first enforced freeze candidate in tooling/docs
- continue reducing reporting dependence on `findings`/`metrics`/`buckets`/
  `contributors`
- keep `risk_scores` explicitly framed as derived, not canonical

### 3. Score Audit / Explanation

Goal:

- explain score meaning and document inflation sources before major
  recalibration

Tasks:

- document which detectors/categories drive inflated grades
- document permission-score inflation separately from finding-based severity
- add or improve “why this score” explanation on app report
- keep raw/internal score diagnostics out of analyst-default surfaces

Expected outputs:

- score-model audit note
- concrete recommendations for later recalibration
- UI explanation that links score to top risk patterns

### 4. App Report Discipline

Goal:

- keep `app_report.php` summary-only by product rule

Tasks:

- remove or avoid full detailed tables on app report
- keep only:
  - top metrics
  - top risk patterns
  - data source
  - data quality
  - links to detail pages
- redirect missing-data explanations toward Run Health where appropriate

### 5. Provider-First Scope Labeling

Goal:

- be honest about current component coverage

Tasks:

- label `components.php` as provider-first fleet exposure
- label `app_components.php` as provider-first app detail
- avoid implying full Activities/Services/Receivers coverage until it exists

### 6. Run Health Maturity

Goal:

- make missing/partial data explainable without opening CLI tools

Tasks:

- improve empty-state language on analyst pages so they point to Run Health
- add session/package/run-type filtering to `run_health.php`
- make Run Health the default explanation target for:
  - missing findings
  - missing permissions
  - partial sessions
  - newer incomplete sessions

## Suggested Execution Order

1. finish the direct-read inventory and classification
2. label provider-first component coverage clearly
3. add “why this score” explanation to app report
4. tighten app report one more pass to summary-only
5. improve Run Health explanations and filtering
6. keep narrowing `static_reconcile.py` and enforce bridge freeze posture

