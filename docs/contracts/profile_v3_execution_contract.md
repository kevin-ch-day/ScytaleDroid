# Profile v3 Execution Contract (Paper #3)

This contract defines the fixed execution protocol for **Profile v3 (STRUCTURAL)** used in Paper #3.
It exists to make Phase 2 capture and downstream analysis reproducible and reviewer-auditable.

## Cohort (Predefined)

- Cohort is defined by `profiles/profile_v3_app_catalog.json` (hash-locked).
- Each app has a predefined `app_category` (domain label) used for domain-level comparisons.

## Environment (Controlled)

- Same physical device model/serial for the capture window.
- Same OS build for the capture window.
- Same network type (Wi-Fi) and capture interface (`wlan0`).
- Play auto-updates paused for the capture window (recommended).

## Phases (Required)

Per app, collect repeated captures for:

1. **Idle**: `baseline_idle` (phase = `idle`)
2. **Interactive**: `interaction_scripted` (phase = `interactive`)
   - If time-constrained, `interaction_manual` may be used, but must be explicitly labeled and included only in predefined datasets.

## Interaction Definition

- **Idle** means: app in foreground, screen on, no intentional operator interactions.
- **Interactive** means: bounded interaction under one of:
  - a scripted template (preferred), or
  - manual interaction with operator guidance and a bounded duration.

## Windowing (Fixed)

- Window size: 10 seconds
- Stride: 5 seconds

## Duration (Fixed)

- Minimum duration per run: 120 seconds
- Target duration per run: 180-240 seconds (script templates may overrun; overruns are allowed)

## Eligibility (Per-Run)

A run is eligible for inclusion only if:

- windows >= 20
- PCAP bytes meets the active phase-specific minimum (see `docs/dynamic_analysis_contract.md`)
- ML artifacts exist:
  - `analysis/ml/v1/window_scores.csv`
  - `analysis/ml/v1/baseline_threshold.json`

## Repeats (Reproducibility Target)

- Target: 3 eligible runs per app per phase (3 idle + 3 interactive).

## Version Policy

- Runs are retained (no pruning during Phase 2 burn-down).
- Mixed `version_code` within an app is recorded as a warning for Phase 2 progress.
- Paper analysis must include a predefined sensitivity dataset excluding mixed-version apps.

## Predefined Sensitivity Filters (Paper)

Paper #3 conclusions should be reported with:

- Primary dataset: interactive = scripted|manual (if manual was used)
- Sensitivity A: scripted-only interactive
- Sensitivity B: single-version-only apps

## Outputs (What Must Be Recorded)

Per run, the system must persist:

- `run_id`, package, app_category
- run_profile + phase
- template id/hash (if scripted)
- version_code (+ version_name when available)
- window count and PCAP bytes
- ML artifacts + receipt fields indicating success/failure
