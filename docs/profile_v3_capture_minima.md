# Profile v3 Capture Minima (Operator Contract)

This document is the human-visible summary of the capture minima enforced by the
tooling for **Profile v3 (STRUCTURAL)**. It exists to prevent under-capture and
redo work during cohort stabilization.

## Required Per-App Runs (Profile v3)

Each app in the v3 catalog requires, at minimum:

- `baseline_idle` (idle/baseline phase)
- `interaction_scripted` (interactive scripted phase)

Manual-only interaction is excluded by default for Profile v3 publication exports.

## Windowing (Fixed)

- Window size: `10s`
- Stride: `5s`

## Capture Duration (Targets and Minimums)

- Target duration per run: `180s` (`scytaledroid/Config/app_config.py:DYNAMIC_TARGET_DURATION_S`)
- Minimum duration for dataset-tier validity: `120s` (`scytaledroid/Config/app_config.py:DYNAMIC_MIN_DURATION_S`)

If a run does not meet the minimum duration, it will not be eligible for paper-grade
cohort inclusion.

## Minimum Windows (Dataset-Tier Validity)

- Minimum windows per run: `20` (`scytaledroid/DynamicAnalysis/pcap/dataset_tracker.py:MIN_WINDOWS_PER_RUN`)

Runs below this threshold are not paper-grade.

Additional (export-math) requirement:

- Pooled idle windows for a given app must be `>= 2` so pooled `sigma_idle` can be computed with `ddof=1`.
  - Source: `scytaledroid/Publication/profile_v3_metrics.py` (pooled idle SD with `ddof=1`)

## Minimum PCAP Bytes (Dataset-Tier Validity)

Profile v3 uses phase-specific minima:

- `baseline_idle` minimum (paper eligibility): `0B`
  - Source: `scytaledroid/DynamicAnalysis/ml/ml_parameters_profile.py:MIN_PCAP_BYTES_V3_IDLE`
- `interaction_scripted` minimum (paper eligibility): `40,000B`
  - Source: `scytaledroid/DynamicAnalysis/ml/ml_parameters_profile.py:MIN_PCAP_BYTES_V3_SCRIPTED`

Capture observer default minimum (capture QA):

- `100,000B`
  - Source: `scytaledroid/Config/app_config.py:DYNAMIC_MIN_PCAP_BYTES`

Operator guidance:

- Treat the run as paper-grade only when the run summary reports `VALID` and the
  reported `MIN_PCAP_BYTES` threshold is satisfied for that run.
- If the capture observer reports the PCAP is too small, re-run the capture with
  a longer duration or ensure interaction generates sufficient traffic.

## Scripted-Only Policy (Profile v3 Publication)

Profile v3 publication exports are scripted-only by default:

- Included: `interaction_scripted`
- Excluded (default): `interaction_manual`

## Related Tools

- Reporting -> Profile v3 -> Run v3 integrity gates
- `scripts/profile_tools/profile_v3_apk_freshness_check.py`
- `scripts/profile_tools/profile_v3_scripted_coverage_audit.py`
- `scripts/profile_tools/profile_v3_manifest_build.py`
- `scripts/operator/run_profile_v3_demo.sh` (strict export + strict lint)
