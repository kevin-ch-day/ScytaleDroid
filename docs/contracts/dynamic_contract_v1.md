# Dynamic Contract v1 (Canonical Research Path)

## Scope
This contract applies to the canonical research dynamic pipeline path (`evidence_pack_ml_orchestrator.py`), not operational query snapshots.

## Selection and Freeze
- Selector source is the canonical checksummed freeze manifest.
- Runs are selected strictly from `included_run_ids`.
- Execution is fail-closed if the freeze manifest is missing or missing required checksum fields.
- Freeze failures are classified with:
  - `ML_SKIPPED_MISSING_FREEZE_MANIFEST`
  - `ML_SKIPPED_BAD_FREEZE_CHECKSUM`
- Exclusion reason taxonomy is closed. Unknown reason codes are invalid.

## Identity and Grouping
- Canonical group key: `base_apk_sha256` only.
- Grouping fallback to package name is not allowed in paper mode.
- Missing `base_apk_sha256` is excluded with `ML_SKIPPED_MISSING_BASE_APK_SHA256`.
- Missing or conflicting static linkage is excluded with `ML_SKIPPED_MISSING_STATIC_LINK`.

## Time-Series Windowing
- Window size: `10.0s`
- Stride: `5.0s`
- Overlapping windows are allowed.
- Partial tail windows are dropped.

## Modeled Features (Per Window)
- `bytes_per_sec` = `byte_count / window_size_s`
- `packets_per_sec` = `packet_count / window_size_s`
- `avg_packet_size_bytes`

Source fields are from PCAP packet timeline (`frame.time_relative`, `frame.len`) via `tshark`.

## Models
- Primary model: Isolation Forest.
- Robustness model: One-Class SVM.
- Both models are unsupervised and use fixed parameters.

## Training Policy
- Training mode is baseline-only.
- Baseline gates (must pass):
  - `baseline_windows >= MIN_WINDOWS_BASELINE`
  - `baseline_pcap_bytes >= baseline_min_pcap_bytes`
- Locked values (Paper v1):
  - `MIN_WINDOWS_BASELINE = 30`
  - `MIN_PCAP_BYTES = 50000`
- If gates fail, app is skipped with `ML_SKIPPED_BASELINE_GATE_FAIL` (fail-closed).
- Union fallback is not allowed in paper mode.

## Thresholding and Scores
- Per model × app threshold is the 95th percentile of training scores.
- NumPy percentile method is pinned to `linear`.
- Score semantics: higher score means more anomalous.

## Reproducibility Stamps
Each run manifest/summary must carry:
- `ml_schema_version`
- model parameters
- `threshold_percentile`
- `threshold_value`
- `np_percentile_method`
- deterministic seed metadata

## Static Linkage Requirement
Dynamic canonical linkage must include:
- `static_run_id`
- `static_handoff_hash`
- `base_apk_sha256`
- `artifact_set_hash`
- `run_signature` + `run_signature_version`

Missing/mismatched linkage must fail plan validation.

## Cohort Status Artifact
- Each paper-mode run emits `analysis/ml/v1/cohort_status.json` with:
  - `status`: `CANONICAL_PAPER_ELIGIBLE` or `EXCLUDED`
  - `reason_code`: null for eligible, exclusion reason for excluded runs
  - optional gate details for auditability

## Output Integrity
- Per-run outputs are immutable in frozen paper mode.
- Existing v1 outputs are reused; no overwrite.
- Canonical paper artifacts per run include:
  - `window_scores.csv`
  - `top_anomalous_windows.csv`
  - `attribution_proxy.csv`
  - `baseline_threshold.json`
  - `dars_v1.json` + `dars_v1.sha256`

## Perturbation Protocol (Locked)
- Controlled experiment: `idle` vs deterministic `scripted interaction`.
- No account login is required; deterministic timing only.
- Reference helpers:
  - `scripts/dynamic/run_idle.sh`
  - `scripts/dynamic/run_scripted_interaction.sh`
