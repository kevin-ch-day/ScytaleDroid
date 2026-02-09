# Phase F1 Touchpoint Map (Planning)

This map enumerates where Phase E assumptions live so Phase F1 can introduce query mode
without breaking the paper freeze path. It is an orientation artifact (not code changes).

## 1) Run selection + freeze coupling (Phase E / paper snapshot)

**Primary selector (hard-coded to freeze)**
- `scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py`
  - Reads the canonical freeze manifest, loads `included_run_ids`, and enforces baseline + 2 interactive
    per app when running the locked Phase E flow. Query mode should be layered alongside this entrypoint,
    not replace it.【F:scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py†L1-L209】

**Freeze artifact generator (enforces “1 baseline + 2 interactive”)**
- `scytaledroid/DynamicAnalysis/tools/evidence/freeze_manifest.py`
  - Builds `included_run_ids` from dataset plan and run profiles; enforces baseline + interactive quotas;
    includes checksums for frozen inputs and canonical PCAPs.【F:scytaledroid/DynamicAnalysis/tools/evidence/freeze_manifest.py†L1-L216】

**Freeze immutability verifier**
- `scytaledroid/DynamicAnalysis/tools/evidence/freeze_verify.py`
  - Validates frozen inputs for the included run set using `included_run_ids` and checksums.【F:scytaledroid/DynamicAnalysis/tools/evidence/freeze_verify.py†L1-L140】

**Locked constants**
- `scytaledroid/DynamicAnalysis/ml/ml_parameters_paper2.py`
  - Anchors the canonical freeze filename and other PM-locked constants (windowing, thresholds).【F:scytaledroid/DynamicAnalysis/ml/ml_parameters_paper2.py†L1-L77】

**Minimal interface needed for query mode**
- Introduce a selector interface that returns `RunRef` objects (run_id, package_name, mode, tags, paths).
- Freeze mode = selector backed by `included_run_ids`.
- Query mode = selector backed by evidence packs / DB filtering (Phase F1).

## 2) Label normalization + phase inference

**Evidence-pack inputs (current fields used)**
- `run_manifest.json`:
  - `target.package_name`
  - `operator.run_profile`
  - `dataset.tier`, `dataset.valid_dataset_run`
  - `artifacts[].type == pcapdroid_capture` → canonical PCAP path
  - These are read in `load_run_inputs` and `is_valid_dataset_run`.【F:scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_preflight.py†L36-L116】

**Preflight report (current output fields)**
- `evidence_pack_ml_preflight_report.py` exports `run_profile`, `identity_key`, `dataset_valid`,
  and windowing expectations. This is the current “label visibility” surface for F1 audits.【F:scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_preflight_report.py†L14-L83】

**Minimal normalization hooks for F1**
- Normalize `run_profile` values into `mode = baseline | interactive | unknown`.
- Allow missing/ambiguous labels to map to `unknown` (as discussed with PM).
- Keep Phase E freeze behavior unchanged.

## 3) Windowing + feature determinism

**Deterministic window spec + drop-partial behavior**
- `telemetry_windowing.iter_windows()`:
  - Windows are `[start, end)`; windows where `end > duration_s` are dropped.
  - Returns count of dropped partial windows for auditability.【F:scytaledroid/DynamicAnalysis/ml/telemetry_windowing.py†L12-L46】

**Feature construction**
- `pcap_window_features.build_window_features()`:
  - Deterministically bins packets into fixed windows and returns row counts + dropped windows.
  - Uses tshark packet timeline (time_relative + length) only.【F:scytaledroid/DynamicAnalysis/ml/pcap_window_features.py†L13-L139】

## 4) Models, scoring, thresholds

**Fixed model specs and score semantics**
- `anomaly_model_training.py`:
  - IsolationForest + OneClassSVM, fixed params.
  - Scores inverted so “higher = more anomalous.”【F:scytaledroid/DynamicAnalysis/ml/anomaly_model_training.py†L1-L66】

**Training regime + thresholding**
- `evidence_pack_ml_orchestrator.py`:
  - Baseline-only training with union fallback if baseline gates fail.
  - Threshold = 95th percentile of training scores.【F:scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py†L271-L389】

**Edge-case metrics to audit (Phase F1 tracking)**
- baseline gate failures (bytes + MIN_WINDOWS_BASELINE)
- union fallback frequency
- training sample size distribution
- threshold == max(score_train)

## 5) Experimental pipeline wiring (non-authoritative)

**Scaffold only**
- `ml/experimental/pipelines/phase_e_v1.py` defines staged pipeline placeholders; it does not replace
  the orchestrator’s operational flow. Keep refactors aligned to orchestrator unless explicitly switching
  to the pipeline system.【F:scytaledroid/DynamicAnalysis/ml/experimental/pipelines/phase_e_v1.py†L1-L90】

## 6) Scripts to generate Phase F counts (operational audits)

Use these scripts to generate the “how often does X happen?” planning metrics:
- `scripts/operator/log_run_timeline.py`
- `scripts/operator/log_error_summary.py`
- `scripts/operator/audit_dynamic_network_consistency.py`
- `scripts/operator/diagnose_scope.py`
- `scripts/operator/diagnose_static_pipeline.py`
- `scripts/operator/env_check.py`
- `scripts/dev/check_dataset_ready.sh`
- `scripts/dev/get_latest_run.py`
- `scripts/dev/netstats_verify.py`
- `scripts/dev/debug_netstats_uid.sh`

## 7) Deliverable for Phase F1 planning

**Recommended output**: a lightweight audit table (CSV/JSON) that records:
- union_fallback frequency
- baseline gate failures (bytes + window count)
- training sample size distribution
- threshold == max(score_train) incidence
- dropped window counts
- missing label frequency (run_profile missing/unknown)

This map should be updated once query mode and label normalization are implemented.
