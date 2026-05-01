# DynamicAnalysis ML module layout

This package is organized to keep freeze/profile-mode ML work modular and
extensible. The current batch runner (`evidence_pack_ml_orchestrator.py`) remains
the source of truth for freeze-anchored outputs.

Important: pipeline-oriented scaffolding exists, but is intentionally isolated
under `experimental/` so it cannot accidentally drift locked semantics.

## Authoritative modules (freeze/profile mode)

- `evidence_pack_ml_orchestrator.py`
  - Freeze/profile runner (freeze-driven, DB-free, deterministic).
- `evidence_pack_ml_preflight.py`
  - Frozen-input validation and deterministic window expectations.
- `pcap_window_features.py`
  - Windowing + metadata-only feature extraction from PCAP via tshark.
- `anomaly_model_training.py`
  - Fixed-model training + score normalization (higher = more anomalous).
  - Supports config-bound model specs so operational mode can tune without
    modifying locked defaults.
- `artifact_bundle_writer.py` + `deliverable_bundle_paths.py`
  - Canonical publication artifact surface under `output/publication/`.
  - Internal regression/provenance bundle under `output/_internal/` (no-drift target).
  - `io/`
  - Evidence-pack and output path helpers.

## Operational tuning hooks

- `ml_parameters_operational.py`
  - Enables feature stabilisation (`log1p`, winsorization, robust scaling).
  - Provides operational hyperparameter overrides (e.g., IF estimator count,
    OCSVM `nu`) while preserving deterministic seed behavior.
- `query_mode_runner.py`
  - Applies operational preprocessing in a deterministic order:
    matrix build -> winsorization -> robust scaling -> model fit/score.

## Experimental (NOT used for freeze/profile mode)

`experimental/` contains early pipeline abstractions that may be used in future
work. Do not import or use them for freeze/profile runs.
