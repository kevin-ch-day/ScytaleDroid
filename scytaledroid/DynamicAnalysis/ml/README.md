# DynamicAnalysis ML module layout

This package is organized to keep Phase E (Paper #2) work modular and
extensible. The current batch runner (`evidence_pack_ml_orchestrator.py`) remains
source-of-truth for Paper #2 outputs.

Important: pipeline-oriented scaffolding exists, but is intentionally isolated
under `experimental/` so it cannot accidentally drift Paper #2 semantics.

## Authoritative modules (Paper #2)

- `evidence_pack_ml_orchestrator.py`
  - Paper #2 Phase E runner (freeze-driven, DB-free, deterministic).
- `evidence_pack_ml_preflight.py`
  - Frozen-input validation and deterministic window expectations.
- `pcap_window_features.py`
  - Windowing + metadata-only feature extraction from PCAP via tshark.
- `anomaly_model_training.py`
  - Fixed-model training + score normalization (higher = more anomalous).
- `artifact_bundle_writer.py` + `deliverable_bundle_paths.py`
  - Canonical paper artifact surface under `output/paper/` (stable paths for LaTeX).
  - Internal Phase E baseline bundle under `output/paper/internal/baseline/` (regression/no-drift target).
- `io/`
  - Evidence-pack and output path helpers.

## Experimental (NOT used for Paper #2)

`experimental/` contains early pipeline abstractions that may be used in future
work. Do not import or use them for Paper #2 Phase E.
