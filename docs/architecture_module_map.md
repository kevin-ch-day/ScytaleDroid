# Module Map (Navigation Aid)

This document is a lightweight index to help developers/reviewers answer:
"Where is the code that does X?"

It is not a design spec. It is a map.

## Paper #2 Phase E (DynamicAnalysis/ml)

Location: `scytaledroid/DynamicAnalysis/ml/`

### Dataset selector + orchestration

- `evidence_pack_ml_orchestrator.py`
  - Batch Phase E runner (DB-free).
  - Reads the canonical checksummed freeze anchor and processes **only** `included_run_ids` (36).
  - Windowing (10s/5s), baseline-only training with union fallback for training-only.
  - Writes per-run v1 outputs under each evidence pack:
    - `output/evidence/dynamic/<run_id>/analysis/ml/v1/…`
  - Writes dataset-level derived CSVs under `data/`:
    - `data/anomaly_prevalence_per_app_phase.csv`
    - `data/model_overlap_per_run.csv`
    - `data/transport_mix_by_phase.csv`
  - Writes exemplar pin file:
    - `data/archive/paper_artifacts.json`

### Evidence-pack preflight + input loading

- `evidence_pack_ml_preflight.py`
  - DB-free evidence-pack loader (`load_run_inputs`) + validity gates (`is_valid_dataset_run`).
  - Computes deterministic per-run preflight (`compute_ml_preflight`).

- `evidence_pack_ml_preflight_report.py`
  - Writes a single CSV summary of ML readiness across evidence packs (DB-free).

### Windowing + PCAP-derived window features

- `telemetry_windowing.py`
  - Deterministic 10s/5s window enumeration (`iter_windows`).

- `pcap_window_features.py`
  - Streams packet timeline via tshark (`extract_packet_timeline`) and aggregates into windows (`build_window_features`).

### Models + scoring semantics

- `anomaly_model_training.py`
  - Fixed model specs (Isolation Forest + One-Class SVM).
  - Fits models and returns anomaly scores normalized to:
    - `higher_is_more_anomalous`

### Locked parameters

- `ml_parameters_paper2.py`
  - PM/reviewer locked constants: freeze anchor filename, windowing, gates, thresholds, model IDs.

### Paths + deliverables bundle

- `deliverable_bundle_paths.py`
  - Centralizes `data/` vs `output/` path conventions for Phase E.

- `artifact_bundle_writer.py`
  - Generates a zip-and-share paper bundle under:
    - `output/paper/paper2/phase_e/`
  - Copies canonical tables, copies freeze anchor for convenience, writes Fig B1 timeline, writes a bundle manifest with hashes.

