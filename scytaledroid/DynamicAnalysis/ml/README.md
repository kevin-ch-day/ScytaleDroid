# DynamicAnalysis ML module layout

This package is organized to keep Phase E (Paper #2) work modular and
extensible. The current batch runner (`evidence_pack_ml_orchestrator.py`) remains
source-of-truth for Paper #2 outputs, while new pipeline-oriented work should be
built in the packages below.

## Subpackages

- `core/`
  - Pipeline primitives (`Pipeline`, `PipelineStage`, `PipelineContext`).
  - Use these to build reusable, testable data engineering flows.
- `io/`
  - Evidence-pack path helpers and future dataset readers/writers.
- `features/`
  - Feature extraction components (window stats, protocol aggregation, etc.).
- `models/`
  - Model specs, training, and scoring utilities.
- `pipelines/`
  - End-to-end pipelines built from `core` stages (preflight → feature extraction
    → training → scoring → outputs).
  - `phase_e_v1.py` provides an initial scaffold with explicit stage boundaries.

## Next steps

1. Move windowing + feature extraction utilities into `features/` as dedicated
   stage implementations.
2. Split model training/scoring into `models/` with explicit interfaces for
   dataframes/arrays.
3. Define a `pipelines/phase_e_v1.py` that wires the existing logic into
   composable stages (keeping output schemas unchanged).
4. Keep `evidence_pack_ml_orchestrator.py` as the command entrypoint, but have
   it delegate to a pipeline object for better testability.
