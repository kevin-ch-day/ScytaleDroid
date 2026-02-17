# Phase F (Operational Generalization)

Phase F extends the system for operational/field use while keeping Phase E (Paper #2) frozen and reproducible.

## Phase F1 (Structural, No ML Math Changes)

What it guarantees:
- Query mode supports **N runs per app** (grouped by `base_apk_sha256`) and writes provenance to an operational snapshot.

Acceptance checks:
- `python scripts/operational/query_mode_smoke_gate.py`

## Phase F2 (Operational Math Stability + Explainability)

Applies to **query-mode operational snapshots only** (`output/operational/...`):
- Feature stabilisation: `log1p` + robust scaling (operational config).
- Persistence metrics: anomaly streak count + longest streak (seconds).
- Threshold stability diagnostics and coverage/confidence signals.
 - Operational risk summary tables (heuristic, explainable).

Operational tables:
- `output/operational/<snapshot_id>/tables/anomaly_persistence_per_run.csv`
- `output/operational/<snapshot_id>/tables/threshold_stability_per_group_model.csv`
- `output/operational/<snapshot_id>/tables/coverage_confidence_per_group.csv`
- `output/operational/<snapshot_id>/tables/dynamic_math_audit_per_group_model.csv`
- `output/operational/<snapshot_id>/tables/risk_summary_per_group.csv`

Risk scoring spec:
- `docs/operational_risk_scoring.md`

## Phase F3 (Snapshots + Closure)

Implemented:
- Each operational snapshot writes closure artifacts:
  - `selection_manifest.json` (selector provenance, config fingerprint)
  - `freeze_manifest.json` (checksummed evidence-pack inputs for immutability verification)
  - `operational_lint.json` (DB-free math/consistency audit)
  - `model_registry.json` (per group x model provenance: training run ids, thresholds, transforms)
  - `snapshot_bundle_manifest.json` (sha256 inventory of snapshot artifacts)

Tools:
- `python scripts/operational/semantic_lint_operational.py --snapshot output/operational/<snapshot_id>`
- `python scripts/operational/write_snapshot_bundle.py --snapshot output/operational/<snapshot_id>`
- `python scripts/operational/phase_f3_acceptance_gate.py`
