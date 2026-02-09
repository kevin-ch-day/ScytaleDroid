# Phase F (Operational Generalization)

Phase F extends the system for operational/field use while keeping Phase E (Paper #2) frozen and reproducible.

## Phase F1 (Structural, No ML Math Changes)

What it guarantees:
- Freeze mode (Phase E) remains DB-free and reproduces under the pinned paper toolchain.
- Query mode supports **N runs per app** (grouped by `base_apk_sha256`) and writes provenance to an operational snapshot.

Acceptance gates:
- Run in the UI: `Reporting → Paper / ML → Phase F1 acceptance gates (regression + query smoke)`
- Or run headless: `python scripts/operational/write_phase_f1_closure.py`

Closure artifact:
- `data/archive/phase_f1_closure.json`

## Phase F2 (Operational Math Stability + Explainability)

Applies to **query-mode operational snapshots only** (`output/operational/...`):
- Feature stabilisation: `log1p` + robust scaling (operational config).
- Persistence metrics: anomaly streak count + longest streak (seconds).
- Threshold stability diagnostics and coverage/confidence signals.

Operational tables:
- `output/operational/<snapshot_id>/tables/anomaly_persistence_per_run.csv`
- `output/operational/<snapshot_id>/tables/threshold_stability_per_group_model.csv`
- `output/operational/<snapshot_id>/tables/coverage_confidence_per_group.csv`
- `output/operational/<snapshot_id>/tables/dynamic_math_audit_per_group_model.csv`
- `output/operational/<snapshot_id>/tables/risk_summary_per_group.csv`

Risk scoring spec:
- `docs/operational_risk_scoring.md`

## Phase F3 (Snapshots + Closure)

Not implemented yet:
- Snapshot protocol v2 (query selection → new freeze artifact).
- Model lifecycle / registry artifacts and paper sensitivity packaging.
