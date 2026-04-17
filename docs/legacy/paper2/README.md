# Paper #2 — Dynamic Dataset + Phase E (ML) Index

This folder contains the **authoritative operator + implementation contracts**
for Paper #2.

> Note: this is a legacy document kept for historical reproducibility context.
> Current ScytaleDroid versions use freeze/profile terminology and write the
> canonical publication bundle under `output/publication/` (with internal
> provenance under `output/_internal/`).

## What Paper #2 is (and is not)

Paper #2 thesis (locked):
- Execution-dependent behavior matters: static analysis shows **where exposure exists**; dynamic analysis quantifies **when deviation manifests**
  under real user interaction (idle vs interactive; messaging/text/voice/video tags).

Non-goals (explicit, reviewer-facing):
- Not malware detection.
- Not supervised classification.
- No model tuning / accuracy claims.
- No DPI / payload inspection / decryption.

## Terminology (lock for reviewer clarity)

Paper #2 uses three distinct score-like constructs; do not collapse them:
- **Static Exposure Score (StaticPostureScore, 0–100):** relative static posture index over the frozen 12-app cohort (context only).
- **Runtime Deviation Index (RDI, flagged %):** baseline-relative deviation prevalence under interaction (dynamic; not harm/risk).
- **Static (Permissions) Risk Score (0–10, A–F):** separate permissions-centric static score used outside Phase E (not a Paper #2 final score).

Semantic hierarchy (non-negotiable for interpretation):
- Primary analytic outputs: **StaticPostureScore** and **RDI (flagged %)**.
- Secondary context outputs: permission risk score/grade, MASVS finding counts.
- Interpretive overlays: exposure/deviation grades (bins) and quadrant/regime labels (not system outputs).

## Frozen Dataset Anchor (Ground Truth)

Canonical citation anchor (do not switch unless intentionally versioning dataset inputs):
- `data/archive/dataset_freeze-20260208T201527Z.json`

Selection rule (locked):
- Phase E selects **only** `included_run_ids` from the freeze manifest (exactly 36).
- Extra valid runs may exist on disk; they are **out-of-dataset** and must not be selected.

Immutability rule (locked):
- Evidence packs are authoritative.
- Freeze immutability is verified via `included_run_checksums` in the freeze manifest.
- Do not recompute frozen artifacts (`pcap_report.json`, `pcap_features.json`) for included runs.

## Where Outputs Live (Phase E)

Authoritative inputs:
- Freeze anchor: `data/archive/dataset_freeze-20260208T201527Z.json`
- Exemplar pin: `data/archive/paper_artifacts.json`

Derived dataset tables (regenerable; developer/analyst-facing):
- `data/anomaly_prevalence_per_app_phase.csv`
- `data/anomaly_prevalence_per_run.csv` *(appendix; per-run breakdown + distribution stats)*
- `data/model_overlap_per_run.csv`
- `data/transport_mix_by_phase.csv`
- `data/transport_mix_per_run.csv` *(appendix; per-run transport ratios)*

Publication deliverables bundle (zip-and-share; operator-facing):
- Canonical publication artifact surface: `output/publication/`
  - `output/publication/tables/`, `output/publication/figures/`,
    `output/publication/appendix/`, `output/publication/manifests/`
- Internal provenance/regression outputs: `output/_internal/`

Older versions of the bundle writer used `output/paper/`. New builds should not
write to that path by default.

Bundle integrity receipts:
- See `output/publication/manifests/` for canonical receipts/manifests.
- See `output/_internal/` for provenance bundles and internal audit trails.

Semantic lint (optional, recommended before sharing a bundle):
- `scripts/operational/semantic_lint_operational.py`

## Key Docs

- `docs/legacy/paper2/operator_runbook.md`
  - Operator workflow for Phase D collection, freeze, and Phase E execution.
- `docs/legacy/paper2/phase_e_plan.md`
  - Phase E (ML) contract (inputs, windowing, gates, models, outputs).
- `docs/legacy/paper2/phase_e_intelligence_map.md`
  - Research-grade control document: what is measured, where structure emerges, what ML quantifies, and non-claims.
- `docs/evidence_pack_spec.md`
  - Frozen input contract and where outputs live.
- `docs/database/derived_index.md`
  - DB posture (derived/rebuildable; Phase E runner is DB-free).
