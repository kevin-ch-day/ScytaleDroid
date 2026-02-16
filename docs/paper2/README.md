# Paper #2 — Dynamic Dataset + Phase E (ML) Index

This folder contains the **authoritative operator + implementation contracts**
for Paper #2.

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

Paper-ready deliverables bundle (zip-and-share; operator/paper-facing):
- Canonical paper artifact surface: `output/paper/`
  - Paper-facing: `output/paper/tables/`, `output/paper/figures/`, `output/paper/appendix/`, `output/paper/manifests/`
  - Internal provenance: `output/paper/internal/`

Bundle integrity receipts (inside the bundle):
- `output/paper/internal/provenance/phase_e_artifacts_manifest.json` (hashes + provenance pointers)
- `output/paper/manifests/phase_e_closure_record.json` (pins freeze sha256 + bundle-manifest sha256)

Semantic lint (optional, recommended before sharing a bundle):
- `scripts/operational/semantic_lint_operational.py`

## Key Docs

- `docs/paper2/operator_runbook.md`
  - Operator workflow for Phase D collection, freeze, and Phase E execution.
- `docs/paper2/phase_e_plan.md`
  - Phase E (ML) contract (inputs, windowing, gates, models, outputs).
- `docs/paper2/phase_e_intelligence_map.md`
  - Research-grade control document: what is measured, where structure emerges, what ML quantifies, and non-claims.
- `docs/evidence_pack_spec.md`
  - Frozen input contract and where outputs live.
- `docs/database/derived_index.md`
  - DB posture (derived/rebuildable; Phase E runner is DB-free).
