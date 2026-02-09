# Paper #2 — Dynamic Dataset + Phase E (ML) Index

This folder contains the **authoritative operator + implementation contracts**
for Paper #2.

## What Paper #2 is (and is not)

Paper #2 thesis (locked):
- **Android app security risk is execution-dependent.**
- Static analysis shows **where risk exists**; dynamic analysis shows **when risk matters**
  under real user interaction (idle vs interactive; messaging/text/voice/video tags).

Non-goals (explicit, reviewer-facing):
- Not malware detection.
- Not supervised classification.
- No model tuning / accuracy claims.
- No DPI / payload inspection / decryption.

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
- `data/model_overlap_per_run.csv`
- `data/transport_mix_by_phase.csv`

Paper-ready deliverables bundle (zip-and-share; operator/paper-facing):
- `output/paper/paper2/phase_e/`

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
