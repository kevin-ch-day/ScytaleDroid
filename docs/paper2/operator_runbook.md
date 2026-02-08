# Paper #2 Operator Runbook (Dynamic Collection + Freeze + Phase E)

This runbook is for operators collecting and validating the Paper #2 dataset and
running Phase E ML without drifting the frozen inputs.

Index / context:
- `docs/paper2/README.md`

## 1) During Dynamic Collection (Phase D)

Goal per app (Paper #2 quota, locked):
- 1 baseline idle run
- 2 interactive runs

Notes:
- Run order does not matter. Operators choose run tags (Idle/Normal/Heavy).
- Extra valid runs are allowed (out-of-dataset) but should be capped to avoid time variance.
- Messaging apps must be tagged with messaging activity (text/voice/video/mixed/none) going forward.

Recommended operator loop (per app):
1. Run baseline idle (>= 3 minutes recommended; minimum enforced by QA).
2. Run interactive (normal use) twice.
3. For messaging apps, collect at least one interactive run that exercises the intended activity.

## 2) Evidence Pack Verification (Workspace & Evidence)

Use the menu:
- **Workspace & Evidence → Verify evidence packs (overview)**
- **Workspace & Evidence → Dynamic evidence packs → Deep checks**

Use cleanup only when needed:
- Delete INVALID dataset runs (local only)
- Prune DB orphans (derived; safe)

Important:
- Evidence packs are authoritative.
- DB is derived and may drift; rebuild index when needed.

## 3) Freeze (Dataset Anchor, Non-Mutating)

Freeze file (canonical citation anchor for Paper #2):
- `data/archive/dataset_freeze-20260208T201527Z.json`

Freeze rules:
- Freeze manifest lists the exact included run set (36 run_ids).
- It contains checksums for the frozen inputs per included run.
- The freeze manifest does not mutate evidence packs.

After freeze:
- Do NOT run “Recompute PCAP artifacts” on the 36 included runs.
- Do NOT delete or rename included evidence pack directories.
- If a run must be removed/replaced, that is a dataset version bump (rare).

## 4) Freeze Immutability Check (Hash-Based)

Use:
- **Dynamic evidence packs → V) Verify freeze immutability (hash-based)**

Expected:
- scanned=36
- mismatches=0
- missing=0

If mismatches occur:
- Stop.
- Do not “fix” the packs in place.
- Decide whether this is an operator error (wrong file) or a dataset version bump.

## 5) Phase E (ML) Execution

Paper #2 Phase E posture:
- Evidence-pack-only inputs (no DB reads for selection/training/scoring).
- Deterministic windowing and seeds.
- Fixed models (IF + OC-SVM), percentile thresholding.

Run:
- **Reporting → Run ML on frozen dataset (offline, evidence-pack only)**

Outputs:
- Per run: `output/evidence/dynamic/<run_id>/analysis/ml/v1/…`
- Dataset tables:
  - `data/anomaly_prevalence_per_app_phase.csv`
  - `data/model_overlap_per_run.csv`
  - `data/transport_mix_by_phase.csv`

Paper artifact lock file:
- `data/archive/paper_artifacts.json` (pins Fig B1 exemplar run_id)

Post-freeze bug policy:
- Version ML outputs (bump `ml_schema_version` / output path).
- Do not mutate evidence packs.
