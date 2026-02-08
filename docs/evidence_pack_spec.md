# Evidence Pack Specification (Paper #2)

This spec defines what is considered **authoritative** for Paper #2.

## 1) Authority Model

- Evidence packs under `output/evidence/dynamic/<run_id>/` are the authoritative per-run record.
- The database is a **derived index** (rebuildable accelerator), not ground truth.
- The dataset freeze manifest is the authoritative **dataset-level selector** for Phase E.
  - Freeze manifest checksums are the **immutability anchor**; per-artifact hashes inside
    `run_manifest.json` are best-effort audit aids.

## 2) Required Frozen Inputs (Per VALID Run)

For each VALID included run, the frozen dataset consists of exactly these artifacts:

- `run_manifest.json` (single source of truth for run metadata + validity flags)
- `inputs/static_dynamic_plan.json` (embedded static snapshot; context only)
- Canonical PCAP (`pcapdroid_capture` artifact referenced in `run_manifest.json`)
- `analysis/summary.json`
- `analysis/pcap_report.json`
- `analysis/pcap_features.json`

Anything derived after freeze (ML outputs, dataset CSVs, DB rows) is not part of the frozen dataset.

## 3) Dataset Freeze Manifest (Selector + Checksums)

Canonical Paper #2 anchor:
- `data/archive/dataset_freeze-20260208T201527Z.json`

Key fields:
- `included_run_ids`: exactly 36 run_ids (12 apps x 3 runs)
- `apps[package].baseline_run_ids` and `.interactive_run_ids`
- `included_run_checksums[run_id]`:
  - `files_sha256` for the required frozen inputs
  - canonical PCAP checksum (sha256) + size

Freeze immutability verification must rely on `included_run_checksums` (dataset-level checksums),
not per-artifact hashes inside `run_manifest.json`.

## 4) Validity and Trainability

Validity (dataset correctness) lives in:
- `run_manifest.json` → `dataset.valid_dataset_run` (boolean)
- `run_manifest.json` → `dataset.invalid_reason_code` (string, when invalid)
- `run_manifest.json` → `dataset.countable` (boolean; counts toward quota)

Trainability is separate:
- `run_manifest.json` → `dataset.low_signal` (boolean)
- Low-signal does not invalidate a run.

## 5) ML Outputs (Derived, Versioned, Immutable Post-Freeze)

Per-run ML outputs live under the evidence pack:
- `output/evidence/dynamic/<run_id>/analysis/ml/v1/`
  - `anomaly_scores_iforest.csv`
  - `anomaly_scores_ocsvm.csv`
  - `model_manifest.json`
  - `ml_summary.json`

After freeze:
- ML outputs must not overwrite existing outputs for included runs.
- Bug fixes require bumping ML output version (e.g., `v2/`).

## 6) Sealing + Post-Seal Writes (Correctness Contract)

Evidence packs have a sealing moment: the final write of `run_manifest.json` for the run.

The manifest records:
- `sealed_at` (UTC ISO timestamp)
- `sealed_by` (tool identifier)

After a run is sealed:
- `run_manifest.json` must not be rewritten.
- Frozen inputs listed in the freeze manifest must not be recomputed in place.
- Only new, **versioned derived outputs** may be added (e.g., `analysis/ml/v2/`).

DB persistence is derived and must not mutate the sealed manifest. Any DB persistence status
is written as a separate derived file:
- `analysis/index/v1/db_persistence_status.json`
