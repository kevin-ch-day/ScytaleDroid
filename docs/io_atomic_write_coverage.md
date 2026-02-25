# Atomic Write Coverage (Derived Artifacts)

ScytaleDroid treats the filesystem as the canonical source of truth for OSS vNext
(freeze manifests + evidence packs + derived artifacts). To reduce corruption and
"random flakiness" during interrupts/crashes, a subset of *derived* artifacts are
written atomically (temp file in same directory + `os.replace`).

Atomic writes are implemented in:

- `scytaledroid/Utils/IO/atomic_write.py`

## Covered (atomic)

### Derived dataset index

- `data/archive/dataset_plan.json`

### Canonical publication bundle

- `output/publication/README.md`
- `output/publication/manifests/canonical_receipt.json`
- `output/publication/manifests/publication_snapshot_id.txt` (when snapshots are surfaced)
- Copy operations performed by the canonical bundle writer (copy -> temp -> replace)

### ML orchestrator derived outputs (per-run / per-dataset)

Written by `scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py`:

- per-run `analysis/ml/<schema>/model_manifest.json`
- per-run `analysis/ml/<schema>/ml_summary.json`
- per-run `analysis/ml/<schema>/baseline_threshold.json` (and other small JSON sidecars)
- per-run `analysis/ml/<schema>/dars_v1.json` and hash sidecars (if present)
- per-run `analysis/ml/<schema>/cohort_status.json`
- per-run `analysis/ml/<schema>/ml_semantic_config.json` (fingerprint sidecar)

## Intentionally not atomic (authoritative raw evidence / large binaries)

These are authoritative evidence artifacts or large binaries and are intentionally
not rewritten by atomic helpers:

- Evidence pack directories under `output/evidence/**` (append-only ground truth)
- PCAPs and other capture binaries
- Large raw logs or device-side artifacts

