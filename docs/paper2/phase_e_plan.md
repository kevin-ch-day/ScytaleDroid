# Phase E (ML) Plan — Paper #2 (v1.2, Locked)

This document is the implementation-facing contract for **Phase E**.

Paper framing:
- Not malware detection.
- Not a classifier accuracy paper (no precision/recall, no tuning).
- ML is a **deterministic lens** to quantify **execution-dependent runtime behavior**.

## 1) Inputs (Strictly Frozen, Evidence-Pack-Only)

Selector (authoritative):
- `data/archive/dataset_freeze-20260208T201527Z.json`
- Use `included_run_ids` **only** (exactly 36 runs).
- Extra valid runs may exist; they are **out-of-dataset** and **must not** be selected.

Required evidence-pack artifacts for each included run:
- `run_manifest.json`
- `inputs/static_dynamic_plan.json` (context-only; never ML features)
- `analysis/summary.json`
- `analysis/pcap_report.json`
- `analysis/pcap_features.json` (aggregate context only)
- Canonical PCAP referenced by the manifest/report (`pcapdroid_capture` artifact)

Hard rules:
- No DB reads for selection/training/scoring.
- No recomputation of frozen artifacts for included runs (do not rewrite `pcap_report.json` or `pcap_features.json`).

## 2) Windowing (Locked)

- Window size: **10 seconds**
- Stride: **5 seconds**
- Drop partial windows at end
- Window time base: **PCAP-relative seconds** (no wall-clock in ML outputs)

## 3) Features (Metadata-Only)

Tier A (run-level, frozen aggregates; context only):
- Transport ratios: TLS/QUIC/TCP/UDP (from `pcap_features.json` proxies or report fallback)
- Aggregate rates (bytes/s, packets/s) where present
- Diversity proxies (DNS/SNI/domain top-N + concentration) where present

Tier B (window-level, computed at ML time from canonical PCAP):
- bytes/s
- packets/s
- avg packet size

Optional (only if deterministically parsable; header-level only; no DPI):
- DNS query-name counts
- TLS SNI counts

Forbidden:
- Payload inspection / DPI
- URL paths / content inspection
- Decryption
- Static signals in ML feature vectors

## 4) Training & Scoring (Per App, Deterministic)

Models (fixed params; no tuning):
- Isolation Forest (primary)
- One-Class SVM (secondary)

Score semantics:
- Normalize so **higher score = more anomalous** for both models.
- Document raw score definitions and transforms in `model_manifest.json`.

Training definition:
- Primary: baseline-only training per app (idle baseline windows only)
- Fallback: if baseline fails quality gates, train on **union** (baseline + both interactive runs)

Thresholding:
- Fixed percentile thresholding: **95th percentile** of the training score distribution
- Threshold is per model × app
- Apply threshold to score interactive windows (and also output baseline scores for transparency)

## 5) Quality Gates (Train Mode Selection Only)

These gates affect training mode; they do not change run validity.

- `MIN_WINDOWS_BASELINE = 30` (10s/5s windowing)
- Baseline PCAP bytes gate:
  - Prefer `run_manifest.dataset.min_pcap_bytes` if present
  - Else fallback constant `MIN_PCAP_BYTES = 100_000` (100KB)
  - Log the gate and fallback usage in `model_manifest.json`

## 6) Low-Signal Handling (Valid != Trainable)

- `low_signal` is a **flag**, not invalidation.
- Low-signal runs are still scored and reported.
- `low_signal` alone does not trigger union fallback; only the explicit gates do.

## 7) Outputs (Immutable, Versioned)

Per-run outputs live under the evidence pack:
- `output/evidence/dynamic/<run_id>/analysis/ml/v1/`
  - `anomaly_scores_iforest.csv`
  - `anomaly_scores_ocsvm.csv`
  - `model_manifest.json`
  - `ml_summary.json`

Dataset-level derived outputs (not frozen inputs):
- `data/anomaly_prevalence_per_app_phase.csv`
- `data/anomaly_prevalence_per_run.csv` (appendix; per-run breakdown + distribution stats)
- `data/model_overlap_per_run.csv`
- `data/transport_mix_by_phase.csv`
- `data/transport_mix_per_run.csv` (appendix; per-run transport ratios)

Paper-ready deliverables bundle (zip-and-share; operator/paper-facing):
- Canonical paper artifact surface: `output/paper/` (tables/figures/appendix/manifests).
  - `figures/` (main figures)
    - `fig_b1_timeline_<runid8>.png/.pdf`
    - `fig_b2_rdi_by_app.png/.pdf`
    - `fig_b4_static_vs_rdi_social.png/.pdf`
    - `fig_b4_static_vs_rdi_messaging.png/.pdf`
  - `tables/` (main paper tables; **triple-format**)
    - `table_1_rdi_prevalence.csv/.xlsx/.tex`
    - `table_2_transport_mix.csv/.xlsx/.tex`
    - `table_3_model_agreement.csv/.xlsx/.tex`
    - `table_4_signature_deltas.csv/.xlsx/.tex`
    - `table_5_masvs_coverage.csv/.xlsx/.tex` *(static context; derived from Phase B reports; not ML inputs)*
    - `table_6_static_posture_scores.csv/.xlsx/.tex` *(static context; emitted to make Fig B4 auditable)*
    - `table_7_exposure_deviation_summary.csv/.xlsx/.tex` *(interpretive; tertile bins over the frozen cohort; no combined scalar)*
  - `appendix/`
    - `repro_appendix_phase_e.md`
  - `manifest/`
    - `dataset_freeze.json` (copy; canonical stays in `data/archive/`)
    - `paper_artifacts.json` (copy of the exemplar pin lockfile)
    - `phase_e_artifacts_manifest.json` (hashes + provenance pointers)
    - `phase_e_closure_record.json` (close-out receipt: freeze sha256 + bundle-manifest sha256)

Provenance header requirement (paper-grade reproducibility):
- Every main table `.csv` and `.tex` must embed a comment header with:
  - freeze anchor filename + sha256
  - `ml_schema_version`
  - `report_schema_version`
  - generation timestamp (UTC)

Immutability after freeze:
- Do not overwrite ML outputs for included runs.
- If a bug is found post-freeze, bump `ml_schema_version` and write to a new versioned path.

## 8) Paper Artifacts (Minimum)

Required:
- Table: anomaly prevalence by phase (paper-facing: Baseline vs Interactive; IF + OC-SVM)
  - Note: the pipeline also records per-run phases (`idle`, `interactive_a`, `interactive_b`)
    for auditability; paper tables may collapse the two interactive runs into a single
    Interactive group.
- Table: model overlap (Jaccard + disagreement counts)
- Table: transport mix by phase (Baseline vs Interactive; contextual)
- Table: behavioral signature deltas (idle vs interactive deltas; descriptive)
- One flagship timeline figure (bytes/s + flags over time) for a messaging call interaction (voice or video)
- Repro appendix:
  - freeze filename + checksum
  - tool versions
  - seeds / determinism statement
  - quality gates + fallback rules

Paper artifact lock file (derived, dataset-level; does not mutate packs):
- `data/archive/paper_artifacts.json`
  - Must pin the canonical exemplar run_id used for Fig B1 so it cannot drift.
  - Selection protocol (PM-locked): choose the best eligible *messaging call* run (voice or video) from the frozen 36:
    - messaging app only
    - interaction tag must be call (`voice_call` or `video_call`)
    - must not be `low_signal`
    - primary metric: sustained bytes/sec over K consecutive windows (K=6 => 30s)
    - tie-break: higher IF prevalence, then higher OC-SVM prevalence, then later `ended_at`
