# Paper #2 — Phase E Intelligence Map (Locked)

Baseline-Relative Runtime Deviation in Mobile Apps

This is a **research-grade control document** for Phase E. It defines:
- what is measured,
- how structure emerges,
- what ML quantifies,
- what is explicitly *not* claimed.

This document is intended to keep Paper #2 disciplined and reviewer-safe. It is not a
feature wishlist.

## 1) Goal (single sentence, locked)

Quantify and visualize **execution-dependent runtime divergence** (idle -> interactive) per
application, using **unsupervised, baseline-relative scoring** on a frozen set of evidence packs,
**without labels, payload inspection, or DPI**.

## 2) Authoritative Inputs (Frozen)

All Phase E results derive exclusively from the canonical frozen dataset.

Freeze selector:
- `data/archive/dataset_freeze-20260208T201527Z.json`
- `included_run_ids = 36` (12 apps x 1 idle baseline + 2 interactive)

Per-run required artifacts (for each included run):
- `output/evidence/dynamic/<run_id>/run_manifest.json`
- `output/evidence/dynamic/<run_id>/analysis/summary.json`
- `output/evidence/dynamic/<run_id>/analysis/pcap_report.json`
- `output/evidence/dynamic/<run_id>/analysis/pcap_features.json`
- Canonical PCAP referenced by `run_manifest.json` (pcap_path / pcapdroid_capture artifact)
- `output/evidence/dynamic/<run_id>/inputs/static_dynamic_plan.json` (context only; never ML features)

Authority rule:
- Evidence packs + freeze manifest are authoritative.
- DB state is **not consulted** for Phase E selection/training/scoring.

## 3) Raw Signals Measured (No DPI, No Payload)

PCAP header-level time series (windowed):
- bytes per window
- packets per window
- mean packet size per window

Run-level aggregates (context):
- transport mix ratios: TLS / QUIC / TCP / UDP

Operator/context metadata:
- phase labels: idle vs interactive_a / interactive_b (freeze-derived)
- interaction tags (best effort): `messaging_activity`, `interaction_level`

Explicit exclusions:
- no payload inspection
- no URLs / API paths / message content
- no decryption
- no destination semantics used in ML feature vectors

## 4) Temporal Abstraction Layer (Where Structure Emerges)

Windowing (locked):
- 10s window / 5s stride
- drop partial windows
- deterministic ordering per run

Purpose:
- convert packet-level noise into temporal structure (behavior regimes)

Structure visible *before* ML:
- sustained vs spiky throughput regimes
- intensity vs shape differences (bytes/s vs packets/s vs avg pkt size)
- phase-aligned shifts (idle -> interactive)

Key insight (paper language):
- Windowing is the **structure extraction** step; ML operates on already-structured behavior.

## 5) ML Role (What Is Quantified)

Training:
- per-app, baseline-relative
- idle baseline training by default
- union fallback only if baseline gates fail (training only; explicitly logged)

Models (locked):
- Isolation Forest (IF)
- One-Class SVM (OC-SVM)

Thresholding (locked):
- 95th percentile of the training distribution per model x app

Primary metric:
- **RDI (Runtime Deviation Index)** = `flagged_pct` (proportion of windows exceeding threshold)
- baseline-relative, per-app

Interpretation:
- RDI quantifies how much runtime behavior deviates from an app's own idle baseline under interaction.

## 6) Explicit Limits (What ML Is NOT Learning)

- not learning destinations, semantics, or content
- not inferring harm (security risk, maliciousness, privacy violation)
- not providing cross-app risk ranking or global normalization
- more sensitive to sustained regimes than isolated bursts

Locked boundary statement (paper-ready):

  "The ML quantifies baseline-relative deviation in traffic intensity and shape; it does not infer
  destination semantics, content, or harm."

## 7) Core Outputs (Paper-Facing)

Tables:
- `output/paper/paper2/phase_e/tables/table_1_anomaly_prevalence.csv`
- `output/paper/paper2/phase_e/tables/table_2_transport_mix.csv`
- `output/paper/paper2/phase_e/tables/table_3_model_overlap.csv`

Fig B1 exemplar timeline:
- pinned in `data/archive/paper_artifacts.json`
- constraints (PM-locked):
  - frozen-only
  - messaging app
  - call interaction (voice or video)
  - not `low_signal`
  - selection metric: sustained bytes/sec over K=6 windows (30s)

## 8) Appendix-Only Outputs (Hard Separation)

Appendix-only root:
- `output/paper/paper2/phase_e_appendix_exploratory/`

Rules:
- extra runs allowed
- must be labeled: "Supplementary exploratory runs not part of the frozen dataset used for primary claims."
- never mix frozen + exploratory runs in the same plot/table used for main claims

## 9) Epistemic Boundary (Locked)

- claims are execution-dependent, not app-intrinsic
- static posture provides context, not prediction (and is never an ML feature input)
- ML is an analytical lens, not a detector

