# Paper 2 v2 Decision Register

Status: **NOT READY** for manuscript rewrite.

## Research Question

Do app-filtered runtime network windows from interactive Android app use show
higher runtime deviation prevalence than baseline-idle windows within a locked
15-app evidence set?

## Primary Hypothesis

Interactive windows have higher app-level RDI than baseline-idle windows under
the locked Isolation Forest scoring contract.

## Measurement Unit

Primary measurement unit: PCAP-derived network windows.

Inference unit: application-level paired baseline versus interactive RDI values
for 15 apps.

## Primary Aggregation

Primary aggregation: pooled/window-weighted app-level Isolation Forest RDI.

Sensitivity checks currently exported:
- equal-run RDI
- standard-duration-only RDI

Sensitivity checks still required:
- standard plus extended
- excluding long and soak
- duration-matched sampling
- equal-window sampling
- equal-run sampling with resampling policy documented

## Current Supported Claims

- The current locked package has exact inclusion/exclusion accounting.
- The current locked package has 15 app-level IF baseline/interactive pairs.
- Static alignment is exact for the current 112-run lock.
- Window reconciliation is exact for scored versus ML-eligible window counts.
- The independent validator recomputes pooled IF RDI and the paired Wilcoxon
  result from persisted score files.

## Qualified Claims

- Low baseline RDI is in-sample calibration prevalence, not independent proof of
  baseline stability.
- OC-SVM results are secondary because calibration warnings remain.
- App-level network attribution is package-filtered capture, not absolute
  process-level ground truth.

## Prohibited Claims Until Further Validation

- Do not say Paper 2 v2 is ready.
- Do not claim held-out baseline stability.
- Do not claim Isolation Forest beats simple traffic-volume baselines.
- Do not claim sequence/time-series learning unless temporal-order controls
  justify it.
- Do not mix CNN build 19250507 with CNN build 19407005.
- Do not modify the manuscript based on this package yet.

## Paper Boundary

Paper 2 v2 should stay dynamic/runtime-ML focused. Static posture may be used as
context only. Detailed static-runtime integration belongs outside this Paper 2
rewrite path.

## Title Guidance

Avoid strong "time-series" wording until temporal-order controls are completed.
Current evidence supports "windowed runtime network behavior" more directly than
sequence modeling.
