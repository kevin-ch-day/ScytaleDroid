# Paper 2 v2 Research Record

Status: **READY WITH SPECIFIC QUALIFICATIONS** for the current 114-run checkpoint; minimum validation complete. This is a checkpoint, not the final submission lock, while optional collection continues.

Merged 2026-10 from the former decision register, method validation, scientific interpretation and the repository-root claim map, which repeated the same figures. The final rerun procedure stays in [paper2_v2_final_rerun_workflow.md](paper2_v2_final_rerun_workflow.md).

## Research Question and Title

Does controlled interactive use produce a consistent increase in baseline-relative network deviation compared with idle execution across Android applications?

Working title: *Unsupervised Baseline-Relative Analysis of Dynamic Network Behavior in Android Applications*

## Current Checkpoint

- Canonical package: `output/_internal/publication/paper2_v2/`
- Minimum validation: `output/_internal/publication/paper2_v2/minimum_validation/`
- Locked checkpoint: 15 apps, 114 included runs (56 baseline, 58 interactive), 14-day selected build groups
- Run tiers: Standard 80, Extended 32, Long observation 1, Soak 1
- QA status: `OK`; scientific validation status: `MINIMUM_COMPLETE`
- Independent validator: `scripts/publication/validate_paper2_results_v2.py`
- Minimum validation generator: `scripts/publication/generate_paper2_minimum_validation.py`

## Analysis Contract

- **Measurement unit:** PCAP-derived time-windowed network telemetry.
- **Inference unit:** app/build-group paired baseline versus interactive RDI values. Windows and held-out folds are audit/estimation units, not inferential sample size: windows within one app/build group are not independent applications, and counting them would inflate N.
- **Primary model and aggregation:** Isolation Forest; RDI is computed from full-precision per-window anomaly flags, then pooled/window-weighted to app-level values.
- **Sensitivity checks exported:** equal-run RDI, standard-duration-only RDI, held-out baseline validation, compact feature ablation, bytes/sec P95 control, 20-seed stability, temporal-order control.

## Results

### Primary result

- Apps: 15; positive app deltas 15, negative 0, zero 0
- Median delta: 0.6449
- Wilcoxon W = 0; two-sided exact p = 0.00006103515625

### Held-out baseline validation

Leave-one-baseline-run-out: train on the remaining baseline runs, derive the P95 threshold from the training baseline windows, and score the held-out baseline plus interactive windows.

- Held-out eligible apps: 15/15; folds: 56
- App-level positive deltas: 15/15
- App-level median delta 0.6129; mean 0.6161; Cohen's dz 3.8795

This addresses the earlier limitation that low baseline RDI was only in-sample calibration prevalence, and supports held-out baseline generalization within the selected app/build groups.

### Feature ablation

All tested profiles produce 15/15 positive app deltas. Spearman rank correlation with the full model:

| Profile | Spearman vs. full IF delta | Note |
| --- | --- | --- |
| bytes/sec only | 0.9393 | |
| packets/sec only | 0.9321 | |
| average packet size only | 0.7107 | Lower median delta (0.5643) |
| bytes/sec + packets/sec | 0.9643 | |
| all three features | (full model) | |

Average packet size contributes some traffic-shape information but does not dominate the effect.

### Bytes/sec P95 control

- Positive app deltas: 15/15; median delta 0.5934
- Wilcoxon W = 0; two-sided exact p = 0.00006103515625
- Spearman correlation with IF delta: 0.9679

### Seed stability (20 predetermined IF seeds)

- Positive app deltas: 15/15 for every seed
- Median-delta range: 0.6150 to 0.6556; Cohen's dz range 4.0954 to 4.3120
- Wilcoxon p = 0.00006103515625 for every seed

### Temporal-order control

Outputs: `paper2_temporal_order_control_v2.csv`, `paper2_temporal_order_control_v2.json`.

- The feature multiset is identical under original, shuffled, reversed and timestamp-removed variants.
- Removing timestamps leaves scores unchanged.
- Shuffling and reversing row order cause small IF score differences: estimator row-order sensitivity, not temporal-dependency learning.

### OC-SVM

Secondary/appendix only, because baseline calibration warnings remain. Usable as a robustness comparison, not the primary result.

## Interpretation (direct verdict)

The effect is primarily a **traffic-intensity transition** from idle to interactive use. The multivariate Isolation Forest adds traffic-shape context and modestly changes app ordering, but the bytes/sec control explains much of the separation. Present IF as a baseline-relative runtime deviation model over time-windowed network features, not as proof of a large independent behavioural signal beyond traffic intensity.

Required wording: the method analyzes **time-windowed feature vectors** (or "time-series-derived traffic-shape features"); window order is not a model input; Isolation Forest does not model temporal dependencies; no recurrent or sequence modeling.

## Claims

### Supported

| Claim | Evidence | Caveat |
| --- | --- | --- |
| The checkpoint contains 15 apps and 114 included runs. | `publication_results_v2.json`, `paper2_qa_v2.json` | Current checkpoint only. |
| The selected analysis window is a 14-day selected build-group lock. | `publication_results_v2.json` | Not an all-current-build claim. |
| Inclusion/exclusion accounting is exact. | `paper2_excluded_runs_v2.csv`, QA exclusion accounting | Candidate pool may change if final collection continues. |
| Static/dynamic identity alignment is exact for selected runs. | `paper2_static_alignment_v2.csv` | Static posture is context only in Paper 2 v2. |
| Scored window counts reconcile for included runs. | `paper2_window_reconciliation_v2.csv` | Raw pre-drop rows are represented through plan/window metadata. |
| Interactive RDI exceeds baseline RDI for all 15 apps under pooled IF. | `paper2_per_app_rdi_v2.csv`, independent validation | App/build-group inference only. |
| The paired Wilcoxon result is W=0, two-sided exact p=0.00006103515625. | `paper2_statistics_v2.csv`, independent validation | Use two-sided p unless a directional hypothesis is explicitly stated. |
| Held-out baseline validation is available for all 15 apps (median delta 0.6129). | `minimum_validation/heldout_baseline_by_app_v2.csv` | Do not use 56 folds as inferential N. |
| Bytes/sec alone reproduces a strong positive transition. | `minimum_validation/bytes_p95_control_summary_v2.csv` | This qualifies the interpretation of the IF effect. |
| The 20-seed audit preserves the direction and Wilcoxon result. | `minimum_validation/seed_stability_by_seed_v2.csv` | Applies to tested IF seeds. |
| The method uses time-windowed network telemetry, not sequence learning. | `minimum_validation/paper2_temporal_order_control_v2.json` | Shuffled/reversed row controls show small estimator row-order sensitivity. |

### Qualified

| Claim | Qualification |
| --- | --- |
| The primary effect is a baseline-to-interactive runtime deviation effect. | Supported, but most of the effect appears traffic-intensity driven. |
| The multivariate IF model captures traffic-shape context. | It changes ordering modestly; bytes/sec and packets/sec explain much of the effect. |
| Baseline behaviour generalizes. | Held-out validation supports this within the checkpoint; it remains one-device, one-network, one-OS evidence. |
| Low baseline RDI shows baseline stability. | For the primary model it is in-sample calibration prevalence, not independent proof. |
| OC-SVM agrees with the broad pattern. | Secondary only because calibration warnings remain. |
| Static posture can contextualize runtime results. | Context only; detailed static-runtime integration is outside Paper 2 v2. |

### Prohibited

| Claim | Reason |
| --- | --- |
| This is the final submission lock. | Optional collection is still continuing; the final workflow has not run. |
| The method detects malicious behaviour. | The study measures baseline-relative runtime network deviation. |
| The model learns temporal dependencies, recurrent state or sequence transitions. | Window order and timestamps are not model inputs. |
| 56 held-out folds are independent samples for inference. | The app/build group is the inferential unit. |
| Isolation Forest proves a large effect beyond traffic intensity. | Bytes/sec P95 control is highly correlated with IF delta. |
| All apps were current-build complete. | The paper uses selected build-group evidence, not live current-build completion. |
| Builds may be mixed within a selected build group. | Each build group is locked to its selected builds. |
| Prior/current/churn labels are equivalent to evidence validity. | App churn is handled through selected build-group locks and provenance. |

## Limitations

- One physical Android device, one Android OS/device configuration, one network environment
- Manual interaction traces
- Package-filtered VPN capture rather than perfect kernel-level process attribution
- Consumer app update churn handled through selected build-group locks rather than an all-current-build claim
- The current package is a checkpoint until final collection is closed

## Final Rerun Decision

After collection is declared complete, run the final bounded rerun workflow once and compare it with this 114-run checkpoint before manuscript edits: [paper2_v2_final_rerun_workflow.md](paper2_v2_final_rerun_workflow.md).
