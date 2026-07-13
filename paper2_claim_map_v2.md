# Paper 2 v2 Claim Map

Status: **READY WITH SPECIFIC QUALIFICATIONS** for the current 114-run checkpoint. Not the final submission lock until optional collection is closed and the final rerun workflow is executed.

## Supported Claims

| Claim | Status | Evidence | Caveat |
| --- | --- | --- | --- |
| The checkpoint contains 15 apps and 114 included runs. | Supported | `publication_results_v2.json`, `paper2_qa_v2.json` | Current checkpoint only. |
| The selected analysis window is a 14-day selected build-group lock. | Supported | `publication_results_v2.json` | Not an all-current-build claim. |
| Inclusion/exclusion accounting is exact. | Supported | `paper2_excluded_runs_v2.csv`, QA exclusion accounting | Candidate pool may change if final collection continues. |
| Static/dynamic identity alignment is exact for selected runs. | Supported | `paper2_static_alignment_v2.csv` | Static posture is context only in Paper 2 v2. |
| Scored window counts reconcile for included runs. | Supported | `paper2_window_reconciliation_v2.csv` | Raw pre-drop rows are represented through plan/window metadata. |
| Interactive RDI exceeds baseline RDI for all 15 apps under pooled IF. | Supported | `paper2_per_app_rdi_v2.csv`, independent validation | App/build-group inference only. |
| The paired Wilcoxon result is W=0, two-sided exact p=0.00006103515625. | Supported | `paper2_statistics_v2.csv`, independent validation | Use two-sided p unless a directional hypothesis is explicitly stated. |
| Held-out baseline validation is available for all 15 apps. | Supported | `minimum_validation/heldout_baseline_by_app_v2.csv` | Do not use 56 folds as inferential N. |
| Bytes/sec alone reproduces a strong positive transition. | Supported | `minimum_validation/bytes_p95_control_summary_v2.csv` | This qualifies the interpretation of the IF effect. |
| The 20-seed audit preserves the direction and Wilcoxon result. | Supported | `minimum_validation/seed_stability_by_seed_v2.csv` | Applies to tested IF seeds. |
| The method uses time-windowed network telemetry, not sequence learning. | Supported | `minimum_validation/paper2_temporal_order_control_v2.json` | Shuffled/reversed row controls show small estimator row-order sensitivity. |

## Qualified Claims

| Claim | Qualification |
| --- | --- |
| The primary effect is a baseline-to-interactive runtime deviation effect. | Supported, but most of the effect appears traffic-intensity driven. |
| The multivariate IF model captures traffic-shape context. | Qualified: it changes ordering modestly; bytes/sec and packets/sec explain much of the effect. |
| Baseline behavior generalizes. | Qualified: held-out baseline validation supports this within the checkpoint, but this is not multi-device/multi-network evidence. |
| OC-SVM agrees with the broad pattern. | Secondary only because calibration warnings remain. |
| Static posture can contextualize runtime results. | Context only; detailed static-runtime integration is outside Paper 2 v2. |

## Prohibited Claims

| Claim | Reason |
| --- | --- |
| This is the final submission lock. | Optional collection is still continuing. |
| The method detects malicious behavior. | The study measures baseline-relative runtime network deviation. |
| The model learns temporal dependencies or sequence transitions. | Window order and timestamps are not model inputs. |
| 56 held-out folds are independent samples for inference. | The app/build group is the inferential unit. |
| Isolation Forest proves a large effect beyond traffic intensity. | Bytes/sec P95 control is highly correlated with IF delta. |
| All apps were current-build complete. | The paper uses selected build-group evidence, not live current-build completion. |
| Prior/current/churn labels are equivalent to evidence validity. | App churn is handled through selected build-group locks and provenance. |

## Recommended Research Question

Does controlled interactive use produce a consistent increase in baseline-relative network deviation compared with idle execution across Android applications?

## Recommended Title

Unsupervised Baseline-Relative Analysis of Dynamic Network Behavior in Android Applications
