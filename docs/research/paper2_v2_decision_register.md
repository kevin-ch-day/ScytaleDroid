# Paper 2 v2 Decision Register

Status: **READY WITH SPECIFIC QUALIFICATIONS** for the current 114-run checkpoint. This is not the final submission lock while optional collection continues.

## Research Question

Does controlled interactive use produce a consistent increase in baseline-relative network deviation compared with idle execution across Android applications?

## Working Title

Unsupervised Baseline-Relative Analysis of Dynamic Network Behavior in Android Applications

## Current Checkpoint

- Canonical package: `output/_internal/publication/paper2_v2/`
- Minimum validation: `output/_internal/publication/paper2_v2/minimum_validation/`
- Locked checkpoint: 15 apps, 114 included runs, 14-day selected build groups
- Run tiers: Standard 80, Extended 32, Long observation 1, Soak 1
- QA status: `OK`
- Scientific validation status: `MINIMUM_COMPLETE`

## Measurement Unit

Primary measurement unit: PCAP-derived time-windowed network telemetry.

Inference unit: app/build-group paired baseline versus interactive RDI values. Folds and windows are audit/estimation units, not inferential sample size.

## Primary Aggregation

Primary aggregation: pooled/window-weighted app-level Isolation Forest RDI.

Sensitivity checks exported:
- equal-run RDI
- standard-duration-only RDI
- held-out baseline validation
- compact feature ablation
- bytes/sec P95 control
- 20-seed stability
- temporal-order control

## Current Supported Claims

- The current checkpoint has exact inclusion/exclusion accounting for 15 apps and 114 included runs.
- Interactive RDI exceeds baseline RDI for all 15 apps under the primary pooled/window-weighted Isolation Forest aggregation.
- The paired Wilcoxon result is W=0 with two-sided exact p=0.00006103515625.
- Held-out baseline validation is available for all 15 apps; the held-out app-level median delta is 0.6129.
- Bytes/sec alone reproduces a strong 15/15 positive transition and is highly correlated with the full IF delta.
- The multivariate feature set changes ranking modestly, but the dominant effect is a traffic-intensity transition.
- Timestamp fields are not model inputs. The method analyzes time-windowed feature vectors and is not sequence learning.

## Qualified Claims

- Low baseline RDI is in-sample calibration prevalence for the primary model, not independent proof of baseline stability.
- Held-out baseline validation supports generalization beyond the exact baseline windows used for each fold, but it remains one-device, one-network, one-OS evidence.
- Shuffled/reversed row controls preserve the feature multiset but cause small IF score differences, consistent with implementation-level row-order sensitivity rather than temporal-dependency modeling.
- OC-SVM remains secondary because calibration warnings persist.
- Static posture is context only for this paper; detailed static-runtime integration belongs outside this dynamic-focused rewrite.

## Prohibited Claims

- Do not claim this is the final submission freeze until optional collection is closed and the final workflow is run once.
- Do not claim malicious behavior detection.
- Do not claim temporal-dependency learning, recurrent modeling, or sequence learning.
- Do not use 56 held-out folds as the inferential sample size.
- Do not claim Isolation Forest proves a large effect beyond traffic intensity.
- Do not mix app builds across a selected build group.

## Final Rerun Decision

After collection is declared complete, run the final bounded rerun workflow once and compare it to this 114-run checkpoint before manuscript edits.
