# Paper 2 v2 Method Validation

Status: **minimum validation complete for the current 114-run checkpoint**. This is a checkpoint, not the final submission lock.

## Current Package

- Canonical package: `output/_internal/publication/paper2_v2/`
- Minimum validation: `output/_internal/publication/paper2_v2/minimum_validation/`
- Dataset: 15 apps, 114 included runs, 14-day selected build groups
- QA status: `OK`
- Independent validator: `scripts/publication/validate_paper2_results_v2.py`
- Minimum validation generator: `scripts/publication/generate_paper2_minimum_validation.py`

## Primary Analysis Contract

The primary model is Isolation Forest over time-windowed network telemetry. RDI is computed from full-precision per-window anomaly flags, then aggregated to paired app/build-group baseline and interactive values.

The primary inferential unit is the app/build group. Windows and held-out folds are not treated as independent inferential samples.

## Primary Result

- Apps: 15
- Positive app deltas: 15
- Negative app deltas: 0
- Zero app deltas: 0
- Primary median delta: 0.6449
- Wilcoxon W: 0
- Two-sided exact p: 0.00006103515625

## Held-Out Baseline Validation

Leave-one-baseline-run-out validation is available for all 15 apps:

- Held-out eligible apps: 15
- Held-out folds: 56
- App-level positive deltas: 15
- App-level median delta: 0.6129
- App-level mean delta: 0.6161
- Cohen's dz: 3.8795

This supports held-out baseline generalization, but the app remains the inferential unit.

## Feature Ablation

All tested feature profiles produce 15/15 positive app deltas:

- bytes/sec only
- packets/sec only
- average packet size only
- bytes/sec + packets/sec
- all three features

The average packet size-only profile has lower median delta and lower rank agreement with the full model than bytes/sec or packets/sec. This suggests average packet size contributes some traffic-shape information, but does not dominate the observed effect.

## Bytes/sec P95 Control

The simple bytes/sec P95 control also produces 15/15 positive app deltas:

- Median delta: 0.5934
- Wilcoxon W: 0
- Two-sided exact p: 0.00006103515625
- Spearman correlation with IF delta: 0.9679

Interpretation: the primary effect is mostly a traffic-intensity transition from baseline to interactive use. The multivariate IF model changes app ordering modestly and preserves a broader traffic-shape framing, but it should not be described as uncovering a large independent signal beyond traffic intensity.

## Seed Stability

Twenty predetermined Isolation Forest seeds were tested:

- Positive app deltas: 15/15 for every seed
- Median-delta range across seeds: 0.6150 to 0.6556
- Cohen's dz range: 4.0954 to 4.3120
- Wilcoxon p-value: 0.00006103515625 for every seed

Interpretation: the direction and significance of the primary result are stable to the tested IF seeds.

## Temporal-Order Control

Control outputs:

- `paper2_temporal_order_control_v2.csv`
- `paper2_temporal_order_control_v2.json`

The feature multiset is identical under original, shuffled, reversed, and timestamp-removed variants. Removing timestamps leaves scores unchanged. Shuffling and reversing row order produce small score differences, which should be described as estimator row-order sensitivity, not sequence learning.

Required wording:

- The method analyzes time-windowed feature vectors.
- Window order is not a model input.
- Isolation Forest does not model temporal dependencies.
- Do not claim recurrent or sequence modeling.

## OC-SVM Role

OC-SVM remains secondary/appendix material because baseline calibration warnings remain. It may be used as a robustness comparison, not the primary result.

## Limitations

- One physical Android device
- One Android OS/device configuration
- One network environment
- Manual interaction traces
- Package-filtered VPN capture rather than perfect kernel-level process attribution
- Consumer app churn requires selected build-group locks rather than an all-current-build claim

## Final Collection Dependency

If optional collection continues, this package remains a checkpoint. The final submission package must be produced by one final freeze rebuild and full rerun workflow after collection is explicitly closed.
