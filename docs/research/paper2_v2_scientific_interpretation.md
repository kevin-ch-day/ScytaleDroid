# Paper 2 v2 Scientific Interpretation

Status: **current 114-run checkpoint, ready with qualifications**. This is not the final submission freeze while optional collection continues.

## What The Primary IF Result Establishes

The primary Isolation Forest result establishes a consistent app-level increase in baseline-relative network deviation during controlled interactive use compared with idle execution.

For the current checkpoint:

- Apps: 15
- Included runs: 114
- Baseline runs: 56
- Interactive runs: 58
- Primary aggregation: pooled/window-weighted app-level IF RDI
- Positive app deltas: 15/15
- Median delta: 0.6449
- Wilcoxon W: 0
- Two-sided exact p: 0.00006103515625

The inferential unit is the app/build group. Windows and folds support estimation and auditability, but they are not independent inferential samples.

## What Held-Out Baseline Validation Adds

Held-out baseline validation leaves out one baseline run at a time, trains on the remaining baseline runs, derives the P95 threshold from training baseline windows, and scores the held-out baseline plus interactive windows.

Current result:

- Held-out eligible apps: 15/15
- Held-out folds: 56
- App-level positive deltas: 15/15
- Median app-level delta: 0.6129
- Mean app-level delta: 0.6161
- Cohen's dz: 3.8795

This addresses the earlier limitation that low baseline RDI was only in-sample calibration prevalence. It supports held-out baseline generalization within the selected app/build groups.

## What The Bytes/sec Control Reveals

The bytes/sec P95 control shows that a simple traffic-intensity metric reproduces the main direction of the effect:

- Positive app deltas: 15/15
- Median delta: 0.5934
- Spearman correlation with IF delta: 0.9679

This means the primary effect is largely a traffic-intensity transition from idle to interactive use.

## Does Average Packet Size Contribute Independently?

Average packet size alone also produces 15/15 positive deltas, but it has a lower median delta and weaker rank agreement with the full model:

- Average packet size-only median delta: 0.5643
- Spearman correlation with full IF delta: 0.7107

Interpretation: average packet size contributes some traffic-shape information, but it is not the dominant driver of the primary result.

## Does The Multivariate Model Materially Change App Ranking?

The multivariate IF model changes app ordering modestly. Bytes/sec only and packets/sec only are strongly correlated with the full model:

- bytes/sec only Spearman vs. full: 0.9393
- packets/sec only Spearman vs. full: 0.9321
- bytes/sec + packets/sec Spearman vs. full: 0.9643

The full model is useful as a richer traffic-shape framing, but the manuscript should not overclaim that IF uncovers a substantially different phenomenon from traffic intensity.

## Seed Audit

Twenty predetermined Isolation Forest seeds were tested:

- Positive app deltas: 15/15 for every seed
- Median-delta range: 0.6150 to 0.6556
- Cohen's dz range: 4.0954 to 4.3120
- Wilcoxon p-value: 0.00006103515625 for every seed

The direction, paired-test result, and broad interpretation are stable across the tested seeds.

## OC-SVM Role

OC-SVM remains secondary because calibration warnings remain. It may be used as a robustness appendix or secondary comparison, but it should not carry the primary result.

## Why App-Level Inference Is Used

Network windows within the same app/build group are not independent applications. Treating windows or held-out folds as independent inferential samples would inflate the sample size. The app/build group remains the defensible paired unit for statistical claims.

## Why This Is Not Sequence Learning

The model analyzes time-windowed feature vectors. It does not use recurrent layers, temporal state, sequence transitions, or ordered time dependencies as model inputs.

Temporal-order controls show:

- Feature multisets are unchanged for original, shuffled, reversed, and timestamp-removed variants.
- Removing timestamps leaves scores unchanged.
- Shuffled and reversed row variants cause small IF score differences, consistent with estimator row-order sensitivity, not temporal-dependency learning.

Use wording such as **time-windowed network telemetry** or **time-series-derived traffic-shape features**, not sequence learning.

## Direct Verdict

The Paper 2 effect is primarily a traffic-intensity transition from idle to interactive use. The multivariate Isolation Forest captures additional traffic-shape context and modestly changes app ordering, but the bytes/sec control explains much of the observed separation. The paper should present IF as a baseline-relative runtime deviation model over time-windowed network features, not as proof of a large independent behavioral signal beyond traffic intensity.

## Limitations

- One physical Android device
- One Android OS/device configuration
- One network environment
- Manual interaction traces
- Package-filtered VPN capture rather than perfect kernel-level process attribution
- Consumer app update churn handled through selected build-group locks
- Current package is a checkpoint until final collection is closed
