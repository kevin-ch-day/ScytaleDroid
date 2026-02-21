# Canonical Score Definition (DARS v1)

## Purpose
Define one canonical Dynamic Anomaly Score (DARS) equation for reproducible research reporting.

## Inputs
For a run with window anomaly scores `a_t` and baseline-derived threshold `theta`:
- `N`: number of windows
- `k`: number of top anomalous windows used for severity

## Components
1. Exceedance ratio:

`E = (1/N) * sum_t 1(a_t >= theta)`

2. Severity ratio:

`S = mean(top_k(a_t)) / theta`

## Canonical DARS Equation

`DARS = 100 * clip(0.5 * E + 0.5 * clip(S/2, 0, 1), 0, 1)`

Where `clip(x, 0, 1)` bounds to `[0, 1]`.

## Defaults (v1)
- `theta`: 95th percentile of baseline training scores (per model × app)
- `k`: `max(1, ceil(0.10 * N))` (top 10% windows)
- Percentile implementation: NumPy `linear`

## Reporting Policy
- Isolation Forest DARS is the primary paper dynamic score.
- OCSVM DARS is reported as robustness check.
- DARS is a deviation score, not harm/malware probability.

## Required Artifacts
Per run, retain:
- full window score CSV
- threshold value
- `N`, `k`, exceedance count
- computed DARS
- schema/version stamps
