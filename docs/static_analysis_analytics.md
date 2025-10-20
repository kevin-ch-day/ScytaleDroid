# Static analysis analytics extensions

## Overview
The static-analysis pipeline now generates rich analytics artefacts alongside the
traditional baseline report. Each scan produces:

- **Finding matrices** that capture severity, MASVS category, detector, and tag
  co-occurrence, as well as guard-strength distributions for exported
  components.
- **Novelty indicators** derived from entropy and coverage measurements to
  highlight when a build introduces statistically unusual patterns.
- **Workload profiles** that classify detector runtimes and throughput so the
  pipeline load can be monitored and tuned over time.

These artefacts are embedded in the reproducibility bundle, surfaced through the
CLI, and persisted in the canonical database for longitudinal analysis.

## Matrices
The `scytaledroid.StaticAnalysis.analytics.matrices` module transforms detector
results into serialisable matrices. The current set includes:

| Matrix key                | Description |
|---------------------------|-------------|
| `severity_by_category`    | Counts severities per MASVS category |
| `severity_by_detector`    | Severity distribution per detector |
| `category_by_section`     | MASVS category counts per pipeline section |
| `status_by_detector`      | Detector status tallies (OK/WARN/FAIL/etc.) |
| `tags_by_severity`        | Tag usage grouped by severity |
| `guard_strength_by_severity` | Export guard-levels observed for exported components |

The module also emits entropy-based indicators:

- `severity_entropy` and `category_entropy` quantify distribution uniformity.
- `masvs_coverage_ratio` measures category coverage relative to the MASVS
  taxonomy.
- `novelty_index` blends the above metrics to flag atypical runs.

## Workload profiling
`scytaledroid.StaticAnalysis.analytics.workload` analyses detector runtimes to
produce:

- A summary block with total/mean/median/P90 durations and findings-per-second.
- Detector-level classifications (`idle`, `baseline`, `elevated`, `critical`).
- Section-level aggregates to identify hotspots within the pipeline.

## Persistence
The canonical schema adds JSON columns to `static_analysis_runs` for
`analysis_matrices`, `analysis_indicators`, and `workload_profile`. CLI ingest
and canonical ingestion now populate these columns so longitudinal queries can
track drift, detector health, and the effectiveness of remediation campaigns.

## Academic novelty
The entropy and coverage-derived novelty index provides a repeatable, literature
aligned signal for comparing builds. Combining severity entropy with MASVS
coverage mirrors established approaches in vulnerability trend analysis while
surfacing actionable correlations between component guards, detector outcomes,
and MASVS areas.
