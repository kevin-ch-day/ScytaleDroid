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

## MASVS + CVSS synthesis

The MASVS summary pipeline now fuses severity tallies with CVSS v4.0 scoring to
help reviewers reason about real risk rather than raw finding counts. For each
MASVS area we persist:

- `worst_score`, `worst_vector`, and `worst_identifier` – identify the highest
  scoring control breach and its originating rule. Each area also exposes a
  `worst_basis` payload detailing the tie-break inputs (scope rank, impact
  counts, vector length) so analysts can explain why one vector outranked
  another when scores match.
- `average_score`, `scored_count`, and `missing` – quantify how many findings
  in the area provide CVSS data and where gaps remain.
- `band_counts` – Critical/High/Medium/Low tallies derived via
  `cvss_v4.severity_band` so analysts can quickly gauge exposure intensity.
- `quality` – derived metrics that combine severity weighting with CVSS
  coverage to express:
  - `risk_index` – a 0–100 score blending severity density, CVSS band strength,
    and worst-score intensity. The `risk_components` structure breaks this score
    down into its weighted inputs and per-factor contributions to aid
    remediation planning.
  - `cvss_coverage` – proportion of findings in the area that include CVSS
    vectors.
  - `severity_pressure` and `cvss_band_score` – intermediate measures that
    highlight overloaded controls and stacked high-band findings.

The CLI surfaces these metrics in both the run-summary footer and the read-only
MASVS menu, alongside severity counts and pass/fail status. These additions make
it easy to spot situations where, for example, a single Critical CVSS issue is
hiding amongst Low severities.

### Known gaps

- Findings without CVSS vectors currently contribute to the `missing` counter
  but are otherwise invisible in risk roll-ups. Hooking rule metadata into the
  CVSS loader should be prioritised so every MASVS breach can be scored.
- MASVS area status still treats any High as a FAIL and any Medium as WARN; we
  do not yet downgrade Medium findings that score Low on CVSS. Future work can
  consider blending severity and CVSS banding when deriving PASS/WARN/FAIL.
- The CVSS aggregation is base-score only. Once dynamic threat intelligence or
  environment profiles are available they should be folded into the view so the
  dashboard highlights threat-adjusted risk rather than theoretical impact.

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
