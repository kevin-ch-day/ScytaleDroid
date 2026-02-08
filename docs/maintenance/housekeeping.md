# Workspace housekeeping & logs

Keeping local workspaces tidy ensures repeatable scans and prevents stale
artifacts from confusing follow-up investigations. This guide summarises the
built-in maintenance helpers and documents where the CLI writes log files and
reports.

## Workspace & Evidence (menu)

The CLI provides a **Workspace & Evidence** menu intended for Paper #2
collection operations and safe cleanup. Typical actions include:

- Workspace disk usage (APK storage, evidence packs, logs, caches).
- Dynamic evidence pack verification (overview, deep checks).
- Dataset freeze manifest writing and immutability verification.
- Deleting INVALID dataset runs locally (evidence-pack cleanup).
- Pruning derived DB orphans (safe; DB is not authoritative).

Important:
- Evidence packs are authoritative.
- The DB is derived/rebuildable and may drift if runs are deleted locally.
- After dataset freeze, do not recompute artifacts for the included run set.

Paper #2 references:
- `docs/paper2/README.md`
- `docs/paper2/operator_runbook.md`

## Static analysis caches & retention

Static analysis may use caches under:
- `data/static_analysis/cache/`
- `output/cache/` (if used)

Retention settings (if enabled by the CLI) should be treated as housekeeping
only. Do not rely on retention as a correctness mechanism for paper-grade runs.

## Where logs live

`Utils → Show log directories` prints the resolved paths for each subsystem. By
default logs live under `./logs/` with paired human-readable and JSONL streams
so you can tail text locally or feed structured events to tooling:

| Category         | Human readable          | Structured JSONL               |
|------------------|-------------------------|--------------------------------|
| Application      | `app.log`               | `app.jsonl`                    |
| Database         | —                       | `db.jsonl`                     |
| Device analysis  | `device_analysis.log`   | `device_analysis.jsonl`        |
| Static analysis  | `static_analysis.log`   | `static_analysis.jsonl`        |
| Dynamic analysis | `dynamic_analysis.log`  | `dynamic_analysis.jsonl`       |
| Metrics          | —                       | `metrics.jsonl`                |
| Error funnel     | `error.log`             | —                              |
| Audit trail      | `audit.log`             | `audit.jsonl`                  |

Harvest runs also emit dedicated JSONL files under
`logs/harvest/<timestamp>_run-<id>.jsonl` so you can review a single device
session without combing through global logs.

The same helper also reminds operators where device state and static-analysis
report directories live so they can inspect or archive them manually when
needed.

## Recommended cadence

* Use Workspace & Evidence verification checks during collection to avoid silent drift.
* Run prune-orphans only when DB drift is observed (ad-hoc; derived index).
* Keep ML runs offline and evidence-pack-only; do not depend on DB state.
* Keep the log directory under version control ignores (e.g. `.gitignore`)
  so logs never end up in commits.

For additional operational notes see the [static-analysis pipeline
plan](../static_analysis/static_analysis_pipeline_plan.md).
