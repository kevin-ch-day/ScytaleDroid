# Static-analysis housekeeping & logs

Keeping local workspaces tidy ensures repeatable scans and prevents stale
artifacts from confusing follow-up investigations. This guide summarises the
built-in maintenance helpers and documents where the CLI writes log files and
reports.

## Utilities → Housekeep static-analysis artefacts

The Utilities menu now exposes an option named **"Housekeep static-analysis
artefacts"**. When selected it will:

1. Delete JSON, NDJSON, HTML, and archive exports older than the configured
   retention window (30 days by default).
2. Reset `data/static_analysis/tmp/` and `data/static_analysis/cache/` so the
   next scan starts with a fresh workspace.
3. Report how many files were removed and how much disk space was reclaimed.

The retention window defaults to
`scytaledroid.Config.app_config.STATIC_ANALYSIS_RETENTION_DAYS` (30 days), but it
can be overridden per run by setting the
`SCYTALEDROID_STATIC_RETENTION_DAYS` environment variable to a positive integer.
For example:

```bash
export SCYTALEDROID_STATIC_RETENTION_DAYS=7
```

Running the housekeeping action after setting the variable will prune reports
older than a week.

## Where logs live

`Utils → Show log directories` prints the resolved paths for each subsystem. By
default logs live under `./logs/` and the following files are created as they
are needed:

| Category        | File name               |
|-----------------|-------------------------|
| Application     | `application.log`       |
| Database        | `database.log`          |
| Device analysis | `device_analysis.log`   |
| Static analysis | `static_analysis.log`   |
| Dynamic analysis| `dynamic_analysis.log`  |
| VirusTotal      | `virus_total.log`       |
| Error funnel    | `error.log`             |

The same helper also reminds operators where device state and static-analysis
report directories live so they can inspect or archive them manually when
needed.

## Recommended cadence

* Run the housekeeping action before large batch scans or when switching
  between projects to ensure caches are empty.
* Archive any reports you want to keep before triggering housekeeping; files
  older than the retention window are permanently deleted.
* Keep the log directory under version control ignores (e.g. `.gitignore`)
  so logs never end up in commits.

For additional operational notes see the [static-analysis pipeline
plan](../static_analysis/static_analysis_pipeline_plan.md).
