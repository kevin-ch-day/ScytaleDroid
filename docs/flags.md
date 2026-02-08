# SCYTALEDROID_* flag classification

Classification follows: **keep** (supported) and **deprecated** (do not use for research runs).

## Keep
- `SCYTALEDROID_PIPELINE_VERSION`, `SCYTALEDROID_CATALOG_VERSIONS`, `SCYTALEDROID_CONFIG_HASH`, `SCYTALEDROID_STUDY_TAG` (static run metadata)
- `SCYTALEDROID_STATIC_*` toggles for CLI verbosity and limits (e.g., `SCYTALEDROID_STATIC_SHOW_TIMINGS`, `SCYTALEDROID_STATIC_FINDING_LIMIT`)
- `SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT` (controls permission snapshot refresh)
- `SCYTALEDROID_STATIC_QUIET`, `SCYTALEDROID_STATIC_SHOW_FINDINGS`, `SCYTALEDROID_STATIC_SHOW_PIPELINE`
- `SCYTALEDROID_STRINGS_INCLUDE_HTTPS_RISK`, `SCYTALEDROID_STRINGS_DEBUG` (string analysis knobs)
- `SCYTALEDROID_INVENTORY_STALE_SECONDS` (inventory staleness threshold)
- `SCYTALEDROID_OBSERVER_PROMPTS` (dynamic observer prompts; operator UX only)
- `SCYTALEDROID_PCAPDROID_API_KEY` (PCAPdroid integration; secret; do not log raw value)

## Deprecated (do not use for research runs)
- `SCYTALEDROID_INVENTORY_MODE=legacy` (old inventory path).
- Legacy harvest pull modes (`pull_mode="legacy"`) – hidden from UI.
- Boxed UI output (`SCYTALEDROID_UI_BOXED`) – dev-only switch.
- `SCYTALEDROID_DATASET_RUNS_PER_APP` and related quota overrides – legacy scope-creep footgun.
  Paper #2 quota is locked to **1 baseline + 2 interactive** per app; extra runs are allowed but
  out-of-dataset and deterministically excluded. These env overrides are ignored in dataset-tier paths.

These flags are retained for backward compatibility but should not be used for Tier-1 runs.
