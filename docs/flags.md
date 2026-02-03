# SCYTALEDROID_* flag classification

Classification follows: **keep** (supported) and **deprecated** (do not use for research runs).

## Keep
- `SCYTALEDROID_PIPELINE_VERSION`, `SCYTALEDROID_CATALOG_VERSIONS`, `SCYTALEDROID_CONFIG_HASH`, `SCYTALEDROID_STUDY_TAG` (static run metadata)
- `SCYTALEDROID_STATIC_*` toggles for CLI verbosity and limits (e.g., `SCYTALEDROID_STATIC_SHOW_TIMINGS`, `SCYTALEDROID_STATIC_FINDING_LIMIT`)
- `SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT` (controls permission snapshot refresh)
- `SCYTALEDROID_STATIC_QUIET`, `SCYTALEDROID_STATIC_SHOW_FINDINGS`, `SCYTALEDROID_STATIC_SHOW_PIPELINE`
- `SCYTALEDROID_STRINGS_INCLUDE_HTTPS_RISK`, `SCYTALEDROID_STRINGS_DEBUG` (string analysis knobs)
- `SCYTALEDROID_INVENTORY_STALE_SECONDS` (inventory staleness threshold)

## Deprecated (do not use for research runs)
- `SCYTALEDROID_INVENTORY_MODE=legacy` (old inventory path).
- Legacy harvest pull modes (`pull_mode="legacy"`) – hidden from UI.
- Boxed UI output (`SCYTALEDROID_UI_BOXED`) – dev-only switch.

These flags are retained for backward compatibility but should not be used for Tier-1 runs.
