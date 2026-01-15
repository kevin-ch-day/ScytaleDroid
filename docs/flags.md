# SCYTALEDROID_* flag classification

Classification follows: **keep** (supported), **warn** (legacy, to deprecate), **remove** (not for normal use).

## Keep
- `SCYTALEDROID_PIPELINE_VERSION`, `SCYTALEDROID_CATALOG_VERSIONS`, `SCYTALEDROID_CONFIG_HASH`, `SCYTALEDROID_STUDY_TAG` (static run metadata)
- `SCYTALEDROID_STATIC_*` toggles for CLI verbosity and limits (e.g., `SCYTALEDROID_STATIC_SHOW_TIMINGS`, `SCYTALEDROID_STATIC_FINDING_LIMIT`)
- `SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT` (controls permission snapshot refresh)
- `SCYTALEDROID_STATIC_QUIET`, `SCYTALEDROID_STATIC_SHOW_FINDINGS`, `SCYTALEDROID_STATIC_SHOW_PIPELINE`
- `SCYTALEDROID_STRINGS_INCLUDE_HTTPS_RISK`, `SCYTALEDROID_STRINGS_DEBUG` (string analysis knobs)
- `SCYTALEDROID_INVENTORY_STALE_SECONDS` (inventory staleness threshold)

## Warn (legacy behavior; deprecate)
- `SCYTALEDROID_INVENTORY_MODE=legacy` (old inventory path); warn on use.
- Legacy harvest pull modes (`pull_mode="legacy"`) – warn; hidden from UI.
- Boxed UI output (`SCYTALEDROID_UI_BOXED`) – hidden dev-only switch.

## Remove (or move to legacy-only)
- `SCYTALEDROID_LOAD_LEGACY_INVENTORY` (legacy loader removed; new inventory package is the only path).
- Any flags that select legacy schemas/persistence paths (not currently required for PhD runs).
- Any flags that resurrect legacy runners (quick_harvest) for normal operation.

This list should be updated as flags are added/removed; “warn” items are expected to be phased out once v2 pipelines are fully validated.
