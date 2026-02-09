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
- Historical legacy toggles and experimental knobs are intentionally not documented here.
  If you find an env var in older notes that is not in the **Keep** list above, treat it as unsupported.

These flags are retained for backward compatibility but should not be used for Tier-1 runs.
