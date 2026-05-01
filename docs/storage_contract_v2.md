# Storage Contract V2

## Goal

ScytaleDroid should stop treating filesystem layout as artifact identity.

The current `data/device_apks/<device>/<date>/<package>/...` layout is acceptable
as an ingest layout, but it is not suitable as the long-term identity and
retention model because:

- payload retention grows unbounded across sessions
- raw paths act like identity
- reports and receipts accumulate with mixed semantics

V2 separates canonical bytes, provenance receipts, and derived outputs.

## Authority Model

- Database catalog: canonical artifact identity and lookup
- Filesystem receipts: canonical session/package provenance
- Filesystem payload paths: storage/materialization only
- Output reports: operator-facing latest/archive views
- Frozen evidence: pinned material that prune must not touch

This means:

- `local_artifact_path` is not identity
- a package/session receipt references canonical artifact ids and hashes
- payload movement is allowed as long as catalog resolution remains valid

## Directory Contract

```text
data/
  store/
    apk/
      sha256/
        ab/
          <sha256>.apk

  receipts/
    sessions/
      <session>/
        session_receipt.json
        run_map.json
        selected_artifacts.json
    harvest/
      <session>/
        <package>.json

  inventory/
    <device_serial>/
      latest.json
      history/
        inventory_<timestamp>.json

  analysis/
    static/
      latest/
        reports/
        baseline/
        dynamic_plan/
      archive/
        <session>/
          reports/
          baseline/
          dynamic_plan/

  audit/
    storage/
    selection/
    persistence/
    dynamic/

output/
  reports/
    static/
      latest/
      archive/

evidence/
  frozen/

logs/
cache/
tmp/
```

## Canonical Units

### Canonical payload

The canonical retained unit is the individual APK artifact.

Retention identity:

- `sha256`
- `file_size`
- `artifact_kind`

Lookup/grouping metadata:

- `package_name`
- `version_code`
- `artifact_name`
- `source_kind`
- `source_session`
- `device_serial`

### Canonical receipt

Receipts record what happened in a session.

- one session receipt per session
- one harvest receipt per package per session

Receipts reference artifact ids and hashes, not raw local paths as identity.

## Catalog Tables

Recommended primary tables:

### `artifact_catalog`

- `artifact_id`
- `sha256`
- `file_size`
- `artifact_kind`
- `canonical_relpath`
- unique on `(sha256, file_size, artifact_kind)`

### `artifact_provenance`

- `artifact_id`
- `source_kind`
- `device_serial`
- `session_label`
- `package_name`
- `version_code`
- `artifact_name`
- `snapshot_id`
- `original_relpath`

### `artifact_sets`

- `artifact_set_id`
- `session_label`
- `package_name`
- `version_code`
- `set_hash`
- `research_status`

### `artifact_set_members`

- `artifact_set_id`
- `artifact_id`
- `artifact_name`
- `ordinal`

## Retention Rules

### Canonical payloads

- store one retained copy per unique retention identity
- dedupe globally across harvest and upload sources
- never delete a payload unless another retained payload with the same identity exists
- frozen evidence pins payload reachability logically, not by duplicating bytes

### Derived outputs

Default policy:

- `latest` by default
- `archive` only when explicitly requested or freeze-bound

Examples:

- `output/reports/static/latest/<package>/<artifact>.html`
- `output/reports/static/archive/<session>/<package>/<artifact>.html`
- `data/analysis/static/latest/...`
- `data/analysis/static/archive/<session>/...`

## Migration Order

1. Write and adopt this contract.
2. Add catalog tables and path resolution layer.
3. Add dry-run storage retention audit for the old `data/device_apks` tree.
4. Audit all readers that assume `local_artifact_path` is stable.
5. Change derived outputs to latest-by-default.
6. Change harvest/upload writers to target `data/store/apk/...`.
7. Re-pull or re-ingest into the new layout.
8. Only then allow destructive prune of the old path-first layout.

## Current Implementation Status

Implemented first:

- dry-run retention auditor for the legacy `data/device_apks` tree
- JSON/CSV audit outputs under `output/audit/storage`
- static HTML reports now support `latest|archive|both` mode
- default HTML output now writes to `output/reports/static/latest/...`
- archive HTML output now writes to `output/reports/static/archive/<session>/...`
- static JSON reports now support `latest|archive|both` mode
- default JSON output now writes to `data/static_analysis/reports/latest/...`
- archive JSON output now writes to `data/static_analysis/reports/archive/<session>/...`
- report readers now scan legacy + new locations and dedupe duplicate latest/archive copies
- canonical APK store service now writes retained payloads to `data/store/apk/sha256/...`
- harvest now mirrors per-package receipts to `data/receipts/harvest/<session>/<package>.json`
- API upload now lands in an inbox and materializes retained APKs into the canonical store
- harvest sidecars/manifests now include `canonical_store_path` during the transition

Still pending:

- canonical artifact catalog tables
- path resolver/indirection layer
- destructive prune
- migration/prune of legacy flat files already present under `data/static_analysis/reports`
- migration/re-pull of legacy harvest payloads still rooted under `data/device_apks/...`
- migration away from `data/device_apks/<device>/<date>/...` as canonical storage
