# Permission Intel Contract

This is the active ScytaleDroid contract for the shared Permission Intel
surface. Older S1/S2 design notes are archived under
`docs/database/archive/permission-intel-phase-notes/`.

## Active Boundaries

- ScytaleDroid core evidence uses `SCYTALEDROID_DB_*`.
- Permission Intel dictionary, queue, governance, and signal reads use
  `SCYTALEDROID_PERMISSION_INTEL_DB_*` or `SCYTALEDROID_PERMISSION_INTEL_DB_URL`.
- Erebus uses `EREBUS_*` or its own project-specific DSN. Do not point
  ScytaleDroid at an Erebus catalog unless the deployment intentionally shares
  the same Permission Intel schema.
- Static analysis results remain in the ScytaleDroid core catalog; Permission
  Intel is not the static results database.

## Static Writer Surface

ScytaleDroid may write shared Permission Intel intake rows for static manifest
permission tokens. The static report preserves two distinct roles:

- `permissions.declared` is the legacy report field for `<uses-permission>`
  requests, including SDK-specific request variants.
- `permissions.custom` contains exact `<permission>` definitions owned by the
  analyzed APK.

Both roles feed dictionary intake, and a definition must remain visible even
when the same APK does not request it. They are not collapsed into shared
`android_permission_obs_sample` facts: that table has no agreed source-aware
identity capable of preserving requested-versus-defined evidence.

Dictionary intake deduplicates permission identity case-insensitively to match
the shared catalog collation. If request and definition spellings differ only
by case, the exact `<permission>` definition spelling and `app_defined` role
win, and the ledger is updated once for that analyzed artifact.

The current intake tables are:

- `android_permission_dict_unknown`
- `android_permission_dict_queue`
- OEM `last_seen` style metadata through repo-owned helper functions

ScytaleDroid static may emit these `dict_unknown.triage_status` values:

- `malformed`
- `app_defined`
- `oem_candidate`
- `aosp_missing`
- `new`

Unresolved AOSP candidates are written as review-only `queue_action = 'defer'`.
Legacy `aosp` and `aosp_promote` inputs are normalized to `defer`; neither is a
direct platform-promotion authority.

## Read Surface

Reference reads must go through `scytaledroid.Database.db_core.permission_intel`
or helper facades that use that seam. Do not add direct application SQL against
`android_permission_*` tables on the core DB connection.

Current reads include:

- AOSP permission dictionary and protection metadata
- OEM/vendor dictionaries and prefix rules
- accepted v1 catalog views (`android_permission_v1_catalog_release`,
  `android_permission_v1_current_permission`,
  `android_permission_v1_scytaledroid_permission`) used as the static analysis
  catalog when Permission Intel is reachable
- current-interpretation fact tables (authority / non-permission / token
  anomaly / concept / declaration conflicts)
- governance snapshot readiness signals
- signal catalog/mapping data used by static scoring and reporting

`config/framework_permissions.yaml` is the offline fallback when those v1 views
are unset or unreadable. The undeployed `android_permission_v1_1_*` candidate
is not a Scytale read surface.

## Observation Writes

ScytaleDroid does not currently write `android_permission_obs_sample` rows.
Future observation writes must satisfy the observation-readiness checks before
any apply path exists:

- include `permission_string`, `artifact_sha256`, `static_run_id`, and
  `package_name`
- preserve static lineage back to `static_analysis_runs`
- preserve an occurrence role such as `REQUESTED` or `DEFINED`; a generic
  `apk_manifest` source label alone is insufficient
- account for brownfield PI catalogs where Erebus migrations may add optional
  columns such as `run_id`, `bucket`, `rule_fired`, or `sha256`

## Operational Checks

Use these read-only checks before paper-grade or cross-repo Permission Intel
work:

```bash
PYTHONPATH=. python scripts/db/check_permission_intel.py
PYTHONPATH=. python scripts/db/audit_permission_intel_queue_compatibility.py \
  --json --output /absolute/private/path/queue-compatibility.json
PYTHONPATH=. python scripts/db/audit_static_permission_observation_linkage.py
./scripts/db/run_permission_intel_scytale_s2_readiness_audit.sh
```

The queue report remains read-only. When `--output` is supplied, it writes a
mode-`0600` evidence file outside the repository and binds the result to the
live v1 release, schema/catalog digests, and its own semantic digest.

Related active docs:

- `docs/maintenance/permission_intelligence_pipeline.md`
- `docs/maintenance/pi_erebus_operational_boundary.md`
- `docs/database/permission_split_migration_history.md` (historical execution record)
- `docs/database/permission_intel_schema_drift_erebus_vs_scytaledroid.md`
- `docs/database/permission_intel_observation_readiness.md`
