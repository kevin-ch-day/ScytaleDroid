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
permissions:

- `android_permission_dict_unknown`
- `android_permission_dict_queue`
- OEM `last_seen` style metadata through repo-owned helper functions

ScytaleDroid static may emit these `dict_unknown.triage_status` values:

- `malformed`
- `app_defined`
- `oem_candidate`
- `aosp_missing`
- `new`

Static AOSP promotion queue rows use `queue_action = 'aosp'`. Legacy
`aosp_promote` callers are normalized before insert.

## Read Surface

Reference reads must go through `scytaledroid.Database.db_core.permission_intel`
or helper facades that use that seam. Do not add direct application SQL against
`android_permission_*` tables on the core DB connection.

Current reads include:

- AOSP permission dictionary and protection metadata
- OEM/vendor dictionaries and prefix rules
- governance snapshot readiness signals
- signal catalog/mapping data used by static scoring and reporting

## Observation Writes

ScytaleDroid does not currently write `android_permission_obs_sample` rows.
Future observation writes must satisfy the S2-P1A readiness checks before any
apply path exists:

- include `permission_string`, `artifact_sha256`, `static_run_id`, and
  `package_name`
- preserve static lineage back to `static_analysis_runs`
- use source semantics compatible with Erebus (`apk_manifest` for manifest
  observations)
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
- `docs/database/permission_split_execution_phases.md`
- `docs/database/permission_intel_schema_drift_erebus_vs_scytaledroid.md`
- `docs/database/permission_intel_scytaledroid_s2_p1a_operational_readiness.md`
