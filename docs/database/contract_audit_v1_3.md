# Database Contract Audit v1.3

Date: 2026-04-27

This pass moves the database review from evidence collection into
design-and-acceptance control. The inventory/harvest foundation remains locked,
the key static operator bugs are fixed, and the next schema boundary is now the
permission-intelligence split.

This document does not authorize destructive schema changes. It locks the
current project direction and points to the new v1.3 artifacts.

Related artifacts:

- [`ownership_matrix_v1_3.csv`](./ownership_matrix_v1_3.csv)
- [`permission_split_execution_phases.md`](./permission_split_execution_phases.md)
- [`../static_analysis/static_analysis_data_model.md`](../static_analysis/static_analysis_data_model.md)
- [`schema_domain_inventory.md`](./schema_domain_inventory.md)
- [`../risk_scoring_contract.md`](../risk_scoring_contract.md)
- [`../maintenance/workflow_entrypoint_map.md`](../maintenance/workflow_entrypoint_map.md)
- [`../maintenance/operator_acceptance_matrix.md`](../maintenance/operator_acceptance_matrix.md)

## Locked current state

### Inventory and harvest foundation

These remain locked as `CORE_KEEP`:

- `device_inventory_snapshots`
- `device_inventory`
- `apps`
- `android_apk_repository`
- `harvest_source_paths`
- `harvest_artifact_paths`
- `harvest_storage_roots`
- `apk_split_groups`

Interpretation:

- inventory is a retained device-state snapshot ledger
- harvest is a cumulative APK artifact catalog with lineage
- `apps` remains the package identity anchor

### Static operator workflow baseline

These operator bugs are now treated as fixed baseline behavior:

- single-app static analysis enters scan flow instead of drilldown
- version diff selects distinct analyzed versions/builds
- APK Library device grouping resolves the real harvested device serial
- static `View previous runs` opens canonical run history instead of an
  opaque diagnostics wrapper
- package lineage browsing is canonical-first and shows legacy bridge IDs as
  secondary context
- CLI prompts are EOF-safe under exhausted stdin
- reset cancel now aborts the static run cleanly
- auto-suffixed static sessions keep the resolved run context
- interrupted static runs skip the old post-run verification detour

These fixes define the baseline for the new static workflow contract.

### `app_versions`

`app_versions` remains locked as `CORE_REVIEW`.

Working contract:

- `android_apk_repository` = harvested artifact/version truth
- `app_versions` = analyzed static-version parent table
- new runs can create missing `app_versions` rows incrementally
- harvest alone still does not make `app_versions` a complete version ledger

This is unchanged from v1.2.

## New v1.3 direction

The next cleanup milestone is no longer just "schema review." It is a
separation milestone with four explicit tracks:

1. operator workflow
2. database contract
3. permission dictionary separation
4. static-analysis cleanup

The new highest-priority architecture decision is:

- permission meaning and governance move toward a shared DB named
  `android_permission_intel`
- ScytaleDroid keeps operational run outputs locally
- Web is an explicit dependency in the rollout because
  `/var/www/html/ScytaleDroid-Web` still reads older static summary surfaces
  directly in places

## Phase status

Current rollout status:

- Phase 0: complete
- Phase 1: complete
- Phase 2: complete
- Phase 2A: complete
- Phase 2B: complete
- Phase 3: complete
- Phase 4A: complete
- Phase 4B: complete
- Phase 4C: complete
- Phase 5A: complete
- Phase 5B: complete
- Phase 5C: in progress

Interpretation:

- design and ownership are now good enough to guide implementation
- the app seam for permission-intel exists
- the operator stabilization lane required for the current CLI baseline is
  closed
- the permission-intel provisioning/validation lane is complete
- the full Phase 4 lane is now complete
- the active implementation lane is now `Phase 5C` bridge freeze/deprecation
  prep and read-model hardening work
- `Phase 5B` is now complete on current code:
  - dedicated permission-intel runtime cutover
  - duplicate managed permission-intel table freeze
  - bridge-first DB operator surfaces reduced
  - `Persistence/compat_writer.py` removed
  - `StaticAnalysis/cli/core/run_persistence.py` removed
- legacy `correlations` bridge writer removed
- `Phase 5` is now treated as its own staged bridge-reduction lane:
  `5A / 5B / 5C`, with active implementation now concentrated in `5C`
- remaining workflow/data-trust debt now belongs primarily to reporting/read-model
  hardening and later bridge-reduction work, not to keeping Phase 4 open

## Permission split lock

### Shared permission-intel DB candidates

These are now documented as first-wave move candidates:

- `android_permission_dict_aosp`
- `android_permission_dict_oem`
- `android_permission_dict_unknown`
- `android_permission_dict_queue`
- `android_permission_meta_oem_prefix`
- `android_permission_meta_oem_vendor`
- `permission_governance_snapshots`
- `permission_governance_snapshot_rows`
- `permission_signal_catalog`
- `permission_signal_mappings`
- `permission_cohort_expectations`

### ScytaleDroid-local permission outputs

These remain in the ScytaleDroid operational DB:

- `permission_signal_observations`
- `permission_audit_snapshots`
- `permission_audit_apps`
- `static_permission_matrix`
- `static_permission_risk_vnext`

Interpretation:

- shared DB = permission meaning, governance, mapping, reference metadata
- ScytaleDroid DB = observations, per-run matrices, per-run scoring, evidence
  linked outputs

## Execution rule

The permission split is copy-first and non-destructive:

1. provision `android_permission_intel`
2. copy schema
3. copy data
4. validate counts and keys
5. redirect reads through a dedicated permission-intel boundary
6. keep compatibility mirrors/views temporarily
7. preserve `governance_version` and `governance_sha256` on outputs

Not approved in v1.3:

- permission table drops
- table renames during first migration
- forced `app_versions` redesign
- broad static legacy-table retirement

## Definition of done

v1.3 is complete when:

- static workflow is documented around actual operator scopes
- operator acceptance matrix covers the active workflows
- permission split design is documented and decision-complete
- ownership matrix reflects the shared-DB move candidates and the ScytaleDroid
  local output tables
- no destructive schema changes have been executed

## Biggest remaining risks

The biggest open risks after the current fixes are:

1. package-name collation mismatch across core and legacy tables
2. active static dual-write bridge and older static readers still consuming it
3. dynamic evidence retention gaps in the current workspace
4. package-wide cross-analysis view performance for broad scans
5. interrupted-run UX still being more verbose than ideal
6. scan-first static persistence still leaves stale partial sessions that are
   better purged and re-run than reconstructed in place
7. package identity drift still exists in some report and DB surfaces

Additional data-contract seams now made explicit:

6. the project has three different static-risk surfaces with different meaning
7. the project has three different static-finding surfaces with different row
   semantics

Recent execution progress:

- explicit latest-package views now exist for static risk and static finding
  surfaces
- recent run/read-model dashboards have started moving off direct
  `static_findings_summary` and direct permission-audit assumptions
- Web-facing `v_web_app_directory` and `v_web_static_dynamic_app_summary` now
  resolve canonical latest finding counts and latest permission-audit posture
  through those explicit latest-package surfaces
- a materialized cache table,
  `web_static_dynamic_app_summary_cache`, now exists as the preferred fast
  read model for broad latest-package cross-analysis reporting
- Phase A package-name collation normalization has started on the first six core
  tables, using column-level changes where full-table conversion would collide
  with foreign-key constraints
- additional derived/reporting package columns have since been normalized, and
  the remaining mixed package columns are now mostly legacy bridge surfaces
- full all-app static execution has now been proven through post-processing and
  DB reconciliation, shifting the next risk from “does it complete?” to “how
  trustworthy is the persistence/recovery/reporting contract?”
- runtime-mode controls now exist to keep normal operator runs quiet while
  allowing DEV/debug validation context when explicitly enabled
- the latest DB audit also shows the current live `20260428-all-full` session
  is a partial/stale pre-fix batch:
  - `119` completed
  - `1` failed
  - `0` `static_session_run_links`
  - partial Web/session bleed
  - structured `run.end` status still needs stricter coherence with
    persistence failure state
- latest prune / bridge-isolation validation now also includes:
  - `49 passed, 2 skipped`
  - `40 passed, 3 skipped`

## Phase 4 closeout

Phase 4 is now closed:

- `Phase 4A`: lifecycle, persistence, operator trust, and data hygiene
- `Phase 4B`: permission-reference read redirection through the seam
- `Phase 4C`: reporting/read-model/cache cleanup after the read cutover

Closeout evidence:

- smoke closeout session: `phase4a-closeout-smoke`
- full validation session: `20260429-all-full`
- full validation run highlights:
  - `120` analyzed apps
  - `459/459` artifacts
  - `120` canonical runs finalized
  - `3872` normalized findings
  - `120` `permission_audit_apps` child rows
  - permission snapshot parity:
    `checked=120 changed=3 skipped=117 errors=0`
  - DB verification:
    `OK (group scope) static_run_id=1338`
- focused closeout suite:
  - `53 passed`

Current 4B implementation reading:

- governance status/count reads are routed through the `permission_intel` seam
- AOSP/OEM/vendor permission dictionary reads are routed through the seam
- signal catalog reads/updates are routed through the seam
- permission-intel managed-table ownership is centralized in the seam and
  reused by reset/schema/tooling paths
- no remaining app-facing direct `permission_intel` raw SQL reads are expected
  outside the seam
- follow-on bridge reduction/read-model tightening now belongs to `Phase 5`,
  not to keeping `Phase 4` open

## Phase 5 direction

The bridge-reduction lane is now split into:

- `Phase 5A`: bridge parity, collation cleanup, and reader inventory freeze
- `Phase 5B`: bridge write isolation and canonical-first reader migration
- `Phase 5C`: narrow freeze/deprecation of low-risk bridge surfaces

Practical implication:

- do not treat Phase 5 as one large “retire the bridge” task
- `5A` is now closed through the reader inventory, parity, and collation-plan
  artifact
- active implementation work is now `5B` and `5C`
- `5B` now also includes major database/table-control cleanup because the
  biggest remaining pain is mixed table roles and stale support surfaces
- `5C` should continue that cleanup into freeze/deprecation decisions and
  low-risk table retirement

Current adjustment based on execution:

- the project has now done enough pruning that `Phase 5` should be read as:
  - bridge reduction
  - database/table simplification
  - stable read-model and operator-contract hardening
- `Phase 6` should start only after this DB/table shape is cleaner, otherwise
  research-surface work will keep inheriting legacy complexity
