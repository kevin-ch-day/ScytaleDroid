# Phase B1/B2 Schema Normalization Spec (2026-06-14)

This is a repo-specific implementation spec for the next schema work after the
current Phase A checkpoint.

This document is based on:

- [scytaledroid_canonical_schema_map_2026-06-14.md](./scytaledroid_canonical_schema_map_2026-06-14.md)
- [scytaledroid_external_schema_research_2026-06-14.md](./scytaledroid_external_schema_research_2026-06-14.md)
- [database_schema_upgrade_research_2026-06-14.md](./database_schema_upgrade_research_2026-06-14.md)
- `scripts/db/report_canonical_schema_map.py`
- `scripts/db/report_type_normalization_preflight.py`
- `scripts/db/report_phase_a_typed_read_parity.py`
- `scytaledroid/Database/db_utils/schema_migration_registry.py`
- `scytaledroid/Database/db_queries/sql_typed_reads.py`

This pass is a specification only.

- no live `ALTER TABLE`
- no column drops
- no FK enforcement yet
- no Permission Intel changes

## Objective

Phase B is not a generic cleanup pass. It has two bounded goals:

1. B1: define and normalize the canonical join-key contract
2. B2: cut reads over to already-populated typed replacement columns

## Current live checkpoint

Current live state at spec time:

- `artifact_registry` total rows: `22351`
- dynamic dangling rows: `0`
- static dangling rows: `8810`
- fallback-needed rows: `0`
- live schema version: `0.3.3-typed-backfill`
- typed-read parity clean: `True`

This matters because:

- B1 can focus on join-key normalization without reopening detached dynamic prune work
- B2 can focus on read preference and deprecation planning because typed columns already have parity

## Canonical collation recommendation

Recommended canonical collation for shared textual identity and join keys:

- charset: `utf8mb4`
- collation: `utf8mb4_unicode_ci`

Reasoning:

- package names, profile keys, session stamps, and UUID strings are ASCII-like
  operational identifiers, not locale-sensitive free text
- the repo already uses `utf8mb4_unicode_ci` in core canonical tables such as
  `apps.package_name` and `android_app_profiles.profile_key`
- adopting one utf8mb4 family across canonical key surfaces is safer than
  keeping mixed `utf8mb4_general_ci` and `latin1_swedish_ci`
- duplicate-collapse checks against `LOWER(CONVERT(... USING utf8mb4) COLLATE utf8mb4_unicode_ci)`
  are currently clean for the target families in live data

Non-goal:

- do not use `latin1`
- do not normalize keys to binary collation in this pass

## Phase B1: canonical join-key collation and width normalization

### B1 scope

This spec treats the following live families as the minimum B1 target set:

1. `session_stamp`
2. `package_name`
3. `package_name_lc`
4. `profile_key`
5. `dynamic_run_id`
6. `dynamic_run_uuid`

Planned B1 target column count for the first implementation wave: `12`

Those 12 table/column targets are:

1. `static_analysis_sessions.session_stamp`
2. `static_analysis_runs.session_stamp`
3. `static_session_run_links.session_stamp`
4. `static_findings_summary.session_stamp`
5. `static_string_summary.session_stamp`
6. `apps.package_name`
7. `apk_sets.package_name`
8. `harvest_apk_observations.package_name`
9. `analysis_dynamic_cohort_status.package_name_lc`
10. `dynamic_sessions.profile_key`
11. `static_analysis_runs.profile_key`
12. `android_app_profiles.profile_key`

`dynamic_run_id` and `dynamic_run_uuid` are part of the contract definition,
but do not require a shape change beyond consistency verification in the first
B1 wave because their live widths are already effectively aligned to UUID use.

### B1 target contract tables

#### session_stamp family

Target contract:

- type: `varchar(128)`
- charset/collation: `utf8mb4_unicode_ci`

Table details:

| Table | Column | Current Type | Current Collation | Current Width | Target | Max Len | Distinct | Nulls | Duplicate Collapse Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `static_analysis_sessions` | `session_stamp` | `varchar(128)` | `utf8mb4_general_ci` | 128 | `varchar(128) utf8mb4_unicode_ci` | 31 | 28 | 0 | 0 |
| `static_analysis_runs` | `session_stamp` | `varchar(128)` | `utf8mb4_general_ci` | 128 | `varchar(128) utf8mb4_unicode_ci` | 31 | 28 | 0 | 0 |
| `static_session_run_links` | `session_stamp` | `varchar(128)` | `latin1_swedish_ci` | 128 | `varchar(128) utf8mb4_unicode_ci` | 31 | 26 | 0 | 0 |
| `static_findings_summary` | `session_stamp` | `varchar(64)` | `utf8mb4_general_ci` | 64 | `varchar(128) utf8mb4_unicode_ci` | 31 | 28 | 0 | 0 |
| `static_string_summary` | `session_stamp` | `varchar(64)` | `utf8mb4_general_ci` | 64 | `varchar(128) utf8mb4_unicode_ci` | 31 | 28 | 0 | 0 |

Known live issue:

- `static_session_run_links.session_stamp` is still `latin1_swedish_ci`
- child evidence summary tables still use `varchar(64)` even though the canonical session shell uses `varchar(128)`

Index membership:

- `static_analysis_sessions`: `ix_static_session_stamp`, `ux_static_session_natural`
- `static_analysis_runs`: `ix_static_runs_session`, `ix_static_runs_session_version`
- `static_session_run_links`: `uniq_session_package`
- `static_findings_summary`: `ix_findings_session`, `ix_findings_session_pkg`, `ix_ssum_sess_pkg`, `ux_findings_summary`
- `static_string_summary`: `ix_string_summary_session`, `ux_string_summary`

View dependencies:

- `v_static_session_health_v2`
- `v_static_session_cleanup_candidates_v2`
- `v_run_overview`
- `v_web_app_sessions`
- `v_web_static_dynamic_app_summary`
- `vw_static_*` and `v_static_*` session-scoped summaries

Writer dependencies:

- static run/session persistence writers
- static session refresh and rollup utilities
- static findings/string summary persistence

Preflight SQL:

```sql
SELECT
  table_name,
  column_name,
  character_set_name,
  collation_name,
  character_maximum_length
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND column_name = 'session_stamp';

SELECT
  COUNT(DISTINCT session_stamp) AS raw_distinct,
  COUNT(DISTINCT LOWER(CONVERT(session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci)) AS normalized_distinct
FROM static_analysis_sessions;
```

Rollback note:

- revert views first if comparison queries show changed join cardinality
- keep a dry-run comparison of affected `v_static_session_*` and `v_web_*` row counts

Migration risk:

- moderate, because `session_stamp` is the highest-fanout static join key

#### package_name family

Target contract:

- type: `varchar(255)`
- charset/collation: `utf8mb4_unicode_ci`

Table details:

| Table | Column | Current Type | Current Collation | Current Width | Target | Max Len | Distinct | Nulls | Duplicate Collapse Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `apps` | `package_name` | `varchar(255)` | `utf8mb4_unicode_ci` | 255 | keep | 81 | 578 | 0 | 0 |
| `apk_sets` | `package_name` | `varchar(255)` | `utf8mb4_general_ci` | 255 | `varchar(255) utf8mb4_unicode_ci` | 45 | 152 | 0 | 0 |
| `harvest_apk_observations` | `package_name` | `varchar(255)` | `utf8mb4_general_ci` | 255 | `varchar(255) utf8mb4_unicode_ci` | 45 | 152 | 0 | 0 |

Known live issue:

- `package_name` collations are mixed across identity, harvest, and analysis/read-model tables

Index membership:

- `apps`: unique `package_name`
- `apk_sets`: `ix_apk_sets_package_version`
- `harvest_apk_observations`: `ix_harvest_obs_package`, `ux_harvest_obs_member`

View dependencies:

- `v_run_identity`
- `v_static_handoff_v1`
- `v_web_app_directory`
- `v_web_runtime_run_detail`
- `v_web_static_dynamic_app_summary`
- `vw_latest_apk_per_package`

Writer dependencies:

- inventory sync
- harvest persistence
- APK set linkage
- static and dynamic session persistence

Preflight SQL:

```sql
SELECT
  table_name,
  column_name,
  collation_name
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND column_name = 'package_name';

SELECT
  COUNT(DISTINCT package_name) AS raw_distinct,
  COUNT(DISTINCT LOWER(CONVERT(package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci)) AS normalized_distinct
FROM apps;
```

Rollback note:

- compare row counts in `apps`, `apk_sets`, and package-keyed views before and after

Migration risk:

- moderate, because package-name joins cross identity, harvest, dynamic, and reporting surfaces

#### package_name_lc family

Current live state:

- not broadly implemented yet as a canonical base-table family
- present locally on `analysis_dynamic_cohort_status.package_name_lc`
- also present in some views including `v_static_handoff_v1`

Recommended target contract:

- type: `varchar(255)`
- charset/collation: `utf8mb4_unicode_ci`
- semantics: deterministic lowercase projection of canonical package name

Reason for spec inclusion:

- this is a target-state helper key that should be added deliberately to the
  canonical identity/read-model spine, not inferred ad hoc from view definitions

Initial B1 table target:

| Table | Column | Current Type | Current Collation | Current Width | Target | Max Len | Distinct | Nulls | Duplicate Collapse Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `analysis_dynamic_cohort_status` | `package_name_lc` | `varchar(255)` | `utf8mb4_unicode_ci` | 255 | keep | derive from package data | live derived | unknown | 0 expected |

Migration risk:

- low for existing derived usage
- higher if later promoted into canonical identity tables without writer support

#### profile_key family

Target contract:

- type: `varchar(64)`
- charset/collation: `utf8mb4_unicode_ci`

Table details:

| Table | Column | Current Type | Current Collation | Current Width | Target | Max Len | Distinct | Nulls | Duplicate Collapse Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dynamic_sessions` | `profile_key` | `varchar(64)` | `utf8mb4_general_ci` | 64 | `varchar(64) utf8mb4_unicode_ci` | 0 live | 0 | 143 | 0 |
| `static_analysis_runs` | `profile_key` | `varchar(64)` | `utf8mb4_general_ci` | 64 | `varchar(64) utf8mb4_unicode_ci` | 4 | 1 | 0 | 0 |
| `android_app_profiles` | `profile_key` | `varchar(64)` | `utf8mb4_unicode_ci` | 64 | keep | 22 | 12 | 0 | 0 |

Known live issue:

- `profile_key` collations are mixed across canonical profile taxonomy and execution tables
- `dynamic_sessions.profile_key` is currently all null in live data, which lowers migration risk but also shows weak current use

Index membership:

- `android_app_profiles`: primary key
- `apps`: `idx_apps_profile_key`
- `web_static_dynamic_app_summary_cache`: `idx_wsdsac_profile`

View dependencies:

- `v_run_identity`
- `v_web_runtime_run_detail`
- `v_web_static_dynamic_app_summary`
- `v_dep_static_profile`

Writer dependencies:

- static run persistence
- dynamic session persistence
- app/profile catalog workflows

Preflight SQL:

```sql
SELECT
  COUNT(DISTINCT profile_key) AS raw_distinct,
  COUNT(DISTINCT LOWER(CONVERT(profile_key USING utf8mb4) COLLATE utf8mb4_unicode_ci)) AS normalized_distinct
FROM android_app_profiles
WHERE profile_key IS NOT NULL;
```

Rollback note:

- compare `v_dep_static_profile` and profile-filtered run indexes before and after

Migration risk:

- low to moderate because live distinct count is small and collision risk is zero

#### dynamic_run_id and dynamic_run_uuid contract

Canonical contract:

- authoritative dynamic session key: `dynamic_sessions.dynamic_run_id`
- type: `char(36)`
- charset/collation: `utf8mb4_unicode_ci` recommended for cross-family consistency

Legacy-compatible ledger field:

- `artifact_registry.dynamic_run_id`
- current type: `varchar(64) utf8mb4_general_ci`
- max observed length: `36`
- non-null rows: `3109`
- distinct values: `133`

Typed replacement field:

- `artifact_registry.dynamic_run_uuid`
- current type: `char(36) utf8mb4_general_ci`
- non-null rows: `3109`
- distinct values: `133`

Current state:

- no dangling dynamic rows
- parity clean
- no collapse risk detected under the canonical collation

Spec implication:

- B1 does not need a risky re-shape of the dynamic UUID family
- B1 should normalize collation only if done as part of a wider key-family pass
- B2 should prefer `dynamic_run_uuid` immediately in reads

### B1 implementation notes

Recommended order:

1. preflight duplicate-collapse checks
2. widen short `session_stamp` children to the canonical width
3. convert `latin1_swedish_ci` `session_stamp` in `static_session_run_links`
4. normalize `package_name` collations
5. normalize `profile_key` collations
6. rebuild or validate affected repo-owned views

Do not do in B1:

- FK enforcement
- legacy column drops
- `package_name_lc` greenfield rollout across all canonical tables

## Phase B2: typed-read cutover

### B2 objective

Prefer typed replacement fields in read paths now that Phase A backfill and
parity are clean, while preserving legacy columns for compatibility.

Current typed-read helper adoption count: `11` repo read-path files

Current typed-read helper surfaces:

1. `scripts/db/report_apk_lineage_availability.py`
2. `scripts/db/report_dynamic_static_pairing_eligibility.py`
3. `scripts/db/verify_static_session_id_rollout.py`
4. `scytaledroid/Database/db_queries/views_bridge.py`
5. `scytaledroid/Database/db_queries/views_web.py`
6. `scytaledroid/Database/db_scripts/dynamic_static_alignment_report.py`
7. `scytaledroid/Database/db_scripts/package_lineage_read_model.py`
8. `scytaledroid/Database/db_utils/health_checks/analysis_integrity.py`
9. `scytaledroid/Database/db_utils/health_checks/summary.py`
10. `scytaledroid/Database/db_utils/menus/health_checks.py`
11. `scytaledroid/Database/db_utils/phase_a_read_parity.py`

### B2 cutover matrix

#### 1. `artifact_registry.dynamic_run_uuid` over `artifact_registry.dynamic_run_id`

- legacy column: `artifact_registry.dynamic_run_id`
- typed column: `artifact_registry.dynamic_run_uuid`
- current parity evidence:
  - `dynamic_run_uuid_parity_mismatch_rows = 0`
- writer dual-write status:
  - active
  - `scytaledroid/Database/db_utils/artifact_registry.py` populates typed linkage fields
- read paths already typed-aware:
  - integrity/parity/audit surfaces
  - canonical schema map
- read paths still using legacy:
  - direct dynamic-run string lookups in dynamic storage and maintenance code
  - legacy fallback predicates in registry readers
- fallback policy:
  - prefer `dynamic_run_uuid`
  - fall back to normalized `dynamic_run_id` only for legacy rows or compatibility probes
- tests needed:
  - keep `tests/db/test_artifact_registry_typed_linkage.py`
  - keep `tests/db/test_phase_a_typed_read_parity.py`
  - add view/read-model tests when more consumers switch to typed-only preference
- deprecation condition:
  - after all canonical read paths prefer `dynamic_run_uuid`
  - after live parity stays clean across at least one more migration cycle

#### 2. `dynamic_sessions.static_run_id_u` over `dynamic_sessions.static_run_id`

- legacy column: `dynamic_sessions.static_run_id`
- typed column: `dynamic_sessions.static_run_id_u`
- current parity evidence:
  - `static_link_state_mismatch_rows = 0`
- writer dual-write status:
  - active
  - `scytaledroid/DynamicAnalysis/storage/persistence.py` writes both
- read paths already typed-aware:
  - rollout verification
  - dynamic/static pairing
  - alignment and lineage reports
  - web/db typed helper surfaces
- read paths still using legacy:
  - some dynamic maintenance utilities still query `static_run_id` directly
  - some operator displays still expose the legacy column name
- fallback policy:
  - use `resolved_dynamic_session_static_run_id()` everywhere practical
  - legacy signed value remains fallback only
- tests needed:
  - existing typed parity tests
  - targeted dynamic maintenance tests once maintenance SQL is switched
- deprecation condition:
  - once direct reads of `dynamic_sessions.static_run_id` are removed from runtime/report code
  - after future FK preflight confirms `static_run_id_u` can support hardening

#### 3. `static_analysis_runs.run_started_at_utc` over `static_analysis_runs.run_started_utc`

- legacy column: `static_analysis_runs.run_started_utc`
- typed column: `static_analysis_runs.run_started_at_utc`
- current parity evidence:
  - `started_at_parity_mismatch_rows = 0`
- writer dual-write status:
  - active on current persistence path
- read paths already typed-aware:
  - `views_bridge`
  - health-check summary surfaces
  - typed parity audit
- read paths still using legacy:
  - some ad hoc SQL/report surfaces and legacy textual projections
- fallback policy:
  - prefer `resolved_static_run_started_at_utc()` for comparisons and ordering
  - use `resolved_static_run_started_utc_text()` only for legacy-compatible display text
- tests needed:
  - keep `tests/db/test_phase_a_typed_read_parity.py`
  - keep static health/report tests that assert ordering and summary logic
- deprecation condition:
  - when no canonical read path relies on textual timestamp parsing
  - when run-ordering and view parity are proven after cutover

## Proposed Phase B migration governance entries

Do not apply these yet. Register only when implementation starts.

Recommended IDs:

- `20260614_phase_b1_join_key_collation_width_spec_v1`
- `20260614_phase_b2_typed_read_cutover_spec_v1`

Recommendation:

- do not add them as active `MigrationSpec` entries yet unless the registry is
  explicitly extended to support non-applying spec checkpoints
- if added early, they should be marked manual/spec-only and should not alter
  the live DB

## Required preflight SQL before implementation

### Duplicate-collapse checks

```sql
SELECT
  COUNT(DISTINCT package_name) AS raw_distinct,
  COUNT(DISTINCT LOWER(CONVERT(package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci)) AS normalized_distinct
FROM apps;
```

Repeat for:

- `apk_sets.package_name`
- `harvest_apk_observations.package_name`
- `android_app_profiles.profile_key`
- `static_analysis_sessions.session_stamp`
- `static_session_run_links.session_stamp`

### Width checks

```sql
SELECT
  table_name,
  column_name,
  character_maximum_length,
  MAX(CHAR_LENGTH(session_stamp)) AS max_observed_length
FROM information_schema.columns
JOIN static_analysis_sessions ON 1=1
WHERE table_schema = DATABASE()
  AND column_name = 'session_stamp';
```

Use equivalent per-table checks for:

- `session_stamp`
- `package_name`
- `profile_key`
- `dynamic_run_id`

### Typed-read parity checks

Reuse:

- `PYTHONPATH=. python scripts/db/report_phase_a_typed_read_parity.py`

## Risks and rollback

### B1 risks

- join cardinality changes in static session/read-model views
- hidden collated comparison behavior changes in unique indexes
- child table/index rebuild cost on high-fanout static summary tables

Rollback strategy:

- stage migrations on a clone first
- take before/after counts for repo-owned views
- cut over one key family at a time
- keep view recreation scripts ready for immediate parity rebuild

### B2 risks

- lingering runtime/report code directly reading legacy columns
- mixed display semantics where typed reads are used in one path and raw legacy text in another

Rollback strategy:

- typed-read helper functions already encapsulate fallback
- if a consumer breaks, revert that read path to the helper rather than raw legacy SQL

## Tests required for implementation

Keep and extend:

- `tests/db/test_schema_migration_governance.py`
- `tests/db/test_report_canonical_schema_map.py`
- `tests/db/test_phase_a_typed_read_parity.py`
- `tests/db/test_artifact_registry_typed_linkage.py`
- `tests/db/test_report_artifact_registry_integrity.py`
- `tests/db/test_report_artifact_registry_dynamic_dangling.py`
- `tests/db/test_artifact_registry_dynamic_prune.py`
- `tests/database/test_schema_manifest_static_handoff_view.py`
- `tests/database/test_static_session_operator_audit.py`
- `tests/unit/test_analysis_integrity_summary.py`
- `tests/static_analysis/test_report_json_storage.py`
- `tests/static_analysis/test_run_health.py`

Add when implementing B1:

- duplicate-collapse audit tests for target key families
- session-stamp width/collation contract tests
- package-name collation parity tests across identity/harvest tables

Add when implementing B2:

- typed-helper adoption tests for remaining dynamic maintenance/read-model code
- deprecation-guard tests that fail if new direct legacy reads are introduced on canonical paths

## Decision summary

The next schema work should be:

1. implement B1 on the explicit `12` table/column targets above
2. implement B2 as typed-read preference expansion and legacy-read reduction

The next schema work should not be:

- a new research memo
- a broad FK hardening pass
- a legacy column drop pass
- a Permission Intel integration rewrite
