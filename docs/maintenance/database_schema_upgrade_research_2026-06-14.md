# Database Schema Upgrade Research

Date: 2026-06-14  
Repo: ScytaleDroid  
DB target observed live: MariaDB `10.11.16-MariaDB`

This note is a repo-specific schema upgrade memo, not a generic database
wishlist. It combines:

- live ScytaleDroid schema inspection
- current MariaDB 10.11 documentation
- the repo's current operational posture around canonical tables, views, and
  rebuildable ledgers

## Live facts

Observed on the current analyst DB:

- `artifact_registry` row count after the detached dynamic prune: `22351`
- `artifact_registry` engine: `InnoDB`
- `artifact_registry` row format: `Dynamic`
- dynamic dangling registry rows after targeted prune: `0`
- static dangling registry rows remain: `8810`

Important live schema observations:

1. `artifact_registry.dynamic_run_id` is `varchar(64)`, while the authoritative
   dynamic key in `dynamic_sessions` and related dynamic tables is `char(36)`.
2. `dynamic_sessions.static_run_id` is `bigint(20)` signed, while
   `static_analysis_runs.id` is `bigint(20) unsigned`.
3. `static_analysis_runs.run_started_utc` is stored as `varchar(64)` instead of
   a temporal type.
4. `static_analysis_runs` has important logical parent links but the live table
   currently lacks foreign keys to `app_versions` and `static_analysis_sessions`.
5. `analysis_dynamic_cohort_status.dynamic_run_id` is logically a 1:1 dynamic
   child surface but has no foreign key to `dynamic_sessions`.
6. The schema is heavy on JSON payload columns in MariaDB, which in practice are
   `LONGTEXT` plus `JSON_VALID(...)` checks rather than a native binary JSON
   storage type.

## Current MariaDB guidance that matters here

Primary sources:

- MariaDB JSON data type docs: <https://mariadb.com/docs/server/reference/data-types/string-data-types/json>
- MariaDB foreign keys docs: <https://mariadb.com/docs/server/ha-and-performance/optimization-and-tuning/optimization-and-indexes/foreign-keys>
- MariaDB generated columns docs: <https://mariadb.com/docs/server/reference/sql-statements/data-definition/create/generated-columns>
- MariaDB ALTER TABLE docs: <https://mariadb.com/docs/server/reference/sql-statements/data-definition/alter/alter-table>
- MariaDB instant alter docs: <https://mariadb.com/docs/server/server-usage/storage-engines/innodb/innodb-online-ddl/innodb-online-ddl-operations-with-the-instant-alter-algorithm>
- MariaDB constraints docs: <https://mariadb.com/docs/server/reference/sql-statements/data-definition/constraint>
- MariaDB ANALYZE TABLE docs: <https://mariadb.com/docs/server/reference/sql-statements/table-statements/analyze-table>
- MariaDB engine-independent statistics docs: <https://mariadb.com/docs/server/ha-and-performance/optimization-and-tuning/query-optimizations/statistics-for-optimizing-queries/engine-independent-table-statistics>
- MariaDB ignored indexes docs: <https://mariadb.com/docs/server/ha-and-performance/optimization-and-tuning/optimization-and-indexes/ignored-indexes>

What those docs imply for ScytaleDroid:

1. MariaDB `JSON` is an alias, not a native binary JSON type.
   That means JSON-heavy tables should not be treated like MySQL native JSON
   designs. Query-critical JSON attributes should be promoted to relational
   columns or generated columns.

2. Foreign keys require compatible types.
   MariaDB requires referenced and referencing columns to be the same or similar
   type, and for integer keys the size and sign must match. That blocks some of
   the FK work ScytaleDroid needs until key typing is normalized.

3. Generated columns are useful, but only when deterministic and stable.
   MariaDB allows indexed generated columns, but the expressions need to be
   deterministic and stable across SQL mode differences. This is good for
   projecting a few hot JSON fields, not for turning every JSON blob into a
   generated-column forest.

4. Online DDL needs explicit discipline.
   MariaDB can do some operations with `ALGORITHM=INSTANT` or online modes, but
   not all schema changes qualify. For ScytaleDroid, migration scripts should
   always state `ALGORITHM` and `LOCK` explicitly for high-risk tables so the
   server either does the intended operation or errors clearly.

5. `CHECK` constraints are enforced.
   MariaDB 10.11 enforces `CHECK` constraints, so ScytaleDroid can use them for
   bounded status domains and shape validation instead of relying only on
   application-side conventions.

6. Statistics/histograms are available and useful.
   `ANALYZE TABLE PERSISTENT` and engine-independent stats are available in this
   MariaDB line. This is relevant because ScytaleDroid has skewed distributions
   on status, package, session, and hash columns, and some query performance
   problems can be improved without schema surgery.

7. Ignored indexes are available in MariaDB 10.11.
   This is useful for safe index cleanup experiments: ScytaleDroid can mark
   candidate indexes ignored before dropping them, instead of guessing.

## What should change

### 1. Add real migration governance

This is the highest ROI schema change, because the current repo mixes:

- canonical DDL in Python
- additive `ALTER TABLE ... IF NOT EXISTS`
- ad hoc maintenance scripts
- live schema drift

Recommended change:

- Add a repo-owned `schema_migrations` table.
- Add versioned migration units with stable identifiers.
- Make bootstrap responsible for creating a base schema and applying pending
  migrations in order, rather than carrying an ever-growing pile of additive
  `ALTER TABLE` statements forever.
- Keep view deployment separate from table migrations, but tracked.

Why:

- The live DB already diverges from the intended manifest on important FK
  surfaces.
- This repo is now beyond the phase where "best effort additive bootstrap" is
  enough.

### 2. Normalize key types before adding more FKs

This is the next P0/P1 schema task.

Recommended normalization targets:

- `artifact_registry.dynamic_run_id`: move from `varchar(64)` toward `char(36)`
  or add a new normalized `dynamic_run_uuid char(36)` and backfill first.
- `dynamic_sessions.static_run_id`: change from signed `bigint(20)` to
  `bigint(20) unsigned`.
- Audit every `*_run_id`, `*_session_id`, and `apk_set_id` cross-table linkage
  column for signedness/length/collation compatibility.
- Replace temporal `varchar` fields such as `static_analysis_runs.run_started_utc`
  with typed `datetime` or `datetime(6)` columns.

Why:

- MariaDB FK rules make some desired integrity upgrades impossible until this is
  cleaned up.
- Typed temporal columns unlock sane range predicates, indexes, and ordering.

### 3. Add selective referential integrity, not blanket FK coverage

ScytaleDroid should not add foreign keys everywhere.

Recommended FK additions after type normalization:

- `static_analysis_runs.static_session_id -> static_analysis_sessions.static_session_id`
- `static_analysis_runs.app_version_id -> app_versions.id`
- `dynamic_sessions.static_run_id -> static_analysis_runs.id`
  after signedness normalization
- `analysis_dynamic_cohort_status.dynamic_run_id -> dynamic_sessions.dynamic_run_id`
  if that surface is intended to be 1:1 and canonical

Recommended non-goal:

- Do not add hard FKs from `artifact_registry` to runtime/session tables.

Why:

- `artifact_registry` is a lifecycle ledger with known cleanup/repair semantics.
  The project has already converged on typed linkage plus audit/prune workflows,
  which is the right posture for that table.
- The canonical session/run tables should be tighter.
- The rebuildable or operational ledgers should stay more flexible.

### 4. Promote hot JSON fields instead of querying blobs directly

Because MariaDB JSON is text-backed, ScytaleDroid should not keep growing
query-critical read models on top of raw JSON extraction alone.

High-value projection candidates:

- `static_analysis_runs`
  - run-health / fidelity / canonical-class booleans already partly relational
  - consider promoting any repeatedly-filtered handoff/fidelity fields
- `dynamic_sessions`
  - keep grade/reasons JSON for evidence, but project any frequently filtered
    status/regime fields to scalar columns
- `artifact_registry.meta_json`
  - do not try to normalize everything
  - only project fields that appear repeatedly in operational filters/audits

Recommended mechanism:

- use generated columns only for a small number of deterministic, stable JSON
  extracts
- otherwise add explicit scalar columns and populate them in writers

Why:

- This matches MariaDB’s JSON implementation realities.
- It reduces repeated `JSON_EXTRACT(...)` in views and reports.

### 5. Tighten domain constraints on statuses and modes

ScytaleDroid currently uses many freeform `varchar` status/mode fields.

High-value candidates for `CHECK` constraints:

- `artifact_registry.run_type`
- `artifact_registry.linkage_migration_status`
- `static_analysis_sessions.session_status`
- `static_analysis_sessions.session_disposition`
- `static_analysis_sessions.web_visibility_default`
- `static_analysis_runs.status`
- `dynamic_sessions.status`
- `analysis_dynamic_cohort_status.status`

This should be done selectively and only after:

- enumerating current real values
- adding compatibility aliases where needed

Why:

- MariaDB 10.11 enforces checks.
- This will stop future drift in status vocabularies.

### 6. Standardize collation and character strategy on shared identity columns

The live schema shows a mix of `utf8mb4_general_ci` and `utf8mb4_unicode_ci`
across tables that share `package_name` and other identity fields.

Recommended direction:

- choose one repo-wide collation policy for cross-table identifiers
- apply it first to:
  - `package_name`
  - `session_stamp`
  - `profile_key`
  - `publisher_key`
  - `scenario_id`

Why:

- It reduces view/query collation hacks.
- It makes joins less brittle and more predictable.

### 7. Add a formal index review pass instead of just adding more indexes

ScytaleDroid now has enough indexes that the next index pass should be evidence
driven.

Recommended approach:

- inventory current indexes on hot tables
- map each to real query families
- use MariaDB ignored indexes to test suspicious indexes before dropping them
- add histograms/statistics for skewed predicate columns before adding more
  wide composite indexes

High-value tables for that pass:

- `artifact_registry`
- `static_analysis_runs`
- `dynamic_sessions`
- `analysis_dynamic_cohort_status`

Why:

- Some query problems are stats/selectivity issues, not missing-index issues.
- Blind index growth increases write cost and schema complexity.

## What should not change yet

### 1. Do not partition these tables yet

The current live sizes do not justify partition complexity.

Partitioning is not the next bottleneck for:

- `artifact_registry`
- `static_analysis_runs`
- `dynamic_sessions`

Retention and cleanup discipline matter more right now.

### 2. Do not force `artifact_registry` into strict canonical ownership semantics

That table is now on the right trajectory:

- typed linkage
- audit reports
- receipt-first prune

The better move is to keep improving auditability, not to pretend it is a fully
strict child table.

### 3. Do not over-normalize evidence payloads

JSON evidence has value as evidence. The goal is not to explode every JSON
document into relational child tables. The goal is:

- keep evidence blobs
- project hot filter keys
- keep canonical summary surfaces relational

## Recommended rollout order

### Phase A: migration discipline

- add `schema_migrations`
- define migration execution order
- separate table migrations from view deployment

### Phase B: key and time typing

- normalize signedness/length of linkage keys
- add typed temporal columns
- dual-write/backfill before cutover

### Phase C: selective FK hardening

- add FKs to canonical run/session tables
- keep `artifact_registry` soft-linked

### Phase D: JSON/query surface cleanup

- promote hot JSON keys
- remove repeated view-time JSON extraction where possible

### Phase E: domain constraints and collation cleanup

- add checked enums/status domains
- standardize collation on identity columns

### Phase F: index/statistics review

- run `ANALYZE TABLE PERSISTENT`
- test candidate removals with ignored indexes
- only then add/drop indexes

## Highest ROI concrete changes

If this turns into implementation work, the next bounded schema changes should
be:

1. Introduce `schema_migrations`.
2. Add typed replacement columns for:
   - `dynamic_sessions.static_run_id` unsigned
   - `static_analysis_runs.run_started_at_utc` typed datetime
   - optional normalized `artifact_registry.dynamic_run_uuid char(36)`
3. Backfill those columns and dual-write them.
4. Add `static_analysis_runs -> static_analysis_sessions` FK after data cleanup.
5. Add a small generated-column or explicit scalar-column pass for one or two
   high-value JSON predicates, not a broad rewrite.

## Bottom line

ScytaleDroid does not primarily need "more schema." It needs:

- stronger migration governance
- cleaner key typing
- more selective integrity on canonical tables
- less dependence on text-backed JSON for hot query paths
- more disciplined statistics/index operations

That is the right big schema update direction for the current database.
