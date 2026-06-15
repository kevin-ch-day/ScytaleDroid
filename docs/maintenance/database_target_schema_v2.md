# ScytaleDroid target database schema (V2) — domain model and migration design

**Status:** normative **target** design — **session header tables implemented** in `canonical/schema.py` (and on some catalogs in production); run FKs, v2 views, and permission split remain **planned**.  
**Intent:** MariaDB becomes the **primary query surface** for Web and operators for static (and bounded dynamic) truth; JSON and filesystem paths remain **evidence and reproducibility**, not the authoritative catalog.  
**Supersedes as architecture direction:** patch-level notes in [database_schema_cleanup_design.md](database_schema_cleanup_design.md) remain useful for near-term tactics; **this document** defines the **better schema** end state and migration spine.

**Constraints for all phases until explicitly approved:** no fake repair of broken historical sessions; no detector semantic changes as part of schema work (persistence/normalization layers may change); destructive SQL only in late phases with backup, preview, and verify.

**Repo parity:** The DDL for **`static_analysis_sessions`** and **`static_session_disposition_history`** matching the first production deploy is now in `scytaledroid/Database/db_queries/canonical/schema.py` (`ordered_schema_statements` / `schema_manifest`). See **Appendix A0** for differences vs the older illustrative sketches in Appendix A.

---

## 1. Target domain model (layers)

Each layer lists **primary physical tables** (or well-defined views). Arrows are conceptual lineage, not SQL FKs unless stated.

### 1.1 Identity layer

| Concept | Role | Target artifacts |
| --- | --- | --- |
| **App** | Stable package identity | `apps` (package_name, profile_key, publisher metadata) |
| **App version** | Version line for an app | `app_versions` (FK `app_id`, version_name, version_code) |
| **APK artifact** | Single file hash / role | Optional future `apk_artifacts` (sha256, file_size, role enum: base/split/config/unknown) — today implied by hashes on runs; **normalize** under `apk_set_id` |
| **APK set / split bundle** | One logical install for static | New **`static_apk_artifact_sets`** (or `artifact_install_sets`): `id`, `app_version_id`, `artifact_set_hash`, `base_apk_sha256`, optional `split_count`, `provenance_json` — ties harvest + static |

**Principle:** Web and static joins should key on **`app_id` / `app_version_id` / `apk_set_id`**, not free-text package strings alone.

### 1.2 Harvest layer

| Concept | Role | Target artifacts |
| --- | --- | --- |
| **Inventory snapshot** | Device state at a point in time | `device_inventory_snapshots`, `device_inventory` (existing) |
| **Harvest session** (target) | Operator workflow unit: “pulled these captures for this profile” | New optional **`harvest_sessions`** (`harvest_session_id`, `device_serial`, `profile_ref`, `started_at`, `ended_at`, `snapshot_id` nullable FK) — links inventory to later static |
| **Harvested APK set** | Concrete files selected for analysis | FK from **`static_apk_artifact_sets`** to harvest session and/or inventory row keys |

Today much of this lives in filesystem evidence; the target is **referenceable IDs in DB** without duplicating full APK bytes.

### 1.3 Static execution layer

| Concept | Role | Target artifacts |
| --- | --- | --- |
| **Static analysis session** | One operator batch: scope, intent, aggregate outcome | **`static_analysis_sessions`** (center of gravity) |
| **Static analysis run** | One static attempt for one app version / APK set inside a session | **`static_analysis_runs`** extended with `static_session_id`, `app_id`, `app_version_id`, `apk_set_id` |
| **Session–run link** | Finalized membership (optional redundancy if runs always FK session) | `static_session_run_links` **evolves** to FK `static_session_id` + `static_run_id` + package identity for Web joins without string drift |

**Separation of concerns:** Session answers “how did the batch go?” Run answers “what happened for this package/version in that batch?”

### 1.4 Static facts (append-mostly, per run)

| Area | Tables (target) |
| --- | --- |
| Findings | `static_analysis_findings` (unchanged grain: `run_id`) |
| Permissions | **`static_permission_observations`** (raw + context); **`static_permission_canonical_rollups`** or evolved matrix+risk with strict uniqueness (see Section 4) |
| Strings | `static_string_summary`, `static_string_samples`, `static_string_sample_sets` |
| Providers | `static_fileproviders` |
| Correlations | `static_correlation_results` |
| MASVS coverage | `masvs_control_coverage` (collation-normalized) |

### 1.5 Derived / read models

| Kind | Examples |
| --- | --- |
| Risk rollups | Session-level permission score, package rollups — **computable** from facts or **materialized** in `static_session_rollups` + `risk_scores` (legacy name; may rename to `static_permission_session_scores` in far future) |
| Web views | `v_web_*`, **`v_web_static_*_v2`** (Section 6) |
| Caches | Explicit **cache** tables only if needed; prefer views over shadow tables |

### 1.6 Dynamic layer

Unchanged ownership: `dynamic_sessions`, telemetry tables, handoff consumption from **`v_static_handoff_v1`** contract until a deliberate **v2 handoff** project. Target schema **adds** `static_session_id` exposure on dynamic rows via joins, not breaking handoff hashes prematurely.

### 1.7 Governance / evidence layer

| Concept | Role |
| --- | --- |
| Permission Intel | Separate DSN — dictionary / governance, **not** static results |
| Operational governance | `permission_governance_snapshots` (per project rules), `permission_audit_snapshots` / `permission_audit_apps` |
| Persistence audit | `static_persistence_failures`, `static_session_disposition_history` |
| Tooling provenance | `tool_semver`, `tool_git_commit`, `schema_version` on session and run |

### 1.8 Legacy layer

`runs`, `findings`, `metrics`, `buckets`, `contributors` — **read-only archive** then **empty** then **drop** (Section 7). Not part of Web default queries in the target world.

---

## 2. `static_analysis_sessions` — missing center

### 2.1 Primary key

- **`static_session_id`** `BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY` — stable surrogate used everywhere internally.
- **Natural uniqueness:** `UNIQUE (session_stamp, scope_label)` preserved for operator mental model and backward compatibility with existing columns on runs.

### 2.2 Core fields

| Column | Type | Purpose |
| --- | --- | --- |
| `session_stamp` | `VARCHAR(128)` NOT NULL | Existing external id. |
| `scope_label` | `VARCHAR(191)` NOT NULL DEFAULT '' | Scope partition. |
| `session_label` | `VARCHAR(191)` NULL | Human label; may mirror stamp. |
| `profile_key` / `scenario_id` | nullable | Session intent routing. |
| `inventory_snapshot_id` / `harvest_session_id` | nullable FKs | Tie to harvest when known. |
| `session_status` | ENUM or VARCHAR | `OPEN`, `FINALIZING`, `CLOSED`. |
| `session_disposition` | VARCHAR(64) | Machine classification (Section 5). |
| `disposition_confidence` | ENUM(`high`,`medium`,`low`) | From heuristic or manual override. |
| `disposition_updated_at_utc` | TIMESTAMP | Last classification change. |
| `expected_package_count` | INT UNSIGNED NULL | From profile manifest. |
| `expected_apk_set_count` | INT UNSIGNED NULL | Optional. |
| `completed_run_count` | INT UNSIGNED | Aggregates. |
| `failed_run_count` | INT UNSIGNED | Includes user abort. |
| `interrupted_run_count` | INT UNSIGNED | Subset of failed. |
| `persist_error_run_count` | INT UNSIGNED | Subset. |
| `total_findings_rows` | BIGINT UNSIGNED | Sum across runs in session. |
| `total_permission_observation_rows` | BIGINT UNSIGNED | After observation table exists. |
| `total_permission_canonical_rows` | BIGINT UNSIGNED | Rollup/matrix row count policy documented. |
| `total_string_summary_rows` | INT UNSIGNED | |
| `session_link_rows` | INT UNSIGNED | From `static_session_run_links`. |
| `rollup_present` | TINYINT(1) | |
| `runs_with_handoff_ready` | INT UNSIGNED | Policy-defined (hash + JSON path rules). |
| `paper_grade_ready` | TINYINT(1) NOT NULL DEFAULT 0 | |
| `paper_grade_blockers_json` | JSON NULL | |
| `web_visibility_default` | ENUM(`public`,`operator`,`hidden`,`archive`) | Drives v2 Web views. |
| `cleanup_status` | VARCHAR(32) | `none`, `export_pending`, `prune_candidate`, `archived`, `pruned`. |
| `superseded_by_session_id` | BIGINT UNSIGNED NULL FK self | Pointer to replacing session. |
| `tool_semver` / `tool_git_commit` / `schema_version` | VARCHAR | Session-level provenance (copy from finalize or dominant run). |
| `created_at_utc` / `closed_at_utc` | TIMESTAMP / DATETIME | |

### 2.3 How this differs from `static_analysis_runs`

| Dimension | `static_analysis_sessions` | `static_analysis_runs` |
| --- | --- | --- |
| Cardinality | **One row per batch** | **One row per package attempt** inside the batch |
| Primary key | `static_session_id` | `id` (static run id) |
| Status | Aggregate + disposition | Per-run pipeline status (`COMPLETED`, `FAILED`, …) |
| Canonical “winner” | **Not** the place for per-package winners; optional `preferred_static_run_id` only for diagnostics | Per-run flags; deprecate confusing **`is_canonical` as “one row per session”** for Web — replace with **session disposition** + **v2 latest view** logic per package |
| Child counts | Rolled up | Row-level links to findings, observations, etc. |

---

## 3. Static run identity — redesign

### 3.1 `static_analysis_runs` extensions

Add (nullable during migration, then NOT NULL where safe):

| Column | Purpose |
| --- | --- |
| `static_session_id` | FK → `static_analysis_sessions.static_session_id` |
| `app_id` | Denormalized from `app_versions` for join-free Web paths; FK `apps(id)` |
| `apk_set_id` | FK → `static_apk_artifact_sets.id` (what was analyzed) |
| `session_label` | **Retain temporarily** for compatibility; dual-write with session header |

Keep existing: `app_version_id`, `sha256`, `base_apk_sha256`, `artifact_set_hash`, status, abort fields, handoff columns, hashes.

**Deprecation path:** queries switch to `static_session_id`; `session_stamp`/`session_label` on runs become **redundant copies** of session header for backward compatibility, then read-only ignored by Web v2.

### 3.2 `static_apk_artifact_sets` (new, thin)

| Column | Notes |
| --- | --- |
| `id` BIGINT PK | `apk_set_id` |
| `app_version_id` | FK |
| `artifact_set_hash` | CHAR(64) |
| `base_apk_sha256` | CHAR(64) |
| `split_manifest_json` | optional |
| `harvest_session_id` / `inventory_snapshot_id` | optional provenance |

Uniqueness: `UNIQUE (app_version_id, artifact_set_hash)` or include `base_apk_sha256` if policy requires.

### 3.3 `v_static_run_identity_v2` (new view)

**Goals:** include **session** fields; avoid CHAR run id confusion; single join path for Web.

Suggested columns (illustrative):

- `static_run_id` as **`BIGINT`** (alias `sar.id`) — primary join key for apps/Web.
- `static_session_id`, `session_stamp`, `scope_label`, `session_label`, `session_disposition`, `web_visibility_default`.
- `app_id`, `package_name`, `display_name` (from apps/profiles), `app_version_id`, `version_name`, `version_code`.
- `apk_set_id`, `artifact_set_hash`, `base_apk_sha256`.
- `run_status`, `abort_reason`, `abort_signal`, `created_at`, `ended_at_utc`.
- `tool_semver`, `tool_git_commit`, `schema_version` (from run or session).
- Optional: `static_handoff_hash` present flag.

**Join contract:** no `CAST` for run id in consumers that adopt v2; legacy `v_run_identity` remains until Phase 6+ consumers migrate.

---

## 4. Permission schema redesign

### 4.1 Problem statement

Unique keys on **canonical string alone** collide when:

- Collation normalizes differently than application `lower()`, or
- Multiple **raw** manifest strings should map to one **logical** permission but are inserted as separate facts without a stable **normalization_key**.

### 4.2 Target tables

**A. `static_permission_observations` (fact, per run)**

One row per **raw observation** (or per raw + source tuple if deduplicated at ingest).

| Column | Purpose |
| --- | --- |
| `id` | PK |
| `static_run_id` | FK |
| `raw_permission_name` | VARCHAR — as emitted by manifest/detector |
| `canonical_permission_name` | VARCHAR NULL — resolved Android permission id when known |
| `normalization_key` | CHAR(64) or VARCHAR — **hash or stable lowercase ASCII fold** computed in **one** shared function (SQL generation from same rules as app) |
| `source_context` | ENUM or VARCHAR — `manifest`, `dex`, `merged_manifest`, `tooling_inference`, … |
| `apk_role` | ENUM — `base`, `split`, `unknown` |
| `split_name` | VARCHAR NULL |
| `dictionary_source` | VARCHAR NULL — PI dictionary version / internal catalog ref |
| `observed_attributes_json` | JSON — guards, dangerous flags as observed |

**Uniqueness:** `UNIQUE (static_run_id, normalization_key, source_context, apk_role, split_name)` — tune to avoid over-collapse; alternative is `UNIQUE (static_run_id, raw_permission_name, source_context)` if raw is always stable.

**B. `static_permission_canonical_rollup` (derived, per run)** — evolution of today’s matrix + risk into clearer split:

| Column | Purpose |
| --- | --- |
| `static_run_id` | FK |
| `canonical_permission_name` | logical permission |
| `normalization_key` | same algorithm as observations |
| `risk_tier` / `risk_score` / `rationale_code` | aggregated |
| `matrix_facts_json` or normalized columns | guard strength, OEM flags, etc. |

**Uniqueness:** `UNIQUE (static_run_id, normalization_key)`.

**C. Legacy path:** `static_permission_matrix` + `static_permission_risk_vnext` can be **views** over A/B in the far future, or **dual-written** during migration then dropped.

### 4.3 Preventing duplicate canonical failures

1. **Single normalization_key** algorithm shared by observation writer and rollup upsert (tests lock behavior).  
2. **No** unique constraint on `(run_id, LOWER(raw))` alone if collation differs — use explicit **`normalization_key`** column populated in Python/SQL identically.  
3. Rollup upsert uses `ON DUPLICATE KEY UPDATE` on `(static_run_id, normalization_key)` only.  
4. **Permission Intel** joins on `canonical_permission_name` / dictionary id, not on raw vendor strings.

### 4.4 Matrix “fact vs rollup”

- **Observations** = **fact** (what was seen, possibly duplicate raw strings).  
- **Canonical rollup** = **derived** scientific row for Web and risk.  
- **`static_permission_matrix` today** = mixed fact + interpretation — **migrate** toward observation + rollup split rather than growing one table indefinitely.

---

## 5. Session disposition model (extended)

| Disposition | Meaning | Web default | Cleanup behavior |
| --- | --- | --- | --- |
| `completed_full_session` | Full intent satisfied; all runs completed; finalize OK | **public** | None; retain as reference |
| `completed_profile_session` | Profile-scoped success | **public** | None |
| `interrupted_partial_session` | Dominant user/system interrupt; partial data | **operator** or **hidden** | Retain short term; **prune_candidate** after superseded |
| `mixed_completed_failed_session` | Mix of completed and failed | **public** at **session index** only if policy exposes “partial success”; per-package Web uses **completed runs** | Selective rerun preferred over delete |
| `broken_persist_error_session` | Persistence/schema errors dominate | **hidden** | **prune_candidate** after export + newer session |
| `broken_missing_artifacts_session` | “Complete” but missing hashes/handoff/strings per policy | **hidden** | Fix via rerun; prune after superseded |
| `superseded` | Replaced by newer session for same intent | **hidden** or **archive** | Prune after retention |
| `prune_candidate` | Approved for removal | **hidden** | Export then delete |
| `archived` | Dumped to cold storage; may still exist read-only | **hidden** | No Web queries |

**`legacy_historical_session`** (optional extra tag) can be folded into `broken_*` or `archived` for old pipeline era.

Manual override: `static_session_disposition_history` stores operator corrections without rewriting child fact rows.

---

## 6. Web source-of-truth model

### 6.1 Default query rule

Web **default** queries must:

1. Filter **`static_analysis_sessions.web_visibility_default IN ('public')`** (or join through v2 views that embed this).  
2. For per-package surfaces, pick **latest successful run** within a **public** session using **`session_preference_rank`-style** logic anchored on **`session_disposition`** and run `status=COMPLETED`, not on legacy `is_canonical` alone.

### 6.2 Proposed v2 views

| View | Purpose |
| --- | --- |
| **`v_static_session_health_v2`** | One row per `static_session_id`: counts, disposition, persistence failure flags, handoff coverage, paper flags — operator dashboard + Web “session health” widget. |
| **`v_static_run_identity_v2`** | Per-run row with BIGINT `static_run_id` + session columns + app/apk set identity (Section 3.3). |
| **`v_web_static_session_index_v2`** | Web session picker: only **public** (and optionally **operator** when role allows); sort by `closed_at_utc` / `created_at_utc`; never lists **broken** or **prune_candidate** by default. |
| **`v_web_static_findings_current_v2`** | Findings joined through “current” run resolution: **completed** run in latest **usable** session per package. |
| **`v_web_static_permissions_current_v2`** | Permissions from **canonical rollup** (or matrix during migration) for same “current” run logic. |

Existing `v_web_app_sessions` / `v_web_app_findings` remain during transition; Web repo migrates consumer queries to `*_v2` under explicit project.

---

## 7. Legacy retirement strategy

### 7.1 Target

**Future truth** excludes: `runs`, `findings`, `metrics`, `buckets`, `contributors`.

### 7.2 Blockers (current repo reality)

- **`v_run_overview`** — defined over `runs` + `buckets` (`views_bridge.py`). Must be **replaced** with canonical-based overview or dropped.  
- **Readers:** `static_reconcile`, `run_persistence_queries`, `risk_actions` backfill joins, MASVS report fallbacks, `reset_static` / `SCIENTIFIC_UOW_TABLES` — see [legacy_static_deprecation_playbook.md](legacy_static_deprecation_playbook.md) and [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md).  
- **`metrics.run_id` ambiguity** — must be eliminated from any path that could confuse canonical vs legacy.

### 7.3 Stages

1. **Export** full legacy five + mysqldump metadata.  
2. **Archive** tables renamed `_archive_YYYYMMDD` *or* moved to read-only replica — policy choice.  
3. **Empty** in dev only after grep proves zero readers.  
4. **Drop** after view DDL and contracts updated; Web smoke green.

---

## 8. Collation and identifier policy

### 8.1 Standards (target)

| Data kind | Column type | Collation / notes |
| --- | --- | --- |
| `package_name`, session stamps/labels | `VARCHAR(191)` or `VARCHAR(255)` per existing lengths | **`utf8mb4_unicode_ci`** everywhere |
| Display names, free text | `VARCHAR` / `TEXT` | **`utf8mb4_unicode_ci`** |
| Hex hashes | `CHAR(64)` **ASCII** | **no collation semantics** — binary comparison |
| JSON | `JSON` type | N/A |
| ENUMs / status tokens | `VARCHAR` with check constraints or ENUM | `utf8mb4_unicode_ci` if string |

### 8.2 First migration targets (no ALTER in this doc)

1. `static_session_run_links.package_name` and related text columns.  
2. `masvs_control_coverage` text columns.  
3. Any `VARCHAR` on **`latin1_swedish_ci`** in `information_schema` export for this catalog.  
4. **`static_string_summary.session_stamp`** is **`VARCHAR(64)`** while `static_analysis_runs.session_stamp` is **`VARCHAR(128)`** — widen summary (and any matching indexes) in a collation phase if stamps can exceed 64 characters or joins truncate silently.

### 8.3 Identifiers

- **Internal:** BIGINT ids (`static_session_id`, `static_run_id`, `apk_set_id`).  
- **External:** `session_stamp` stable string; UUIDs only where already used (e.g. dynamic run id).

---

## 9. Migration phases

| Phase | Name | Content |
| --- | --- | --- |
| **0** | Backup + read-only audit | Full dump; inventory views/tables; disposition histograms from current data. Use `scripts/db/sql/audit_information_schema_static_relationships.sql` plus [database_static_child_table_join_map.md](database_static_child_table_join_map.md) before writing prune/footprint SQL. |
| **1** | Additive schema | `static_analysis_sessions`, `static_session_disposition_history`, `static_apk_artifact_sets`; add nullable FK columns on `static_analysis_runs`; **no** deletes. |
| **2** | Honest backfill | Populate `static_analysis_sessions` from `GROUP BY session_stamp, scope_label`; set disposition from facts (interrupt vs persist_error); **do not** mark broken April data as completed. **Operator SQL pack:** `scripts/db/sql/session_summary_from_static_analysis_runs.sql` (preview `SELECT`, optional child-count CTE, commented `INSERT … ON DUPLICATE KEY UPDATE`). |
| **3** | v2 views | Create `v_static_session_health_v2`, `v_static_run_identity_v2`, `v_web_static_session_index_v2`, findings/permissions v2 — read-only for Web until cutover. |
| **4** | Permission observation + rollup | New tables; dual-write or backfill from matrix; switch writers; retire old unique collision path. |
| **5** | Export / prune | Broken and superseded sessions per policy; PREVIEW/VERIFY scripts. |
| **6** | Legacy mirror retirement | Reader removal, `v_run_overview` replacement, drop legacy tables. |
| **7** | Collation normalization | Column-by-column after Phase 3–6 stable. |

---

## 10. First implementation slice (recommended PR)

**Scope:** Phase **0–1** plus **read-only** v2 session/run health views (no Web cutover required yet).

**Deliverables:**

1. **`CREATE TABLE static_analysis_sessions`** — full column set per Section 2 (subset acceptable if documented as “minimal v1”: ids + stamp + scope + disposition + core counts nullable).  
2. **`CREATE TABLE static_session_disposition_history`** — `id`, `static_session_id`, `from_disposition`, `to_disposition`, `reason`, `actor`, `created_at_utc`.  
3. **`CREATE TABLE static_apk_artifact_sets`** — minimal columns + unique key.  
4. **`ALTER TABLE static_analysis_runs ADD COLUMN`** `static_session_id`, `app_id`, `apk_set_id` (all nullable); add FKs **without** enforcing NOT NULL yet.  
5. **Views:** `v_static_session_health_v2`, `v_static_run_identity_v2` (read-only aggregations / joins).  
6. **Script:** read-only hygiene report listing sessions + proposed disposition (can extend `session_static_health` pattern).

**Forbidden in first PR:** `DELETE`, `TRUNCATE`, `DROP`, shrinking columns, changing `v_static_handoff_v1`, changing detector outputs, NOT NULL on new FKs until backfill proven.

---

## Appendix A0 — As-deployed session tables (authoritative in repo)

These match **`scytaledroid_core_prod`** manual DDL and **`canonical/schema.py`** (utf8mb4 **general_ci**; `disposition_confidence` as **VARCHAR(16)**; `detail_json` as **LONGTEXT**; `actor` default **`manual_sql`**; aggregate counters including **`total_run_count`**, **`missing_artifacts_run_count`**, matrix/risk/sample row totals, **`persistence_failure_rows`**, **`rollup_rows`**; timestamps **`first_created_at`**, **`last_ended_at`**, **`refreshed_at_utc`**, **`created_at_utc`**).

Planned later columns from Section 2 (paper-grade flags, `expected_package_count`, harvest FKs) remain **future `ADD COLUMN`** migrations — do not require them for backfill v1.

---

## Appendix A — Proposed DDL sketches (illustrative)

> **Note:** Appendix A sketches are **superseded for the two session tables** by Appendix A0 / `canonical/schema.py`. Remaining sketches (apk sets, permission observations) are still illustrative. Syntax may need MariaDB version tweaks; indexes are indicative; review with `schema_manifest.py` ordering and FK dependency graph.

### A.1 `static_analysis_sessions`

```sql
CREATE TABLE IF NOT EXISTS static_analysis_sessions (
  static_session_id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_stamp           VARCHAR(128) NOT NULL,
  scope_label             VARCHAR(191) NOT NULL DEFAULT '',
  session_label           VARCHAR(191) NULL,
  profile_key             VARCHAR(64) NULL,
  scenario_id             VARCHAR(64) NULL,
  inventory_snapshot_id   BIGINT UNSIGNED NULL,
  harvest_session_id      BIGINT UNSIGNED NULL,
  session_status          VARCHAR(32) NOT NULL DEFAULT 'OPEN',
  session_disposition     VARCHAR(64) NOT NULL DEFAULT 'mixed_completed_failed_session',
  disposition_confidence  ENUM('high','medium','low') NOT NULL DEFAULT 'medium',
  disposition_updated_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
  expected_package_count   INT UNSIGNED NULL,
  expected_apk_set_count   INT UNSIGNED NULL,
  completed_run_count      INT UNSIGNED NOT NULL DEFAULT 0,
  failed_run_count         INT UNSIGNED NOT NULL DEFAULT 0,
  interrupted_run_count    INT UNSIGNED NOT NULL DEFAULT 0,
  persist_error_run_count  INT UNSIGNED NOT NULL DEFAULT 0,
  total_findings_rows              BIGINT UNSIGNED NOT NULL DEFAULT 0,
  total_permission_observation_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
  total_permission_canonical_rows   BIGINT UNSIGNED NOT NULL DEFAULT 0,
  total_string_summary_rows        INT UNSIGNED NOT NULL DEFAULT 0,
  session_link_rows        INT UNSIGNED NOT NULL DEFAULT 0,
  rollup_present           TINYINT(1) NOT NULL DEFAULT 0,
  runs_with_handoff_ready  INT UNSIGNED NOT NULL DEFAULT 0,
  paper_grade_ready        TINYINT(1) NOT NULL DEFAULT 0,
  paper_grade_blockers_json JSON NULL,
  web_visibility_default   ENUM('public','operator','hidden','archive') NOT NULL DEFAULT 'operator',
  cleanup_status           VARCHAR(32) NOT NULL DEFAULT 'none',
  superseded_by_session_id BIGINT UNSIGNED NULL,
  tool_semver              VARCHAR(32) NULL,
  tool_git_commit          VARCHAR(40) NULL,
  schema_version           VARCHAR(64) NULL,
  created_at_utc           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at_utc            DATETIME NULL,
  PRIMARY KEY (static_session_id),
  UNIQUE KEY ux_static_session_natural (session_stamp, scope_label),
  KEY ix_static_session_disposition (session_disposition, web_visibility_default),
  CONSTRAINT fk_static_session_supersedes
    FOREIGN KEY (superseded_by_session_id) REFERENCES static_analysis_sessions(static_session_id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### A.2 `static_session_disposition_history`

```sql
CREATE TABLE IF NOT EXISTS static_session_disposition_history (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  static_session_id    BIGINT UNSIGNED NOT NULL,
  from_disposition     VARCHAR(64) NULL,
  to_disposition       VARCHAR(64) NOT NULL,
  reason               VARCHAR(512) NULL,
  actor                VARCHAR(128) NOT NULL DEFAULT 'system',
  detail_json          JSON NULL,
  created_at_utc       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_sess_disp_hist_session (static_session_id, created_at_utc),
  CONSTRAINT fk_sess_disp_hist_session
    FOREIGN KEY (static_session_id) REFERENCES static_analysis_sessions(static_session_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### A.3 `static_apk_artifact_sets`

```sql
CREATE TABLE IF NOT EXISTS static_apk_artifact_sets (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_version_id       BIGINT UNSIGNED NOT NULL,
  artifact_set_hash    CHAR(64) NOT NULL,
  base_apk_sha256      CHAR(64) NOT NULL,
  split_manifest_json  JSON NULL,
  harvest_session_id   BIGINT UNSIGNED NULL,
  inventory_snapshot_id BIGINT UNSIGNED NULL,
  created_at_utc       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_apk_set_version_hash (app_version_id, artifact_set_hash),
  KEY ix_apk_set_hash (artifact_set_hash),
  CONSTRAINT fk_apk_set_app_version
    FOREIGN KEY (app_version_id) REFERENCES app_versions(id)
    ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### A.4 `static_analysis_runs` — additive columns (sketch)

```sql
ALTER TABLE static_analysis_runs
  ADD COLUMN IF NOT EXISTS static_session_id BIGINT UNSIGNED NULL AFTER id,
  ADD COLUMN IF NOT EXISTS app_id BIGINT UNSIGNED NULL AFTER static_session_id,
  ADD COLUMN IF NOT EXISTS apk_set_id BIGINT UNSIGNED NULL AFTER app_version_id;

-- FKs after backfill subset validated:
-- ALTER TABLE static_analysis_runs ADD CONSTRAINT fk_sar_session
--   FOREIGN KEY (static_session_id) REFERENCES static_analysis_sessions(static_session_id)
--   ON DELETE RESTRICT;
-- ALTER TABLE static_analysis_runs ADD CONSTRAINT fk_sar_app
--   FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE RESTRICT;
-- ALTER TABLE static_analysis_runs ADD CONSTRAINT fk_sar_apk_set
--   FOREIGN KEY (apk_set_id) REFERENCES static_apk_artifact_sets(id) ON DELETE RESTRICT;
```

### A.5 `static_permission_observations` (sketch)

```sql
CREATE TABLE IF NOT EXISTS static_permission_observations (
  id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  static_run_id            BIGINT UNSIGNED NOT NULL,
  raw_permission_name      VARCHAR(384) NOT NULL,
  canonical_permission_name VARCHAR(384) NULL,
  normalization_key        CHAR(64) NOT NULL,
  source_context             VARCHAR(32) NOT NULL,
  apk_role                 ENUM('base','split','unknown') NOT NULL DEFAULT 'unknown',
  split_name               VARCHAR(191) NULL,
  dictionary_source        VARCHAR(64) NULL,
  observed_attributes_json JSON NULL,
  created_at_utc           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_perm_obs_run_norm_src (static_run_id, normalization_key, source_context, apk_role, split_name),
  KEY ix_perm_obs_run (static_run_id),
  CONSTRAINT fk_perm_obs_run
    FOREIGN KEY (static_run_id) REFERENCES static_analysis_runs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### A.6 `static_permission_canonical_rollup` (sketch)

```sql
CREATE TABLE IF NOT EXISTS static_permission_canonical_rollup (
  id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  static_run_id            BIGINT UNSIGNED NOT NULL,
  canonical_permission_name VARCHAR(384) NOT NULL,
  normalization_key        CHAR(64) NOT NULL,
  risk_tier                VARCHAR(32) NULL,
  risk_score               DECIMAL(7,3) NULL,
  rationale_code           VARCHAR(64) NULL,
  matrix_facts_json        JSON NULL,
  updated_at_utc           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_perm_roll_run_norm (static_run_id, normalization_key),
  CONSTRAINT fk_perm_roll_run
    FOREIGN KEY (static_run_id) REFERENCES static_analysis_runs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

---

## Appendix B — Migration risks

| Risk | Mitigation |
| --- | --- |
| FK `NOT NULL` too early | Keep nullable through Phase 2–3; batch backfill with verification queries. |
| `superseded_by_session_id` self-FK cycles | Constraint + application check; optional DB trigger. |
| Dual session keys (`session_stamp` vs `static_session_id`) drift | Triggers or single writer path for session header updates. |
| Web duplicate rows during dual views | Feature-flag Web to **only** v2 or **only** v1 per environment until cutover. |
| Permission migration doubles storage | Phase 4 compress / drop old tables only after writer switch + parity tests. |
| Collation migration changes UNIQUE semantics | Preview distinct-key counts before/after on golden sessions. |

---

## Appendix C — Tests needed

| Layer | Tests |
| --- | --- |
| Schema registration | `schema_manifest` / gate tests if new tables join ordered DDL. |
| Backfill job | Unit tests for disposition classification from synthetic run rows. |
| Views | SQL snapshot or `EXPLAIN` contract tests under `tests/database/` for v2 view definitions (string contains expected joins, no legacy table names in v2). |
| Permission normalization | Golden files for `normalization_key` from raw strings (Turkish I, spaces, vendor perms). |
| Integration | `recreate_web_consumer_views.py posture` after view module changes; Web smoke when consumers switch. |

---

## Appendix D — Verification SQL (read-only)

```sql
-- Sessions table row count vs distinct natural keys from runs
SELECT COUNT(*) AS session_rows FROM static_analysis_sessions;
SELECT COUNT(DISTINCT CONCAT(session_stamp, '|', scope_label)) AS distinct_from_runs
FROM static_analysis_runs;

-- Runs with session FK populated vs not
SELECT
  SUM(static_session_id IS NULL) AS missing_session_fk,
  SUM(static_session_id IS NOT NULL) AS has_session_fk
FROM static_analysis_runs;

-- Disposition distribution
SELECT session_disposition, web_visibility_default, COUNT(*)
FROM static_analysis_sessions
GROUP BY 1, 2
ORDER BY COUNT(*) DESC;

-- v2 run identity: no duplicate static_run_id
SELECT static_run_id, COUNT(*) AS c
FROM v_static_run_identity_v2
GROUP BY static_run_id
HAVING c > 1;

-- Legacy isolation: v2 views must not reference legacy five (manual / CI grep)
```

---

## Appendix E — What not to touch yet

- **`v_static_handoff_v1`** definition and **handoff hash contracts** — dynamic readiness; change only under a dedicated handoff v2 project with paired dynamic tests.  
- **Detector modules and rule packs** — schema work must not alter finding semantics.  
- **`permission_intel` DSN** — separate product boundary.  
- **Physical tables named `v_*` / `vw_*`** — forbidden; only views use those prefixes.  
- **NOT NULL enforcement** on new FKs until backfill completeness is proven per environment.  
- **Dropping legacy tables** before reader retirement and `v_run_overview` replacement.

---

## Revision log

| Date | Action |
| --- | --- |
| 2026-05-09 | Initial target schema V2 proposal. |
| 2026-05-09 | Appendix A0: production-aligned `static_analysis_sessions` + `static_session_disposition_history` DDL added to `canonical/schema.py`; `reset_static` + `static_schema_audit` catalog updates. |
