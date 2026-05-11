# Database cleanup / audit plan (read-only phase)

**Design proposal (phased schema + Web SOT):** [database_schema_cleanup_design.md](database_schema_cleanup_design.md).

**Scope:** Operational analyst MariaDB (core / results catalog) — *not* the separate Permission Intel dictionary DB unless noted.  
**Constraints (this document):** No `DROP` / `DELETE` / `TRUNCATE` / `ALTER`. No migrations. No Web repo edits. Treat production data as valuable until lineage is proven.  
**Observed inventory (phpMyAdmin snapshot):** ~107 objects, ~250,983 rows, ~157.7 MiB — use as a baseline; **re-verify** with the SQL in §9.

**Authority in code:** `scytaledroid/Database/db_queries/schema_manifest.py`, `canonical/schema.py`, `dynamic/schema.py`, `analysis/schema.py`, `views_web.py`, `views_bridge.py`, `views_static.py`, `views_dynamic.py`, `bridge_posture.py`, `legacy_static_mirror_diagnostics.py`, `docs/maintenance/legacy_static_deprecation_playbook.md`.

---

## 1. Object classification

Use **`information_schema.TABLES`** (`TABLE_SCHEMA = DATABASE()`) to list every `BASE TABLE` and `VIEW`. Assign **exactly one** primary class per object (secondary tags allowed in notes).

| Class | Meaning | Examples (this repo) |
| --- | --- | --- |
| **canonical_current** | Ground truth for static/dynamic results the product owns today | `static_analysis_runs`, `static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, `static_session_run_links`, `static_session_rollups`, `apps`, `app_versions`, `dynamic_sessions`, `dynamic_telemetry_*` (as defined in `dynamic/schema.py`) |
| **legacy_static_mirror** | Historical / compatibility mirror; **not** populated by current static writers per `AGENTS.md` | `runs`, legacy `findings`, `metrics`, `buckets`, `contributors` |
| **derived_rebuildable** | Can be recomputed from canonical + artifacts + reruns (with caveats) | `static_findings_summary`, `static_findings`, `risk_scores`, rollups, string summary/sample tables, cohort ML windows/scores *if* pipelines can replay |
| **cache** | Safe to discard in dev; may repopulate from jobs | Session caches under `data/` (filesystem — not DB); DB-side caches are rare — classify per-table when seen |
| **operator_state** | Menus, audits, operator workflow — not “scientific truth” but valuable | `schema_version`, `static_persistence_failures`, heartbeat/session diagnostics tables if present |
| **dynamic_current** | Dynamic run + telemetry truth | `dynamic_sessions`, `dynamic_telemetry_network`, `dynamic_telemetry_process`, related feature/window tables from `dynamic/schema.py` |
| **permission_audit** | Permission audit snapshots on **operational** DB | `permission_audit_snapshots`, `permission_audit_apps` (from `permission_support` DDL in manifest) |
| **future_empty** | DDL reserved; zero rows is normal until feature ships | `ml_feature_windows`, `ml_scores` (`canonical/schema.py`), `perm_groups` (seed/operator taxonomy), `static_dynload_events`, `static_reflection_calls` (dynload path), `analysis_dynamic_cohort_status` (analysis phase registry) |
| **web_view** | `v_*` / `vw_*` consumer views owned by this repo | `v_web_app_directory`, `v_web_app_sessions`, `v_web_app_findings`, `v_web_static_session_health`, `vw_static_*_latest`, … (`schema_manifest.py`, `check_schema_posture.sql`) |
| **admin_system** | `information_schema`, users, grants — out of scope for row cleanup | N/A inside app schema |
| **drop_candidate_later** | Only after archive + reader retirement + Web smoke | Legacy five tables **eventually**; **not** until playbook exit criteria |
| **unknown_needs_review** | Any of the ~107 objects not matching above after inventory | Third-party tables, one-off experiments, renamed clones |

**Important:** Your DB has **more than DDL in one file** — anything not in `ordered_schema_statements()` still gets **`unknown_needs_review`** until traced.

---

## 2. Current canonical static health

### Minimum static truth (must remain for “paper path” static)

| Layer | Tables / views | Role |
| --- | --- | --- |
| **Run identity** | `static_analysis_runs` (+ `apps` / `app_versions` FK graph) | One row per analysis attempt; `session_label`, `is_canonical`, status, hashes |
| **Findings** | `static_analysis_findings` | Detector output rows keyed to `static_analysis_runs` |
| **Permission cohort** | `static_permission_matrix`, `static_permission_risk_vnext` | Permission posture / risk vnext for packages tied to runs |
| **Handoff** | `v_static_handoff_v1` (view; do not alter contract casually) | Dynamic planning reads handoff — see `AGENTS.md` |

### Summaries / rollups (derived but operationally sticky)

| Surface | Role |
| --- | --- |
| `static_session_run_links`, `static_session_rollups` | Session-level linkage and rollups — support, not substitute for `static_analysis_*` row stores |
| `static_findings_summary`, `static_findings`, string tables | Downstream / presentation / string pipelines — rebuildable **if** replay inputs exist |

### Read models

| Surface | Role |
| --- | --- |
| `v_web_*`, `vw_static_*`, `v_static_risk_surfaces_v1` | Web + CLI read façades — **views**, not second physical truth |

**Health checks (no writes):** `PYTHONPATH=. python scripts/db/check_permission_intel.py` (Intel DB), `scripts/db/check_schema_posture.sql`, `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture|semantic` + `smoke_web_db.sh` when touching views.

---

## 3. Legacy mirror disposition (`runs`, `findings`, `metrics`, `buckets`, `contributors`)

### Row counts (your snapshot)

| Table | Rows |
| --- | ---: |
| `runs` | 410 |
| `findings` | 13,154 |
| `metrics` | 27,347 |
| `buckets` | 3,073 |
| `contributors` | 7,004 |

### Current readers (code — non-exhaustive; see `bridge_posture.py` + playbook)

| Table | Readers / scripts (from `bridge_posture.py`) |
| --- | --- |
| `findings` | `static_reconcile`, `query_runner`, `static_run_audit`, `db_verification`, `run_persistence_queries`, `audit_static_session.py`, MASVS report fallback |
| `metrics` | `static_reconcile`, `risk_actions` (ambiguous `run_id` — **critical**), `db_schema_snapshot`, `db_verification`, `dep_view`, `run_persistence_queries`, `audit_static_session.py` |
| `buckets` | `static_reconcile`, **`views_bridge` → `v_run_overview`**, `db_schema_snapshot`, `db_verification`, `run_persistence_queries`, `audit_static_session.py` |
| `contributors` | `static_reconcile`, `health_checks_permission`, `run_persistence_queries` |
| `runs` | Join hub for legacy `findings`/`metrics`/…; `static_reconcile` package lists |

### Maps to canonical sessions?

- **Partially / historically.** Reconcile and audit scripts compare **package sets per `session_stamp`** between canonical `static_analysis_runs` and legacy `runs` — drift is **expected** when only canonical writers run (`static_reconcile.py` legacy package queries).
- **Do not assume** `runs.run_id` ↔ `static_analysis_runs.id` without per-query verification (`metrics.run_id` semantic split is a known hazard in `bridge_posture.py`).

### Export

- Per-session: `PYTHONPATH=. python scripts/db/audit_static_session.py --session …` (includes legacy block when tables exist).
- Bulk: mysqldump **specific tables** to dated files after legal/retention sign-off (playbook Phase 5).

### Cannot drop yet / blocks

1. **`v_run_overview`** is defined **only** over `runs` + `buckets` (`views_bridge.py`) — dropping either breaks the view until DDL/consumers change.
2. **`static_reconcile` / `run_persistence_queries`** encode drift semantics — retirement **last** per playbook.
3. **`reset_static`** and **`SCIENTIFIC_UOW_TABLES`** (`contracts.py`) still **name** legacy tables for transaction envelope / reset — contract change required before physical drop.
4. **Web / external SQL** outside this repo — grep Web consumers before any DDL.

---

## 4. Empty / future tables (your list)

| Table | Why it exists | Code refs | Recommended action |
| --- | --- | --- | --- |
| `ml_feature_windows`, `ml_scores` | Publication / ML scoring schema (`canonical/schema.py`) | `publication_pipeline_audit_service.py` | **future_empty** — keep; verify 0-row OK in prod until ML pipeline runs |
| `perm_groups` | Permission taxonomy / grouping (`schema_manifest` + `permissions/taxonomy.py`) | `reset_static` list, taxonomy module | **future_empty** or seed later — **do not drop** without taxonomy review |
| `static_dynload_events`, `static_reflection_calls` | Static dynamic-load harvest feature (`harvest/dynamic_loading.py`) | `views_static.py` (`vw_dynload_hotspots`), `static_schema_audit.py` `SPARSE_ZERO_OK_TABLES` | **future_empty** if feature unused — classify **read-only**; clear only in dev after backup |
| `analysis_dynamic_cohort_status` | Analysis registry (`analysis/schema.py`) | `health_checks/analysis_integrity.py` REQUIRED list, `bootstrap.py` | **future_empty** until analysis jobs populate — **do not drop** (posture check expects BASE TABLE) |

---

## 5. Derived / rebuildable data

| Area | Safe to clear **dev** | Safe to rebuild | Not safe **prod** without plan | Unclear |
| --- | --- | --- | --- | --- |
| String samples / selected sets | Often yes (large) | From static re-run + ingest | If only copy of evidence | Check evidence_pack retention policy |
| `static_findings_summary` / `static_findings` | Dev only | From canonical findings + exporters | Web may rely on shape | Compare `v_web_app_findings` deps |
| `risk_scores` | Dev | From permission matrix / risk job | Downstream dashboards | Join keys vs legacy `metrics` |
| Legacy five | **Never “safe” in prod”** as blind truncate | **Not** rebuildable from current static writers | Historical evidence | Archive first |

---

## 6. Collation audit (plan only — no `ALTER`)

### Observed

- `utf8mb4_general_ci`, `utf8mb4_unicode_ci`, `latin1_swedish_ci` coexist — **join risk** on `package_name`, `session_label`, text IDs.

### Evidence in repo

- `views_web.py` already uses explicit `CONVERT(... USING utf8mb4) COLLATE utf8mb4_unicode_ci` / `utf8mb4_general_ci` in places (e.g. `v_web_app_directory`) — **symptom of past drift**, not proof all joins are safe.

### High-risk columns (normalize **after** inventory)

- `package_name`, `session_label` / `session_stamp`, `permission_name`, hex `sha256` / `CHAR(64)` hashes, `dynamic_run_id`, `static_run_id` string vs numeric mismatches.

### Normalization plan (later DB-4)

1. Export full collation per column: `information_schema.COLUMNS` where `TABLE_SCHEMA = DATABASE()`.
2. Pick **one** utf8mb4 collation for **new** objects (prefer `utf8mb4_unicode_ci` to match `dynamic_sessions` DDL in repo).
3. **`latin1_swedish_ci`**: identify tables; plan **convert-to-utf8mb4** in maintenance window (still not in this phase).
4. Re-run `recreate_web_consumer_views.py` + Web smoke after any collation migration.

---

## 7. Views and Web read models

### `v_run_overview` (**legacy-dependent**)

```sql
-- Definition source: scytaledroid/Database/db_queries/views_bridge.py
-- FROM runs r LEFT JOIN buckets b ON b.run_id = r.run_id
```

**Class:** **legacy-dependent** bridge view. Not canonical static truth.

### `v_run_identity` (**canonical + dynamic**)

- `static_analysis_runs` ∪ `dynamic_sessions` — **canonical** for identity browsing.

### `v_web_*` / `vw_*` (consumer façade)

| Bucket | Examples | Classification |
| --- | --- | --- |
| Web app directory / sessions / findings | `v_web_app_directory`, `v_web_app_sessions`, `v_web_app_findings` | **web** — canonical-first; may join `static_findings_*` in overlays (see `cli_web_db_filesystem_boundary.md`) |
| Latest static surfaces | `vw_static_finding_surfaces_latest`, `vw_static_risk_surfaces_latest` | **canonical / bridge** — “preferred run” window logic |
| Dynamic runtime | `v_web_runtime_run_index`, `v_web_runtime_run_detail` | **dynamic_current** read models |
| Dynload | `vw_dynload_hotspots` | **derived** / optional feature |

### View definitions referencing legacy tables

Run §9.10 SQL to list `VIEW_TABLE_USAGE` / `information_schema.VIEWS` where `VIEW_DEFINITION` contains `runs`, `findings`, `metrics`, `buckets`, `contributors`.

---

## 8. Cleanup phases

| Phase | Goal | Deliverable |
| --- | --- | --- |
| **DB-0** | Backup / export | mysqldump full + optional per-table dumps for legacy five |
| **DB-1** | Read-only audit | This plan + query outputs archived (`/evidence/` or ticket) |
| **DB-2** | Safe empty-table classification | Per-table “why empty” note; dev-only truncate list **separate** from prod |
| **DB-3** | Legacy mirror retirement | Playbook Phase 3–5: reader removal order, then export, then DDL last |
| **DB-4** | Collation plan | Column-level matrix; maintenance window; **no ALTER until signed** |
| **DB-5** | Reviewed SQL patches | `PREVIEW` / `VERIFY` sections; peer review; still no prod execution without CAB |
| **DB-6** | Verification | `pytest tests/database`, `smoke_web_db.sh`, `audit_static_session.py` on sample sessions |

---

## 9. SQL to run manually (read-only)

Run in order; save outputs.

### 9.1 Row counts by table

```sql
SELECT TABLE_NAME, TABLE_ROWS
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_ROWS DESC;
```

### 9.2 Approximate size by table

```sql
SELECT
  TABLE_NAME,
  ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS approx_mib
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC;
```

### 9.3 Collation inventory (table default)

```sql
SELECT TABLE_COLLATION, COUNT(*) AS tables
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
GROUP BY TABLE_COLLATION
ORDER BY tables DESC;
```

### 9.4 Column collation drift (key string columns)

```sql
SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME, COLUMN_TYPE
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND COLLATION_NAME IS NOT NULL
  AND COLUMN_NAME IN (
    'package_name','session_label','session_stamp','permission_name',
    'base_apk_sha256','apk_sha256','artifact_set_hash','static_handoff_hash'
  )
ORDER BY TABLE_NAME, COLUMN_NAME;
```

### 9.5 Legacy `runs` vs canonical `static_analysis_runs` (session coverage)

```sql
SELECT 'legacy_runs_sessions' AS k, COUNT(DISTINCT session_stamp) AS n FROM runs
UNION ALL
SELECT 'canonical_sar_sessions', COUNT(DISTINCT session_label) FROM static_analysis_runs;
```

### 9.6 Orphan legacy runs (no matching canonical session label)

Adjust join keys if your legacy `session_stamp` vs canonical `session_label` naming differs in edge cases:

```sql
SELECT r.run_id, r.session_stamp, r.package, r.ts
FROM runs r
LEFT JOIN static_analysis_runs sar ON sar.session_label = r.session_stamp
WHERE sar.id IS NULL
LIMIT 200;
```

### 9.7 Failed / incomplete canonical static runs

```sql
SELECT status, COUNT(*) FROM static_analysis_runs GROUP BY status;
SELECT session_label, COUNT(*) c
FROM static_analysis_runs
WHERE UPPER(COALESCE(status,'')) NOT IN ('COMPLETED')
GROUP BY session_label
ORDER BY c DESC
LIMIT 50;
```

### 9.8 Largest sessions by finding volume

```sql
SELECT sar.session_label, COUNT(*) AS findings
FROM static_analysis_findings saf
JOIN static_analysis_runs sar ON sar.id = saf.static_run_id
GROUP BY sar.session_label
ORDER BY findings DESC
LIMIT 30;
```

### 9.9 Dynamic telemetry volume sanity

```sql
SELECT 'dynamic_sessions' AS t, COUNT(*) FROM dynamic_sessions
UNION ALL SELECT 'dynamic_telemetry_network', COUNT(*) FROM dynamic_telemetry_network
UNION ALL SELECT 'dynamic_telemetry_process', COUNT(*) FROM dynamic_telemetry_process;
```

### 9.10 Views whose definition mentions legacy tables

```sql
SELECT TABLE_NAME AS view_name
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA = DATABASE()
  AND (
    LOWER(VIEW_DEFINITION) LIKE '%`runs`%'
    OR LOWER(VIEW_DEFINITION) LIKE '% runs %'
    OR LOWER(VIEW_DEFINITION) LIKE '%`findings`%'
    OR LOWER(VIEW_DEFINITION) LIKE '%`metrics`%'
    OR LOWER(VIEW_DEFINITION) LIKE '%`buckets`%'
    OR LOWER(VIEW_DEFINITION) LIKE '%`contributors`%'
  )
ORDER BY view_name;
```

*(MariaDB 10.5+ also has `information_schema.VIEW_TABLE_USAGE` where available — prefer it if present.)*

---

## 10. Safety rules (before any `DELETE` / `TRUNCATE` / `DROP` / `ALTER`)

All must be **true**:

1. **Backup** exists and was **restored to a scratch instance** successfully (DB-0).
2. **Written disposition** for legacy rows (legal / retention / publication needs).
3. **Reader grep** clean for targeted table in `scytaledroid/` **and** Web repo (playbook Phase 3 exit).
4. **View dependency** list empty or views recreated (`recreate_web_consumer_views.py` + smoke).
5. **`metrics.run_id` semantics** resolved for any surviving query (no accidental cross-ID joins).
6. **`reset_static` / `SCIENTIFIC_UOW_TABLES`** updated in same release as destructive DDL.
7. **Dynamic handoff** consumers still see `v_static_handoff_v1` for chosen `static_run_id` (if dynamic is in scope).
8. **Permission Intel** governance posture unchanged or consciously out of scope (separate DSN).
9. **CAB / change window** for production; rollback script prepared.
10. **Post-change verification:** `audit_static_session.py`, `session_static_health.py` (as applicable), Web smoke, targeted `pytest tests/database`.

---

## 11. Interrupted / aborted static sessions (disposition class)

Treat **operator-interrupted** sessions (`abort_reason` / `abort_signal` such as `user_abort`, `SIGINT`) as a **separate class** from:

- detector / pipeline **execution errors**,
- **persistence** or **schema** failures,
- **governance** / paper-grade gaps.

**Typical partial pattern (expected):**

| Artifact | Interrupted session |
| --- | --- |
| `static_analysis_runs` | Many `FAILED` rows with explicit abort metadata |
| `static_analysis_findings` | May exist for packages that completed artifacts before stop |
| `static_session_run_links` | Often **empty** if finalization never ran |
| Handoff columns / `v_static_handoff_v1` | May be absent or incomplete for non-completed runs |
| `is_canonical` | At most **one** row per `session_label` should win `is_canonical=1` when canonicalization succeeds; many rows may show `is_canonical=0` |

**`canonical_reason` vs `is_canonical`:** `canonical_reason` stores the session-resolution **action token** (e.g. `first_run`, `append`) from persistence (`run_summary.py` / `run_writers.py`). It is **not** a synonym for “this row is the canonical winner.” The **winner** flag is `is_canonical=1` for exactly one row per `session_label` when enforcement succeeds. Seeing `canonical_reason='first_run'` with `is_canonical=0` on some rows can still be **consistent** (non-winning attempts in the same session). Run:

```sql
SELECT session_label, SUM(is_canonical=1) AS winners, COUNT(*) AS rows
FROM static_analysis_runs
GROUP BY session_label
HAVING winners <> 1 AND winners <> 0;
```

…to find sessions worth a deeper review (not necessarily errors).

### `static_analysis_runs` keys (no `package_name` column)

Identity is **`app_version_id`** (+ hashes). For reporting, join **`v_run_identity`** on run id:

- View defines `run_id` as **`CAST(static_analysis_runs.id AS CHAR(64))`** (`views_bridge.py`). Prefer an explicit join to avoid type surprises:

```sql
ON vri.run_id = CAST(sar.id AS CHAR(64))
```

`v_run_identity` does **not** expose `session_label` / `session_stamp` — filter on `static_analysis_runs.session_label` (or `session_stamp` when matching harvest-era paths), then join the view for display fields.

### Read-only session drill pack (schema-corrected)

**A — Runs + identity + finding counts** (your query 1, with explicit cast):

```sql
SELECT
    sar.id,
    vri.display_name,
    vri.package_name,
    sar.status,
    sar.abort_reason,
    sar.abort_signal,
    sar.created_at,
    sar.ended_at_utc,
    sar.findings_total,
    COUNT(saf.id) AS finding_rows
FROM static_analysis_runs sar
LEFT JOIN v_run_identity vri
    ON vri.run_id = CAST(sar.id AS CHAR(64))
LEFT JOIN static_analysis_findings saf
    ON saf.run_id = sar.id
WHERE sar.session_label = '20260511-all-full'
GROUP BY
    sar.id,
    vri.display_name,
    vri.package_name,
    sar.status,
    sar.abort_reason,
    sar.abort_signal,
    sar.created_at,
    sar.ended_at_utc,
    sar.findings_total
ORDER BY sar.id;
```

**B — Persistence failures for session** (your query 2; join unchanged):

```sql
SELECT
    sar.id,
    vri.display_name,
    vri.package_name,
    spf.stage,
    spf.exception_class,
    LEFT(spf.exception_message, 300) AS exception_message,
    spf.occurred_at_utc
FROM static_persistence_failures spf
JOIN static_analysis_runs sar ON sar.id = spf.static_run_id
LEFT JOIN v_run_identity vri ON vri.run_id = CAST(sar.id AS CHAR(64))
WHERE sar.session_label = '20260511-all-full'
ORDER BY spf.occurred_at_utc DESC
LIMIT 50;
```

**C — Child row counts** (corrected: `static_analysis_findings.run_id`, `static_permission_matrix.run_id`, `static_permission_risk_vnext.run_id`; **string samples** link through `static_string_summary`, not `sample_set_id` on samples):

```sql
SELECT 'static_analysis_findings' AS table_name, COUNT(*) AS row_count
FROM static_analysis_findings saf
JOIN static_analysis_runs sar ON sar.id = saf.run_id
WHERE sar.session_label = '20260511-all-full'
UNION ALL
SELECT 'static_permission_matrix', COUNT(*)
FROM static_permission_matrix spm
JOIN static_analysis_runs sar ON sar.id = spm.run_id
WHERE sar.session_label = '20260511-all-full'
UNION ALL
SELECT 'static_permission_risk_vnext', COUNT(*)
FROM static_permission_risk_vnext spr
JOIN static_analysis_runs sar ON sar.id = spr.run_id
WHERE sar.session_label = '20260511-all-full'
UNION ALL
SELECT 'static_string_summary', COUNT(*)
FROM static_string_summary sss
WHERE sss.session_stamp = '20260511-all-full'
UNION ALL
SELECT 'static_string_samples', COUNT(*)
FROM static_string_samples ssi
JOIN static_string_summary sss ON sss.id = ssi.summary_id
WHERE sss.session_stamp = '20260511-all-full'
UNION ALL
SELECT 'static_string_sample_sets', COUNT(*)
FROM static_string_sample_sets sset
JOIN static_string_summary sss ON sss.id = sset.summary_id
WHERE sss.session_stamp = '20260511-all-full'
UNION ALL
SELECT 'static_session_run_links', COUNT(*)
FROM static_session_run_links
WHERE session_stamp = '20260511-all-full'
   OR origin_session_stamp = '20260511-all-full'
UNION ALL
SELECT 'static_session_rollups', COUNT(*)
FROM static_session_rollups
WHERE session_stamp = '20260511-all-full';
```

**D / E / F** — your global FAILED breakdown, completed sessions, and canonical grid queries remain valid as written (they only touch `static_analysis_runs`).

### Future tooling (not implemented here)

A **session hygiene** one-screen summary (CLI or script) would echo operator-safe labels, for example:

`session`, `outcome_class` (completed / aborted / persistence_failed / unknown), `runs`, `findings_rows`, `session_links`, `handoff_ready`, `paper_safe` (no).

---

## Top 10 database risks

1. **`metrics.run_id` ambiguity** (canonical vs legacy) — wrong join silently corrupts reporting.  
2. **`v_run_overview` hard-wires legacy** — any “cleanup” of `runs`/`buckets` without view change breaks consumers.  
3. **Collation drift** — subtle non-matches on `package_name` / session strings.  
4. **Legacy rows look “current”** to operators — trust / reconcile confusion (`static_reconcile` exists for a reason).  
5. **Truncating derived tables** while Web caches assumptions — UI empty states vs errors.  
6. **`static_session_*` vs canonical row counts** — different artifacts; misread as “missing static”.  
7. **Dynamic ↔ static handoff** — deleting canonical runs with linked `dynamic_sessions.static_run_id`.  
8. **Empty `analysis_dynamic_cohort_status`** — posture tests expect table **type** = BASE TABLE.  
9. **Evidence on filesystem vs DB** — DB cleanup without artifact retention loses reproducibility.  
10. **Out-of-repo SQL** — grep Web only inside this plan’s assumptions; verify separately.  
11. **Misreading `status=FAILED`** — always inspect **`abort_reason` / `abort_signal`** (`user_abort` / `SIGINT` = interrupted, not necessarily broken detectors or persistence).

---

## First 10 read-only SQL commands to run

1. §9.1 — row counts by table.  
2. §9.2 — sizes by table.  
3. §9.3 — table default collation histogram.  
4. §9.4 — key column collations.  
5. §9.5 — legacy vs canonical session distinct counts.  
6. §9.6 — sample orphan legacy `runs` (if any).  
7. §9.7 — canonical run status histogram + top incomplete sessions.  
8. §9.8 — top sessions by `static_analysis_findings` volume.  
9. §9.9 — dynamic table counts.  
10. `scripts/db/check_schema_posture.sql` (from repo) — view naming + `analysis_dynamic_cohort_status` type check.

---

## First cleanup candidates (still **plan** — not executed here)

1. **Dev-only:** large string sample tables **after** confirming evidence_pack / rerun path.  
2. **Dev-only:** duplicate scratch sessions in `static_analysis_runs` with explicit test labels (if your policy allows).  
3. **Investigate first:** legacy `runs` rows with **no** canonical `session_label` match — archive or document.  
4. **Investigate first:** `STARTED` / stuck `static_analysis_runs` from crashed processes (finalize policy — already has cleanup hook in scan flow; DB may still list rows).  
5. **Collation:** tables still on `latin1_swedish_ci` — candidate for **DB-4** only.

---

## Things that must **not** be touched yet

- **`v_static_handoff_v1`**, **`v_run_identity`**, **`static_analysis_*` core tables** — without dynamic + publication impact review.  
- **Legacy five** — until reader retirement + export + Web smoke per playbook.  
- **Any `v_*` / `vw_*` physicalized as BASE TABLE** — violates project rule; repair via views posture, not ad hoc drop.  
- **Permission Intel DB** — separate product boundary; do not “clean” as if it were static results.  
- **Unknown tables** in the 107-object inventory — classify before any action.

---

## Revision

| When | Action |
| --- | --- |
| After first SQL pass | Attach actual `information_schema` exports; move objects from `unknown_needs_review` to definitive classes |
| After Web grep | Update “legacy view consumer” subsection with out-of-repo findings |
