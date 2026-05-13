# Static and related tables — join patterns, audits, and safe cleanup SQL

**Purpose:** Eliminate guesswork when counting or deleting rows scoped to a **static session** (`session_stamp` / `scope_label`) or to a **`static_analysis_runs.id`**. Wrong column names produce **ERROR 1054** (unknown column) or **silent wrong counts** (joins that match zero rows or double rows).

**Authority:** Physical truth is **`information_schema`** on your catalog plus DDL in `scytaledroid/Database/db_queries/canonical/schema.py` and `scytaledroid/Database/db_queries/static_analysis/`. This document is a **curated map** and workflow; it does not replace running the audit SQL on each environment.

**Operator SQL pack:** `scripts/db/sql/audit_information_schema_static_relationships.sql` (Blocks A–C + commented `DESCRIBE` list).

**Related:** [session_identity_contract.md](session_identity_contract.md), [database_target_schema_v2.md](database_target_schema_v2.md), [database_cleanup_audit_plan.md](database_cleanup_audit_plan.md), [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md), `scripts/db/sql/session_summary_from_static_analysis_runs.sql`.

---

## Part A — Why this is hard (and not “bad data”)

### A.1 One English word, several different meanings

The name **`run_id`** appears on many tables but does **not** always mean **`static_analysis_runs.id`**.

| Context | Typical type | Points to |
| --- | --- | --- |
| Child of **`static_analysis_runs`** (canonical static) | `BIGINT UNSIGNED` | **`static_analysis_runs.id`** — but the column might be named **`run_id`** *or* **`static_run_id`** depending on the table |
| Legacy mirror **`runs`** | `BIGINT` | **`runs.run_id`** — different universe from canonical static |
| **`artifact_registry`**, ML windows | `VARCHAR(64)` | Opaque key paired with **`run_type`** — **not** safe to cast to `sar.id` |
| **`dynamic_sessions`** | `static_run_id` as BIGINT | Canonical static run when linked; dynamic is a separate concern |

If you assume “every `run_id` joins to `static_analysis_runs.id`”, you will eventually write a query that **parses** but returns **wrong results** or **breaks** on legacy tables.

### A.2 SQL does not “pick the branch that works” for missing columns

Expressions like:

```sql
COALESCE(tbl.static_run_id, tbl.run_id)
```

are **compiled** with **both** column names resolved. If **`static_run_id`** does not exist on `tbl`, you get **ERROR 1054** before any row logic runs. This is not a `COALESCE` bug; it is how SQL name resolution works.

**Safe patterns:**

- Use **only** the column that exists (after `DESCRIBE`).
- Or use **dynamic SQL** generated only after introspection (rare; usually unnecessary if you classify tables first).
- Or use **separate `UNION ALL` arms** per table family, each arm referencing only valid columns for that table.

### A.3 Same deploy, two DDL stories for file providers

The repo still contains **two** file-provider shapes:

1. **Canonical** (`canonical/schema.py`): `static_fileproviders.run_id` → `static_analysis_runs.id`, `static_provider_acl.provider_id` → `static_fileproviders.id`.
2. **Legacy harvest surface** (`harvest/storage_surface.py`): `run_key`, row-level `session_stamp`, no `run_id` FK — older or alternate path.

Your catalog might match (1), (2), or a **partially migrated** mix. **`DESCRIBE static_fileproviders`** on the **target database** is mandatory before writing joins.

---

## Part B — Classification patterns (use these labels consistently)

When you add a table to a footprint or prune plan, assign **one primary pattern** (and note secondary keys).

| Pattern ID | Name | How to reach `static_analysis_runs` or session |
| --- | --- | --- |
| **P1** | `session_direct` | Filter on **`session_stamp`** / **`session_label`** / **`scope_label`** on the row itself (no join to `sar` required, but you may join for package identity). |
| **P2** | `canonical_run_fk_run_id` | **`child.run_id = sar.id`** (BIGINT, FK semantics in DDL). |
| **P3** | `canonical_run_fk_static_run_id` | **`child.static_run_id = sar.id`**. |
| **P4** | `dual_canonical_run_fk` | Table has **both** `run_id` and **`static_run_id`** (nullable) pointing at `sar` — use whichever is populated or prefer `static_run_id` when both set (verify with `SELECT`). |
| **P5** | `string_summary_tree` | String pipeline: **`static_string_summary`** then **`summary_id`** on samples / sets; summary may also carry **`session_stamp`** and **`static_run_id`**. |
| **P6** | `provider_tree` | **`static_provider_acl.provider_id`** → **`static_fileproviders.id`** → **`static_fileproviders.run_id`** → **`sar.id`**. |
| **P7** | `legacy_runs_mirror` | **`metrics`**, **`buckets`**, legacy **`findings`**, **`contributors`**: `run_id` means **`runs.run_id`**, not `sar.id`. |
| **P8** | `string_opaque_run_id` | **`run_id` VARCHAR** (e.g. `artifact_registry`) — classify with **`run_type`**; do not join to `sar.id` without a documented mapping. |
| **P9** | `session_link_row` | **`static_session_run_links`**: `static_run_id` → `sar.id`, **`session_stamp`** on link (no `scope_label` on link — scope is only on `sar` / rollups). |
| **P10** | `ambiguous` | Needs **`DESCRIBE` + sample values** before classification. |

---

## Part C — Decision tree: “How do I scope this table to a session?”

Start with **`DESCRIBE your_table`** (or Block A output). Then:

1. **Does the table have `session_stamp` (or `session_label`) on the row?**  
   - Yes → Prefer **P1**: `WHERE session_stamp = @s` (and `scope_label` if the table has it and your policy is per-scope).  
   - Watch **width**: `static_string_summary.session_stamp` is often **`VARCHAR(64)`** while `static_analysis_runs.session_stamp` is **`VARCHAR(128)`** — long stamps can truncate or fail to match; treat as a **migration risk** (see [database_target_schema_v2.md](database_target_schema_v2.md) Section 8).

2. **Does the table have `static_run_id` (BIGINT)?**  
   - Yes → **P3**: `JOIN static_analysis_runs sar ON sar.id = tbl.static_run_id WHERE sar.session_stamp = @s`.

3. **Does the table have `run_id` (BIGINT) and no reliable `static_run_id`?**  
   - If the table is **`static_analysis_findings`**, **`static_permission_matrix`**, **`static_permission_risk_vnext`**, **`static_fileproviders`** (canonical) → **P2**: `JOIN sar ON sar.id = tbl.run_id`.  
   - If the table is **`metrics`**, **`buckets`**, legacy **`findings`** → **P7**: join to **`runs`**, not `sar`, unless you have a proven bridge query.

4. **Does the table have both `run_id` and `static_run_id` (nullable)?**  
   - **P4** (`static_findings_summary`, `static_findings`): use  
     `JOIN sar ON sar.id = COALESCE(tbl.static_run_id, tbl.run_id)` **only if both columns exist** on that table (they do on these two). For other tables, **do not assume** both exist.

5. **Is the table string pipeline (`static_string_*`)?**  
   - **P5**: join **`static_string_samples.summary_id = static_string_summary.id`**, then filter summary by `session_stamp` / `scope_label` and/or `static_run_id`.

6. **Is the table `static_provider_acl`?**  
   - **P6**: always go through **`static_fileproviders`**; do not invent `static_run_id` on ACL rows.

7. **Is the table `artifact_registry` or ML tables with `VARCHAR run_id`?**  
   - **P8**: stop and read code / `run_type` semantics; do not join to BIGINT `sar.id` without a contract.

---

## Part D — Repo-authoritative cheatsheet (canonical static, typical deploy)

> **Reminder:** Your catalog may lag DDL or mix migrations. **Block A** output wins over this table if they disagree.

| Table | Pattern | Join / filter to session `@s` (typical) |
| --- | --- | --- |
| `static_analysis_runs` | hub | `WHERE session_stamp = @s` (+ `scope_label` if needed) |
| `static_analysis_findings` | P2 | `JOIN sar ON sar.id = f.run_id` |
| `static_permission_matrix` | P2 | `JOIN sar ON sar.id = pm.run_id` |
| `static_permission_risk_vnext` | P2 | `JOIN sar ON sar.id = pr.run_id` |
| **`static_fileproviders`** | P2 | **`JOIN sar ON sar.id = fp.run_id`** — **no** `static_run_id` column in canonical DDL |
| **`static_provider_acl`** | P6 | `JOIN fp ON fp.id = spa.provider_id JOIN sar ON sar.id = fp.run_id` |
| `static_correlation_results` | P3 | `JOIN sar ON sar.id = cr.static_run_id` |
| `static_persistence_failures` | P3 | `JOIN sar ON sar.id = spf.static_run_id` |
| `permission_signal_observations` | P3 | `JOIN sar ON sar.id = pso.static_run_id` |
| `static_string_summary` | P1 / P5 | `WHERE session_stamp = @s` **or** `JOIN sar ON sar.id = ss.static_run_id` (nullable); mind **64 vs 128** `session_stamp` |
| `static_string_samples` | P5 | Join through **`summary_id`** → summary → session |
| `static_string_sample_sets` | P5 | Join through **`summary_id`** |
| `static_string_selected_samples` | P5 | Same tree |
| `static_findings_summary` | P1 + P4 | `WHERE session_stamp = @s` **and/or** `JOIN sar ON sar.id = COALESCE(s.static_run_id, s.run_id)` **both columns exist here** |
| `static_findings` | P4 | Via `summary_id` to summary, or `COALESCE(static_run_id, run_id)` to `sar` when populated |
| `static_session_run_links` | P9 | `WHERE session_stamp = @s` (no `scope_label` on row — same stamp with different scopes is a **data model edge case**) |
| `static_session_rollups` | P1 | `WHERE session_stamp = @s AND scope_label = @scope` |
| `risk_scores` | P1 | `WHERE session_stamp = @s` (+ `scope_label`, `package_name` as needed) |
| `masvs_control_coverage` | P2 (typical) | `JOIN sar ON sar.id = mcc.run_id` — confirm **`run_id`** on your catalog with `DESCRIBE` |
| `static_persistence_failures` | P3 | `static_run_id` only |
| `permission_audit_snapshots` | mixed | May store `static_run_id`; apps link via `snapshot_id` — classify per Block A |
| `permission_audit_apps` | mixed | Often `snapshot_id` + `package_name`; `static_run_id` nullable |
| `artifact_registry` | P8 | **Do not** `JOIN sar ON sar.id = ar.run_id` |

---

## Part E — COALESCE: when it is allowed vs forbidden

| Situation | Safe? |
| --- | --- |
| `COALESCE(static_run_id, run_id)` on **`static_findings_summary`** where **both** columns exist | Yes (still verify nullability / which writer fills which). |
| `COALESCE(static_run_id, run_id)` on **`static_fileproviders`** | **No** — `static_run_id` does not exist on canonical DDL → **ERROR 1054**. |
| `COALESCE(run_id, other)` where you have not run `DESCRIBE` | **No** — prove columns first. |

**Rule:** `COALESCE` is only safe when **every** identifier inside it exists on that **physical** table for your catalog version.

---

## Part F — Session footprint template (read-only, two strategies)

Use **`@target_session`** and optionally **`@target_scope`**.

### F.1 Strategy 1 — Everything through `sar` (preferred when child uses run FK)

```sql
SET @target_session = '20260511-all-full';

SELECT 'static_analysis_findings' AS t, COUNT(*) AS c
FROM static_analysis_findings f
JOIN static_analysis_runs sar ON sar.id = f.run_id
WHERE sar.session_stamp = @target_session;

SELECT 'static_fileproviders' AS t, COUNT(*) AS c
FROM static_fileproviders fp
JOIN static_analysis_runs sar ON sar.id = fp.run_id
WHERE sar.session_stamp = @target_session;
```

Repeat per **P2** / **P3** table from Part D.

### F.2 Strategy 2 — Session-direct tables (no `sar` join)

```sql
SELECT 'risk_scores' AS t, COUNT(*) AS c
FROM risk_scores rs
WHERE rs.session_stamp = @target_session;

SELECT 'static_string_summary' AS t, COUNT(*) AS c
FROM static_string_summary ss
WHERE ss.session_stamp = @target_session;
```

### F.3 Strategy 3 — String samples through summary

```sql
SELECT 'static_string_samples' AS t, COUNT(*) AS c
FROM static_string_samples samp
JOIN static_string_summary ss ON ss.id = samp.summary_id
WHERE ss.session_stamp = @target_session;
```

**Do not** merge these strategies into one mega-join across unrelated children; use **`UNION ALL`** of small `SELECT`s so one wrong join does not invalidate the whole report.

---

## Part G — Deletes, truncates, and FK order (preview before destructive work)

### G.1 Prefer narrowing by `sar.id` list first

For a session, the safest mental model is:

1. `SELECT id FROM static_analysis_runs WHERE session_stamp = @s …` → id list.  
2. For **P2** / **P3** children, `WHERE run_id IN (…)` or `WHERE static_run_id IN (…)`.  
3. For **P1** tables, `DELETE` / `WHERE session_stamp = @s` explicitly.

### G.2 What `ON DELETE CASCADE` does for you

From `canonical/schema.py`, many canonical children **CASCADE** when `static_analysis_runs` rows are deleted (`static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, `static_fileproviders`, etc.). **You still must handle** tables without an FK to `sar` (e.g. **`risk_scores`**, **`static_string_summary`** keyed by stamp).

### G.3 Tables that commonly need explicit cleanup

| Table | Why explicit |
| --- | --- |
| `risk_scores` | No FK to `sar`; **P1** |
| `static_string_summary` / samples / sets | Session stamp + summary tree; FKs may be nullable |
| `static_session_rollups` | PK is `(session_stamp, scope_label)` |
| `static_session_run_links` | `session_stamp` + `package_name`; verify before delete |
| `permission_audit_*` | Snapshot model; may retain `static_run_id` nullable |

Always **`SELECT COUNT(*)`** preview per table before **`DELETE`**.

---

## Part H — Collation and width mismatches (silent bugs)

| Issue | Symptom | Mitigation |
| --- | --- | --- |
| `package_name` different collations | Fewer rows than expected in joins | Use explicit `CONVERT(... COLLATE utf8mb4_unicode_ci)` only after audit; align collation in Phase 7 migrations |
| `session_stamp` **64** vs **128** | Truncation or non-match | Widen summary tables or shorten stamps; document in migration plan |
| `static_session_run_links` latin1 vs apps utf8mb4 | Missing links in Web | Collation migration target (see cleanup audit plan) |

---

## Part I — Troubleshooting checklist

| Symptom | Likely cause | Action |
| --- | --- | --- |
| **ERROR 1054** unknown column | Wrong column name for this table version | `DESCRIBE`; fix join; remove bogus `COALESCE` arm |
| Count **0** but UI shows data | Join uses wrong FK pattern (e.g. `sar.id = legacy.run_id`) | Reclassify table (P7 vs P2) |
| Count **too high** | Missing join condition (`scope_label`, `package_name`) | Add predicates; confirm session grain |
| Duplicate rows in report | `JOIN` multiplies rows (1:N without aggregation) | Use `COUNT(DISTINCT …)` or subquery per table |
| Interrupt session still has findings | Expected — partial persistence | disposition `interrupted_partial_session`; do not treat as detector failure |

---

## Part J — Audit workflow (repeatable)

1. Run **Block A** from `audit_information_schema_static_relationships.sql` → save CSV.  
2. Run **Block B** → build a checklist of `DESCRIBE` targets.  
3. Run **Block C** → note large tables and **TABLE_COLLATION** outliers.  
4. Label each table with **P1–P10** from Part B.  
5. Build footprint SQL only from Part F patterns for that label.  
6. For any destructive step later: preview counts, backup, verify zero orphans.

---

## Part K — Session-scoped snippets (canonical `static_fileproviders`)

```sql
SET @target_session = '20260511-all-full';

SELECT 'static_fileproviders' AS table_name, COUNT(*) AS row_count
FROM static_fileproviders fp
JOIN static_analysis_runs sar ON sar.id = fp.run_id
WHERE sar.session_stamp = @target_session;

SELECT 'static_provider_acl' AS table_name, COUNT(*) AS row_count
FROM static_provider_acl spa
JOIN static_fileproviders fp ON fp.id = spa.provider_id
JOIN static_analysis_runs sar ON sar.id = fp.run_id
WHERE sar.session_stamp = @target_session;
```

---

## Revision

| Date | Note |
| --- | --- |
| 2026-05-09 | Initial map: COALESCE trap, patterns, audit SQL pointer. |
| 2026-05-09 | Expanded: mental model, decision tree P1–P10, dual-FK tables, footprint templates, delete notes, troubleshooting, collation/width. |
