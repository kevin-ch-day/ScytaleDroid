# Static and related tables — join patterns and relationship audit

**Purpose:** Stop guessing column names for session-scoped counts, prune previews, and cleanup SQL. MariaDB resolves **every** identifier in an expression (including both branches of `COALESCE(a, b)`); if one column does not exist, the statement fails before runtime short-circuiting.

**Authority:** Runtime DDL in `scytaledroid/Database/db_queries/canonical/schema.py` and domain modules; this doc is a **human map** — when in doubt, run the SQL pack in `scripts/db/sql/audit_information_schema_static_relationships.sql` on your catalog.

**Related:** [session_identity_contract.md](session_identity_contract.md), [database_target_schema_v2.md](database_target_schema_v2.md), [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md).

---

## 1. Relationship patterns (classification)

Use these labels when building prune previews or tooling.

| Pattern | Meaning | Examples |
| --- | --- | --- |
| **session_direct** | Row carries `session_stamp` / `session_label` (and often `scope_label`) without going through `static_analysis_runs` first | `risk_scores`, `static_string_summary`, `static_session_rollups`, `static_session_run_links` |
| **canonical_run_fk_run_id** | BIGINT `run_id` → `static_analysis_runs.id` | `static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, **`static_fileproviders`** |
| **canonical_run_fk_static_run_id** | BIGINT `static_run_id` → `static_analysis_runs.id` | `static_correlation_results`, `static_persistence_failures`, `permission_signal_observations` |
| **string_summary_child** | Join to `static_string_summary.id` via `summary_id` | `static_string_samples`, `static_string_sample_sets` |
| **provider_child** | Join to `static_fileproviders.id` via `provider_id` | `static_provider_acl` (canonical DDL) |
| **legacy_run_fk** | `run_id` (or similar) refers to **`runs.run_id`**, not `static_analysis_runs.id` | `metrics`, `buckets`, legacy `findings`, `contributors` — see legacy map |
| **dynamic_only** | `dynamic_run_id` (UUID) or dynamic session tables | Not static prune by `session_stamp` alone |
| **string_run_id** | `run_id` is `VARCHAR` / opaque token, not numeric static PK | `artifact_registry.run_id`, some ML tables |
| **ambiguous** | Must `DESCRIBE` + sample data | Mixed migrations, one-off tables |

---

## 2. COALESCE trap (why your query failed)

Wrong (fails if `static_run_id` does not exist on the table):

```sql
JOIN static_analysis_runs sar
  ON sar.id = COALESCE(sfp.static_run_id, sfp.run_id)   -- ERROR 1054 if static_run_id missing
```

Right for **canonical** `static_fileproviders` (repo DDL: only `run_id`):

```sql
JOIN static_analysis_runs sar ON sar.id = sfp.run_id
```

Rule: **only reference columns that exist on that physical table**; use pattern classification above instead of guessing dual columns.

---

## 3. Repo-authoritative join cheatsheet (canonical static)

These match **`canonical/schema.py`** as of this writing.

**DDL drift warning:** `Database/db_queries/harvest/storage_surface.py` still documents an **older** fileprovider shape (`run_key`, `session_stamp` on the row without `run_id`). Many catalogs instead have the **canonical** table (`run_id` FK → `static_analysis_runs.id`, `provider_id` on ACL). **Never** assume; use Block A/B from the audit SQL pack and `DESCRIBE static_fileproviders` before writing joins.

| Table | Join to `static_analysis_runs` | Session filter |
| --- | --- | --- |
| `static_analysis_findings` | `f.run_id = sar.id` | `sar.session_stamp` / `scope_label` |
| `static_permission_matrix` | `pm.run_id = sar.id` | via `sar` |
| `static_permission_risk_vnext` | `pr.run_id = sar.id` | via `sar` |
| **`static_fileproviders`** | **`fp.run_id = sar.id`** | via `sar` (no `static_run_id`) |
| **`static_provider_acl`** | `acl.provider_id = fp.id` then `fp.run_id = sar.id` | via `sar` |
| `static_correlation_results` | `cr.static_run_id = sar.id` | via `sar` |
| `static_persistence_failures` | `spf.static_run_id = sar.id` | via `sar` |
| `static_string_summary` | `ss.static_run_id = sar.id` optional; or match `package_name` + `session_stamp` + `scope_label` | direct `ss.session_stamp` (note `VARCHAR(64)` vs 128 on runs — see target schema doc) |
| `static_string_samples` | `samp.summary_id = ss.id` → summary → run or stamp | prefer join through summary |
| `permission_signal_observations` | `pso.static_run_id = sar.id` | via `sar` |
| `permission_audit_apps` | `static_run_id` nullable; often `snapshot_id` + `package_name` — inspect | not a simple run FK only |
| `artifact_registry` | **Do not** join `artifact_registry.run_id` to `sar.id` without interpreting `run_type` / conventions | ambiguous string key |

---

## 4. Audit workflow (do not skip)

1. Run **Block A** in `scripts/db/sql/audit_information_schema_static_relationships.sql` — full column list for base tables touching run/session/stamp columns.  
2. Run **Block B** — distinct table list for targeted `DESCRIBE`.  
3. Run **Block C** — inventory size/collation for static/permission/risk/legacy names.  
4. Classify each table using Section 1; only then write `UNION ALL` session footprint or prune preview SQL.  
5. Long term: add `static_analysis_runs.static_session_id` and prefer `child → sar → session` over string stamps (see [database_target_schema_v2.md](database_target_schema_v2.md)).

---

## 5. Session-scoped preview snippets (canonical DDL)

Use a session variable for repeatability:

```sql
SET @target_session = '20260511-all-full';
```

**Fileproviders (canonical):**

```sql
SELECT 'static_fileproviders' AS table_name, COUNT(*) AS row_count
FROM static_fileproviders fp
JOIN static_analysis_runs sar ON sar.id = fp.run_id
WHERE sar.session_stamp = @target_session;
```

**Provider ACL (canonical):**

```sql
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
| 2026-05-09 | Initial map: COALESCE trap, patterns A–E, audit SQL pointer, canonical fileproviders joins. |
