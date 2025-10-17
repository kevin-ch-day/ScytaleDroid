# Static Analysis Data Model & Persistence Map

This document explains how the static-analysis pipeline persists its results, how
those records map onto the MySQL schema, and which helper modules or CLI
commands interact with each table. It complements the pipeline plan and the
string-intelligence exploratory guide so analysts can trace any rendered finding
back to a concrete database record.

## 1. High-level flow

1. The pipeline ingests an APK and produces detector outputs plus
   string-intelligence observations.
2. The renderer exports a JSON artefact and (when configured) invokes the
   database persistence adapters.
3. Persistence helpers in `scytaledroid/Database/db_queries/` create or update
   the static-analysis tables. These helpers are wrapped by
   `scytaledroid/Database/db_utils/diagnostics.py` and the CLI diagnostics menu.
4. Analysts can verify schema health through **Database Utilities → Schema
   snapshot** and cross-check counts via **Quick stats**.

## 2. Core tables

| Table | Purpose | Primary keys & relationships | Populated by |
| --- | --- | --- | --- |
| `static_findings_summary` | One row per scan session (`package_name`, `session_stamp`, `scope_label`). Stores severity counts, manifest flag snapshot, and string-summary foreign keys. | PK `id`; unique index on `(package_name, session_stamp, scope_label)`. Referenced by `static_findings` and `static_string_samples`. | `db_queries/static_findings.py` (`INSERT_FINDINGS_SUMMARY`). |
| `static_findings` | Individual findings from detectors/correlation (title, severity, evidence JSON). | PK `id`; FK `summary_id` → `static_findings_summary.id`. | `db_queries/static_findings.py` (`INSERT_FINDING`). |
| `static_string_summary` | Aggregated counts for string buckets (endpoints, cleartext, cloud references, etc.). | PK `id`; unique index on `(package_name, session_stamp, scope_label)`. | `db_queries/string_analysis.py` (`INSERT_STRING_SUMMARY`). |
| `static_string_samples` | Top-N string samples per bucket with masking, provenance, and tag metadata. | PK `id`; FK `summary_id` → `static_string_summary.id`. | `db_queries/string_analysis.py` (`INSERT_SAMPLE`). |
| `risk_scores` / `static_permission_risk` | Roll-up risk metrics for permissions and overall scoring. | `risk_scores` keyed by `(package_name, session_stamp, scope_label)`; `static_permission_risk` keyed by `apk_id`. | `db_queries/risk_scores.py` and `db_queries/static_permission_risk.py`. |
| `static_fileproviders`, `static_provider_acl` | Provider posture (authority, exported flag, ACLs). | PK `id`; optional `apk_id` / `session_stamp` for joins. | `db_queries/storage_surface.py`. |

All tables share the `session_stamp` convention so they can be joined with the
latest APK metadata from `android_apk_repository` or with `permission_audit`
records when building cross-signal reports.

## 3. Extended columns for string evidence

Recent iterations expanded `static_string_samples` to capture richer provenance.
When migrations are applied, each row includes:

* `source_type` – `dex`, `res`, `asset`, or `native`.
* `finding_type` – Logical classification (e.g., `endpoint`, `aws_pair`).
* `provider` / `risk_tag` – Normalised tags aligned with the SNI catalog.
* `confidence` – Low/medium/high confidence value echoed from the detectors.
* `sample_hash` – SHA-1 of the masked string payload for deduplication.
* `root_domain`, `scheme`, `resource_name` – Normalised URL fragments where
  applicable.

If your schema snapshot still reflects the previous column set
(`bucket`, `value_masked`, `src`, `tag`, `rank`), run the database migration
script provided in `db_utils`:

```bash
python -m scytaledroid.Database.db_utils.diagnostics --apply string_analysis_upgrade
```

The command creates/updates the table definitions using
`CREATE_STRING_SUMMARY` and `CREATE_STRING_SAMPLES` from
`db_queries/string_analysis.py`.

## 4. Query helpers & diagnostics

* **Creation scripts** – `db_queries/*` files hold the canonical `CREATE TABLE`
  statements. They are sourced by setup scripts and migrations.
* **Diagnostics menu** – `python -m scytaledroid.Database.db_utils.diagnostics`
  exposes the menu shown in the schema snapshot (options 1–4, 9). Option **2**
  emits the Markdown schema summary used above; option **3** cross-checks row
  counts for `static_findings`, `static_string_summary`, and related tables.
* **String intel snapshot** – After a run, use the exploratory renderer
  (`--explore`) to compare JSON metrics against `static_string_summary`
  aggregates. The `summary_id` from the JSON payload should match the FK stored
  in `static_string_samples` once persistence is enabled.

## 5. Joining with APK metadata

Static-analysis tables intentionally avoid duplicating APK metadata. To enrich a
report:

```sql
SELECT sfs.package_name,
       latest.version_name,
       sfs.high,
       sss.endpoints,
       sss.http_cleartext
FROM static_findings_summary AS sfs
JOIN static_string_summary AS sss
  ON sfs.package_name = sss.package_name
 AND sfs.session_stamp = sss.session_stamp
JOIN vw_latest_apk_per_package AS latest
  ON latest.package_name = sfs.package_name;
```

When you need split-specific metadata, join via `android_apk_repository` using
`package_name` and `split_group_id` to align with the `split_id` recorded by the
string-intelligence extractor.

## 6. Related documentation

* [Static analysis pipeline plan](static_analysis_pipeline_plan.md) – detector
  architecture and execution flow.
* [String intelligence exploratory guide](string_intelligence_explore.md) – how
  to interpret collection metrics, issue flags, and evidence samples.

Together with this data-model reference, the trio of documents provides a full
view of **how** the static analysis runs, **what** it collects, and **where** the
results live.
