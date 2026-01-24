# Static Analysis Data Model & Persistence Map

This document explains how the static-analysis pipeline persists its results, how
those records map onto the MySQL schema, and which helper modules or CLI
commands interact with each table. It complements the pipeline plan and the
string-intelligence exploratory guide so analysts can trace any rendered finding
back to a concrete database record.

## 1. High-level flow

1. The pipeline ingests an APK and produces detector outputs plus
   string-intelligence observations.
2. The renderer exports a JSON artefact and invokes the canonical persistence
   adapter (`ingest_baseline_payload`) even when database writes are optional.
3. Persistence helpers in `scytaledroid/StaticAnalysis/persistence/ingest.py`
   call the idempotent DDL from
   `scytaledroid/Database/db_queries/canonical/schema.py` and promote provider
   exposures as needed. Database views are not used; all validations run
   directly on canonical tables.
4. Analysts can verify schema health through the CLI database utilities
   (**Database Utilities → Schema snapshot**) or by running the canonical helper
   snippet shown in the persistence runbook.

## 2. Canonical static-analysis tables

| Table | Purpose | Keys & relationships | Populated by |
| --- | --- | --- | --- |
| `apps` / `app_versions` | Normalised package + version metadata used by every downstream table. | `apps.package_name` unique; `app_versions` unique on `(app_id, version_name, version_code)` with FK → `apps`. | Canonical ingest (`_ensure_schema_ready`). |
| `static_analysis_runs` | One row per scan with SHA-256, session/scope, lineage metadata, detector metrics, reproducibility bundle, matrices, indicators, and workload profile. | PK `id`; FK `app_version_id` → `app_versions`. Indexed on `session_stamp`, `sha256`, `app_version_id`. | `ingest_baseline_payload`. |
| `static_analysis_findings` | Normalised findings (rule, severity, status, tags, CVSS, MASVS control, detector/module attribution, evidence JSON). | PK `id`; FK `run_id` → `static_analysis_runs`. Indexed on `(run_id, rule_id)` and `(rule_id, severity, run_id)`. | `ingest_baseline_payload` and provider promotion helpers. |
| `static_fileproviders` | Exported ContentProvider posture with authorities, guard strength, grant flags, and component metrics. | PK `id`; FK `run_id` → `static_analysis_runs`. Indexed on `component_name`, `effective_guard`. | `ingest_baseline_payload`. |
| `static_provider_acl` | Path-permission breakdowns for providers (path/prefix/pattern + guard levels). | PK `id`; FK `provider_id` → `static_fileproviders`. Indexed on provider + path columns. | `ingest_baseline_payload`. |
Legacy `static_findings_summary`, `static_findings`, and string tables remain for
backward compatibility, but all new analytics flows should rely on the canonical
tables above. Canonical ingest updates both worlds when legacy writes are
enabled, ensuring existing dashboards continue to function.

## 3. Session string samples

Session-scoped queries now read directly from `static_string_samples`. If a
legacy run lacks `session_stamp`, rerun the scan or use the stored evidence
paths; the CLI no longer depends on a fallback view.

## 4. Query helpers & diagnostics

* **Creation scripts** – Canonical DDL lives under
  `Database/db_queries/canonical/schema.py` and is invoked automatically via
  `ensure_provider_plumbing()`.
* **Provider promotion** – `upsert_base002_for_session()` materialises BASE-002
  findings into `static_analysis_findings` with structured evidence payloads.
* **Diagnostics menu** – `python -m scytaledroid.Database.db_utils.database_menu`
  still exposes schema snapshots. For standalone validation without the CLI,
  run the manual helper snippet (see runbook) to ensure schema readiness and
  promote provider exposures.
* **String intel snapshot** – The exploratory renderer (`--explore`) mirrors the
  canonical string tables; evidence counts in the CLI read from the persisted
  `static_string_summary` and `static_string_samples` rows.

## 5. Joining with APK metadata

Canonical tables already reference `app_versions`, so enriching reports usually
requires a single join:

```sql
SELECT av.version_name,
       av.version_code,
       sar.session_stamp,
       sar.scope_label,
       sar.analysis_version,
       saf.rule_id,
       saf.severity,
       saf.title,
       saf.evidence
FROM static_analysis_runs AS sar
JOIN app_versions AS av
  ON sar.app_version_id = av.id
JOIN static_analysis_findings AS saf
  ON saf.run_id = sar.id
WHERE av.package_name = 'com.example.app'
  AND sar.session_stamp = '20241019-163000';
```

When you need legacy `static_string_samples` context, join directly on
`static_string_samples` and apply any required normalisation in the query.

## 6. Related documentation

* [Static analysis pipeline plan](static_analysis_pipeline_plan.md) – detector
  architecture and execution flow.
* [Static analysis analytics extensions](../static_analysis_analytics.md) –
  matrices, novelty indicators, and workload payloads.
* [String intelligence exploratory guide](string_intelligence_explore.md) – how
  to interpret collection metrics, issue flags, and evidence samples.

Together with this data-model reference, the trio of documents provides a full
view of **how** the static analysis runs, **what** it collects, and **where** the
results live.
