# Database Query Reference

This folder documents the read-side queries the future PHP/MySQL portal will
need. The PHP application consumes data solely from the MySQL
repository—no direct integration with the Python CLI is required. Each
markdown file covers:

* **Purpose** – where the query is used in the UI
* **Inputs** – parameters the web layer must supply
* **Pseudo-SQL** – expressed against placeholder table names (discover the real names first!)
* **Result columns** – shape of the expected rows
* **Example payload** – JSON-like sketch of what the PHP app might render

Start by confirming actual table and column names in your environment before
wiring these queries into the app. Static-analysis reports currently land on
disk; as soon as the `static_analysis_runs` tables are provisioned, extend this
folder with matching read models that join `android_apk_repository` by `apk_id`
or `sha256`.

## PHP consumption checklist

The query specs are intentionally framework-agnostic, but the PHP portal can
standardise on the following workflow when materialising them:

1. **Enforce read-only credentials.** Provision a dedicated database user with
   `SELECT` grants only. Reject any code reviews that introduce `INSERT`,
   `UPDATE`, or `DELETE` statements under the LAMP entry point.
2. **Mirror the pseudo-SQL with prepared statements.** Use PDO or your chosen
   abstraction to translate the query snippets into parameterised statements.
   Avoid string concatenation; every filter described in the docs should map to
   a bound parameter.
3. **Capture query provenance.** Wrap DAO methods with logging that records the
   query name (matching the markdown filename) and execution duration. This
   keeps parity between the documentation and the PHP implementation.
4. **Validate row shape.** Each markdown file lists the expected columns.
   Serialise rows into associative arrays and add unit tests that check the key
   set, so regressions surface quickly when the schema evolves.
5. **Prefer result caching at the PHP layer.** Dashboards that poll frequently
   should memoise results (APCu, Redis, or similar) with short TTLs rather than
   hammering MySQL.

> ℹ️  When you add a new query to the docs, create a matching DAO or repository
> class with the same name in PHP and link back to the markdown file in a
> docblock. This keeps cross-language references aligned.

## Contents

| Document | Focus |
| --- | --- |
| [`apps_by_category.md`](apps_by_category.md) | Category coverage + counts |
| [`uncategorized_apps.md`](uncategorized_apps.md) | Packages missing category assignments |
| [`latest_harvest_by_device.md`](latest_harvest_by_device.md) | Most recent pull per device |
| [`device_inventory_latest.md`](device_inventory_latest.md) | Current inventory view for a device |
| [`artifacts_for_app.md`](artifacts_for_app.md) | Artifact lineup for a single package |
| [`duplicate_artifacts.md`](duplicate_artifacts.md) | SHA-256 collisions and reuse |
| [`harvest_gaps.md`](harvest_gaps.md) | Installed apps without repository entries |
| [`harvest_paths.md`](harvest_paths.md) | DDL for path-related tables |
| [`recent_changes.md`](recent_changes.md) | Version deltas between snapshots |
| [`topline_kpi.md`](topline_kpi.md) | High-level rollup metrics |
> ⚠️ These files describe **read queries only**. Do not run them against
> production data without validating table names and access controls.

## Verification checklist

Use these checks before relying on any query in this folder:

```sql
SHOW TABLES;
DESCRIBE apps;
DESCRIBE app_versions;
DESCRIBE device_inventory;
DESCRIBE device_inventory_snapshots;
DESCRIBE android_apk_repository;
DESCRIBE harvest_source_paths;
DESCRIBE harvest_artifact_paths;
DESCRIBE harvest_storage_roots;
```

Quick row-presence checks:

```sql
SELECT COUNT(*) AS total_apps FROM apps;
SELECT COUNT(*) AS total_app_versions FROM app_versions;
SELECT COUNT(*) AS total_inventory_rows FROM device_inventory;
SELECT COUNT(*) AS total_snapshots FROM device_inventory_snapshots;
SELECT COUNT(*) AS total_artifacts FROM android_apk_repository;
SELECT COUNT(*) AS total_source_paths FROM harvest_source_paths;
SELECT COUNT(*) AS total_artifact_paths FROM harvest_artifact_paths;
```

Latest inventory smoke test:

```sql
SELECT di.package_name, di.version_name, di.version_code, s.snapshot_id, s.captured_at
FROM device_inventory AS di
JOIN device_inventory_snapshots AS s
  ON s.snapshot_id = di.snapshot_id
WHERE s.snapshot_id = (SELECT MAX(snapshot_id) FROM device_inventory_snapshots)
ORDER BY di.package_name
LIMIT 20;
```

Identity/artifact linkage smoke test:

```sql
SELECT
    r.apk_id,
    r.package_name,
    a.display_name,
    r.version_code,
    r.sha256,
    r.device_serial,
    r.harvested_at
FROM android_apk_repository AS r
LEFT JOIN apps AS a ON a.id = r.app_id
ORDER BY r.harvested_at DESC
LIMIT 20;
```

Lineage completeness checks:

```sql
SELECT COUNT(*) AS missing_artifact_path
FROM android_apk_repository AS r
LEFT JOIN harvest_artifact_paths AS hap ON hap.apk_id = r.apk_id
WHERE hap.apk_id IS NULL;

SELECT COUNT(*) AS missing_source_path
FROM android_apk_repository AS r
LEFT JOIN harvest_source_paths AS hsp ON hsp.apk_id = r.apk_id
WHERE hsp.apk_id IS NULL;
```

## Static baseline audit checks

These checks validate canonical static write surfaces:

Core tables covered:
- `apps`
- `app_versions`
- `static_analysis_runs`
- `static_analysis_findings`
- `risk_scores`
- `static_permission_risk`
- `static_permission_matrix`
- `static_persistence_failures`

String tables are optional integrity checks only and are not core invariants.

Snapshot coverage:

```sql
SELECT
  a.package_name,
  av.version_code,
  r.sha256,
  MAX(r.id) AS latest_completed_run_id
FROM static_analysis_runs r
JOIN app_versions av ON av.id = r.app_version_id
JOIN apps a ON a.id = av.app_id
WHERE r.status = 'COMPLETED'
GROUP BY a.package_name, COALESCE(av.version_code, -1), COALESCE(r.sha256, '');
```

Orphan checks:

```sql
SELECT COUNT(*) AS orphan_app_versions
FROM app_versions av
LEFT JOIN apps a ON a.id = av.app_id
WHERE a.id IS NULL;

SELECT COUNT(*) AS orphan_static_runs
FROM static_analysis_runs r
LEFT JOIN app_versions av ON av.id = r.app_version_id
WHERE av.id IS NULL;

SELECT COUNT(*) AS orphan_findings
FROM static_analysis_findings f
LEFT JOIN static_analysis_runs r ON r.id = f.run_id
WHERE r.id IS NULL;

SELECT COUNT(*) AS orphan_permission_matrix
FROM static_permission_matrix m
LEFT JOIN static_analysis_runs r ON r.id = m.run_id
WHERE r.id IS NULL;
```

Consistency checks:

```sql
SELECT
  r.id AS run_id,
  r.findings_total AS recorded_findings_total,
  COUNT(f.id) AS actual_findings_count
FROM static_analysis_runs r
LEFT JOIN static_analysis_findings f ON f.run_id = r.id
GROUP BY r.id, r.findings_total
HAVING r.findings_total <> COUNT(f.id);

SELECT
  r.id AS run_id,
  a.package_name,
  r.session_stamp,
  r.scope_label
FROM static_analysis_runs r
JOIN app_versions av ON av.id = r.app_version_id
JOIN apps a ON a.id = av.app_id
LEFT JOIN risk_scores rs
  ON rs.package_name = a.package_name
 AND rs.session_stamp = r.session_stamp
 AND rs.scope_label = r.scope_label
WHERE r.status = 'COMPLETED'
  AND rs.id IS NULL;

SELECT
  package_name,
  session_stamp,
  scope_label,
  COUNT(*) AS n
FROM risk_scores
GROUP BY package_name, session_stamp, scope_label
HAVING COUNT(*) > 1;
```

## Harvest path schema note

The harvest path tables are part of the core schema contract:
- `harvest_storage_roots`
- `harvest_artifact_paths`

Their purpose is:
- register the ingest environment (`host_name`, `data_root`)
- attach each harvested artifact to both the original on-device path and the
  local relative path
- preserve lineage for later static-analysis and reporting joins
