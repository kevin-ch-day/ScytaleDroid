# Static Baseline Audit SQL Pack (Paper #1)

Scope: canonical static tables only.

Tables covered:
- `apps`
- `app_versions`
- `static_analysis_runs`
- `static_analysis_findings`
- `risk_scores`
- `static_permission_risk`
- `static_permission_matrix`
- `static_persistence_failures`

String tables are optional integrity checks only and are not core invariants.

## 1) Snapshot Coverage (latest completed per package/version/hash)

Purpose: validate the corpus boundary definition used by Paper #1 scripts.

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

Expected: one row per `(package_name, version_code, sha256)` tuple.

## 2) Orphan Detection

### 2.1 `app_versions` without parent app
```sql
SELECT COUNT(*) AS orphan_app_versions
FROM app_versions av
LEFT JOIN apps a ON a.id = av.app_id
WHERE a.id IS NULL;
```
Expected: `0`.

### 2.2 `static_analysis_runs` without app version
```sql
SELECT COUNT(*) AS orphan_static_runs
FROM static_analysis_runs r
LEFT JOIN app_versions av ON av.id = r.app_version_id
WHERE av.id IS NULL;
```
Expected: `0`.

### 2.3 `static_analysis_findings` without run
```sql
SELECT COUNT(*) AS orphan_findings
FROM static_analysis_findings f
LEFT JOIN static_analysis_runs r ON r.id = f.run_id
WHERE r.id IS NULL;
```
Expected: `0`.

### 2.4 `static_permission_matrix` without run
```sql
SELECT COUNT(*) AS orphan_permission_matrix
FROM static_permission_matrix m
LEFT JOIN static_analysis_runs r ON r.id = m.run_id
WHERE r.id IS NULL;
```
Expected: `0`.

## 3) Run/Findings/Risk Consistency

### 3.1 `findings_total` ledger consistency
```sql
SELECT
  r.id AS run_id,
  r.findings_total AS recorded_findings_total,
  COUNT(f.id) AS actual_findings_count
FROM static_analysis_runs r
LEFT JOIN static_analysis_findings f ON f.run_id = r.id
GROUP BY r.id, r.findings_total
HAVING r.findings_total <> COUNT(f.id);
```
Expected: no rows.

### 3.2 Completed runs missing risk row
```sql
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
```
Expected: no rows.

### 3.3 Duplicate score rows violating unique policy
```sql
SELECT
  package_name,
  session_stamp,
  scope_label,
  COUNT(*) AS n
FROM risk_scores
GROUP BY package_name, session_stamp, scope_label
HAVING COUNT(*) > 1;
```
Expected: no rows.

## 4) Duplicate Identity Checks

### 4.1 Same semantic identity with multiple hashes (allowed, audit only)
```sql
SELECT
  a.package_name,
  av.version_code,
  av.version_name,
  COUNT(DISTINCT r.sha256) AS distinct_hashes
FROM static_analysis_runs r
JOIN app_versions av ON av.id = r.app_version_id
JOIN apps a ON a.id = av.app_id
WHERE r.status = 'COMPLETED'
GROUP BY a.package_name, av.version_code, av.version_name
HAVING COUNT(DISTINCT r.sha256) > 1
ORDER BY distinct_hashes DESC, a.package_name ASC;
```
Expected: may return rows; this is a collision-policy visibility query.

### 4.2 Exact hash/session duplicates (should be reviewed)
```sql
SELECT
  a.package_name,
  r.sha256,
  r.session_stamp,
  COUNT(*) AS n
FROM static_analysis_runs r
JOIN app_versions av ON av.id = r.app_version_id
JOIN apps a ON a.id = av.app_id
GROUP BY a.package_name, r.sha256, r.session_stamp
HAVING COUNT(*) > 1
ORDER BY n DESC, a.package_name ASC;
```
Expected: ideally no rows.

## 5) Persistence Failure Detection

```sql
SELECT
  static_run_id,
  stage,
  exception_class,
  occurred_at_utc
FROM static_persistence_failures
ORDER BY occurred_at_utc DESC
LIMIT 100;
```
Expected: empty for clean batch; non-empty rows require triage.

## 6) `finalize_stale` Validation

### 6.1 Before call
```sql
SELECT COUNT(*) AS stale_running_rows
FROM static_analysis_runs
WHERE status = 'RUNNING'
  AND ended_at_utc IS NULL
  AND COALESCE(
        STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
        STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
      ) < (UTC_TIMESTAMP() - INTERVAL 60 MINUTE);
```

### 6.2 API call
```text
POST /maintenance/finalize_stale?minutes=60
```

### 6.3 After call
```sql
SELECT COUNT(*) AS stale_running_rows_after
FROM static_analysis_runs
WHERE status = 'RUNNING'
  AND ended_at_utc IS NULL
  AND COALESCE(
        STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
        STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
      ) < (UTC_TIMESTAMP() - INTERVAL 60 MINUTE);
```

Expected:
- API `updated` count equals (`before` - `after`).
- `after` should be `0` for stale rows at the chosen threshold.

## 7) Optional String-Table Integrity (non-core)

```sql
SELECT
  (SELECT COUNT(*) FROM static_string_summary) AS summary_rows,
  (SELECT COUNT(*) FROM static_string_samples) AS sample_rows,
  (SELECT COUNT(*) FROM static_string_selected_samples) AS selected_rows,
  (SELECT COUNT(*) FROM static_string_sample_sets) AS sample_set_rows;
```

Expected: informational only; failures here do not block Paper #1 core invariants.
