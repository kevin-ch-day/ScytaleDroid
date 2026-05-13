-- ============================================================================
-- Verification queries: static_session_id rollout (read-only)
-- ============================================================================
-- Run after schema migration + optional backfill. Expect zero rows on checks 1–3
-- once headers and runs are aligned; artifact/dynamic counts may be non-zero
-- until separate cleanup tracks (do not treat as this slice’s failure mode).
-- ============================================================================

-- 1) Runs with a session stamp but no linked static_session_id
SELECT
  COUNT(*) AS sar_rows_with_stamp_null_static_session_id
FROM static_analysis_runs sar
WHERE sar.session_stamp IS NOT NULL
  AND LENGTH(TRIM(BOTH FROM sar.session_stamp)) > 0
  AND sar.static_session_id IS NULL;

-- Sample (first 50)
SELECT
  sar.id,
  sar.session_stamp,
  sar.scope_label,
  sar.static_session_id
FROM static_analysis_runs sar
WHERE sar.session_stamp IS NOT NULL
  AND LENGTH(TRIM(BOTH FROM sar.session_stamp)) > 0
  AND sar.static_session_id IS NULL
ORDER BY sar.id DESC
LIMIT 50;

-- 2) Session headers with no matching runs (by natural key)
SELECT
  COUNT(*) AS session_headers_with_zero_runs
FROM static_analysis_sessions sas
LEFT JOIN static_analysis_runs sar
  ON TRIM(BOTH FROM sar.session_stamp) = TRIM(BOTH FROM sas.session_stamp)
 AND COALESCE(TRIM(BOTH FROM sar.scope_label), '') = COALESCE(TRIM(BOTH FROM sas.scope_label), '')
WHERE sar.id IS NULL;

SELECT
  sas.static_session_id,
  sas.session_stamp,
  sas.scope_label
FROM static_analysis_sessions sas
LEFT JOIN static_analysis_runs sar
  ON TRIM(BOTH FROM sar.session_stamp) = TRIM(BOTH FROM sas.session_stamp)
 AND COALESCE(TRIM(BOTH FROM sar.scope_label), '') = COALESCE(TRIM(BOTH FROM sas.scope_label), '')
WHERE sar.id IS NULL
ORDER BY sas.static_session_id DESC
LIMIT 50;

-- 3) Dynamic sessions referencing a missing static_analysis_runs.id
SELECT
  COUNT(*) AS dynamic_rows_dangling_static_run_id
FROM dynamic_sessions ds
LEFT JOIN static_analysis_runs sar ON sar.id = ds.static_run_id
WHERE ds.static_run_id IS NOT NULL
  AND sar.id IS NULL;

SELECT
  ds.dynamic_run_id,
  ds.package_name,
  ds.static_run_id
FROM dynamic_sessions ds
LEFT JOIN static_analysis_runs sar ON sar.id = ds.static_run_id
WHERE ds.static_run_id IS NOT NULL
  AND sar.id IS NULL
ORDER BY ds.dynamic_run_id DESC
LIMIT 50;

-- 4) Artifact registry: static numeric run_id with no SAR row (integrity view)
SELECT
  COUNT(*) AS artifact_rows_static_numeric_dangling
FROM v_artifact_registry_integrity ar
WHERE ar.run_type = 'static'
  AND ar.link_state = 'dangling_static_run';
