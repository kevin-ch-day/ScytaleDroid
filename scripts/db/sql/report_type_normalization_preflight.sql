-- Phase A type-normalization preflight companion queries.

SELECT
  COUNT(*) AS total_dynamic_registry_rows,
  SUM(CASE WHEN dynamic_run_id IS NULL OR TRIM(dynamic_run_id) = '' THEN 1 ELSE 0 END) AS blank_dynamic_run_id_rows,
  SUM(CASE WHEN CHAR_LENGTH(dynamic_run_id) = 36 THEN 1 ELSE 0 END) AS dynamic_run_id_len36_rows,
  SUM(CASE WHEN dynamic_run_id REGEXP '^[0-9a-fA-F-]{36}$' THEN 1 ELSE 0 END) AS uuid_like_dynamic_run_id_rows
FROM artifact_registry
WHERE run_type = 'dynamic';

SELECT
  COUNT(*) AS dynamic_sessions_static_run_id_nonnull_rows,
  SUM(CASE WHEN sar.id IS NULL THEN 1 ELSE 0 END) AS dynamic_sessions_static_run_id_orphan_rows
FROM dynamic_sessions ds
LEFT JOIN static_analysis_runs sar
  ON sar.id = CAST(ds.static_run_id AS UNSIGNED)
WHERE ds.static_run_id IS NOT NULL;

SELECT
  COUNT(*) AS total_static_runs,
  SUM(CASE WHEN run_started_utc IS NULL OR TRIM(run_started_utc) = '' THEN 1 ELSE 0 END) AS blank_run_started_rows,
  SUM(CASE WHEN
      STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f') IS NOT NULL
      OR STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s') IS NOT NULL
    THEN 1 ELSE 0 END) AS parseable_run_started_rows,
  SUM(CASE WHEN
      run_started_utc IS NOT NULL AND TRIM(run_started_utc) <> ''
      AND STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f') IS NULL
      AND STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s') IS NULL
    THEN 1 ELSE 0 END) AS unparseable_run_started_rows
FROM static_analysis_runs;
