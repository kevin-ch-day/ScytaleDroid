-- Deep DB exploration workbench (READ-ONLY)
-- Scope: current schema-governance / typed-linkage / static-session cleanup checkpoint.
-- Safe: SELECTs only. No DDL, DML, temp tables, or side effects.
--
-- Suggested use:
--   mariadb scytaledroid_core_prod < scripts/db/sql/deep_db_exploration_20260614.sql
--
-- Notes:
-- - information_schema.tables.TABLE_ROWS is often an engine estimate, not an exact COUNT(*).
-- - Prefer exact COUNT(*) for critical backlog/retention/debt metrics.

SELECT 'schema_migrations_recent' AS section;
SELECT
  migration_id,
  status,
  schema_version_before,
  schema_version_after,
  applied_at_utc,
  LEFT(COALESCE(notes, ''), 160) AS notes_prefix
FROM schema_migrations
ORDER BY applied_at_utc DESC, migration_id DESC
LIMIT 20;

SELECT 'largest_base_tables_estimate' AS section;
SELECT
  table_name,
  table_rows,
  ROUND((data_length + index_length) / 1024 / 1024, 2) AS size_mb
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_type = 'BASE TABLE'
ORDER BY table_rows DESC, table_name
LIMIT 25;

SELECT 'session_stamp_contract' AS section;
SELECT
  table_name,
  column_type,
  collation_name
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND column_name = 'session_stamp'
ORDER BY table_name;

SELECT 'typed_linkage_coverage_artifact_registry' AS section;
SELECT
  COUNT(*) AS total_rows,
  SUM(CASE WHEN run_type = 'dynamic' THEN 1 ELSE 0 END) AS dynamic_rows,
  SUM(CASE WHEN run_type = 'static' THEN 1 ELSE 0 END) AS static_rows,
  SUM(CASE WHEN run_type = 'dynamic' AND dynamic_run_uuid IS NOT NULL AND TRIM(dynamic_run_uuid) <> '' THEN 1 ELSE 0 END) AS typed_dynamic_uuid_rows,
  SUM(CASE WHEN run_type = 'dynamic' AND (dynamic_run_id IS NULL OR TRIM(dynamic_run_id) = '') THEN 1 ELSE 0 END) AS dynamic_fallback_rows,
  SUM(CASE WHEN run_type = 'static' AND static_run_id IS NOT NULL THEN 1 ELSE 0 END) AS typed_static_rows,
  SUM(CASE WHEN run_type = 'static' AND static_run_id IS NULL AND run_id REGEXP '^[0-9]+$' THEN 1 ELSE 0 END) AS static_fallback_rows
FROM artifact_registry;

SELECT 'typed_linkage_coverage_dynamic_sessions' AS section;
SELECT
  COUNT(*) AS total_dynamic_sessions,
  SUM(CASE WHEN static_run_id_u IS NOT NULL THEN 1 ELSE 0 END) AS typed_static_run_id_u_rows,
  SUM(CASE WHEN static_run_id IS NOT NULL THEN 1 ELSE 0 END) AS legacy_static_run_id_rows,
  SUM(CASE WHEN static_run_id_u IS NOT NULL AND static_run_id IS NOT NULL THEN 1 ELSE 0 END) AS both_rows
FROM dynamic_sessions;

SELECT 'typed_timestamp_coverage_static_runs' AS section;
SELECT
  COUNT(*) AS total_static_runs,
  SUM(CASE WHEN run_started_at_utc IS NOT NULL THEN 1 ELSE 0 END) AS typed_started_rows,
  SUM(CASE WHEN run_started_utc IS NOT NULL AND TRIM(run_started_utc) <> '' THEN 1 ELSE 0 END) AS legacy_started_rows,
  SUM(CASE WHEN run_started_at_utc IS NOT NULL AND run_started_utc IS NOT NULL AND TRIM(run_started_utc) <> '' THEN 1 ELSE 0 END) AS both_rows
FROM static_analysis_runs;

SELECT 'static_run_status_distribution' AS section;
SELECT
  COALESCE(status, '(null)') AS status,
  COUNT(*) AS row_count
FROM static_analysis_runs
GROUP BY status
ORDER BY row_count DESC, status;

SELECT 'dynamic_session_status_distribution' AS section;
SELECT
  COALESCE(status, '(null)') AS status,
  COUNT(*) AS row_count
FROM dynamic_sessions
GROUP BY status
ORDER BY row_count DESC, status;

SELECT 'web_session_usability_distribution' AS section;
SELECT
  COALESCE(session_usability, '(null)') AS session_usability,
  COUNT(*) AS row_count
FROM v_web_app_sessions
GROUP BY session_usability
ORDER BY row_count DESC, session_usability;

SELECT 'legacy_static_mirror_footprint' AS section;
SELECT 'runs' AS table_name, COUNT(*) AS row_count FROM runs
UNION ALL
SELECT 'metrics', COUNT(*) FROM metrics
UNION ALL
SELECT 'findings', COUNT(*) FROM findings
UNION ALL
SELECT 'contributors', COUNT(*) FROM contributors
UNION ALL
SELECT 'buckets', COUNT(*) FROM buckets
ORDER BY row_count DESC, table_name;

SELECT 'static_dangling_registry_profile' AS section;
SELECT
  MIN(created_at_utc) AS oldest_created_at_utc,
  MAX(created_at_utc) AS newest_created_at_utc,
  COUNT(*) AS dangling_rows,
  COUNT(DISTINCT run_id) AS distinct_legacy_run_ids,
  COUNT(DISTINCT COALESCE(origin, '')) AS distinct_origins,
  COUNT(DISTINCT COALESCE(artifact_type, '')) AS distinct_artifact_types
FROM v_artifact_registry_integrity
WHERE run_type = 'static'
  AND link_state = 'dangling_static_run';

SELECT 'static_dangling_registry_top_origin_artifact_pairs' AS section;
SELECT
  COALESCE(origin, '(null)') AS origin,
  COALESCE(artifact_type, '(null)') AS artifact_type,
  COUNT(*) AS row_count
FROM v_artifact_registry_integrity
WHERE run_type = 'static'
  AND link_state = 'dangling_static_run'
GROUP BY origin, artifact_type
ORDER BY row_count DESC, origin, artifact_type
LIMIT 20;

SELECT 'dynamic_static_linked_samples' AS section;
SELECT
  ds.dynamic_run_id,
  ds.package_name,
  ds.static_run_id_u,
  ds.started_at_utc,
  ds.status
FROM dynamic_sessions ds
WHERE ds.static_run_id_u IS NOT NULL
ORDER BY ds.started_at_utc DESC
LIMIT 20;

SELECT 'referenced_app_versions_missing_sdk_metadata' AS section;
SELECT
  a.package_name,
  av.id AS app_version_id,
  av.version_name,
  av.version_code,
  av.min_sdk,
  av.target_sdk,
  COUNT(*) AS static_run_count
FROM static_analysis_runs sar
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id
WHERE av.min_sdk IS NULL
   OR av.target_sdk IS NULL
GROUP BY a.package_name, av.id, av.version_name, av.version_code, av.min_sdk, av.target_sdk
ORDER BY static_run_count DESC, a.package_name
LIMIT 25;

SELECT 'string_timestamp_surfaces' AS section;
SELECT
  table_name,
  column_name,
  column_type,
  data_type
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND (column_name LIKE '%_utc' OR column_name LIKE '%_at' OR column_name LIKE '%timestamp%')
  AND data_type IN ('varchar', 'text', 'char')
ORDER BY table_name, column_name;

SELECT 'json_longtext_signal_columns' AS section;
SELECT
  table_name,
  column_name,
  column_type,
  data_type,
  collation_name
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND (
    data_type = 'json'
    OR column_name LIKE '%_json'
    OR column_name IN ('meta_json', 'details_json', 'identity_start_json', 'identity_end_json', 'identity_gate_json')
  )
ORDER BY table_name, column_name;

SELECT 'status_domain_columns' AS section;
SELECT
  table_name,
  column_name,
  data_type,
  column_type
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND column_name IN (
    'status',
    'run_status',
    'session_usability',
    'link_state',
    'linkage_migration_status',
    'identity_check_status'
  )
ORDER BY table_name, column_name;

SELECT 'constraint_inventory_counts' AS section;
SELECT
  constraint_type,
  COUNT(*) AS row_count
FROM information_schema.table_constraints
WHERE constraint_schema = DATABASE()
GROUP BY constraint_type
ORDER BY row_count DESC, constraint_type;

SELECT 'check_constraint_inventory' AS section;
SELECT
  tc.table_name,
  tc.constraint_name,
  cc.check_clause
FROM information_schema.table_constraints tc
JOIN information_schema.check_constraints cc
  ON cc.constraint_schema = tc.constraint_schema
 AND cc.constraint_name = tc.constraint_name
WHERE tc.constraint_schema = DATABASE()
  AND tc.constraint_type = 'CHECK'
ORDER BY tc.table_name, tc.constraint_name;
