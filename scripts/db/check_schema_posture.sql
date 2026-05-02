-- Schema posture checks for ScytaleDroid MariaDB/MySQL operational DB (read-only).
-- Example:
--   mariadb -u USER -p -D DATABASE < scripts/db/check_schema_posture.sql
--
-- Keep in rough sync with scripts/db/view_repair_support.py EXPECTED_VIEW_OBJECTS
-- and scytaledroid/Database/db_utils/health_checks/analysis_integrity.py.

-- 1) Naming contract: v_* / vw_* must not be materialized as BASE TABLE
SELECT
  'violation_table_named_like_view' AS check_id,
  TABLE_NAME,
  TABLE_TYPE,
  TABLE_ROWS AS approx_rows
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_TYPE = 'BASE TABLE'
  AND (
    TABLE_NAME REGEXP '^v_.*'
    OR TABLE_NAME REGEXP '^vw_.*'
  )
ORDER BY TABLE_NAME;

-- 2) Expected analytic VIEW names (must exist as TABLE_TYPE = VIEW)
SELECT
  'missing_or_non_view_object' AS check_id,
  e.expected_name AS object_name,
  COALESCE(t.TABLE_TYPE, 'MISSING') AS actual_table_type
FROM (
  SELECT 'v_provider_exposure' AS expected_name
  UNION ALL SELECT 'v_session_string_samples'
  UNION ALL SELECT 'v_static_run_category_summary'
  UNION ALL SELECT 'v_runtime_dynamic_cohort_status_v1'
  UNION ALL SELECT 'v_paper_dynamic_cohort_v1'
  UNION ALL SELECT 'v_run_overview'
  UNION ALL SELECT 'v_run_identity'
  UNION ALL SELECT 'v_static_handoff_v1'
  UNION ALL SELECT 'v_static_masvs_findings_v1'
  UNION ALL SELECT 'v_static_masvs_matrix_v1'
  UNION ALL SELECT 'v_static_masvs_session_summary_v1'
  UNION ALL SELECT 'v_static_risk_surfaces_v1'
  UNION ALL SELECT 'v_masvs_matrix'
  UNION ALL SELECT 'v_web_app_directory'
  UNION ALL SELECT 'v_web_static_dynamic_app_summary'
  UNION ALL SELECT 'v_web_runtime_run_index'
  UNION ALL SELECT 'v_web_runtime_run_detail'
  UNION ALL SELECT 'v_artifact_registry_integrity'
  UNION ALL SELECT 'v_current_artifact_registry'
  UNION ALL SELECT 'vw_latest_apk_per_package'
  UNION ALL SELECT 'vw_latest_permission_risk'
  UNION ALL SELECT 'vw_permission_audit_latest'
  UNION ALL SELECT 'vw_static_risk_surfaces_latest'
  UNION ALL SELECT 'vw_static_finding_surfaces_latest'
  UNION ALL SELECT 'v_web_app_sessions'
  UNION ALL SELECT 'v_web_app_findings'
  UNION ALL SELECT 'v_web_app_permissions'
  UNION ALL SELECT 'v_web_permission_intel_current'
  UNION ALL SELECT 'v_web_static_session_health'
) e
LEFT JOIN information_schema.TABLES t
  ON t.TABLE_SCHEMA = DATABASE()
 AND t.TABLE_NAME = e.expected_name
WHERE t.TABLE_NAME IS NULL OR t.TABLE_TYPE <> 'VIEW';

-- 3) analysis_dynamic_cohort_status must be a BASE TABLE (not a VIEW stub)
SELECT
  'analysis_dynamic_cohort_status_wrong_type' AS check_id,
  t.TABLE_NAME AS object_name,
  t.TABLE_TYPE AS actual_table_type
FROM information_schema.TABLES t
WHERE t.TABLE_SCHEMA = DATABASE()
  AND t.TABLE_NAME = 'analysis_dynamic_cohort_status'
  AND t.TABLE_TYPE <> 'BASE TABLE';

SELECT
  'analysis_dynamic_cohort_status_missing' AS check_id,
  'analysis_dynamic_cohort_status' AS object_name,
  'MISSING' AS actual_table_type
WHERE NOT EXISTS (
  SELECT 1
  FROM information_schema.TABLES t
  WHERE t.TABLE_SCHEMA = DATABASE()
    AND t.TABLE_NAME = 'analysis_dynamic_cohort_status'
);

-- 4) Charset snapshot: non-utf8mb4 text columns on common join hotspots
SELECT
  'non_utf8mb4_text_column' AS check_id,
  TABLE_NAME,
  COLUMN_NAME,
  CHARACTER_SET_NAME,
  COLLATION_NAME
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN (
    'apps',
    'static_fileproviders',
    'static_provider_acl',
    'dynamic_sessions',
    'static_analysis_findings',
    'risk_scores',
    'static_permission_matrix'
  )
  AND DATA_TYPE IN ('varchar', 'char', 'text', 'tinytext', 'mediumtext', 'longtext')
  AND CHARACTER_SET_NAME IS NOT NULL
  AND CHARACTER_SET_NAME <> 'utf8mb4'
ORDER BY TABLE_NAME, COLUMN_NAME;
