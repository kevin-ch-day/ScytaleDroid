-- Schema posture checks for ScytaleDroid MariaDB/MySQL operational DB (read-only).
-- Example:
--   mariadb -u USER -p -D DATABASE < scripts/db/check_schema_posture.sql

-- 1) Web consumer names incorrectly materialized as BASE TABLE (naming-contract violation)
SELECT
  'violation_table_named_like_view' AS check_id,
  TABLE_NAME,
  TABLE_TYPE,
  TABLE_ROWS AS approx_rows
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND (TABLE_NAME LIKE 'v\_web\_%' ESCAPE '\' OR TABLE_NAME LIKE 'vw\_%' ESCAPE '\')
  AND TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_NAME;

-- 2) Expected web views missing or wrong type
SELECT
  'missing_or_non_view_object' AS check_id,
  e.expected_name AS object_name,
  COALESCE(t.TABLE_TYPE, 'MISSING') AS actual_table_type
FROM (
  SELECT 'v_web_app_directory' AS expected_name
  UNION ALL SELECT 'vw_static_finding_surfaces_latest'
  UNION ALL SELECT 'vw_static_risk_surfaces_latest'
  UNION ALL SELECT 'v_web_app_sessions'
  UNION ALL SELECT 'v_web_app_findings'
  UNION ALL SELECT 'v_web_permission_intel_current'
) e
LEFT JOIN information_schema.TABLES t
  ON t.TABLE_SCHEMA = DATABASE()
 AND t.TABLE_NAME = e.expected_name
WHERE t.TABLE_NAME IS NULL OR t.TABLE_TYPE <> 'VIEW';

-- 3) Charset snapshot: non-utf8mb4 text columns on common join hotspots
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
    'static_analysis_findings'
  )
  AND DATA_TYPE IN ('varchar', 'char', 'text', 'tinytext', 'mediumtext', 'longtext')
  AND CHARACTER_SET_NAME IS NOT NULL
  AND CHARACTER_SET_NAME <> 'utf8mb4'
ORDER BY TABLE_NAME, COLUMN_NAME;
