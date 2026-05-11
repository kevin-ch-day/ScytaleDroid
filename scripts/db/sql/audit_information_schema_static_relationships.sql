-- =============================================================================
-- A. Base-table relationship map (columns touching run / session / stamp)
-- =============================================================================
-- Run against your analyst catalog (USE scytaledroid_core_prod; etc.).
-- Output: every BASE TABLE column whose name matches run/session/stamp heuristics
-- or is in the explicit allowlist. Use to build a generated join map — do not
-- guess COALESCE(static_run_id, run_id) unless BOTH columns exist on that table.
--
-- See: docs/maintenance/database_static_child_table_join_map.md

SELECT
    c.TABLE_NAME,
    t.TABLE_TYPE,
    c.COLUMN_NAME,
    c.COLUMN_TYPE,
    c.IS_NULLABLE,
    c.COLUMN_KEY,
    c.COLLATION_NAME
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES t
  ON t.TABLE_SCHEMA = c.TABLE_SCHEMA
 AND t.TABLE_NAME = c.TABLE_NAME
WHERE c.TABLE_SCHEMA = DATABASE()
  AND t.TABLE_TYPE = 'BASE TABLE'
  AND (
      c.COLUMN_NAME IN (
          'id',
          'run_id',
          'static_run_id',
          'session_stamp',
          'session_label',
          'origin_session_stamp',
          'summary_id',
          'provider_id'
      )
      OR c.COLUMN_NAME LIKE '%session%'
      OR c.COLUMN_NAME LIKE '%run%'
      OR c.COLUMN_NAME LIKE '%stamp%'
  )
ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION;


-- =============================================================================
-- B. Distinct BASE TABLE names only (for targeted DESCRIBE)
-- =============================================================================

SELECT DISTINCT
    c.TABLE_NAME
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES t
  ON t.TABLE_SCHEMA = c.TABLE_SCHEMA
 AND t.TABLE_NAME = c.TABLE_NAME
WHERE c.TABLE_SCHEMA = DATABASE()
  AND t.TABLE_TYPE = 'BASE TABLE'
  AND (
      c.COLUMN_NAME IN (
          'run_id',
          'static_run_id',
          'session_stamp',
          'session_label',
          'origin_session_stamp',
          'summary_id',
          'provider_id'
      )
      OR c.COLUMN_NAME LIKE '%session%'
      OR c.COLUMN_NAME LIKE '%run%'
      OR c.COLUMN_NAME LIKE '%stamp%'
  )
ORDER BY c.TABLE_NAME;


-- =============================================================================
-- C. Static / permission / risk / legacy mirror inventory
-- =============================================================================

SELECT
    TABLE_NAME,
    TABLE_ROWS,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb,
    TABLE_COLLATION
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_TYPE = 'BASE TABLE'
  AND (
      TABLE_NAME LIKE 'static_%'
      OR TABLE_NAME LIKE 'permission_%'
      OR TABLE_NAME LIKE 'risk_%'
      OR TABLE_NAME IN (
          'artifact_registry',
          'runs',
          'findings',
          'metrics',
          'buckets',
          'contributors'
      )
  )
ORDER BY TABLE_NAME;


-- =============================================================================
-- D. Targeted DESCRIBE (run manually in client — one table at a time)
-- =============================================================================
-- DESCRIBE static_fileproviders;
-- DESCRIBE static_provider_acl;
-- DESCRIBE static_correlation_results;
-- DESCRIBE static_findings;
-- DESCRIBE static_findings_summary;
-- DESCRIBE permission_audit_apps;
-- DESCRIBE permission_audit_snapshots;
-- DESCRIBE permission_signal_observations;
-- DESCRIBE artifact_registry;
