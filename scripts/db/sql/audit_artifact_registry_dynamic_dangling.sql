-- Read-only companion queries for dangling dynamic artifact_registry rows.
-- Primary workflow: scripts/db/report_artifact_registry_dynamic_dangling.py

-- 1) Discover dynamic-adjacent tables and linkage columns.
SELECT table_name, column_name, column_type
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND (
    table_name LIKE 'dynamic\_%'
    OR table_name IN ('analysis_cohort_runs', 'analysis_dynamic_cohort_status', 'ml_feature_windows', 'ml_scores')
  )
ORDER BY table_name, ordinal_position;

-- 2) Baseline linked vs dangling counts for dynamic registry rows.
SELECT
  SUM(CASE WHEN run_type = 'dynamic' AND link_state = 'linked' THEN 1 ELSE 0 END) AS linked_dynamic_registry_rows,
  SUM(CASE WHEN run_type = 'dynamic' AND link_state = 'dangling_dynamic_run' THEN 1 ELSE 0 END) AS dangling_dynamic_registry_rows
FROM v_artifact_registry_integrity;

-- 3) DB-only linkage posture for dangling rows (filesystem checks are done in the Python audit).
SELECT
  COUNT(*) AS dangling_dynamic_registry_rows,
  SUM(CASE WHEN ds.dynamic_run_id IS NULL THEN 1 ELSE 0 END) AS missing_dynamic_session,
  SUM(
    CASE
      WHEN acr.dynamic_run_id IS NOT NULL
        OR adcs.dynamic_run_id IS NOT NULL
        OR dnf.dynamic_run_id IS NOT NULL
        OR dni.dynamic_run_id IS NOT NULL
        OR dsi.dynamic_run_id IS NOT NULL
        OR dtn.dynamic_run_id IS NOT NULL
        OR dtp.dynamic_run_id IS NOT NULL
        OR mfw.run_id IS NOT NULL
        OR mls.run_id IS NOT NULL
      THEN 1 ELSE 0
    END
  ) AS dangling_rows_with_non_session_db_references
FROM v_artifact_registry_integrity v
LEFT JOIN dynamic_sessions ds
  ON ds.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN analysis_cohort_runs acr
  ON acr.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN analysis_dynamic_cohort_status adcs
  ON adcs.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN dynamic_network_features dnf
  ON dnf.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN dynamic_network_indicators dni
  ON dni.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN dynamic_session_issues dsi
  ON dsi.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN dynamic_telemetry_network dtn
  ON dtn.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN dynamic_telemetry_process dtp
  ON dtp.dynamic_run_id = v.resolved_dynamic_run_id
LEFT JOIN ml_feature_windows mfw
  ON mfw.run_type = 'dynamic'
 AND mfw.run_id = v.resolved_dynamic_run_id
LEFT JOIN ml_scores mls
  ON mls.run_type = 'dynamic'
 AND mls.run_id = v.resolved_dynamic_run_id
WHERE v.run_type = 'dynamic'
  AND v.link_state = 'dangling_dynamic_run';

-- 4) Top dangling run_ids and age ranges.
SELECT
  run_id,
  COUNT(*) AS row_count,
  MIN(created_at_utc) AS created_min_utc,
  MAX(created_at_utc) AS created_max_utc
FROM v_artifact_registry_integrity
WHERE run_type = 'dynamic'
  AND link_state = 'dangling_dynamic_run'
GROUP BY run_id
ORDER BY row_count DESC, run_id;
