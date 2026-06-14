-- =============================================================================
-- artifact_registry typed linkage audit (READ-ONLY)
-- =============================================================================
-- Purpose:
--   Compare legacy polymorphic run_id linkage with typed-linkage-preferring
--   joins during and after the migration.
--
-- This file performs no UPDATE/DELETE/DDL.
-- =============================================================================

-- Overall table size and rows by run_type.
SELECT COUNT(*) AS total_artifact_registry_rows
FROM artifact_registry;

SELECT run_type, COUNT(*) AS row_count
FROM artifact_registry
GROUP BY run_type
ORDER BY run_type;

-- Migration posture.
SELECT COUNT(*) AS migrated_static_rows
FROM artifact_registry
WHERE run_type = 'static'
  AND static_run_id IS NOT NULL;

SELECT COUNT(*) AS migrated_dynamic_rows
FROM artifact_registry
WHERE run_type = 'dynamic'
  AND dynamic_run_id IS NOT NULL
  AND TRIM(dynamic_run_id) <> '';

SELECT COUNT(*) AS malformed_static_run_id_rows
FROM artifact_registry
WHERE run_type = 'static'
  AND static_run_id IS NULL
  AND NOT run_id REGEXP '^[0-9]+$';

SELECT COUNT(*) AS dangling_static_run_id_rows
FROM artifact_registry ar
LEFT JOIN static_analysis_runs sar
  ON sar.id = ar.static_run_id
WHERE ar.run_type = 'static'
  AND ar.static_run_id IS NOT NULL
  AND sar.id IS NULL;

SELECT COUNT(*) AS dangling_dynamic_run_id_rows
FROM artifact_registry ar
LEFT JOIN dynamic_sessions ds
  ON ds.dynamic_run_id = ar.dynamic_run_id
WHERE ar.run_type = 'dynamic'
  AND ar.dynamic_run_id IS NOT NULL
  AND TRIM(ar.dynamic_run_id) <> ''
  AND ds.dynamic_run_id IS NULL;

SELECT COUNT(*) AS fallback_needed_rows
FROM artifact_registry
WHERE (run_type = 'static' AND static_run_id IS NULL AND run_id REGEXP '^[0-9]+$')
   OR (run_type = 'dynamic' AND (dynamic_run_id IS NULL OR TRIM(dynamic_run_id) = '') AND TRIM(COALESCE(run_id, '')) <> '');


-- Legacy integrity logic (pre-migration semantics).
SELECT
  ar.run_type,
  CASE
    WHEN ar.run_type = 'dynamic' AND ds.dynamic_run_id IS NOT NULL THEN 'linked'
    WHEN ar.run_type = 'dynamic' THEN 'dangling_dynamic_run'
    WHEN ar.run_type = 'static' AND ar.run_id REGEXP '^[0-9]+$' AND sar.id IS NOT NULL THEN 'linked'
    WHEN ar.run_type = 'static' THEN 'dangling_static_run'
    ELSE 'unknown_run_type'
  END AS link_state,
  COUNT(*) AS row_count
FROM artifact_registry ar
LEFT JOIN dynamic_sessions ds
  ON ar.run_type = 'dynamic'
 AND ds.dynamic_run_id = ar.run_id
LEFT JOIN static_analysis_runs sar
  ON ar.run_type = 'static'
 AND ar.run_id REGEXP '^[0-9]+$'
 AND sar.id = CAST(ar.run_id AS UNSIGNED)
GROUP BY ar.run_type, link_state
ORDER BY ar.run_type, link_state;


-- Typed-linkage-preferring integrity logic with legacy fallback only for
-- unmigrated rows.
SELECT
  ar.run_type,
  CASE
    WHEN ar.run_type = 'dynamic'
     AND (ds_typed.dynamic_run_id IS NOT NULL OR ds_legacy.dynamic_run_id IS NOT NULL)
      THEN 'linked'
    WHEN ar.run_type = 'dynamic' THEN 'dangling_dynamic_run'
    WHEN ar.run_type = 'static'
     AND (sar_typed.id IS NOT NULL OR sar_legacy.id IS NOT NULL)
      THEN 'linked'
    WHEN ar.run_type = 'static' THEN 'dangling_static_run'
    ELSE 'unknown_run_type'
  END AS link_state,
  COUNT(*) AS row_count
FROM artifact_registry ar
LEFT JOIN dynamic_sessions ds_typed
  ON ar.run_type = 'dynamic'
 AND ar.dynamic_run_id IS NOT NULL
 AND ds_typed.dynamic_run_id = ar.dynamic_run_id
LEFT JOIN dynamic_sessions ds_legacy
  ON ar.run_type = 'dynamic'
 AND ar.dynamic_run_id IS NULL
 AND TRIM(COALESCE(ar.run_id, '')) <> ''
 AND ds_legacy.dynamic_run_id = ar.run_id
LEFT JOIN static_analysis_runs sar_typed
  ON ar.run_type = 'static'
 AND ar.static_run_id IS NOT NULL
 AND sar_typed.id = ar.static_run_id
LEFT JOIN static_analysis_runs sar_legacy
  ON ar.run_type = 'static'
 AND ar.static_run_id IS NULL
 AND ar.run_id REGEXP '^[0-9]+$'
 AND sar_legacy.id = CAST(ar.run_id AS UNSIGNED)
GROUP BY ar.run_type, link_state
ORDER BY ar.run_type, link_state;
