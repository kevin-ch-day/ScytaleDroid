-- =============================================================================
-- Static session header integrity audit (READ-ONLY)
-- =============================================================================
-- Purpose:
--   Diagnose static_analysis_sessions header drift against authoritative child
--   tables without mislabeling interrupted all-FAILED sessions as linkage bugs.
--
-- Important identity rules:
--   * static_analysis_runs primary key is `id` (not `static_run_id`)
--   * static_session_run_links.static_run_id -> static_analysis_runs.id
--   * static_session_rollups are session/scope aggregates, not one row per run
--
-- Operational interpretation:
--   * IN_PROGRESS shells can legitimately have started rows, zero links, and
--     zero rollups until package finalization catches up.
--   * INTERRUPTED / all-FAILED sessions can legitimately have zero links and
--     zero rollups if nothing completed.
--   * Missing links are only a defect when completed run rows exist.
-- =============================================================================

SELECT
  s.session_stamp,
  s.scope_label,
  s.session_status,
  s.session_disposition,
  COALESCE(s.total_run_count, 0) AS header_total_run_count,
  COALESCE(s.session_link_rows, 0) AS header_session_link_rows,
  COALESCE(s.rollup_rows, 0) AS header_rollup_rows,
  COALESCE(r.actual_run_rows, 0) AS actual_run_rows,
  COALESCE(r.completed_rows, 0) AS completed_rows,
  COALESCE(r.started_rows, 0) AS started_rows,
  COALESCE(r.failed_rows, 0) AS failed_rows,
  COALESCE(l.actual_link_rows, 0) AS actual_link_rows,
  COALESCE(ro.actual_rollup_rows, 0) AS actual_rollup_rows,
  CASE
    WHEN COALESCE(r.started_rows, 0) > 0
      AND COALESCE(r.completed_rows, 0) = 0
      AND COALESCE(l.actual_link_rows, 0) = 0
      AND COALESCE(s.total_run_count, 0) < COALESCE(r.actual_run_rows, 0)
      THEN 'in_progress_shell_unrefreshed'
    WHEN COALESCE(s.total_run_count, 0) <> COALESCE(r.actual_run_rows, 0)
      THEN 'run_count_mismatch'
    WHEN COALESCE(r.completed_rows, 0) > 0
      AND COALESCE(l.actual_link_rows, 0) = 0
      THEN 'missing_links_for_completed_runs'
    WHEN COALESCE(r.completed_rows, 0) = COALESCE(r.actual_run_rows, 0)
      AND COALESCE(r.actual_run_rows, 0) > 0
      AND COALESCE(ro.actual_rollup_rows, 0) = 0
      THEN 'missing_rollup_for_completed_session'
    WHEN COALESCE(r.completed_rows, 0) = COALESCE(r.actual_run_rows, 0)
      AND COALESCE(r.actual_run_rows, 0) > 0
      AND COALESCE(ro.actual_rollup_rows, 0) > 0
      AND COALESCE(s.rollup_rows, 0) <> COALESCE(ro.actual_rollup_rows, 0)
      THEN 'completed_header_stale'
    WHEN COALESCE(s.session_link_rows, 0) <> COALESCE(l.actual_link_rows, 0)
      THEN 'link_count_mismatch'
    ELSE 'healthy'
  END AS diagnostic_status
FROM static_analysis_sessions s
LEFT JOIN (
  SELECT
    sar.session_stamp,
    COALESCE(TRIM(BOTH FROM sar.scope_label), '') AS scope_label,
    COUNT(*) AS actual_run_rows,
    SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_rows,
    SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) IN ('STARTED', 'RUNNING') THEN 1 ELSE 0 END) AS started_rows,
    SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'FAILED' THEN 1 ELSE 0 END) AS failed_rows
  FROM static_analysis_runs sar
  GROUP BY sar.session_stamp, COALESCE(TRIM(BOTH FROM sar.scope_label), '')
) r
  ON r.session_stamp = s.session_stamp
 AND r.scope_label = COALESCE(TRIM(BOTH FROM s.scope_label), '')
LEFT JOIN (
  SELECT session_stamp, COUNT(*) AS actual_link_rows
  FROM static_session_run_links
  GROUP BY session_stamp
) l
  ON l.session_stamp = s.session_stamp
LEFT JOIN (
  SELECT
    session_stamp,
    COALESCE(TRIM(BOTH FROM scope_label), '') AS scope_label,
    COUNT(*) AS actual_rollup_rows
  FROM static_session_rollups
  GROUP BY session_stamp, COALESCE(TRIM(BOTH FROM scope_label), '')
) ro
  ON ro.session_stamp = s.session_stamp
 AND ro.scope_label = COALESCE(TRIM(BOTH FROM s.scope_label), '')
ORDER BY diagnostic_status DESC, s.session_stamp DESC, s.scope_label ASC;


-- =============================================================================
-- Focus one session_stamp / scope_label (edit literals before running)
-- =============================================================================
-- This version is useful in phpMyAdmin or MariaDB CLI when validating one live
-- session while a static run is still progressing.

SELECT
  s.session_stamp,
  s.scope_label,
  s.session_status,
  s.session_disposition,
  s.total_run_count,
  s.session_link_rows,
  s.rollup_rows,
  COALESCE(r.actual_run_rows, 0) AS actual_run_rows,
  COALESCE(r.completed_rows, 0) AS completed_rows,
  COALESCE(r.started_rows, 0) AS started_rows,
  COALESCE(r.failed_rows, 0) AS failed_rows,
  COALESCE(l.actual_link_rows, 0) AS actual_link_rows,
  COALESCE(ro.actual_rollup_rows, 0) AS actual_rollup_rows
FROM static_analysis_sessions s
LEFT JOIN (
  SELECT
    sar.session_stamp,
    COALESCE(TRIM(BOTH FROM sar.scope_label), '') AS scope_label,
    COUNT(*) AS actual_run_rows,
    SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_rows,
    SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) IN ('STARTED', 'RUNNING') THEN 1 ELSE 0 END) AS started_rows,
    SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'FAILED' THEN 1 ELSE 0 END) AS failed_rows
  FROM static_analysis_runs sar
  GROUP BY sar.session_stamp, COALESCE(TRIM(BOTH FROM sar.scope_label), '')
) r
  ON r.session_stamp = s.session_stamp
 AND r.scope_label = COALESCE(TRIM(BOTH FROM s.scope_label), '')
LEFT JOIN (
  SELECT session_stamp, COUNT(*) AS actual_link_rows
  FROM static_session_run_links
  GROUP BY session_stamp
) l
  ON l.session_stamp = s.session_stamp
LEFT JOIN (
  SELECT
    session_stamp,
    COALESCE(TRIM(BOTH FROM scope_label), '') AS scope_label,
    COUNT(*) AS actual_rollup_rows
  FROM static_session_rollups
  GROUP BY session_stamp, COALESCE(TRIM(BOTH FROM scope_label), '')
) ro
  ON ro.session_stamp = s.session_stamp
 AND ro.scope_label = COALESCE(TRIM(BOTH FROM s.scope_label), '')
WHERE s.session_stamp = '20260613-all-full'
  AND COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps';
