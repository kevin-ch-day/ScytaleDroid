-- =============================================================================
-- Session summary from static_analysis_runs (READ-ONLY preview pattern)
-- =============================================================================
-- Before joining child tables, classify FK columns using:
--   docs/maintenance/database_static_child_table_join_map.md
--   scripts/db/sql/audit_information_schema_static_relationships.sql
-- =============================================================================
-- Purpose: derive one row per (session_stamp, scope_label) for honest backfill
-- into static_analysis_sessions, or for operator review in phpMyAdmin.
--
-- This file is NOT executed by the Python CLI by default — run manually after
-- review. Do not treat disposition heuristics as product law without aligning
-- static_session_disposition_history when you change rules.
--
-- Schema notes (catalog drift):
--   * static_string_summary.session_stamp is VARCHAR(64) while
--     static_analysis_runs.session_stamp is VARCHAR(128). Long stamps can
--     truncate or fail joins unless widened in a future migration.
--   * static_permission_matrix / static_permission_risk_vnext: UNIQUE on
--     (run_id, permission_name) uses table default collation — keep aligned
--     with normalization_key work in the V2 permission redesign.
--
-- Disposition CASE order matters:
--   1) All FAILED + interrupt signals → interrupted_partial_session
--   2) All FAILED + persist_error      → broken_persist_error_session
--   3) All FAILED + missing_artifacts   → broken_missing_artifacts_session
--   4) Mixed COMPLETED + FAILED        → mixed_completed_failed_session
--   5) All COMPLETED + full-library    → completed_full_session
--   6) All COMPLETED (else)            → completed_profile_session
-- If a session is all-FAILED with both interrupts and persist_error, the
-- interrupt branch wins (rare); reorder if product prefers persist dominance.
--
-- session_status vs session_disposition: status is a coarse rollup; disposition
-- is the cleanup/Web-visibility driver — they may differ (e.g. INTERRUPTED vs
-- interrupted_partial_session).
-- =============================================================================

SELECT
    sar.session_stamp,
    COALESCE(sar.scope_label, '') AS scope_label,

    CASE
      WHEN SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) = COUNT(*) THEN 'COMPLETED'
      WHEN SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) > 0
       AND SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) > 0 THEN 'PARTIAL'
      WHEN SUM(CASE WHEN sar.abort_reason IN ('user_abort', 'SIGINT') OR sar.abort_signal = 'SIGINT' THEN 1 ELSE 0 END) > 0
       THEN 'INTERRUPTED'
      WHEN SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) = COUNT(*) THEN 'FAILED'
      ELSE 'UNKNOWN'
    END AS session_status,

    CASE
      WHEN SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) = COUNT(*)
       AND SUM(CASE WHEN sar.abort_reason IN ('user_abort', 'SIGINT') OR sar.abort_signal = 'SIGINT' THEN 1 ELSE 0 END) > 0
        THEN 'interrupted_partial_session'

      WHEN SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) = COUNT(*)
       AND SUM(CASE WHEN sar.abort_reason = 'persist_error' THEN 1 ELSE 0 END) > 0
        THEN 'broken_persist_error_session'

      WHEN SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) = COUNT(*)
       AND SUM(CASE WHEN sar.abort_reason = 'missing_required_artifacts' THEN 1 ELSE 0 END) > 0
        THEN 'broken_missing_artifacts_session'

      WHEN SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) > 0
       AND SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) > 0
        THEN 'mixed_completed_failed_session'

      WHEN SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) = COUNT(*)
       AND (
          sar.session_stamp LIKE '%all-full%'
          OR COALESCE(sar.scope_label, '') = 'All harvested apps'
        )
        THEN 'completed_full_session'

      WHEN SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) = COUNT(*)
        THEN 'completed_profile_session'

      ELSE 'unknown_needs_review'
    END AS session_disposition,

    COUNT(*) AS total_run_count,
    SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_run_count,
    SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) AS failed_run_count,
    SUM(CASE WHEN sar.abort_reason IN ('user_abort', 'SIGINT') OR sar.abort_signal = 'SIGINT' THEN 1 ELSE 0 END) AS interrupted_run_count,
    SUM(CASE WHEN sar.abort_reason = 'persist_error' THEN 1 ELSE 0 END) AS persist_error_run_count,
    SUM(CASE WHEN sar.abort_reason = 'missing_required_artifacts' THEN 1 ELSE 0 END) AS missing_artifacts_run_count,

    MIN(sar.created_at) AS first_created_at,
    MAX(sar.ended_at_utc) AS last_ended_at
FROM static_analysis_runs sar
WHERE sar.session_stamp IS NOT NULL
GROUP BY sar.session_stamp, COALESCE(sar.scope_label, '')
ORDER BY first_created_at DESC;


-- =============================================================================
-- Optional: extend preview with child row counts per session (still read-only)
-- =============================================================================
-- Uncomment and run separately if you need totals for static_analysis_sessions
-- aggregate columns (findings, matrix, risk, strings, links, rollups, spf).
/*
WITH sess AS (
  SELECT sar.session_stamp, COALESCE(sar.scope_label, '') AS scope_label
  FROM static_analysis_runs sar
  WHERE sar.session_stamp IS NOT NULL
  GROUP BY sar.session_stamp, COALESCE(sar.scope_label, '')
)
SELECT
  s.session_stamp,
  s.scope_label,
  (SELECT COUNT(*) FROM static_analysis_findings f
     JOIN static_analysis_runs r ON r.id = f.run_id
    WHERE r.session_stamp = s.session_stamp AND COALESCE(r.scope_label, '') = s.scope_label) AS total_findings_rows,
  (SELECT COUNT(*) FROM static_permission_matrix pm
     JOIN static_analysis_runs r ON r.id = pm.run_id
    WHERE r.session_stamp = s.session_stamp AND COALESCE(r.scope_label, '') = s.scope_label) AS total_permission_matrix_rows,
  (SELECT COUNT(*) FROM static_permission_risk_vnext pr
     JOIN static_analysis_runs r ON r.id = pr.run_id
    WHERE r.session_stamp = s.session_stamp AND COALESCE(r.scope_label, '') = s.scope_label) AS total_permission_risk_rows,
  (SELECT COUNT(*) FROM static_string_summary ss
    WHERE ss.session_stamp = s.session_stamp AND COALESCE(ss.scope_label, '') = s.scope_label) AS total_string_summary_rows,
  (SELECT COUNT(*) FROM static_string_samples samp
     JOIN static_string_summary ss ON ss.id = samp.summary_id
    WHERE ss.session_stamp = s.session_stamp AND COALESCE(ss.scope_label, '') = s.scope_label) AS total_string_sample_rows,
  (SELECT COUNT(*) FROM static_session_run_links l
    WHERE l.session_stamp = s.session_stamp) AS session_link_rows_hint,
  (SELECT COUNT(*) FROM static_session_rollups u
    WHERE u.session_stamp = s.session_stamp AND u.scope_label = s.scope_label) AS rollup_rows,
  (SELECT COUNT(*) FROM static_persistence_failures p
     JOIN static_analysis_runs r ON r.id = p.static_run_id
    WHERE r.session_stamp = s.session_stamp AND COALESCE(r.scope_label, '') = s.scope_label) AS persistence_failure_rows
FROM sess s
ORDER BY s.session_stamp DESC;
*/


-- =============================================================================
-- Optional: INSERT … ON DUPLICATE KEY UPDATE (COMMENTED — run only after review)
-- =============================================================================
-- Target: static_analysis_sessions natural key (session_stamp, scope_label).
-- Populate session_link_rows from static_session_run_links WHERE session_stamp
-- only (scope not stored on links — adjust if your policy differs).
/*
INSERT INTO static_analysis_sessions (
  session_stamp,
  scope_label,
  session_label,
  session_status,
  session_disposition,
  disposition_confidence,
  total_run_count,
  completed_run_count,
  failed_run_count,
  interrupted_run_count,
  persist_error_run_count,
  missing_artifacts_run_count,
  total_findings_rows,
  total_permission_matrix_rows,
  total_permission_risk_rows,
  total_string_summary_rows,
  total_string_sample_rows,
  session_link_rows,
  rollup_rows,
  persistence_failure_rows,
  first_created_at,
  last_ended_at
)
SELECT
  agg.session_stamp,
  agg.scope_label,
  NULL AS session_label,
  agg.session_status,
  agg.session_disposition,
  'medium' AS disposition_confidence,
  agg.total_run_count,
  agg.completed_run_count,
  agg.failed_run_count,
  agg.interrupted_run_count,
  agg.persist_error_run_count,
  agg.missing_artifacts_run_count,
  0, 0, 0, 0, 0, 0, 0, 0, 0,
  agg.first_created_at,
  agg.last_ended_at
FROM (
  /* Replace this subquery with the full grouped SELECT above, aliased columns
     to match agg.session_stamp, agg.scope_label, agg.session_status, … */
  SELECT
    CAST(NULL AS CHAR(128)) AS session_stamp,
    CAST('' AS CHAR(191)) AS scope_label,
    CAST('UNKNOWN' AS CHAR(32)) AS session_status,
    CAST('unknown_needs_review' AS CHAR(64)) AS session_disposition,
    0 AS total_run_count,
    0 AS completed_run_count,
    0 AS failed_run_count,
    0 AS interrupted_run_count,
    0 AS persist_error_run_count,
    0 AS missing_artifacts_run_count,
    CAST(NULL AS DATETIME) AS first_created_at,
    CAST(NULL AS DATETIME) AS last_ended_at
  WHERE 0
) AS agg
ON DUPLICATE KEY UPDATE
  session_status = VALUES(session_status),
  session_disposition = VALUES(session_disposition),
  total_run_count = VALUES(total_run_count),
  completed_run_count = VALUES(completed_run_count),
  failed_run_count = VALUES(failed_run_count),
  interrupted_run_count = VALUES(interrupted_run_count),
  persist_error_run_count = VALUES(persist_error_run_count),
  missing_artifacts_run_count = VALUES(missing_artifacts_run_count),
  first_created_at = VALUES(first_created_at),
  last_ended_at = VALUES(last_ended_at);
*/
