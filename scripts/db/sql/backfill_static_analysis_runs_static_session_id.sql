-- ============================================================================
-- Backfill static_analysis_runs.static_session_id from static_analysis_sessions
-- ============================================================================
-- Natural key: (session_stamp, scope_label) on static_analysis_sessions matching
--   sar.session_stamp
--   sas.scope_label = COALESCE(TRIM(BOTH FROM sar.scope_label), '')
--
-- Idempotent: safe to run more than once (only NULL sar.static_session_id rows
-- are updated). No FK on static_session_id yet — validate counts using
-- verify_static_session_id_rollout.sql or scripts/db/verify_static_session_id_rollout.py.
--
-- Optional: wrap in START TRANSACTION / COMMIT in your client if you want a
-- single review step before commit.
-- ============================================================================

UPDATE static_analysis_runs sar
INNER JOIN static_analysis_sessions sas
  ON sas.session_stamp = sar.session_stamp
 AND sas.scope_label = COALESCE(TRIM(BOTH FROM sar.scope_label), '')
SET sar.static_session_id = sas.static_session_id
WHERE sar.static_session_id IS NULL
  AND sar.session_stamp IS NOT NULL
  AND LENGTH(TRIM(BOTH FROM sar.session_stamp)) > 0;
