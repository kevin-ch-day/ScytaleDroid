"""SQL VIEW definitions for static session health and Web-facing session pickers (v2).

Repo-owned replacements for hand-maintained ``SHOW CREATE VIEW`` strings.  Eligibility
columns follow the stricter ``web_default_eligible`` contract (public completed sessions
only, no failed/interrupted/persist counters, no persistence-failure rows, smoke/test
fingerprints excluded, and rollup / link requirements split by full-library intent)."""

from __future__ import annotations

CREATE_V_STATIC_SESSION_HEALTH_V2 = """
CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_health_v2 AS
SELECT
  s.static_session_id,
  s.session_stamp,
  s.scope_label,
  s.session_label,
  s.session_status,
  s.session_disposition,
  s.disposition_confidence,
  s.total_run_count,
  s.completed_run_count,
  s.failed_run_count,
  s.interrupted_run_count,
  s.persist_error_run_count,
  s.missing_artifacts_run_count,
  s.total_findings_rows,
  s.total_permission_matrix_rows,
  s.total_permission_risk_rows,
  s.total_string_summary_rows,
  s.total_string_sample_rows,
  s.session_link_rows,
  s.rollup_rows,
  s.persistence_failure_rows,
  s.expected_package_count,
  s.reconciled_package_count,
  s.completion_reconciliation_status,
  s.selection_artifact_manifest_sha256,
  s.completion_reconciled_at_utc,
  s.web_visibility_default,
  s.cleanup_status,
  s.superseded_by_session_id,
  CASE
    WHEN COALESCE(s.web_visibility_default, '') <> 'public' THEN 0
    WHEN COALESCE(s.session_status, '') <> 'COMPLETED' THEN 0
    WHEN s.session_disposition NOT IN ('completed_full_session', 'completed_profile_session') THEN 0
    WHEN COALESCE(s.failed_run_count, 0) <> 0 THEN 0
    WHEN COALESCE(s.interrupted_run_count, 0) <> 0 THEN 0
    WHEN COALESCE(s.persist_error_run_count, 0) <> 0 THEN 0
    WHEN COALESCE(s.persistence_failure_rows, 0) <> 0 THEN 0
    WHEN s.completion_reconciliation_status IS NOT NULL
      AND s.completion_reconciliation_status <> 'COMPLETE_RECONCILED' THEN 0
    WHEN s.expected_package_count IS NOT NULL
      AND COALESCE(s.reconciled_package_count, 0) <> s.expected_package_count THEN 0
    WHEN (
      LOWER(COALESCE(s.session_stamp, '')) LIKE '%qa%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%qa%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%headless%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%headless%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%stability%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%stability%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%debug%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%debug%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%static-batch%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%static-batch%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%smoke%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%smoke%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%phase4a%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%phase4a%'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%closeout-smoke%'
      OR LOWER(COALESCE(s.session_label, '')) LIKE '%closeout-smoke%'
    ) THEN 0
    WHEN (
      COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
      OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
    ) THEN CASE
      WHEN COALESCE(s.session_link_rows, 0) > 0
       AND COALESCE(s.rollup_rows, 0) > 0
      THEN 1 ELSE 0
    END
    WHEN COALESCE(s.rollup_rows, 0) > 0 THEN 1
    ELSE 0
  END AS web_default_eligible,
  CASE
    WHEN COALESCE(s.session_status, '') = 'IN_PROGRESS' THEN 'in_progress_unfinalized'
    WHEN s.completion_reconciliation_status IS NOT NULL
      AND s.completion_reconciliation_status <> 'COMPLETE_RECONCILED'
      THEN 'completion_reconciliation_failed'
    WHEN s.expected_package_count IS NOT NULL
      AND COALESCE(s.reconciled_package_count, 0) <> s.expected_package_count
      THEN 'completion_reconciliation_failed'
    WHEN s.session_disposition = 'interrupted_partial_session' THEN 'interrupted_by_operator'
    WHEN s.session_disposition = 'mixed_completed_failed_session' THEN 'mixed_needs_review'
    WHEN s.session_disposition = 'broken_persist_error_session' THEN 'broken_persistence_historical'
    WHEN s.session_disposition = 'broken_missing_artifacts_session' THEN 'broken_missing_artifacts'
    WHEN COALESCE(s.session_status, '') = 'COMPLETED'
      AND COALESCE(s.failed_run_count, 0) = 0
      AND COALESCE(s.persistence_failure_rows, 0) = 0
    THEN CASE
      WHEN (
        COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
        OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
      ) AND (
        COALESCE(s.session_link_rows, 0) = 0
        OR COALESCE(s.rollup_rows, 0) = 0
      )
        THEN 'completed_missing_finalization_artifacts'
      WHEN NOT (
        COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
        OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
      ) AND COALESCE(s.rollup_rows, 0) = 0 THEN 'completed_missing_finalization_artifacts'
      ELSE 'healthy_completed'
    END
    ELSE 'unknown_needs_review'
  END AS health_class,
  CASE
    WHEN s.session_status = 'IN_PROGRESS' THEN 'operator_review'
    WHEN s.completion_reconciliation_status IS NOT NULL
      AND s.completion_reconciliation_status <> 'COMPLETE_RECONCILED'
      THEN 'not_default_usable'
    WHEN s.expected_package_count IS NOT NULL
      AND COALESCE(s.reconciled_package_count, 0) <> s.expected_package_count
      THEN 'not_default_usable'
    WHEN s.session_status IN ('FAILED', 'INTERRUPTED') THEN 'not_default_usable'
    WHEN s.session_status = 'PARTIAL' THEN 'operator_review'
    WHEN COALESCE(s.session_status, '') = 'COMPLETED'
      AND COALESCE(s.failed_run_count, 0) = 0
      AND COALESCE(s.persistence_failure_rows, 0) = 0
      AND (
        (
          (
            COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
            OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
          )
          AND COALESCE(s.session_link_rows, 0) > 0
          AND COALESCE(s.rollup_rows, 0) > 0
        )
        OR (
          NOT (
            COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
            OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
          )
          AND COALESCE(s.rollup_rows, 0) > 0
        )
      )
      THEN 'ready'
    WHEN COALESCE(s.session_status, '') = 'COMPLETED'
      AND COALESCE(s.failed_run_count, 0) = 0
      THEN 'usable_with_warnings'
    ELSE 'unknown'
  END AS usability_class,
  CASE
    WHEN s.session_status = 'IN_PROGRESS' THEN 1
    WHEN s.completion_reconciliation_status IS NOT NULL
      AND s.completion_reconciliation_status <> 'COMPLETE_RECONCILED' THEN 2
    WHEN s.expected_package_count IS NOT NULL
      AND COALESCE(s.reconciled_package_count, 0) <> s.expected_package_count THEN 2
    WHEN COALESCE(s.session_status, '') = 'COMPLETED'
      AND COALESCE(s.failed_run_count, 0) = 0
      AND COALESCE(s.persistence_failure_rows, 0) = 0
      AND (
        (
          (
            COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
            OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
          )
          AND COALESCE(s.session_link_rows, 0) > 0
          AND COALESCE(s.rollup_rows, 0) > 0
        )
        OR (
          NOT (
            COALESCE(TRIM(BOTH FROM s.scope_label), '') = 'All harvested apps'
            OR LOWER(COALESCE(s.session_stamp, '')) LIKE '%all-full%'
          )
          AND COALESCE(s.rollup_rows, 0) > 0
        )
      )
      THEN 0
    WHEN COALESCE(s.session_status, '') = 'COMPLETED'
      AND COALESCE(s.failed_run_count, 0) = 0
      THEN 1
    WHEN s.session_disposition = 'interrupted_partial_session' THEN 2
    WHEN s.session_disposition = 'mixed_completed_failed_session' THEN 3
    WHEN s.session_disposition LIKE 'broken%' THEN 4
    ELSE 5
  END AS risk_order,
  CASE
    WHEN s.total_permission_matrix_rows = s.total_permission_risk_rows THEN 1
    ELSE 0
  END AS permission_matrix_risk_parity,
  CASE
    WHEN s.total_run_count > 0
      THEN ROUND(s.completed_run_count / s.total_run_count * 100, 1)
    ELSE 0
  END AS completion_pct,
  CASE
    WHEN COALESCE(s.expected_package_count, 0) > 0
      THEN ROUND(
        LEAST(COALESCE(s.reconciled_package_count, 0), s.expected_package_count)
        / s.expected_package_count * 100,
        1
      )
    ELSE NULL
  END AS selection_reconciliation_pct,
  s.tool_semver,
  s.tool_git_commit,
  s.schema_version,
  s.first_created_at,
  s.last_ended_at,
  s.refreshed_at_utc
FROM static_analysis_sessions s;
"""

CREATE_V_WEB_STATIC_SESSION_INDEX_V2 = """
CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_web_static_session_index_v2 AS
SELECT
  h.static_session_id,
  h.session_stamp,
  h.scope_label,
  h.session_status,
  h.session_disposition,
  h.health_class,
  h.usability_class,
  h.completion_pct,
  h.total_run_count,
  h.completed_run_count,
  h.failed_run_count,
  h.total_findings_rows,
  h.total_permission_matrix_rows,
  h.total_permission_risk_rows,
  h.total_string_summary_rows,
  h.session_link_rows,
  h.rollup_rows,
  h.web_visibility_default,
  h.web_default_eligible,
  h.cleanup_status,
  h.first_created_at,
  h.last_ended_at
FROM v_static_session_health_v2 h
WHERE h.web_default_eligible = 1;
"""

CREATE_V_WEB_STATIC_LATEST_SESSION_BY_SCOPE_V2 = """
CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_web_static_latest_session_by_scope_v2 AS
SELECT ranked.*
FROM (
  SELECT
    h.*,
    ROW_NUMBER() OVER (
      PARTITION BY h.scope_label
      ORDER BY h.last_ended_at DESC, h.static_session_id DESC
    ) AS rn
  FROM v_static_session_health_v2 h
  WHERE h.web_default_eligible = 1
) ranked
WHERE ranked.rn = 1;
"""

CREATE_V_STATIC_SESSION_CLEANUP_CANDIDATES_V2 = """
CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_cleanup_candidates_v2 AS
SELECT
  h.static_session_id,
  h.session_stamp,
  h.scope_label,
  h.session_status,
  h.session_disposition,
  h.health_class,
  h.usability_class,
  h.total_run_count,
  h.completed_run_count,
  h.failed_run_count,
  h.interrupted_run_count,
  h.persist_error_run_count,
  h.missing_artifacts_run_count,
  h.total_findings_rows,
  h.total_permission_matrix_rows,
  h.total_permission_risk_rows,
  h.total_string_summary_rows,
  h.total_string_sample_rows,
  h.session_link_rows,
  h.rollup_rows,
  h.persistence_failure_rows,
  h.web_visibility_default,
  h.cleanup_status,
  CASE
    WHEN h.session_disposition = 'broken_persist_error_session' THEN 100
    WHEN h.session_disposition = 'broken_missing_artifacts_session' THEN 90
    WHEN h.session_disposition = 'mixed_completed_failed_session' THEN 70
    WHEN h.session_disposition = 'interrupted_partial_session' THEN 40
    ELSE 10
  END AS cleanup_priority,
  CASE
    WHEN h.session_disposition = 'broken_persist_error_session'
      THEN 'export_then_prune_after_supersession_confirmed'
    WHEN h.session_disposition = 'broken_missing_artifacts_session'
      THEN 'export_then_prune_after_supersession_confirmed'
    WHEN h.session_disposition = 'mixed_completed_failed_session'
      THEN 'manual_review_do_not_prune_whole_session_yet'
    WHEN h.session_disposition = 'interrupted_partial_session'
      THEN 'keep_short_term_prune_later_after_successful_rerun'
    ELSE 'review'
  END AS recommended_action,
  CASE
    WHEN h.web_visibility_default = 'public' THEN 'blocked_public_session'
    WHEN h.session_disposition = 'mixed_completed_failed_session' THEN 'blocked_mixed_completed_rows_exist'
    WHEN h.session_disposition = 'interrupted_partial_session' THEN 'blocked_recent_interrupt_keep_for_debug'
    WHEN h.cleanup_status = 'export_pending' THEN 'needs_export_before_delete'
    ELSE 'review_required'
  END AS prune_blocker,
  h.first_created_at,
  h.last_ended_at
FROM v_static_session_health_v2 h
WHERE h.cleanup_status IN ('review', 'export_pending')
   OR h.session_disposition IN (
        'interrupted_partial_session',
        'mixed_completed_failed_session',
        'broken_persist_error_session',
        'broken_missing_artifacts_session'
      );
"""

CREATE_V_STATIC_SESSION_SUPERSESSION_CANDIDATES_V1 = """
CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_supersession_candidates_v1 AS
SELECT
  ranked.candidate_session_id,
  ranked.candidate_session_stamp,
  ranked.candidate_scope_label,
  ranked.candidate_disposition,
  ranked.candidate_cleanup_status,
  ranked.candidate_last_ended_at,
  ranked.superseding_session_id,
  ranked.superseding_session_stamp,
  ranked.superseding_disposition,
  ranked.superseding_run_count,
  ranked.superseding_findings_rows,
  ranked.superseding_last_ended_at,
  ranked.rn
FROM (
  SELECT
    bad.static_session_id AS candidate_session_id,
    bad.session_stamp AS candidate_session_stamp,
    bad.scope_label AS candidate_scope_label,
    bad.session_disposition AS candidate_disposition,
    bad.cleanup_status AS candidate_cleanup_status,
    bad.last_ended_at AS candidate_last_ended_at,
    good.static_session_id AS superseding_session_id,
    good.session_stamp AS superseding_session_stamp,
    good.session_disposition AS superseding_disposition,
    good.total_run_count AS superseding_run_count,
    good.total_findings_rows AS superseding_findings_rows,
    good.last_ended_at AS superseding_last_ended_at,
    ROW_NUMBER() OVER (
      PARTITION BY bad.static_session_id
      ORDER BY good.last_ended_at DESC, good.static_session_id DESC
    ) AS rn
  FROM v_static_session_cleanup_candidates_v2 bad
  JOIN v_static_session_health_v2 good
    ON good.scope_label = bad.scope_label
   AND good.web_default_eligible = 1
   AND good.last_ended_at > bad.last_ended_at
  WHERE bad.session_disposition IN (
    'broken_persist_error_session',
    'broken_missing_artifacts_session',
    'mixed_completed_failed_session',
    'interrupted_partial_session'
  )
) ranked
WHERE ranked.rn = 1;
"""
