-- =============================================================================
-- Static session stamp cohort rollups (READ-ONLY)
-- =============================================================================
-- Purpose: operator / analyst checks for a *fixed list* of session_stamp values
-- (golden runs, supersession review, post-prune sanity). Summarizes
-- static_analysis_runs plus canonical child tables using the same join keys as
-- interactive triage (run_id vs static_run_id per child table contract).
--
-- Edit **only** the `cohort_sessions` CTE in each section (or merge sections in
-- your client). Each block below is self-contained so GUI tools that execute
-- one statement at a time can run sections independently.
--
-- See also: scripts/db/sql/session_summary_from_static_analysis_runs.sql
-- Child join map: docs/maintenance/database_static_child_table_join_map.md
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Section A — Global: top (session_stamp, scope_label) by last activity
--          (not cohort-scoped; optional wide inventory)
-- -----------------------------------------------------------------------------
SELECT
    sar.session_stamp,
    COALESCE(TRIM(sar.scope_label), '') AS scope_label,
    COUNT(*) AS run_rows,
    SUM(sar.status = 'COMPLETED') AS completed_rows,
    SUM(COALESCE(f.finding_rows, 0)) AS finding_rows,
    SUM(COALESCE(pm.permission_matrix_rows, 0)) AS permission_matrix_rows,
    SUM(COALESCE(pr.permission_risk_rows, 0)) AS permission_risk_rows,
    SUM(COALESCE(ss.string_summary_rows, 0)) AS string_summary_rows,
    SUM(COALESCE(h.handoff_rows, 0)) AS handoff_rows,
    SUM(COALESCE(sl.session_link_rows, 0)) AS session_link_rows,
    MIN(sar.created_at) AS first_created,
    MAX(sar.created_at) AS last_created
FROM static_analysis_runs sar
LEFT JOIN (
    SELECT run_id, COUNT(*) AS finding_rows
    FROM static_analysis_findings
    GROUP BY run_id
) f ON f.run_id = sar.id
LEFT JOIN (
    SELECT run_id, COUNT(*) AS permission_matrix_rows
    FROM static_permission_matrix
    GROUP BY run_id
) pm ON pm.run_id = sar.id
LEFT JOIN (
    SELECT run_id, COUNT(*) AS permission_risk_rows
    FROM static_permission_risk_vnext
    GROUP BY run_id
) pr ON pr.run_id = sar.id
LEFT JOIN (
    SELECT static_run_id, COUNT(*) AS string_summary_rows
    FROM static_string_summary
    WHERE static_run_id IS NOT NULL
    GROUP BY static_run_id
) ss ON ss.static_run_id = sar.id
LEFT JOIN (
    SELECT static_run_id, COUNT(*) AS handoff_rows
    FROM v_static_handoff_v1
    GROUP BY static_run_id
) h ON h.static_run_id = sar.id
LEFT JOIN (
    SELECT static_run_id, COUNT(*) AS session_link_rows
    FROM static_session_run_links
    GROUP BY static_run_id
) sl ON sl.static_run_id = sar.id
GROUP BY
    sar.session_stamp,
    COALESCE(TRIM(sar.scope_label), '')
ORDER BY
    last_created DESC
LIMIT 25;


-- -----------------------------------------------------------------------------
-- Section B — Cohort: rollup per (session_stamp, scope_label)
--          Edit cohort_sessions UNION list to match your review set.
-- -----------------------------------------------------------------------------
WITH cohort_sessions AS (
    SELECT '20260513-all-full' AS session_stamp UNION ALL
    SELECT '20260512-all-full' UNION ALL
    SELECT '20260511-all-full' UNION ALL
    SELECT '20260510-all-full-145' UNION ALL
    SELECT '20260510-all-full' UNION ALL
    SELECT '20260509-all-full'
),
recent_runs AS (
    SELECT
        sar.id,
        sar.session_stamp,
        COALESCE(TRIM(sar.scope_label), '') AS scope_label,
        sar.status,
        sar.created_at
    FROM static_analysis_runs sar
    INNER JOIN cohort_sessions cs ON cs.session_stamp = sar.session_stamp
)
SELECT
    rr.session_stamp,
    rr.scope_label,
    COUNT(*) AS run_rows,
    SUM(rr.status = 'COMPLETED') AS completed_rows,
    SUM(rr.status <> 'COMPLETED') AS non_completed_rows,
    SUM(COALESCE(f.finding_rows, 0)) AS finding_rows,
    SUM(COALESCE(pm.permission_matrix_rows, 0)) AS permission_matrix_rows,
    SUM(COALESCE(pr.permission_risk_rows, 0)) AS permission_risk_rows,
    SUM(COALESCE(ss.string_summary_rows, 0)) AS string_summary_rows,
    SUM(COALESCE(h.handoff_rows, 0)) AS handoff_rows,
    SUM(COALESCE(sl.session_link_rows, 0)) AS session_link_rows,
    MIN(rr.created_at) AS first_created,
    MAX(rr.created_at) AS last_created
FROM recent_runs rr
LEFT JOIN (
    SELECT saf.run_id, COUNT(*) AS finding_rows
    FROM static_analysis_findings saf
    INNER JOIN recent_runs rr2 ON rr2.id = saf.run_id
    GROUP BY saf.run_id
) f ON f.run_id = rr.id
LEFT JOIN (
    SELECT spm.run_id, COUNT(*) AS permission_matrix_rows
    FROM static_permission_matrix spm
    INNER JOIN recent_runs rr2 ON rr2.id = spm.run_id
    GROUP BY spm.run_id
) pm ON pm.run_id = rr.id
LEFT JOIN (
    SELECT spr.run_id, COUNT(*) AS permission_risk_rows
    FROM static_permission_risk_vnext spr
    INNER JOIN recent_runs rr2 ON rr2.id = spr.run_id
    GROUP BY spr.run_id
) pr ON pr.run_id = rr.id
LEFT JOIN (
    SELECT sss.static_run_id, COUNT(*) AS string_summary_rows
    FROM static_string_summary sss
    INNER JOIN recent_runs rr2 ON rr2.id = sss.static_run_id
    GROUP BY sss.static_run_id
) ss ON ss.static_run_id = rr.id
LEFT JOIN (
    SELECT vh.static_run_id, COUNT(*) AS handoff_rows
    FROM v_static_handoff_v1 vh
    INNER JOIN recent_runs rr2 ON rr2.id = vh.static_run_id
    GROUP BY vh.static_run_id
) h ON h.static_run_id = rr.id
LEFT JOIN (
    SELECT ssrl.static_run_id, COUNT(*) AS session_link_rows
    FROM static_session_run_links ssrl
    INNER JOIN recent_runs rr2 ON rr2.id = ssrl.static_run_id
    GROUP BY ssrl.static_run_id
) sl ON sl.static_run_id = rr.id
GROUP BY
    rr.session_stamp,
    rr.scope_label
ORDER BY
    last_created DESC;


-- -----------------------------------------------------------------------------
-- Section C — Cohort: run_rows by status (session × scope × status)
-- -----------------------------------------------------------------------------
WITH cohort_sessions AS (
    SELECT '20260513-all-full' AS session_stamp UNION ALL
    SELECT '20260512-all-full' UNION ALL
    SELECT '20260511-all-full' UNION ALL
    SELECT '20260510-all-full-145' UNION ALL
    SELECT '20260510-all-full' UNION ALL
    SELECT '20260509-all-full'
)
SELECT
    sar.session_stamp,
    COALESCE(TRIM(sar.scope_label), '') AS scope_label,
    sar.status,
    COUNT(*) AS run_rows
FROM static_analysis_runs sar
INNER JOIN cohort_sessions cs ON cs.session_stamp = sar.session_stamp
GROUP BY
    sar.session_stamp,
    COALESCE(TRIM(sar.scope_label), ''),
    sar.status
ORDER BY
    MAX(sar.created_at) DESC;


-- -----------------------------------------------------------------------------
-- Section D — Cohort: per session_stamp child-table totals (simple joins)
--          (handy when comparing one column at a time; edit cohort list)
-- -----------------------------------------------------------------------------
WITH cohort_sessions AS (
    SELECT '20260513-all-full' AS session_stamp UNION ALL
    SELECT '20260512-all-full' UNION ALL
    SELECT '20260511-all-full' UNION ALL
    SELECT '20260510-all-full-145' UNION ALL
    SELECT '20260510-all-full' UNION ALL
    SELECT '20260509-all-full'
),
recent_runs AS (
    SELECT sar.id, sar.session_stamp
    FROM static_analysis_runs sar
    INNER JOIN cohort_sessions cs ON cs.session_stamp = sar.session_stamp
)
SELECT rr.session_stamp, COUNT(*) AS finding_rows
FROM recent_runs rr
INNER JOIN static_analysis_findings saf ON saf.run_id = rr.id
GROUP BY rr.session_stamp
ORDER BY rr.session_stamp DESC;

WITH cohort_sessions AS (
    SELECT '20260513-all-full' AS session_stamp UNION ALL
    SELECT '20260512-all-full' UNION ALL
    SELECT '20260511-all-full' UNION ALL
    SELECT '20260510-all-full-145' UNION ALL
    SELECT '20260510-all-full' UNION ALL
    SELECT '20260509-all-full'
),
recent_runs AS (
    SELECT sar.id, sar.session_stamp
    FROM static_analysis_runs sar
    INNER JOIN cohort_sessions cs ON cs.session_stamp = sar.session_stamp
)
SELECT rr.session_stamp, COUNT(*) AS permission_matrix_rows
FROM recent_runs rr
INNER JOIN static_permission_matrix spm ON spm.run_id = rr.id
GROUP BY rr.session_stamp
ORDER BY rr.session_stamp DESC;

WITH cohort_sessions AS (
    SELECT '20260513-all-full' AS session_stamp UNION ALL
    SELECT '20260512-all-full' UNION ALL
    SELECT '20260511-all-full' UNION ALL
    SELECT '20260510-all-full-145' UNION ALL
    SELECT '20260510-all-full' UNION ALL
    SELECT '20260509-all-full'
),
recent_runs AS (
    SELECT sar.id, sar.session_stamp
    FROM static_analysis_runs sar
    INNER JOIN cohort_sessions cs ON cs.session_stamp = sar.session_stamp
)
SELECT rr.session_stamp, COUNT(*) AS permission_risk_rows
FROM recent_runs rr
INNER JOIN static_permission_risk_vnext spr ON spr.run_id = rr.id
GROUP BY rr.session_stamp
ORDER BY rr.session_stamp DESC;

WITH cohort_sessions AS (
    SELECT '20260513-all-full' AS session_stamp UNION ALL
    SELECT '20260512-all-full' UNION ALL
    SELECT '20260511-all-full' UNION ALL
    SELECT '20260510-all-full-145' UNION ALL
    SELECT '20260510-all-full' UNION ALL
    SELECT '20260509-all-full'
),
recent_runs AS (
    SELECT sar.id, sar.session_stamp
    FROM static_analysis_runs sar
    INNER JOIN cohort_sessions cs ON cs.session_stamp = sar.session_stamp
)
SELECT rr.session_stamp, COUNT(*) AS string_summary_rows
FROM recent_runs rr
INNER JOIN static_string_summary sss ON sss.static_run_id = rr.id
GROUP BY rr.session_stamp
ORDER BY rr.session_stamp DESC;


-- -----------------------------------------------------------------------------
-- Section E — Optional (MariaDB CLI): temp table for repeated probes on large cohorts
--          Run interactively in one session; DROP when done.
-- -----------------------------------------------------------------------------
-- DROP TEMPORARY TABLE IF EXISTS tmp_recent_static_runs;
-- CREATE TEMPORARY TABLE tmp_recent_static_runs AS
-- SELECT id, session_stamp, COALESCE(TRIM(scope_label), '') AS scope_label, status, created_at
-- FROM static_analysis_runs
-- WHERE session_stamp IN ('20260513-all-full', '20260512-all-full');
-- ALTER TABLE tmp_recent_static_runs ADD PRIMARY KEY (id), ADD KEY idx_tmp_session (session_stamp);
-- -- Then point Section B subqueries at tmp_recent_static_runs instead of recent_runs CTE.
