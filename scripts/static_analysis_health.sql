-- Static analysis health checks (MariaDB-safe).
-- Run after persistence to validate coverage, suppression, and MASVS roll-ups.

-- ────────────────────────────────────────────────────────────────────────────
-- 0) Params
-- ────────────────────────────────────────────────────────────────────────────
SET @N_RECENT := 20;

-- ────────────────────────────────────────────────────────────────────────────
-- 1) Build a reusable recent_runs temp table (works across statements)
-- ────────────────────────────────────────────────────────────────────────────
DROP TEMPORARY TABLE IF EXISTS recent_runs;

SET
    @sql := CONCAT(
        'CREATE TEMPORARY TABLE recent_runs AS ',
        'SELECT r.run_id, r.package ',
        'FROM runs r ',
        'ORDER BY r.run_id DESC ',
        'LIMIT ',
        @N_RECENT
    );

PREPARE stmt FROM @sql;

EXECUTE stmt;

DEALLOCATE PREPARE stmt;

-- Optional: latest run id for convenience
SET @LATEST_RUN := ( SELECT MAX(run_id) FROM runs );

-- ────────────────────────────────────────────────────────────────────────────
-- 2) Coverage summary for recent runs
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    rr.run_id,
    rr.package,
    COUNT(*) AS total,
    SUM(f.rule_id IS NOT NULL) AS ruled,
    ROUND(
        SUM(f.rule_id IS NOT NULL) / NULLIF(COUNT(*), 0) * 100,
        1
    ) AS rule_cov_pct,
    SUM(f.evidence_path IS NOT NULL) AS with_path,
    ROUND(
        SUM(f.evidence_path IS NOT NULL) / NULLIF(COUNT(*), 0) * 100,
        1
    ) AS path_cov_pct,
    SUM(
        f.evidence_preview IS NOT NULL
    ) AS with_preview,
    ROUND(
        SUM(
            f.evidence_preview IS NOT NULL
        ) / NULLIF(COUNT(*), 0) * 100,
        1
    ) AS preview_cov_pct,
    SUM(
        f.cvss_v40_bte_vector IS NOT NULL
    ) AS bte_vectors,
    ROUND(
        SUM(
            f.cvss_v40_bte_vector IS NOT NULL
        ) / NULLIF(COUNT(*), 0) * 100,
        1
    ) AS bte_cov_pct,
    SUM(
        f.cvss_v40_bte_score IS NOT NULL
    ) AS bte_scores,
    ROUND(
        SUM(
            f.cvss_v40_bte_score IS NOT NULL
        ) / NULLIF(COUNT(*), 0) * 100,
        1
    ) AS bte_score_cov_pct
FROM recent_runs rr
    JOIN findings f ON f.run_id = rr.run_id
GROUP BY
    rr.run_id,
    rr.package
ORDER BY rr.run_id DESC;

-- ────────────────────────────────────────────────────────────────────────────
-- 3) MASVS matrix snapshot (recent runs)
-- ────────────────────────────────────────────────────────────────────────────
SELECT vm.*
FROM
    v_masvs_matrix vm
    JOIN recent_runs rr ON rr.run_id = vm.run_id
ORDER BY vm.run_id DESC;

-- ────────────────────────────────────────────────────────────────────────────
-- 4) Effective vs suppressed network evidence snapshot
-- ────────────────────────────────────────────────────────────────────────────
SELECT 'effective' AS evidence_set, COUNT(*) AS rows_total
FROM v_strings_effective
UNION ALL
SELECT 'policy_drift' AS evidence_set, COUNT(*) AS rows_total
FROM v_doc_policy_drift;

-- ────────────────────────────────────────────────────────────────────────────
-- 5) Top suppressed documentary hosts (audit appendix)
-- ────────────────────────────────────────────────────────────────────────────
SELECT package_name, host, COUNT(*) AS hits
FROM v_doc_policy_drift
GROUP BY
    package_name,
    host
ORDER BY hits DESC, package_name
LIMIT 20;

-- ────────────────────────────────────────────────────────────────────────────
-- 6) Control-level evidence for the most recent run
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    c.run_id,
    c.package,
    c.control_id,
    c.status,
    JSON_EXTRACT(c.evidence, '$[0].note') AS example_note,
    JSON_EXTRACT(c.evidence, '$[0].path') AS example_path
FROM masvs_control_coverage c
WHERE
    c.run_id = @LATEST_RUN
ORDER BY c.control_id;

-- ────────────────────────────────────────────────────────────────────────────
-- 7) CVSS v4 band distribution per area (recent runs)
--    Uses findings.masvs (AREA) and known CVSS v4 columns.
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    f.run_id,
    f.masvs AS area,
    COUNT(*) AS total_scored,
    SUM(f.cvss_v40_bte_score >= 9.0) AS critical,
    SUM(
        f.cvss_v40_bte_score >= 7.0
        AND f.cvss_v40_bte_score < 9.0
    ) AS high,
    SUM(
        f.cvss_v40_bte_score >= 4.0
        AND f.cvss_v40_bte_score < 7.0
    ) AS medium,
    SUM(
        f.cvss_v40_bte_score >= 0.1
        AND f.cvss_v40_bte_score < 4.0
    ) AS low,
    SUM(f.cvss_v40_bte_score = 0.0) AS none,
    ROUND(
        SUM(f.cvss_v40_bte_score >= 7.0) / NULLIF(COUNT(*), 0) * 100,
        1
    ) AS pct_high_plus
FROM findings f
    JOIN recent_runs rr USING (run_id)
WHERE
    f.cvss_v40_bte_score IS NOT NULL
GROUP BY
    f.run_id,
    f.masvs
ORDER BY f.run_id DESC, area;

-- ────────────────────────────────────────────────────────────────────────────
-- 8) Findings without a MASVS mapping (recent runs) → hygiene list
-- ────────────────────────────────────────────────────────────────────────────
SELECT f.run_id, r.package, f.rule_id, COALESCE(f.title, '(no title)') AS title, COUNT(*) AS occurrences
FROM
    findings f
    JOIN recent_runs rr USING (run_id)
    JOIN runs r USING (run_id)
WHERE (
        f.masvs IS NULL
        OR f.masvs = ''
        OR f.masvs = 'UNKNOWN'
    )
GROUP BY
    f.run_id,
    r.package,
    f.rule_id,
    COALESCE(f.title, '(no title)')
ORDER BY f.run_id DESC, occurrences DESC, f.rule_id
LIMIT 200;

-- ────────────────────────────────────────────────────────────────────────────
-- 9) Persistence gap check: runs that have 0 findings (should be rare)
-- ────────────────────────────────────────────────────────────────────────────
SELECT r.run_id, r.package, r.session_stamp
FROM runs r
    LEFT JOIN findings f ON f.run_id = r.run_id
GROUP BY
    r.run_id,
    r.package,
    r.session_stamp
HAVING
    COUNT(f.id) = 0
ORDER BY r.run_id DESC
LIMIT 50;

-- ────────────────────────────────────────────────────────────────────────────
-- 10) Effective network hosts by package (recent runs)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    s.summary_id,
    sumry.package_name AS package,
    s.host_normalized AS host,
    SUM(s.bucket = 'http_cleartext') AS http_hits,
    SUM(s.bucket = 'endpoints') AS endpoint_hits,
    COUNT(*) AS total_hits
FROM
    v_strings_effective s
    JOIN static_string_summary sumry ON sumry.id = s.summary_id
    JOIN recent_runs rr ON rr.run_id = sumry.run_id
GROUP BY
    s.summary_id,
    sumry.package_name,
    s.host_normalized
ORDER BY total_hits DESC, package
LIMIT 100;

-- ────────────────────────────────────────────────────────────────────────────
-- 11) Sanity: allow-listed hosts must NOT appear in effective set (expect 0)
-- ────────────────────────────────────────────────────────────────────────────
SELECT e.host_normalized, COUNT(*) AS leaks
FROM
    v_strings_effective e
    JOIN doc_hosts dh ON dh.host = e.host_normalized
GROUP BY
    e.host_normalized
HAVING
    COUNT(*) > 0;

-- ────────────────────────────────────────────────────────────────────────────
-- 12) Drift trend (suppressed vs effective by package)
-- ────────────────────────────────────────────────────────────────────────────
SELECT pkg, SUM(effective) AS eff, SUM(policy_drift) AS drift
FROM (
        SELECT
            sumry.package_name AS pkg, COUNT(*) AS effective, 0 AS policy_drift
        FROM
            v_strings_effective s
            JOIN static_string_summary sumry ON sumry.id = s.summary_id
        GROUP BY
            sumry.package_name
        UNION ALL
        SELECT
            package_name AS pkg, 0 AS effective, COUNT(*) AS policy_drift
        FROM v_doc_policy_drift
        GROUP BY
            package_name
    ) x
GROUP BY
    pkg
ORDER BY drift DESC, eff DESC
LIMIT 50;