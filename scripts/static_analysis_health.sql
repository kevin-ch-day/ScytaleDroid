-- Static analysis health checks.
-- Run these queries after persistence to validate coverage and MASVS roll-ups.

-- Coverage summary for recent runs
SELECT r.run_id,
       r.package,
       COUNT(*) AS total,
       SUM(f.rule_id IS NOT NULL) AS ruled,
       ROUND(SUM(f.rule_id IS NOT NULL) / COUNT(*) * 100, 1) AS rule_cov_pct,
       SUM(f.evidence_path IS NOT NULL) AS with_path,
       ROUND(SUM(f.evidence_path IS NOT NULL) / COUNT(*) * 100, 1) AS path_cov_pct,
       SUM(f.evidence_preview IS NOT NULL) AS with_preview,
       ROUND(SUM(f.evidence_preview IS NOT NULL) / COUNT(*) * 100, 1) AS preview_cov_pct,
       SUM(f.cvss_v40_bte_vector IS NOT NULL) AS bte_vectors,
       ROUND(SUM(f.cvss_v40_bte_vector IS NOT NULL) / COUNT(*) * 100, 1) AS bte_cov_pct,
       SUM(f.cvss_v40_bte_score IS NOT NULL) AS bte_scores,
       ROUND(SUM(f.cvss_v40_bte_score IS NOT NULL) / COUNT(*) * 100, 1) AS bte_score_cov_pct
FROM runs r
JOIN findings f USING (run_id)
WHERE r.run_id IN (
    SELECT run_id
    FROM runs
    ORDER BY run_id DESC
    LIMIT 20
)
GROUP BY r.run_id, r.package
ORDER BY r.run_id DESC;

-- MASVS matrix snapshot
SELECT *
FROM v_masvs_matrix
ORDER BY run_id DESC
LIMIT 20;

-- Effective vs suppressed network evidence snapshot
SELECT 'effective' AS evidence_set,
       COUNT(*) AS rows_total
  FROM v_strings_effective
UNION ALL
SELECT 'policy_drift' AS evidence_set,
       COUNT(*) AS rows_total
  FROM v_doc_policy_drift;

-- Top suppressed documentary hosts (audit appendix)
SELECT package_name,
       host,
       COUNT(*) AS hits
  FROM v_doc_policy_drift
 GROUP BY package_name, host
 ORDER BY hits DESC
 LIMIT 20;

-- Control level evidence for the most recent run
SELECT c.run_id,
       c.package,
       c.control_id,
       c.status,
       JSON_EXTRACT(c.evidence, '$[0].note') AS example_note,
       JSON_EXTRACT(c.evidence, '$[0].path') AS example_path
FROM masvs_control_coverage c
WHERE c.run_id = (
    SELECT run_id
    FROM runs
    ORDER BY run_id DESC
    LIMIT 1
)
ORDER BY c.control_id;
