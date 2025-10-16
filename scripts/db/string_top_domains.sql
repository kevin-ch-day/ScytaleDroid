SELECT
  root_domain,
  COUNT(*) AS total_samples,
  SUM(CASE WHEN scheme = 'http' THEN 1 ELSE 0 END) AS http_count,
  SUM(CASE WHEN scheme = 'https' THEN 1 ELSE 0 END) AS https_count,
  SUM(CASE WHEN risk_tag = 'http_cleartext' THEN 1 ELSE 0 END) AS cleartext_risk
FROM v_string_findings_enriched
WHERE finding_type = 'endpoint'
  AND root_domain IS NOT NULL
GROUP BY root_domain
ORDER BY total_samples DESC
LIMIT 25;
