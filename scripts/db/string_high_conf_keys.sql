SELECT
  provider,
  finding_type,
  confidence,
  COUNT(*) AS sample_count
FROM v_string_findings_enriched
WHERE finding_type IN ('api_key', 'jwt_candidate')
  AND confidence IN ('high', 'medium')
GROUP BY provider, finding_type, confidence
ORDER BY sample_count DESC;
