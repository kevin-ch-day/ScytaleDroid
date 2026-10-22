# db-check

Use default MariaDB client credentials with explicit --user=claude_ro.
Run mariadb --user=claude_ro --batch --execute="SELECT CURRENT_USER".
Stop unless the authenticated account before @ is exactly claude_ro.
Then SHOW GRANTS; redact authentication hashes/secrets.
For each table below run SELECT UTC_TIMESTAMP() AS query_time_utc, COUNT(*) AS n
FROM scytaledroid_core_prod.<table> using the same client:
apps, app_versions, static_analysis_runs, static_analysis_findings, dynamic_sessions.
Report full SQL, UTC query time and exact count. No TABLE_ROWS estimates.
Missing grants/data are UNAVAILABLE, not zero. No writes or alternate users.

Record UTC time with each query. Exact COUNT queries may prompt for approval;
the schema-valid shared allowlist preapproves identity, grants and bounded row reads.
