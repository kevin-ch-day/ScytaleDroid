# db-check

Resolve SCYTALEDROID_AUDIT_DB_USER and SCYTALEDROID_AUDIT_CORE_SCHEMA from the
environment or ignored local guidance. Stop if missing; never guess or use an
administrative account. Use existing local credential configuration without printing it.
Invoke the database client with an explicit quoted --user value. First SELECT
CURRENT_USER and verify its account component equals the configured audit user;
then SHOW GRANTS, redacting authentication material. Stop on any mismatch.
Validate the schema as a plain SQL identifier before interpolation.
For apps, app_versions, static_analysis_runs, static_analysis_findings and
dynamic_sessions, query exact COUNT(*) in that configured core schema.
Report full SQL, UTC query time and result in the configured local report destination.
Missing access/data is UNAVAILABLE, not zero; do not use TABLE_ROWS estimates.
Database commands require normal permission review. No writes or alternate users.
