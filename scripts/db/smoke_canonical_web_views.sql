-- Read-only smoke: proves canonical Web-facing views resolve (parsable SELECT).
-- Usage: mysql -h"$SCYTALEDROID_DB_HOST" -P"${SCYTALEDROID_DB_PORT:-3306}" \
--          -u"$SCYTALEDROID_DB_USER" -p"$SCYTALEDROID_DB_PASSWD" \
--          "$SCYTALEDROID_DB_NAME" < scripts/db/smoke_canonical_web_views.sql

SELECT 1 AS db_ping FROM dual;

SELECT 'v_web_app_sessions' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_app_sessions;
SELECT 'v_web_app_findings' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_app_findings;
SELECT 'v_web_app_permissions' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_app_permissions;

SELECT 'v_static_masvs_matrix_v1' AS view_name,
       COUNT(*) AS row_estimate FROM v_static_masvs_matrix_v1;
SELECT 'v_static_masvs_session_summary_v1' AS view_name,
       COUNT(*) AS row_estimate FROM v_static_masvs_session_summary_v1;
SELECT 'v_static_risk_surfaces_v1' AS view_name,
       COUNT(*) AS row_estimate FROM v_static_risk_surfaces_v1;
SELECT 'v_static_handoff_v1' AS view_name,
       COUNT(*) AS row_estimate FROM v_static_handoff_v1;

SELECT 'v_web_static_session_health' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_static_session_health;
SELECT 'v_web_app_directory' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_app_directory;
SELECT 'v_web_app_masvs_latest_v1' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_app_masvs_latest_v1;
SELECT 'v_web_app_static_handoff_readiness_v1' AS view_name,
       COUNT(*) AS row_estimate FROM v_web_app_static_handoff_readiness_v1;
