"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_VW_LATEST_PERMISSION_RISK = """
CREATE OR REPLACE VIEW vw_latest_permission_risk AS
SELECT ar.package_name,
       ar.apk_id,
       NULL AS app_id,
       ar.sha256,
       rs.session_stamp,
       rs.scope_label,
       rs.risk_score,
       rs.risk_grade,
       rs.dangerous,
       rs.signature,
       rs.vendor,
       ar.version_name,
       ar.version_code,
       ar.updated_at
FROM vw_latest_apk_per_package ar
LEFT JOIN (
  SELECT rs1.*
  FROM risk_scores rs1
  JOIN (
    SELECT package_name, MAX(id) AS max_id
    FROM risk_scores
    GROUP BY package_name
  ) latest
    ON latest.max_id = rs1.id
) rs
  ON LOWER(CONVERT(rs.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
   = LOWER(CONVERT(ar.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci;
"""

CREATE_VW_PERMISSION_AUDIT_LATEST = """
CREATE OR REPLACE VIEW vw_permission_audit_latest AS
SELECT paa.*
FROM permission_audit_apps paa
JOIN (
  SELECT package_name, MAX(snapshot_id) AS max_sid
  FROM permission_audit_apps
  GROUP BY package_name
) t
  ON t.package_name = paa.package_name AND t.max_sid = paa.snapshot_id;
"""

CREATE_V_WEB_PERMISSION_INTEL_CURRENT = """
CREATE OR REPLACE VIEW v_web_permission_intel_current AS
SELECT
  sessions.package_name,
  sessions.static_run_id,
  sessions.session_stamp,
  sessions.session_type_key,
  sessions.session_type_label,
  sessions.session_usability,
  sessions.session_hidden_by_default,
  perms.permission_name,
  perms.source,
  perms.source_family,
  perms.custom_family,
  perms.protection,
  perms.severity,
  perms.is_runtime_dangerous,
  perms.is_signature,
  perms.is_privileged,
  perms.is_special_access,
  perms.is_custom
FROM v_web_app_sessions sessions
JOIN v_web_app_permissions perms
  ON CONVERT(perms.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = CONVERT(sessions.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
 AND perms.static_run_id = sessions.static_run_id
WHERE sessions.session_preference_rank = 1
  AND sessions.session_hidden_by_default = 0
  AND UPPER(COALESCE(sessions.run_status, '')) = 'COMPLETED'
  AND sessions.session_usability IN ('usable_complete', 'partial_rows');
"""

__all__ = [
    "CREATE_VW_LATEST_PERMISSION_RISK",
    "CREATE_VW_PERMISSION_AUDIT_LATEST",
    "CREATE_V_WEB_PERMISSION_INTEL_CURRENT",
]
