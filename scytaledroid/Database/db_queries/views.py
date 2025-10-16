"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_VW_LATEST_APK_PER_PACKAGE = """
CREATE OR REPLACE VIEW vw_latest_apk_per_package AS
SELECT ar.*
FROM android_apk_repository ar
JOIN (
  SELECT package_name, MAX(updated_at) AS max_updated
  FROM android_apk_repository
  WHERE is_split_member = 0
  GROUP BY package_name
) t
  ON t.package_name = ar.package_name AND t.max_updated = ar.updated_at
WHERE ar.is_split_member = 0;
"""

CREATE_VW_LATEST_PERMISSION_RISK = """
CREATE OR REPLACE VIEW vw_latest_permission_risk AS
SELECT v.package_name,
       v.apk_id,
       v.app_id,
       v.sha256,
       v.session_stamp,
       v.scope_label,
       v.risk_score,
       v.risk_grade,
       v.dangerous,
       v.signature,
       v.vendor,
       ar.version_name,
       ar.version_code,
       ar.updated_at
FROM vw_latest_apk_per_package ar
LEFT JOIN static_permission_risk v ON v.apk_id = ar.apk_id;
"""

__all__ = [
    "CREATE_VW_LATEST_APK_PER_PACKAGE",
    "CREATE_VW_LATEST_PERMISSION_RISK",
]

CREATE_VW_DETECTED_PERMISSIONS_FQN = """
CREATE OR REPLACE VIEW v_detected_permissions_fqn AS
SELECT d.*,
       CASE
         WHEN d.namespace = 'android.permission' THEN CONCAT(d.namespace, '.', d.perm_name)
         ELSE d.perm_name
       END AS detected_fqn
FROM android_detected_permissions d;
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

__all__ += [
    "CREATE_VW_DETECTED_PERMISSIONS_FQN",
    "CREATE_VW_PERMISSION_AUDIT_LATEST",
]
