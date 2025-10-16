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

CREATE_VW_STATIC_MODULE_COVERAGE = """
CREATE OR REPLACE VIEW vw_static_module_coverage AS
SELECT package_name,
       'strings' AS module_key,
       MAX(session_stamp) AS last_session
FROM static_string_summary
GROUP BY package_name
UNION
SELECT package_name,
       'dynload' AS module_key,
       MAX(session_stamp) AS last_session
FROM static_dynload_events
GROUP BY package_name
UNION
SELECT package_name,
       'storage_surface' AS module_key,
       MAX(session_stamp) AS last_session
FROM static_fileproviders
GROUP BY package_name;
"""

CREATE_VW_STORAGE_SURFACE_RISK = """
CREATE OR REPLACE VIEW vw_storage_surface_risk AS
SELECT fp.package_name,
       fp.session_stamp,
       fp.scope_label,
       fp.authority,
       fp.provider_name,
       fp.exported,
       fp.grant_flags,
       fp.path_globs,
       fp.risk,
       acl.read_perm,
       acl.write_perm,
       acl.base_perm,
       acl.path_perms_json
FROM static_fileproviders AS fp
LEFT JOIN static_provider_acl AS acl
  ON fp.package_name = acl.package_name
 AND fp.session_stamp = acl.session_stamp
 AND fp.authority = acl.authority;
"""

CREATE_VW_DYNLOAD_HOTSPOTS = """
CREATE OR REPLACE VIEW vw_dynload_hotspots AS
SELECT e.package_name,
       e.session_stamp,
       e.apk_id,
       SUM(CASE WHEN e.event_type = 'classloader' THEN 1 ELSE 0 END) AS classloader_events,
       SUM(CASE WHEN e.event_type = 'native' THEN 1 ELSE 0 END) AS native_loads,
       COUNT(DISTINCT r.id) AS reflection_calls
FROM static_dynload_events AS e
LEFT JOIN static_reflection_calls AS r
  ON e.package_name = r.package_name
 AND e.session_stamp = r.session_stamp
 AND (e.apk_id = r.apk_id OR (e.apk_id IS NULL AND r.apk_id IS NULL))
GROUP BY e.package_name, e.session_stamp, e.apk_id
HAVING classloader_events > 0 AND reflection_calls > 0;
"""

__all__ += [
    "CREATE_VW_STATIC_MODULE_COVERAGE",
    "CREATE_VW_STORAGE_SURFACE_RISK",
    "CREATE_VW_DYNLOAD_HOTSPOTS",
]
