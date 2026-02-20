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
  ON LOWER(rs.package_name) = LOWER(ar.package_name);
"""

__all__ = [
    "CREATE_VW_LATEST_APK_PER_PACKAGE",
    "CREATE_VW_LATEST_PERMISSION_RISK",
]

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

__all__ += ["CREATE_VW_PERMISSION_AUDIT_LATEST"]

CREATE_V_RUN_OVERVIEW = """
CREATE OR REPLACE VIEW v_run_overview AS
SELECT
  r.run_id,
  r.package,
  r.version_name,
  r.version_code,
  r.target_sdk,
  r.ts,
  r.session_stamp,
  SUM(b.points) AS total_points,
  SUM(b.cap)    AS total_cap
FROM runs AS r
LEFT JOIN buckets AS b ON b.run_id = r.run_id
GROUP BY r.run_id, r.package, r.version_name, r.version_code, r.target_sdk, r.ts, r.session_stamp;
"""

__all__ += ["CREATE_V_RUN_OVERVIEW"]

CREATE_V_RUN_IDENTITY = """
CREATE OR REPLACE VIEW v_run_identity AS
SELECT
  CAST(sar.id AS CHAR(64)) AS run_id,
  'static' AS run_type,
  a.package_name,
  a.display_name,
  a.profile_key,
  sar.scenario_id,
  av.version_code AS app_version_code,
  av.version_name AS app_version_name,
  sar.base_apk_sha256 AS apk_sha256,
  sar.run_started_utc AS start_utc,
  sar.ended_at_utc AS end_utc,
  sar.tool_semver,
  sar.tool_git_commit,
  sar.schema_version,
  sar.device_serial,
  NULL AS grade
FROM static_analysis_runs sar
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id
UNION ALL
SELECT
  ds.dynamic_run_id AS run_id,
  'dynamic' AS run_type,
  ds.package_name,
  a.display_name,
  a.profile_key,
  ds.scenario_id,
  ds.version_code AS app_version_code,
  ds.version_name AS app_version_name,
  COALESCE(ds.apk_sha256, ds.base_apk_sha256) AS apk_sha256,
  ds.started_at_utc AS start_utc,
  ds.ended_at_utc AS end_utc,
  ds.tool_semver,
  ds.tool_git_commit,
  ds.schema_version,
  ds.device_serial,
  ds.grade
FROM dynamic_sessions ds
LEFT JOIN apps a ON a.package_name = ds.package_name;
"""

__all__ += ["CREATE_V_RUN_IDENTITY"]

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
       fp.read_perm,
       fp.write_perm,
       fp.grant_uri_permissions,
       fp.path_globs,
       fp.risk,
       acl.path,
       acl.path_type,
       acl.read_perm AS acl_read_perm,
       acl.write_perm AS acl_write_perm,
       acl.base_perm
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

CREATE_V_MASVS_MATRIX = """
CREATE OR REPLACE VIEW v_masvs_matrix AS
SELECT
  r.run_id,
  r.package,
  MAX(CASE WHEN m.control_id LIKE 'NETWORK-%'  AND m.status = 'FAIL' THEN 1 ELSE 0 END) AS network_fail,
  MAX(CASE WHEN m.control_id LIKE 'PLATFORM-%' AND m.status = 'FAIL' THEN 1 ELSE 0 END) AS platform_fail,
  MAX(CASE WHEN m.control_id LIKE 'STORAGE-%'  AND m.status = 'FAIL' THEN 1 ELSE 0 END) AS storage_fail,
  MAX(CASE WHEN m.control_id LIKE 'PRIVACY-%'  AND m.status = 'FAIL' THEN 1 ELSE 0 END) AS privacy_fail,
  MAX(CASE WHEN m.control_id LIKE 'NETWORK-%'  AND m.status = 'INCONCLUSIVE' THEN 1 ELSE 0 END) AS network_inconclusive,
  MAX(CASE WHEN m.control_id LIKE 'PLATFORM-%' AND m.status = 'INCONCLUSIVE' THEN 1 ELSE 0 END) AS platform_inconclusive,
  MAX(CASE WHEN m.control_id LIKE 'STORAGE-%'  AND m.status = 'INCONCLUSIVE' THEN 1 ELSE 0 END) AS storage_inconclusive,
  MAX(CASE WHEN m.control_id LIKE 'PRIVACY-%'  AND m.status = 'INCONCLUSIVE' THEN 1 ELSE 0 END) AS privacy_inconclusive
FROM runs AS r
LEFT JOIN masvs_control_coverage AS m ON m.run_id = r.run_id
GROUP BY r.run_id, r.package;
"""

__all__ += ["CREATE_V_MASVS_MATRIX"]

CREATE_V_STATIC_HANDOFF_V1 = """
CREATE OR REPLACE VIEW v_static_handoff_v1 AS
SELECT
  sar.id AS static_run_id,
  sar.session_label,
  sar.base_apk_sha256,
  sar.artifact_set_hash,
  sar.identity_mode,
  sar.identity_conflict_flag,
  sar.static_handoff_hash,
  sar.tool_semver,
  sar.tool_git_commit,
  sar.schema_version,
  a.package_name AS package_name_lc,
  av.version_code,
  sar.static_handoff_json
FROM static_analysis_runs sar
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id;
"""

__all__ += ["CREATE_V_STATIC_HANDOFF_V1"]
