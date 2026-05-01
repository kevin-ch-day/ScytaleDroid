"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

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
LEFT JOIN apps a
  ON LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
   = LOWER(CONVERT(ds.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci;
"""

__all__ = [
    "CREATE_V_RUN_OVERVIEW",
    "CREATE_V_RUN_IDENTITY",
]
