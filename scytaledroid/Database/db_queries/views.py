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
  ON LOWER(CONVERT(rs.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
   = LOWER(CONVERT(ar.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci;
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
LEFT JOIN apps a
  ON LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
   = LOWER(CONVERT(ds.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci;
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
  sar.run_class,
  sar.non_canonical_reasons,
  sar.static_handoff_hash,
  sar.masvs_mapping_hash,
  sar.tool_semver,
  sar.tool_git_commit,
  sar.schema_version,
  a.package_name AS package_name_lc,
  av.version_code,
  sar.static_handoff_json_path
FROM static_analysis_runs sar
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id
WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
  AND sar.base_apk_sha256 IS NOT NULL
  AND sar.identity_mode IS NOT NULL
  AND sar.run_class IS NOT NULL
  AND sar.static_handoff_hash IS NOT NULL
  AND sar.masvs_mapping_hash IS NOT NULL;
"""

__all__ += ["CREATE_V_STATIC_HANDOFF_V1"]

CREATE_V_RUNTIME_DYNAMIC_COHORT_STATUS_V1 = """
CREATE OR REPLACE VIEW v_runtime_dynamic_cohort_status_v1 AS
SELECT
  adcs.dynamic_run_id,
  adcs.package_name,
  adcs.package_name_lc,
  adcs.version_name,
  adcs.version_code,
  adcs.base_apk_sha256,
  adcs.artifact_set_hash,
  adcs.signer_set_hash,
  adcs.signer_primary_digest,
  adcs.static_handoff_hash,
  adcs.freeze_manifest_sha256,
  adcs.paper_contract_version,
  adcs.reason_taxonomy_version,
  adcs.plan_schema_version,
  adcs.freeze_contract_version,
  adcs.ml_schema_version,
  adcs.identity_check_status,
  adcs.identity_checked_at_start_utc,
  adcs.identity_checked_at_end_utc,
  adcs.identity_checked_at_gate_utc,
  adcs.identity_start_json,
  adcs.identity_end_json,
  adcs.identity_gate_json,
  adcs.paper_eligible,
  adcs.paper_eligible AS runtime_cohort_eligible,
  adcs.status,
  adcs.reason_code,
  adcs.details_json,
  adcs.created_at_utc,
  adcs.updated_at_utc
FROM analysis_dynamic_cohort_status adcs;
"""

CREATE_V_PAPER_DYNAMIC_COHORT_V1 = """
CREATE OR REPLACE VIEW v_paper_dynamic_cohort_v1 AS
SELECT
  dynamic_run_id,
  package_name,
  package_name_lc,
  version_name,
  version_code,
  base_apk_sha256,
  artifact_set_hash,
  signer_set_hash,
  signer_primary_digest,
  static_handoff_hash,
  freeze_manifest_sha256,
  paper_contract_version,
  reason_taxonomy_version,
  plan_schema_version,
  freeze_contract_version,
  ml_schema_version,
  identity_check_status,
  identity_checked_at_start_utc,
  identity_checked_at_end_utc,
  identity_checked_at_gate_utc,
  identity_start_json,
  identity_end_json,
  identity_gate_json,
  paper_eligible,
  status,
  reason_code,
  details_json,
  created_at_utc,
  updated_at_utc
FROM v_runtime_dynamic_cohort_status_v1;
"""

__all__ += ["CREATE_V_RUNTIME_DYNAMIC_COHORT_STATUS_V1", "CREATE_V_PAPER_DYNAMIC_COHORT_V1"]

CREATE_V_WEB_APP_DIRECTORY = """
CREATE OR REPLACE VIEW v_web_app_directory AS
SELECT
  pkg.package_name,
  COALESCE(NULLIF(a.display_name, ''), latest_audit.app_label, pkg.package_name) AS app_label,
  COALESCE(cat.category_name, 'Uncategorized') AS category,
  COALESCE(ap.display_name, a.profile_key, 'Unclassified') AS profile_label,
  latest_audit.grade,
  latest_audit.score_capped,
  COALESCE(latest_audit.last_scanned, latest_static.created_at) AS last_scanned,
  COALESCE(latest_static.session_stamp, latest_audit.session_stamp) AS session_stamp,
  COALESCE(latest_static.high, 0) AS high,
  COALESCE(latest_static.med, 0) AS med,
  COALESCE(latest_static.low, 0) AS low,
  COALESCE(latest_static.info, 0) AS info,
  CASE
    WHEN latest_static.package_name IS NOT NULL AND latest_audit.package_name IS NOT NULL THEN 'static+permission_audit'
    WHEN latest_static.package_name IS NOT NULL THEN 'static'
    WHEN latest_audit.package_name IS NOT NULL THEN 'permission_audit'
    ELSE 'catalog'
  END AS source_state
FROM (
  SELECT package_name
  FROM permission_audit_apps
  UNION
  SELECT package_name
  FROM static_findings_summary
) pkg
LEFT JOIN apps a
  ON a.package_name COLLATE utf8mb4_general_ci = pkg.package_name COLLATE utf8mb4_general_ci
LEFT JOIN android_app_categories cat
  ON cat.category_id = a.category_id
LEFT JOIN android_app_profiles ap
  ON ap.profile_key = a.profile_key
LEFT JOIN (
  SELECT
    pa.package_name,
    pa.app_label,
    pa.grade,
    pa.score_capped,
    pas.created_at AS last_scanned,
    SUBSTRING_INDEX(pas.snapshot_key, ':', -1) AS session_stamp
  FROM permission_audit_apps pa
  JOIN permission_audit_snapshots pas
    ON pas.snapshot_id = pa.snapshot_id
  JOIN (
    SELECT pa2.package_name,
           MAX(pas2.created_at) AS max_created
    FROM permission_audit_apps pa2
    JOIN permission_audit_snapshots pas2
      ON pas2.snapshot_id = pa2.snapshot_id
    GROUP BY pa2.package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_general_ci = pa.package_name COLLATE utf8mb4_general_ci
   AND latest.max_created = pas.created_at
) latest_audit
  ON latest_audit.package_name COLLATE utf8mb4_general_ci = pkg.package_name COLLATE utf8mb4_general_ci
LEFT JOIN (
  SELECT s1.*
  FROM static_findings_summary s1
  JOIN (
    SELECT package_name, MAX(created_at) AS max_created
    FROM static_findings_summary
    GROUP BY package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_general_ci = s1.package_name COLLATE utf8mb4_general_ci
   AND latest.max_created = s1.created_at
) latest_static
  ON latest_static.package_name COLLATE utf8mb4_general_ci = pkg.package_name COLLATE utf8mb4_general_ci;
"""

CREATE_V_WEB_RUNTIME_RUN_INDEX = """
CREATE OR REPLACE VIEW v_web_runtime_run_index AS
SELECT
  ds.dynamic_run_id,
  ds.package_name,
  COALESCE(NULLIF(a.display_name, ''), ds.package_name) AS app_label,
  ds.status,
  ds.tier,
  COALESCE(ds.operator_run_profile, nf.run_profile, ds.profile_key, 'unknown') AS run_profile,
  COALESCE(ds.operator_interaction_level, nf.interaction_level, 'unknown') AS interaction_level,
  ds.started_at_utc,
  ds.ended_at_utc,
  ds.duration_seconds,
  ds.grade,
  ds.countable,
  ds.valid_dataset_run,
  ds.invalid_reason_code,
  ds.pcap_valid,
  ds.pcap_bytes,
  ds.network_signal_quality,
  nf.feature_schema_version,
  nf.packet_count,
  nf.bytes_per_sec,
  nf.packets_per_sec,
  nf.low_signal,
  COALESCE(issues.issue_count, 0) AS issue_count,
  latest_regime.static_grade,
  latest_regime.dynamic_grade_if,
  latest_regime.dynamic_score_if,
  latest_regime.final_regime_if,
  CASE WHEN nf.dynamic_run_id IS NULL THEN 'missing_features' ELSE 'features_available' END AS feature_state,
  CASE
    WHEN ds.static_run_id IS NULL THEN 'missing_static_run_id'
    WHEN sar.id IS NULL THEN 'dangling_static_run_id'
    ELSE 'static_linked'
  END AS static_link_state
FROM dynamic_sessions ds
LEFT JOIN apps a
  ON a.package_name COLLATE utf8mb4_general_ci = ds.package_name COLLATE utf8mb4_general_ci
LEFT JOIN dynamic_network_features nf
  ON nf.dynamic_run_id = ds.dynamic_run_id
LEFT JOIN static_analysis_runs sar
  ON sar.id = ds.static_run_id
LEFT JOIN (
  SELECT dynamic_run_id, COUNT(*) AS issue_count
  FROM dynamic_session_issues
  GROUP BY dynamic_run_id
) issues
  ON issues.dynamic_run_id = ds.dynamic_run_id
LEFT JOIN (
  SELECT rr.*
  FROM analysis_risk_regime_summary rr
  JOIN (
    SELECT package_name, MAX(created_at_utc) AS max_created
    FROM analysis_risk_regime_summary
    GROUP BY package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_general_ci = rr.package_name COLLATE utf8mb4_general_ci
   AND latest.max_created = rr.created_at_utc
) latest_regime
  ON latest_regime.package_name COLLATE utf8mb4_general_ci = ds.package_name COLLATE utf8mb4_general_ci;
"""

CREATE_V_WEB_RUNTIME_RUN_DETAIL = """
CREATE OR REPLACE VIEW v_web_runtime_run_detail AS
SELECT
  ds.*,
  COALESCE(NULLIF(a.display_name, ''), ds.package_name) AS app_label,
  nf.feature_schema_version,
  nf.host_tools_json,
  nf.capture_duration_s,
  nf.packet_count,
  nf.data_size_bytes,
  nf.bytes_per_sec,
  nf.packets_per_sec,
  nf.avg_packet_rate_pps,
  nf.tls_ratio,
  nf.quic_ratio,
  nf.tcp_ratio,
  nf.udp_ratio,
  nf.low_signal,
  nf.low_signal_reasons_json,
  nf.bytes_per_second_p50,
  nf.bytes_per_second_p95,
  nf.bytes_per_second_max,
  nf.packets_per_second_p50,
  nf.packets_per_second_p95,
  nf.packets_per_second_max,
  nf.burstiness_bytes_p95_over_p50,
  nf.burstiness_packets_p95_over_p50,
  nf.unique_dst_ip_count,
  nf.unique_dst_port_count,
  nf.unique_sni_count,
  nf.unique_dns_qname_count,
  nf.domains_per_min,
  nf.new_domain_rate_per_min,
  nf.new_sni_rate_per_min,
  nf.new_dns_rate_per_min,
  CASE WHEN nf.dynamic_run_id IS NULL THEN 'missing_features' ELSE 'features_available' END AS feature_state,
  CASE
    WHEN ds.static_run_id IS NULL THEN 'missing_static_run_id'
    WHEN sar.id IS NULL THEN 'dangling_static_run_id'
    ELSE 'static_linked'
  END AS static_link_state
FROM dynamic_sessions ds
LEFT JOIN apps a
  ON a.package_name COLLATE utf8mb4_general_ci = ds.package_name COLLATE utf8mb4_general_ci
LEFT JOIN dynamic_network_features nf
  ON nf.dynamic_run_id = ds.dynamic_run_id
LEFT JOIN static_analysis_runs sar
  ON sar.id = ds.static_run_id;
"""

__all__ += [
    "CREATE_V_WEB_APP_DIRECTORY",
    "CREATE_V_WEB_RUNTIME_RUN_INDEX",
    "CREATE_V_WEB_RUNTIME_RUN_DETAIL",
]

CREATE_V_ARTIFACT_REGISTRY_INTEGRITY = """
CREATE OR REPLACE VIEW v_artifact_registry_integrity AS
SELECT
  ar.artifact_id,
  ar.run_id,
  ar.run_type,
  ar.artifact_type,
  ar.origin,
  ar.device_path,
  ar.host_path,
  ar.pull_status,
  ar.sha256,
  ar.size_bytes,
  ar.created_at_utc,
  ar.pulled_at_utc,
  ar.status_reason,
  ar.meta_json,
  CASE
    WHEN ar.run_type = 'dynamic' AND ds.dynamic_run_id IS NOT NULL THEN 'linked'
    WHEN ar.run_type = 'dynamic' THEN 'dangling_dynamic_run'
    WHEN ar.run_type = 'static' AND ar.run_id REGEXP '^[0-9]+$' AND sar.id IS NOT NULL THEN 'linked'
    WHEN ar.run_type = 'static' THEN 'dangling_static_run'
    ELSE 'unknown_run_type'
  END AS link_state
FROM artifact_registry ar
LEFT JOIN dynamic_sessions ds
  ON ar.run_type = 'dynamic'
 AND ds.dynamic_run_id = ar.run_id
LEFT JOIN static_analysis_runs sar
  ON ar.run_type = 'static'
 AND ar.run_id REGEXP '^[0-9]+$'
 AND sar.id = CAST(ar.run_id AS UNSIGNED);
"""

CREATE_V_CURRENT_ARTIFACT_REGISTRY = """
CREATE OR REPLACE VIEW v_current_artifact_registry AS
SELECT *
FROM v_artifact_registry_integrity
WHERE link_state = 'linked';
"""

__all__ += ["CREATE_V_ARTIFACT_REGISTRY_INTEGRITY", "CREATE_V_CURRENT_ARTIFACT_REGISTRY"]
