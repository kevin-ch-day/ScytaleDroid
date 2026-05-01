"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_VW_STATIC_RISK_SURFACES_LATEST = """
CREATE OR REPLACE VIEW vw_static_risk_surfaces_latest AS
SELECT
  latest.package_name,
  COALESCE(NULLIF(a.display_name, ''), latest.package_name) AS app_label,
  latest.static_run_id,
  latest.session_stamp,
  latest.session_label,
  latest.version_name,
  latest.version_code,
  legacy.legacy_run_id,
  rs.risk_score AS permission_run_score,
  rs.risk_grade AS permission_run_grade,
  rs.dangerous AS permission_run_dangerous_count,
  rs.signature AS permission_run_signature_count,
  rs.vendor AS permission_run_vendor_count,
  'risk_scores' AS permission_run_surface,
  audit.snapshot_id AS permission_audit_snapshot_id,
  audit_snapshot.snapshot_key AS permission_audit_snapshot_key,
  audit_snapshot.created_at AS permission_audit_created_at,
  SUBSTRING_INDEX(audit_snapshot.snapshot_key, ':', -1) AS permission_audit_session_stamp,
  audit.score_raw AS permission_audit_score_raw,
  audit.score_capped AS permission_audit_score_capped,
  audit.grade AS permission_audit_grade,
  audit.dangerous_count AS permission_audit_dangerous_count,
  audit.signature_count AS permission_audit_signature_count,
  audit.vendor_count AS permission_audit_vendor_count,
  'permission_audit_apps' AS permission_audit_surface,
  bucket_rollup.bucket_points_total AS legacy_bucket_points_total,
  bucket_rollup.bucket_cap_total AS legacy_bucket_cap_total,
  CASE
    WHEN bucket_rollup.legacy_run_id IS NULL THEN 'not_persisted_as_db_score'
    ELSE 'legacy_bucket_rollup_only'
  END AS composite_static_surface_state,
  'cli_runtime_only' AS composite_static_surface
FROM (
  SELECT
    sar.id AS static_run_id,
    sar.session_stamp,
    sar.session_label,
    a.package_name,
    av.version_name,
    av.version_code
  FROM static_analysis_runs sar
  JOIN app_versions av ON av.id = sar.app_version_id
  JOIN apps a ON a.id = av.app_id
  JOIN (
    SELECT
      a2.package_name,
      COALESCE(
        MAX(CASE
          WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
           AND UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
          THEN sar2.id
        END),
        MAX(CASE
          WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
          THEN sar2.id
        END),
        MAX(sar2.id)
      ) AS preferred_static_run_id
    FROM static_analysis_runs sar2
    JOIN app_versions av2 ON av2.id = sar2.app_version_id
    JOIN apps a2 ON a2.id = av2.app_id
    GROUP BY a2.package_name
  ) preferred
    ON CONVERT(preferred.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
   AND preferred.preferred_static_run_id = sar.id
) latest
LEFT JOIN apps a
  ON CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = CONVERT(latest.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
LEFT JOIN risk_scores rs
  ON LOWER(CONVERT(rs.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
   = LOWER(CONVERT(latest.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
 AND rs.session_stamp = latest.session_stamp
LEFT JOIN permission_audit_apps audit
  ON audit.static_run_id = latest.static_run_id
LEFT JOIN permission_audit_snapshots audit_snapshot
  ON audit_snapshot.snapshot_id = audit.snapshot_id
LEFT JOIN (
  SELECT session_stamp, MAX(run_id) AS legacy_run_id
  FROM runs
  GROUP BY session_stamp
) legacy
  ON legacy.session_stamp = latest.session_stamp
LEFT JOIN (
  SELECT
    run_id AS legacy_run_id,
    COALESCE(SUM(points), 0) AS bucket_points_total,
    COALESCE(SUM(cap), 0) AS bucket_cap_total
  FROM buckets
  GROUP BY run_id
) bucket_rollup
  ON bucket_rollup.legacy_run_id = legacy.legacy_run_id;
"""

CREATE_VW_STATIC_FINDING_SURFACES_LATEST = """
CREATE OR REPLACE VIEW vw_static_finding_surfaces_latest AS
SELECT
  latest.package_name,
  COALESCE(NULLIF(a.display_name, ''), latest.package_name) AS app_label,
  latest.static_run_id,
  latest.session_stamp,
  latest.session_label,
  latest.version_name,
  latest.version_code,
  COALESCE(canonical.findings_total, 0) AS canonical_findings_total,
  COALESCE(canonical.high, 0) AS canonical_high,
  COALESCE(canonical.med, 0) AS canonical_med,
  COALESCE(canonical.low, 0) AS canonical_low,
  COALESCE(canonical.info, 0) AS canonical_info,
  latest.run_findings_persisted_rowcount,
  latest.findings_runtime_total,
  latest.findings_capped_total,
  latest.findings_capped_by_detector_json,
  'static_analysis_findings' AS canonical_surface,
  summary.summary_id AS summary_row_id,
  summary.summary_created_at,
  COALESCE(summary.high, 0) AS summary_high,
  COALESCE(summary.med, 0) AS summary_med,
  COALESCE(summary.low, 0) AS summary_low,
  COALESCE(summary.info, 0) AS summary_info,
  'static_findings_summary' AS summary_surface,
  COALESCE(baseline.baseline_detail_rows, 0) AS baseline_detail_rows,
  'static_findings' AS baseline_surface,
  'baseline_section_hits_only' AS baseline_surface_role
FROM (
  SELECT
    sar.id AS static_run_id,
    sar.session_stamp,
    sar.session_label,
    sar.findings_total AS run_findings_persisted_rowcount,
    sar.findings_runtime_total,
    sar.findings_capped_total,
    sar.findings_capped_by_detector_json,
    a.package_name,
    av.version_name,
    av.version_code
  FROM static_analysis_runs sar
  JOIN app_versions av ON av.id = sar.app_version_id
  JOIN apps a ON a.id = av.app_id
  JOIN (
    SELECT
      a2.package_name,
      COALESCE(
        MAX(CASE
          WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
           AND UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
          THEN sar2.id
        END),
        MAX(CASE
          WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
          THEN sar2.id
        END),
        MAX(sar2.id)
      ) AS preferred_static_run_id
    FROM static_analysis_runs sar2
    JOIN app_versions av2 ON av2.id = sar2.app_version_id
    JOIN apps a2 ON a2.id = av2.app_id
    GROUP BY a2.package_name
  ) preferred
    ON CONVERT(preferred.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
   AND preferred.preferred_static_run_id = sar.id
) latest
LEFT JOIN apps a
  ON CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = CONVERT(latest.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
LEFT JOIN (
  SELECT
    saf.run_id AS static_run_id,
    COUNT(*) AS findings_total,
    SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'high' THEN 1 ELSE 0 END) AS high,
    SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'medium' THEN 1 ELSE 0 END) AS med,
    SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'low' THEN 1 ELSE 0 END) AS low,
    SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'info' THEN 1 ELSE 0 END) AS info
  FROM static_analysis_findings saf
  GROUP BY saf.run_id
) canonical
  ON canonical.static_run_id = latest.static_run_id
LEFT JOIN (
  SELECT
    s.static_run_id,
    MAX(s.id) AS summary_id,
    MAX(s.created_at) AS summary_created_at,
    MAX(s.high) AS high,
    MAX(s.med) AS med,
    MAX(s.low) AS low,
    MAX(s.info) AS info
  FROM static_findings_summary s
  GROUP BY s.static_run_id
) summary
  ON summary.static_run_id = latest.static_run_id
LEFT JOIN (
  SELECT
    s.static_run_id,
    COUNT(f.id) AS baseline_detail_rows
  FROM static_findings_summary s
  LEFT JOIN static_findings f ON f.summary_id = s.id
  GROUP BY s.static_run_id
) baseline
  ON baseline.static_run_id = latest.static_run_id;
"""

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

__all__ = [
    "CREATE_VW_STATIC_RISK_SURFACES_LATEST",
    "CREATE_VW_STATIC_FINDING_SURFACES_LATEST",
    "CREATE_VW_STATIC_MODULE_COVERAGE",
    "CREATE_VW_STORAGE_SURFACE_RISK",
    "CREATE_V_MASVS_MATRIX",
    "CREATE_V_STATIC_HANDOFF_V1",
]
