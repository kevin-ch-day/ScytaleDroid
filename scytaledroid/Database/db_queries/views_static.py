"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

# Thin compatibility wrapper: same column names as historic callers expect; core logic lives in
# ``v_static_risk_surfaces_v1`` (no ``runs`` / ``buckets`` / ``metrics``). Legacy bucket totals are NULL.
CREATE_VW_STATIC_RISK_SURFACES_LATEST = """
CREATE OR REPLACE VIEW vw_static_risk_surfaces_latest AS
SELECT
  c.package_name,
  c.app_label,
  c.static_run_id,
  c.session_stamp,
  c.session_label,
  c.version_name,
  c.version_code,
  CAST(NULL AS UNSIGNED) AS legacy_run_id,
  c.permission_run_score,
  c.permission_run_grade,
  c.permission_run_dangerous_count,
  c.permission_run_signature_count,
  c.permission_run_vendor_count,
  c.permission_run_surface,
  c.permission_audit_snapshot_id,
  c.permission_audit_snapshot_key,
  c.permission_audit_created_at,
  c.permission_audit_session_stamp,
  c.permission_audit_score_raw,
  c.permission_audit_score_capped,
  c.permission_audit_grade,
  c.permission_audit_dangerous_count,
  c.permission_audit_signature_count,
  c.permission_audit_vendor_count,
  c.permission_audit_surface,
  CAST(NULL AS DECIMAL(18, 4)) AS legacy_bucket_points_total,
  CAST(NULL AS DECIMAL(18, 4)) AS legacy_bucket_cap_total,
  'canonical_static_latest' AS composite_static_surface_state,
  'cli_runtime_only' AS composite_static_surface
FROM v_static_risk_surfaces_v1 c;
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

# Compatibility name only: ``run_id`` is ``static_analysis_runs.id`` (not legacy ``runs.run_id``).
# Fail columns derive from canonical severity rollups; inconclusive flags are reserved (0).
CREATE_V_MASVS_MATRIX = """
CREATE OR REPLACE VIEW v_masvs_matrix AS
SELECT
  m.static_run_id AS run_id,
  m.package_name AS package,
  CASE WHEN m.masvs_network_status = 'FAIL' THEN 1 ELSE 0 END AS network_fail,
  CASE WHEN m.masvs_platform_status = 'FAIL' THEN 1 ELSE 0 END AS platform_fail,
  CASE WHEN m.masvs_storage_status = 'FAIL' THEN 1 ELSE 0 END AS storage_fail,
  CASE WHEN m.masvs_privacy_status = 'FAIL' THEN 1 ELSE 0 END AS privacy_fail,
  0 AS network_inconclusive,
  0 AS platform_inconclusive,
  0 AS storage_inconclusive,
  0 AS privacy_inconclusive
FROM v_static_masvs_matrix_v1 m;
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

# Canonical MASVS / static risk surfaces (no runs / metrics / buckets / legacy findings).
# Status per area: FAIL (any High), WARN (any Medium, no High), PASS (mapped findings, no Med/High),
# NO_DATA (no mapped findings in that area). See docs/maintenance/canonical_masvs_risk_views.md.
#
# Reuses the same MASVS area normalisation as Python: COALESCE(masvs_area, masvs_control) with
# prefix match (NETWORK, PLATFORM, PRIVACY, STORAGE). Unmapped rows are excluded from area rollups.
CREATE_V_STATIC_MASVS_FINDINGS_V1 = """
CREATE OR REPLACE VIEW v_static_masvs_findings_v1 AS
SELECT
  saf.id AS static_finding_id,
  saf.run_id AS static_run_id,
  sar.session_stamp,
  sar.session_label,
  a.package_name,
  COALESCE(NULLIF(a.display_name, ''), a.package_name) AS app_label,
  av.version_name,
  av.version_code,
  LOWER(COALESCE(saf.severity, '')) AS severity_norm,
  saf.severity,
  saf.rule_id,
  saf.detector,
  saf.masvs_area,
  saf.masvs_control_id,
  saf.masvs_control,
  CASE
    WHEN (
         NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NULL
     AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NULL
     AND NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NULL
    ) THEN 0
    ELSE 1
  END AS is_masvs_mapped,
  CASE
    WHEN (
         NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NULL
     AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NULL
     AND NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NULL
    ) THEN NULL
    WHEN UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
      OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%' THEN 'NETWORK'
    WHEN UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
      OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%' THEN 'PLATFORM'
    WHEN UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
      OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%' THEN 'PRIVACY'
    WHEN UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
      OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%' THEN 'STORAGE'
    ELSE 'OTHER'
  END AS masvs_area_bucket
FROM static_analysis_findings saf
JOIN static_analysis_runs sar ON sar.id = saf.run_id
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id;
"""

CREATE_V_STATIC_MASVS_MATRIX_V1 = """
CREATE OR REPLACE VIEW v_static_masvs_matrix_v1 AS
SELECT
  sar.id AS static_run_id,
  sar.session_stamp,
  sar.session_label,
  a.package_name,
  COALESCE(NULLIF(a.display_name, ''), a.package_name) AS app_label,
  COUNT(saf.id) AS findings_total,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      ) THEN 1
      ELSE 0
    END
  ) AS findings_masvs_mapped,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NULL
       AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NULL
       AND NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NULL
      ) THEN 1
      ELSE 0
    END
  ) AS findings_masvs_unmapped,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'high'
    THEN 1 ELSE 0 END
  ) AS network_high,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'medium'
    THEN 1 ELSE 0 END
  ) AS network_medium,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'low'
    THEN 1 ELSE 0 END
  ) AS network_low,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'info'
    THEN 1 ELSE 0 END
  ) AS network_info,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
      )
    THEN 1 ELSE 0 END
  ) AS network_mapped_count,
  CASE
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
        )
        THEN 1 ELSE 0 END
    ) = 0 THEN 'NO DATA'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'high'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'FAIL'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'NETWORK'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'NETWORK-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'medium'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'WARN'
    ELSE 'PASS'
  END AS masvs_network_status,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'high'
    THEN 1 ELSE 0 END
  ) AS platform_high,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'medium'
    THEN 1 ELSE 0 END
  ) AS platform_medium,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'low'
    THEN 1 ELSE 0 END
  ) AS platform_low,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'info'
    THEN 1 ELSE 0 END
  ) AS platform_info,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
      )
    THEN 1 ELSE 0 END
  ) AS platform_mapped_count,
  CASE
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
        )
        THEN 1 ELSE 0 END
    ) = 0 THEN 'NO DATA'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'high'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'FAIL'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PLATFORM'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PLATFORM-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'medium'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'WARN'
    ELSE 'PASS'
  END AS masvs_platform_status,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'high'
    THEN 1 ELSE 0 END
  ) AS privacy_high,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'medium'
    THEN 1 ELSE 0 END
  ) AS privacy_medium,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'low'
    THEN 1 ELSE 0 END
  ) AS privacy_low,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'info'
    THEN 1 ELSE 0 END
  ) AS privacy_info,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
      )
    THEN 1 ELSE 0 END
  ) AS privacy_mapped_count,
  CASE
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
        )
        THEN 1 ELSE 0 END
    ) = 0 THEN 'NO DATA'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'high'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'FAIL'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'PRIVACY'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'PRIVACY-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'medium'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'WARN'
    ELSE 'PASS'
  END AS masvs_privacy_status,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'high'
    THEN 1 ELSE 0 END
  ) AS storage_high,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'medium'
    THEN 1 ELSE 0 END
  ) AS storage_medium,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'low'
    THEN 1 ELSE 0 END
  ) AS storage_low,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
      )
       AND LOWER(COALESCE(saf.severity, '')) = 'info'
    THEN 1 ELSE 0 END
  ) AS storage_info,
  SUM(
    CASE
      WHEN (
           NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
        OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
      )
       AND (
            UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
         OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
      )
    THEN 1 ELSE 0 END
  ) AS storage_mapped_count,
  CASE
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
        )
        THEN 1 ELSE 0 END
    ) = 0 THEN 'NO DATA'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'high'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'FAIL'
    WHEN SUM(
      CASE
        WHEN (
             NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
          OR NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NOT NULL
        )
         AND (
              UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) = 'STORAGE'
           OR UPPER(TRIM(COALESCE(saf.masvs_area, saf.masvs_control, ''))) LIKE 'STORAGE-%'
        )
         AND LOWER(COALESCE(saf.severity, '')) = 'medium'
        THEN 1 ELSE 0 END
    ) > 0 THEN 'WARN'
    ELSE 'PASS'
  END AS masvs_storage_status
FROM static_analysis_runs sar
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id
LEFT JOIN static_analysis_findings saf ON saf.run_id = sar.id
GROUP BY
  sar.id,
  sar.session_stamp,
  sar.session_label,
  a.id,
  a.package_name,
  a.display_name;
"""

CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1 = """
CREATE OR REPLACE VIEW v_static_masvs_session_summary_v1 AS
SELECT
  m.session_stamp,
  COUNT(*) AS static_run_rows,
  COUNT(DISTINCT m.package_name) AS distinct_packages,
  SUM(m.findings_total) AS findings_total_all_runs,
  SUM(m.findings_masvs_mapped) AS findings_mapped_all_runs,
  SUM(m.findings_masvs_unmapped) AS findings_unmapped_all_runs,
  SUM(CASE WHEN m.masvs_network_status = 'NO DATA' THEN 1 ELSE 0 END) AS runs_network_no_data,
  SUM(CASE WHEN m.masvs_platform_status = 'NO DATA' THEN 1 ELSE 0 END) AS runs_platform_no_data,
  SUM(CASE WHEN m.masvs_privacy_status = 'NO DATA' THEN 1 ELSE 0 END) AS runs_privacy_no_data,
  SUM(CASE WHEN m.masvs_storage_status = 'NO DATA' THEN 1 ELSE 0 END) AS runs_storage_no_data,
  SUM(CASE WHEN m.masvs_network_status = 'FAIL' THEN 1 ELSE 0 END) AS runs_network_fail,
  SUM(CASE WHEN m.masvs_platform_status = 'FAIL' THEN 1 ELSE 0 END) AS runs_platform_fail,
  SUM(CASE WHEN m.masvs_privacy_status = 'FAIL' THEN 1 ELSE 0 END) AS runs_privacy_fail,
  SUM(CASE WHEN m.masvs_storage_status = 'FAIL' THEN 1 ELSE 0 END) AS runs_storage_fail
FROM v_static_masvs_matrix_v1 m
GROUP BY m.session_stamp;
"""

CREATE_V_STATIC_RISK_SURFACES_V1 = """
CREATE OR REPLACE VIEW v_static_risk_surfaces_v1 AS
SELECT
  latest.package_name,
  COALESCE(NULLIF(a.display_name, ''), latest.package_name) AS app_label,
  latest.static_run_id,
  latest.session_stamp,
  latest.session_label,
  latest.version_name,
  latest.version_code,
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
  'canonical_static_v1' AS static_risk_surface_version,
  'no_legacy_runs_or_buckets' AS legacy_mirror_state
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
  ON audit_snapshot.snapshot_id = audit.snapshot_id;
"""

__all__ = [
    "CREATE_VW_STATIC_RISK_SURFACES_LATEST",
    "CREATE_VW_STATIC_FINDING_SURFACES_LATEST",
    "CREATE_VW_STATIC_MODULE_COVERAGE",
    "CREATE_VW_STORAGE_SURFACE_RISK",
    "CREATE_V_MASVS_MATRIX",
    "CREATE_V_STATIC_HANDOFF_V1",
    "CREATE_V_STATIC_MASVS_FINDINGS_V1",
    "CREATE_V_STATIC_MASVS_MATRIX_V1",
    "CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1",
    "CREATE_V_STATIC_RISK_SURFACES_V1",
]
