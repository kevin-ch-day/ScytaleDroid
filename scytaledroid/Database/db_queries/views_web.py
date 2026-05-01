"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_V_WEB_APP_DIRECTORY = """
CREATE OR REPLACE VIEW v_web_app_directory AS
SELECT
  pkg.package_name,
  COALESCE(NULLIF(a.display_name, ''), latest_risk.app_label, latest_static.app_label, pkg.package_name) AS app_label,
  COALESCE(cat.category_name, 'Uncategorized') AS category,
  a.profile_key,
  COALESCE(ap.display_name, a.profile_key, 'Unclassified') AS profile_label,
  COALESCE(latest_risk.permission_audit_grade, latest_risk.permission_run_grade) AS grade,
  COALESCE(latest_risk.permission_audit_score_capped, latest_risk.permission_run_score) AS score_capped,
  COALESCE(
    latest_risk.permission_audit_created_at,
    latest_static.summary_created_at,
    latest_static_run.created_at
  ) AS last_scanned,
  COALESCE(
    latest_static.session_stamp,
    latest_static_run.session_stamp,
    latest_risk.permission_audit_session_stamp,
    latest_risk.session_stamp
  ) AS session_stamp,
  COALESCE(latest_static.canonical_high, 0) AS high,
  COALESCE(latest_static.canonical_med, 0) AS med,
  COALESCE(latest_static.canonical_low, 0) AS low,
  COALESCE(latest_static.canonical_info, 0) AS info,
  CASE
    WHEN latest_static.package_name IS NOT NULL AND latest_risk.package_name IS NOT NULL
         AND latest_risk.permission_audit_snapshot_id IS NOT NULL
      THEN 'static_findings+risk+permission_audit'
    WHEN latest_static.package_name IS NOT NULL AND latest_risk.package_name IS NOT NULL
      THEN 'static_findings+risk'
    WHEN latest_static.package_name IS NOT NULL
      THEN 'static_findings'
    WHEN latest_risk.package_name IS NOT NULL AND latest_risk.permission_audit_snapshot_id IS NOT NULL
      THEN 'permission_audit_only'
    WHEN latest_risk.package_name IS NOT NULL
      THEN 'risk_score_only'
    ELSE 'catalog_only'
  END AS source_state
FROM (
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name
  FROM apps
  UNION
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name
  FROM vw_static_risk_surfaces_latest
  UNION
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name
  FROM vw_static_finding_surfaces_latest
) pkg
LEFT JOIN apps a
  ON a.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN android_app_categories cat
  ON cat.category_id = a.category_id
LEFT JOIN android_app_profiles ap
  ON ap.profile_key = a.profile_key
LEFT JOIN vw_static_risk_surfaces_latest latest_risk
  ON latest_risk.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN vw_static_finding_surfaces_latest latest_static
  ON latest_static.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
-- Canonical preference contract:
-- UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
-- UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
-- UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'
-- UPPER(COALESCE(sar3.run_class, '')) = 'CANONICAL'
LEFT JOIN (
  SELECT sar2.*, a2.package_name AS package_name_lc
  FROM static_analysis_runs sar2
  JOIN app_versions av2 ON av2.id = sar2.app_version_id
  JOIN apps a2 ON a2.id = av2.app_id
  JOIN (
    SELECT a3.package_name,
           COALESCE(
             MAX(CASE
               WHEN UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'
                AND UPPER(COALESCE(sar3.run_class, '')) = 'CANONICAL'
               THEN sar3.id
             END),
             MAX(CASE
               WHEN UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'
               THEN sar3.id
             END),
             MAX(sar3.id)
           ) AS preferred_id
    FROM static_analysis_runs sar3
    JOIN app_versions av3 ON av3.id = sar3.app_version_id
    JOIN apps a3 ON a3.id = av3.app_id
    GROUP BY a3.package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_unicode_ci = a2.package_name COLLATE utf8mb4_unicode_ci
   AND latest.preferred_id = sar2.id
) latest_static_run
  ON latest_static_run.package_name_lc COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci;
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

CREATE_V_WEB_STATIC_SESSION_HEALTH = """
CREATE OR REPLACE VIEW v_web_static_session_health AS
SELECT
  session_rollup.session_stamp,
  session_rollup.created_at,
  session_rollup.status,
  session_rollup.session_type_key,
  session_rollup.session_type_label,
  session_rollup.session_hidden_by_default,
  session_rollup.app_runs,
  session_rollup.findings_ready,
  session_rollup.permissions_ready,
  session_rollup.strings_ready,
  session_rollup.audit_ready,
  session_rollup.link_ready,
  CASE
    WHEN UPPER(COALESCE(session_rollup.status, '')) IN ('FAILED', 'ABORTED') THEN 'failed'
    WHEN UPPER(COALESCE(session_rollup.status, '')) IN ('IN_PROGRESS', 'STARTED', 'RUNNING', 'SCANNED', 'PERSISTING')
      AND session_rollup.findings_ready = 0
      AND session_rollup.permissions_ready = 0
      AND session_rollup.strings_ready = 0
      AND session_rollup.audit_ready = 0
      THEN 'in_progress_no_rows'
    WHEN UPPER(COALESCE(session_rollup.status, '')) = 'COMPLETED'
      AND session_rollup.app_runs > 0
      AND session_rollup.findings_ready = session_rollup.app_runs
      AND session_rollup.permissions_ready = session_rollup.app_runs
      AND session_rollup.strings_ready = session_rollup.app_runs
      THEN 'usable_complete'
    WHEN UPPER(COALESCE(session_rollup.status, '')) = 'COMPLETED' THEN 'partial_rows'
    ELSE 'partial_rows'
  END AS session_usability,
  CASE
    WHEN UPPER(COALESCE(session_rollup.status, '')) = 'COMPLETED'
      AND session_rollup.app_runs > 0
      AND session_rollup.findings_ready = session_rollup.app_runs
      AND session_rollup.permissions_ready = session_rollup.app_runs
      AND session_rollup.strings_ready = session_rollup.app_runs
      THEN 1
    ELSE 0
  END AS is_usable_complete
FROM (
  SELECT
    sar.session_stamp,
    MAX(sar.created_at) AS created_at,
    CASE
      WHEN SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) IN ('FAILED', 'ABORTED') THEN 1 ELSE 0 END) > 0
        THEN 'FAILED'
      WHEN SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) IN ('STARTED', 'RUNNING', 'SCANNED', 'PERSISTING') THEN 1 ELSE 0 END) > 0
           AND SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END) = 0
        THEN 'IN_PROGRESS'
      WHEN SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) IN ('STARTED', 'RUNNING', 'SCANNED', 'PERSISTING') THEN 1 ELSE 0 END) > 0
           AND SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END) > 0
        THEN 'PARTIAL'
      WHEN SUM(CASE WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END) = COUNT(*)
        THEN 'COMPLETED'
      ELSE MAX(COALESCE(sar.status, 'UNKNOWN'))
    END AS status,
    CASE
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%static-batch%'
        THEN 'qa'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%smoke%'
        THEN 'smoke'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rerun%'
        THEN 'rerun'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%fast%'
        THEN 'fast'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%single%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%one-app%'
        THEN 'single_app'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%all-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rda-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%full%'
        THEN 'full'
      ELSE 'session'
    END AS session_type_key,
    CASE
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%static-batch%'
        THEN 'QA / Debug'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%smoke%'
        THEN 'Smoke'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rerun%'
        THEN 'Rerun'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%fast%'
        THEN 'Fast'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%single%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%one-app%'
        THEN 'Single App'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%all-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rda-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%full%'
        THEN 'Full'
      ELSE 'Session'
    END AS session_type_label,
    CASE
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%static-batch%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%smoke%'
        THEN 1
      ELSE 0
    END AS session_hidden_by_default,
    COUNT(*) AS app_runs,
    SUM(CASE WHEN COALESCE(f.c, 0) > 0 THEN 1 ELSE 0 END) AS findings_ready,
    SUM(CASE WHEN COALESCE(pm.c, 0) > 0 THEN 1 ELSE 0 END) AS permissions_ready,
    SUM(CASE WHEN COALESCE(ss.c, 0) > 0 THEN 1 ELSE 0 END) AS strings_ready,
    SUM(CASE WHEN COALESCE(pa.c, 0) > 0 THEN 1 ELSE 0 END) AS audit_ready,
    SUM(CASE WHEN COALESCE(links.c, 0) > 0 THEN 1 ELSE 0 END) AS link_ready
  FROM static_analysis_runs sar
  JOIN app_versions av
    ON av.id = sar.app_version_id
  JOIN apps a
    ON a.id = av.app_id
  LEFT JOIN (
    SELECT run_id, COUNT(*) AS c
    FROM static_analysis_findings
    GROUP BY run_id
  ) f
    ON f.run_id = sar.id
  LEFT JOIN (
    SELECT run_id, COUNT(*) AS c
    FROM static_permission_matrix
    GROUP BY run_id
  ) pm
    ON pm.run_id = sar.id
  LEFT JOIN (
    SELECT package_name, session_stamp, COUNT(*) AS c
    FROM static_string_summary
    GROUP BY package_name, session_stamp
  ) ss
    ON ss.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
   AND ss.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
  LEFT JOIN (
    SELECT static_run_id, COUNT(*) AS c
    FROM permission_audit_apps
    GROUP BY static_run_id
  ) pa
    ON pa.static_run_id = sar.id
  LEFT JOIN (
    SELECT static_run_id, COUNT(*) AS c
    FROM static_session_run_links
    GROUP BY static_run_id
  ) links
    ON links.static_run_id = sar.id
  GROUP BY sar.session_stamp
) session_rollup;
"""

CREATE_V_WEB_APP_SESSIONS = """
CREATE OR REPLACE VIEW v_web_app_sessions AS
SELECT
  session_rows.*,
  ROW_NUMBER() OVER (
    PARTITION BY session_rows.package_name
    ORDER BY
      CASE session_rows.session_usability
        WHEN 'usable_complete' THEN 1
        WHEN 'partial_rows' THEN 2
        WHEN 'in_progress_no_rows' THEN 3
        WHEN 'failed' THEN 4
        ELSE 5
      END,
      session_rows.created_at DESC,
      session_rows.static_run_id DESC
  ) AS session_preference_rank,
  ROW_NUMBER() OVER (
    PARTITION BY session_rows.package_name
    ORDER BY session_rows.created_at DESC, session_rows.static_run_id DESC
  ) AS session_recency_rank
FROM (
  SELECT
    a.package_name,
    sar.id AS static_run_id,
    sar.session_stamp,
    sar.created_at,
    COALESCE(sar.status, 'UNKNOWN') AS run_status,
    sar.profile,
    CASE
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%static-batch%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%static-batch%'
        THEN 'qa'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%smoke%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%smoke%'
        THEN 'smoke'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rerun%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%rerun%'
        THEN 'rerun'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%fast%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%fast%'
        THEN 'fast'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%single%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%single%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%one-app%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%one-app%'
        THEN 'single_app'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%all-full%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%all-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rda-full%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%rda-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%full%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%full%'
        THEN 'full'
      ELSE 'session'
    END AS session_type_key,
    CASE
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%static-batch%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%static-batch%'
        THEN 'QA / Debug'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%smoke%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%smoke%'
        THEN 'Smoke'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rerun%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%rerun%'
        THEN 'Rerun'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%fast%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%fast%'
        THEN 'Fast'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%single%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%single%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%one-app%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%one-app%'
        THEN 'Single App'
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%all-full%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%all-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%rda-full%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%rda-full%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%full%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%full%'
        THEN 'Full'
      ELSE 'Session'
    END AS session_type_label,
    CASE
      WHEN LOWER(COALESCE(sar.session_stamp, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%qa%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%headless%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%stability%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%debug%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%static-batch%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%static-batch%'
        OR LOWER(COALESCE(sar.session_stamp, '')) LIKE '%smoke%'
        OR LOWER(COALESCE(sar.profile, '')) LIKE '%smoke%'
        THEN 1
      ELSE 0
    END AS session_hidden_by_default,
    COALESCE(cf.findings_total, 0) AS findings_total,
    sar.non_canonical_reasons,
    COALESCE(cf.high, 0) AS high,
    COALESCE(cf.med, 0) AS med,
    COALESCE(cf.low, 0) AS low,
    COALESCE(cf.info, 0) AS info,
    COALESCE(pm.permission_rows, 0) AS permission_rows,
    COALESCE(sss.high_entropy, 0) AS high_entropy,
    COALESCE(sss.endpoints, 0) AS endpoints,
    COALESCE(sss.string_rows, 0) AS string_rows,
    audits.grade,
    audits.score_capped,
    audits.audit_created_at,
    COALESCE(audits.audit_rows, 0) AS audit_rows,
    COALESCE(audits.dangerous_count, 0) AS dangerous_count,
    COALESCE(audits.signature_count, 0) AS signature_count,
    COALESCE(audits.vendor_count, 0) AS vendor_count,
    COALESCE(links.link_rows, 0) AS link_rows,
    CASE
      WHEN UPPER(COALESCE(sar.status, '')) IN ('FAILED', 'ABORTED') THEN 'failed'
      WHEN UPPER(COALESCE(sar.status, '')) IN ('STARTED', 'RUNNING', 'SCANNED', 'PERSISTING')
        AND COALESCE(cf.findings_total, 0) = 0
        AND COALESCE(pm.permission_rows, 0) = 0
        AND COALESCE(sss.string_rows, 0) = 0
        AND COALESCE(audits.audit_rows, 0) = 0
        THEN 'in_progress_no_rows'
      WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
        AND COALESCE(cf.findings_total, 0) > 0
        AND COALESCE(pm.permission_rows, 0) > 0
        AND COALESCE(sss.string_rows, 0) > 0
        THEN 'usable_complete'
      WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED' THEN 'partial_rows'
      ELSE 'partial_rows'
    END AS session_usability,
    CASE
      WHEN UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
        AND COALESCE(cf.findings_total, 0) > 0
        AND COALESCE(pm.permission_rows, 0) > 0
        AND COALESCE(sss.string_rows, 0) > 0
        THEN 1
      ELSE 0
    END AS is_usable_complete
  FROM static_analysis_runs sar
  JOIN app_versions av
    ON av.id = sar.app_version_id
  JOIN apps a
    ON a.id = av.app_id
  LEFT JOIN (
    SELECT
      run_id,
      COUNT(*) AS findings_total,
      SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'high' THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'medium' THEN 1 ELSE 0 END) AS med,
      SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'low' THEN 1 ELSE 0 END) AS low,
      SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'info' THEN 1 ELSE 0 END) AS info
    FROM static_analysis_findings
    GROUP BY run_id
  ) cf
    ON cf.run_id = sar.id
  LEFT JOIN (
    SELECT
      run_id,
      COUNT(*) AS permission_rows
    FROM static_permission_matrix
    GROUP BY run_id
  ) pm
    ON pm.run_id = sar.id
  LEFT JOIN (
    SELECT
      package_name,
      session_stamp,
      COUNT(*) AS string_rows,
      MAX(high_entropy) AS high_entropy,
      MAX(endpoints) AS endpoints
    FROM static_string_summary
    GROUP BY package_name, session_stamp
  ) sss
    ON sss.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
   AND sss.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
  LEFT JOIN (
    SELECT
      pa.static_run_id,
      COUNT(*) AS audit_rows,
      MAX(pa.grade) AS grade,
      MAX(pa.score_capped) AS score_capped,
      MAX(pa.dangerous_count) AS dangerous_count,
      MAX(pa.signature_count) AS signature_count,
      MAX(pa.vendor_count) AS vendor_count,
      MAX(pas.created_at) AS audit_created_at
    FROM permission_audit_apps pa
    JOIN permission_audit_snapshots pas
      ON pas.snapshot_id = pa.snapshot_id
    GROUP BY pa.static_run_id
  ) audits
    ON audits.static_run_id = sar.id
  LEFT JOIN (
    SELECT
      static_run_id,
      COUNT(*) AS link_rows
    FROM static_session_run_links
    GROUP BY static_run_id
  ) links
    ON links.static_run_id = sar.id
) session_rows;
"""

CREATE_V_WEB_APP_FINDINGS = """
CREATE OR REPLACE VIEW v_web_app_findings AS
SELECT
  latest.package_name,
  latest.app_label,
  a.profile_key,
  COALESCE(ap.display_name, a.profile_key, 'Unclassified') AS profile_label,
  a.publisher_key,
  latest.static_run_id,
  latest.session_stamp,
  latest.session_label,
  latest.version_name,
  latest.version_code,
  f.id AS finding_id,
  LOWER(COALESCE(f.severity, 'info')) AS severity,
  COALESCE(f.title, 'Untitled finding') AS title,
  COALESCE(f.category, 'Uncategorized') AS category,
  COALESCE(f.masvs_area, 'Unmapped') AS masvs_area,
  COALESCE(f.detector, 'unknown') AS detector,
  f.evidence,
  f.fix,
  f.created_at
FROM vw_static_finding_surfaces_latest latest
LEFT JOIN apps a
  ON a.package_name COLLATE utf8mb4_unicode_ci = latest.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN android_app_profiles ap
  ON ap.profile_key = a.profile_key
JOIN static_analysis_findings f
  ON f.run_id = latest.static_run_id;
"""

CREATE_V_WEB_APP_PERMISSIONS = """
CREATE OR REPLACE VIEW v_web_app_permissions AS
SELECT
  a.package_name,
  sar.id AS static_run_id,
  sar.session_stamp,
  spm.permission_name,
  spm.source,
  CASE
    WHEN COALESCE(spm.is_custom, 0) = 0
      AND spm.permission_name LIKE 'android.permission.%'
      THEN 'Framework'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND (
        spm.permission_name LIKE 'com.android.launcher.%'
        OR spm.permission_name LIKE 'com.android.launcher3.%'
        OR spm.permission_name LIKE 'com.htc.launcher.%'
        OR spm.permission_name LIKE 'com.huawei.android.launcher.%'
        OR spm.permission_name LIKE 'com.huawei.appmarket.%'
        OR spm.permission_name LIKE 'com.oppo.launcher.%'
        OR spm.permission_name LIKE 'com.sonyericsson.home.%'
        OR spm.permission_name LIKE 'com.sonymobile.home.%'
        OR spm.permission_name LIKE 'com.sonymobile.launcher.%'
        OR spm.permission_name LIKE 'com.anddoes.launcher.%'
        OR spm.permission_name LIKE 'com.majeur.launcher.%'
        OR spm.permission_name LIKE 'com.zui.launcher.%'
        OR spm.permission_name LIKE 'com.lge.launcher3.%'
        OR spm.permission_name LIKE 'net.oneplus.launcher.%'
        OR spm.permission_name LIKE 'me.everything.badger.%'
      )
      THEN 'Launcher / Badge Ecosystem'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND (
        spm.permission_name LIKE 'com.amazon.%'
        OR spm.permission_name LIKE 'amazon.%'
        OR spm.permission_name LIKE 'amazon.permission.%'
        OR spm.permission_name LIKE 'amazon.speech.%'
      )
      THEN 'Amazon Ecosystem'
    WHEN spm.permission_name LIKE 'com.google.android.%'
      OR spm.permission_name LIKE 'com.google.%'
      OR spm.permission_name LIKE 'com.android.vending.%'
      OR COALESCE(spm.source, '') = 'play_services'
      THEN 'Google / Platform Adjacent'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND (
        spm.permission_name LIKE 'com.facebook.%'
        OR spm.permission_name LIKE 'com.instagram.%'
      )
      THEN 'Meta Ecosystem'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND (
        spm.permission_name LIKE 'com.android.%'
        OR spm.permission_name LIKE 'android.car.permission.%'
        OR spm.permission_name LIKE 'android.Manifest.permission.%'
        OR spm.permission_name LIKE 'androidx.car.app.%'
        OR spm.permission_name LIKE 'org.chromium.arc.%'
      )
      THEN 'Android Platform Adjacent'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND (
        spm.permission_name LIKE 'bbc.%'
        OR spm.permission_name LIKE 'uk.co.bbc.%'
      )
      THEN 'Publisher Ecosystem'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND (
        spm.permission_name LIKE 'com.sec.%'
        OR spm.permission_name LIKE 'com.samsung.%'
        OR spm.permission_name LIKE 'com.motorola.%'
        OR spm.permission_name LIKE 'com.tmobile.%'
        OR spm.permission_name LIKE 'com.verizon.%'
        OR spm.permission_name LIKE 'com.att.%'
        OR spm.permission_name LIKE 'com.sprint.%'
        OR spm.permission_name LIKE 'com.qualcomm.%'
        OR spm.permission_name LIKE 'com.amazon.device.%'
        OR spm.permission_name LIKE 'com.amazon.dcp.%'
      )
      THEN 'Vendor / OEM'
    WHEN COALESCE(spm.is_custom, 0) = 1
      AND LOWER(CONVERT(spm.permission_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
          LIKE CONCAT(
            LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci,
            '.%'
          )
      THEN 'App Defined Internal'
    WHEN COALESCE(spm.is_custom, 0) = 1
      THEN 'Unknown Custom'
    ELSE 'Framework / Other'
  END AS source_family,
  CASE
    WHEN COALESCE(spm.is_custom, 0) = 0 THEN NULL
    WHEN (
      spm.permission_name LIKE 'com.android.launcher.%'
      OR spm.permission_name LIKE 'com.android.launcher3.%'
      OR spm.permission_name LIKE 'com.htc.launcher.%'
      OR spm.permission_name LIKE 'com.huawei.android.launcher.%'
      OR spm.permission_name LIKE 'com.huawei.appmarket.%'
      OR spm.permission_name LIKE 'com.oppo.launcher.%'
      OR spm.permission_name LIKE 'com.sonyericsson.home.%'
      OR spm.permission_name LIKE 'com.sonymobile.home.%'
      OR spm.permission_name LIKE 'com.sonymobile.launcher.%'
      OR spm.permission_name LIKE 'com.anddoes.launcher.%'
      OR spm.permission_name LIKE 'com.majeur.launcher.%'
      OR spm.permission_name LIKE 'com.zui.launcher.%'
      OR spm.permission_name LIKE 'com.lge.launcher3.%'
      OR spm.permission_name LIKE 'net.oneplus.launcher.%'
      OR spm.permission_name LIKE 'me.everything.badger.%'
    ) THEN 'launcher_badge'
    WHEN (
      spm.permission_name LIKE 'com.amazon.%'
      OR spm.permission_name LIKE 'amazon.%'
      OR spm.permission_name LIKE 'amazon.permission.%'
      OR spm.permission_name LIKE 'amazon.speech.%'
    ) THEN 'amazon_ecosystem'
    WHEN LOWER(CONVERT(spm.permission_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
        LIKE CONCAT(
          LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci,
          '.%'
        )
      THEN 'app_defined_internal'
    WHEN spm.permission_name LIKE 'com.facebook.%'
      OR spm.permission_name LIKE 'com.instagram.%'
      THEN 'meta_ecosystem'
    WHEN spm.permission_name LIKE 'com.google.android.%'
      OR spm.permission_name LIKE 'com.google.%'
      OR spm.permission_name LIKE 'com.android.vending.%'
      OR COALESCE(spm.source, '') = 'play_services'
      THEN 'google_platform_adjacent'
    WHEN spm.permission_name LIKE 'com.android.%'
      OR spm.permission_name LIKE 'android.car.permission.%'
      OR spm.permission_name LIKE 'android.Manifest.permission.%'
      OR spm.permission_name LIKE 'androidx.car.app.%'
      OR spm.permission_name LIKE 'org.chromium.arc.%'
      THEN 'android_platform_adjacent'
    WHEN spm.permission_name LIKE 'bbc.%'
      OR spm.permission_name LIKE 'uk.co.bbc.%'
      THEN 'publisher_ecosystem'
    WHEN spm.permission_name LIKE 'com.sec.%'
      OR spm.permission_name LIKE 'com.samsung.%'
      OR spm.permission_name LIKE 'com.motorola.%'
      OR spm.permission_name LIKE 'com.tmobile.%'
      OR spm.permission_name LIKE 'com.verizon.%'
      OR spm.permission_name LIKE 'com.att.%'
      OR spm.permission_name LIKE 'com.sprint.%'
      OR spm.permission_name LIKE 'com.qualcomm.%'
      OR spm.permission_name LIKE 'com.amazon.device.%'
      OR spm.permission_name LIKE 'com.amazon.dcp.%'
      THEN 'vendor_oem'
    ELSE 'unknown_custom'
  END AS custom_family,
  spm.protection,
  spm.severity,
  spm.is_runtime_dangerous,
  spm.is_signature,
  spm.is_privileged,
  spm.is_special_access,
  spm.is_custom
FROM static_permission_matrix spm
JOIN static_analysis_runs sar
  ON sar.id = spm.run_id
JOIN app_versions av
  ON av.id = sar.app_version_id
JOIN apps a
  ON a.id = av.app_id;
"""

CREATE_V_WEB_APP_PERMISSION_SUMMARY = """
CREATE OR REPLACE VIEW v_web_app_permission_summary AS
SELECT
  package_name,
  static_run_id,
  session_stamp,
  COUNT(*) AS permission_rows,
  SUM(CASE WHEN COALESCE(is_runtime_dangerous, 0) = 1 THEN 1 ELSE 0 END) AS dangerous_count,
  SUM(CASE WHEN COALESCE(is_signature, 0) = 1 THEN 1 ELSE 0 END) AS signature_count,
  SUM(CASE WHEN COALESCE(is_privileged, 0) = 1 THEN 1 ELSE 0 END) AS privileged_count,
  SUM(CASE WHEN COALESCE(is_special_access, 0) = 1 THEN 1 ELSE 0 END) AS special_access_count,
  SUM(CASE WHEN COALESCE(is_custom, 0) = 1 THEN 1 ELSE 0 END) AS custom_count,
  MAX(COALESCE(severity, 0)) AS max_weight
FROM v_web_app_permissions
GROUP BY package_name, static_run_id, session_stamp;
"""

CREATE_V_WEB_APP_STRING_SUMMARY = """
CREATE OR REPLACE VIEW v_web_app_string_summary AS
SELECT
  sss.id AS summary_id,
  sss.package_name,
  sss.session_stamp,
  sss.endpoints,
  sss.http_cleartext,
  sss.api_keys,
  sss.analytics_ids,
  sss.cloud_refs,
  sss.ipc,
  sss.uris,
  sss.flags,
  sss.certs,
  sss.high_entropy,
  sfs.details AS findings_details
FROM static_string_summary sss
LEFT JOIN static_findings_summary sfs
  ON sfs.package_name COLLATE utf8mb4_unicode_ci = sss.package_name COLLATE utf8mb4_unicode_ci
 AND sfs.session_stamp COLLATE utf8mb4_unicode_ci = sss.session_stamp COLLATE utf8mb4_unicode_ci;
"""

CREATE_V_WEB_APP_STRING_SAMPLES = """
CREATE OR REPLACE VIEW v_web_app_string_samples AS
SELECT
  summary.package_name,
  summary.session_stamp,
  summary.id AS summary_id,
  sss.bucket,
  sss.value_masked,
  sss.src,
  sss.tag,
  sss.source_type,
  sss.finding_type,
  sss.provider,
  sss.risk_tag,
  sss.confidence,
  sss.root_domain,
  sss.resource_name,
  sss.scheme,
  sss.rank,
  sss.id AS sample_id
FROM static_string_selected_samples sss
JOIN static_string_summary summary
  ON summary.id = sss.summary_id;
"""

CREATE_V_WEB_APP_COMPONENTS = """
CREATE OR REPLACE VIEW v_web_app_components AS
SELECT
  package_name,
  session_stamp,
  scope_label,
  authority,
  provider_name,
  component_name,
  exported,
  effective_guard,
  risk,
  read_permission,
  write_permission,
  base_permission,
  created_at
FROM static_fileproviders;
"""

CREATE_V_WEB_APP_COMPONENT_SUMMARY = """
CREATE OR REPLACE VIEW v_web_app_component_summary AS
SELECT
  fp.package_name,
  fp.session_stamp,
  COUNT(*) AS providers,
  SUM(CASE WHEN COALESCE(fp.exported, 0) = 1 THEN 1 ELSE 0 END) AS exported_providers,
  SUM(
    CASE
      WHEN COALESCE(fp.exported, 0) = 1
       AND LOWER(COALESCE(fp.effective_guard, '')) IN ('', 'none', 'weak')
      THEN 1 ELSE 0
    END
  ) AS weak_provider_guards,
  COALESCE(acl.acl_rows, 0) AS acl_rows
FROM static_fileproviders fp
LEFT JOIN (
  SELECT
    package_name,
    session_stamp,
    COUNT(*) AS acl_rows
  FROM static_provider_acl
  GROUP BY package_name, session_stamp
) acl
  ON acl.package_name COLLATE utf8mb4_unicode_ci = fp.package_name COLLATE utf8mb4_unicode_ci
 AND acl.session_stamp COLLATE utf8mb4_unicode_ci = fp.session_stamp COLLATE utf8mb4_unicode_ci
GROUP BY fp.package_name, fp.session_stamp, acl.acl_rows;
"""

CREATE_V_WEB_APP_COMPONENT_ACL = """
CREATE OR REPLACE VIEW v_web_app_component_acl AS
SELECT
  package_name,
  session_stamp,
  authority,
  provider_name,
  path,
  path_type,
  exported,
  read_guard,
  write_guard,
  read_perm,
  write_perm,
  base_perm,
  created_at
FROM static_provider_acl;
"""

CREATE_V_WEB_APP_REPORT_SUMMARY = """
CREATE OR REPLACE VIEW v_web_app_report_summary AS
SELECT
  sessions.package_name,
  sessions.static_run_id,
  sessions.session_stamp,
  sessions.created_at,
  sessions.run_status,
  sessions.profile,
  sessions.session_type_key,
  sessions.session_type_label,
  sessions.session_hidden_by_default,
  sessions.session_usability,
  sessions.is_usable_complete,
  sessions.non_canonical_reasons,
  sessions.grade,
  sessions.score_capped,
  sessions.audit_created_at,
  sessions.audit_rows,
  sessions.link_rows,
  sessions.findings_total,
  sessions.high,
  sessions.med,
  sessions.low,
  sessions.info,
  COALESCE(perm.permission_rows, sessions.permission_rows, 0) AS permission_rows,
  COALESCE(perm.dangerous_count, 0) AS dangerous_count,
  COALESCE(perm.signature_count, 0) AS signature_count,
  COALESCE(perm.privileged_count, 0) AS privileged_count,
  COALESCE(perm.special_access_count, 0) AS special_access_count,
  COALESCE(perm.custom_count, 0) AS custom_count,
  COALESCE(sessions.string_rows, 0) AS string_rows,
  COALESCE(strs.endpoints, sessions.endpoints, 0) AS endpoints,
  COALESCE(strs.http_cleartext, 0) AS http_cleartext,
  COALESCE(strs.api_keys, 0) AS api_keys,
  COALESCE(strs.analytics_ids, 0) AS analytics_ids,
  COALESCE(strs.cloud_refs, 0) AS cloud_refs,
  COALESCE(strs.ipc, 0) AS ipc,
  COALESCE(strs.uris, 0) AS uris,
  COALESCE(strs.flags, 0) AS flags,
  COALESCE(strs.certs, 0) AS certs,
  COALESCE(strs.high_entropy, sessions.high_entropy, 0) AS high_entropy,
  COALESCE(comps.providers, 0) AS providers,
  COALESCE(comps.exported_providers, 0) AS exported_providers,
  COALESCE(comps.weak_provider_guards, 0) AS weak_provider_guards,
  COALESCE(comps.acl_rows, 0) AS acl_rows
FROM v_web_app_sessions sessions
LEFT JOIN v_web_app_permission_summary perm
  ON perm.package_name COLLATE utf8mb4_unicode_ci = sessions.package_name COLLATE utf8mb4_unicode_ci
 AND perm.static_run_id = sessions.static_run_id
 AND perm.session_stamp COLLATE utf8mb4_unicode_ci = sessions.session_stamp COLLATE utf8mb4_unicode_ci
LEFT JOIN v_web_app_string_summary strs
  ON strs.package_name COLLATE utf8mb4_unicode_ci = sessions.package_name COLLATE utf8mb4_unicode_ci
 AND strs.session_stamp COLLATE utf8mb4_unicode_ci = sessions.session_stamp COLLATE utf8mb4_unicode_ci
LEFT JOIN v_web_app_component_summary comps
  ON comps.package_name COLLATE utf8mb4_unicode_ci = sessions.package_name COLLATE utf8mb4_unicode_ci
 AND comps.session_stamp COLLATE utf8mb4_unicode_ci = sessions.session_stamp COLLATE utf8mb4_unicode_ci;
"""

CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY = """
CREATE OR REPLACE VIEW v_web_static_dynamic_app_summary AS
SELECT
  pkg.package_name,
  COALESCE(NULLIF(a.display_name, ''), latest_risk.app_label, latest_static.app_label, pkg.package_name) AS app_label,
  COALESCE(cat.category_name, 'Uncategorized') AS category,
  a.profile_key,
  COALESCE(ap.display_name, a.profile_key, 'Unclassified') AS profile_label,
  a.publisher_key,
  latest_apk.apk_id AS latest_apk_id,
  latest_apk.sha256 AS latest_apk_sha256,
  latest_apk.version_name AS latest_version_name,
  latest_apk.version_code AS latest_version_code,
  latest_apk.harvested_at AS latest_harvested_at,
  COALESCE(latest_static_run.id, latest_static.static_run_id, latest_risk.static_run_id) AS latest_static_run_id,
  COALESCE(latest_static.session_stamp, latest_static_run.session_stamp, latest_risk.session_stamp) AS latest_static_session_stamp,
  CASE
    WHEN latest_static.package_name IS NOT NULL AND latest_risk.package_name IS NOT NULL THEN 'static+permission_audit'
    WHEN latest_static.package_name IS NOT NULL THEN 'static'
    WHEN latest_risk.package_name IS NOT NULL THEN 'permission_audit'
    ELSE 'catalog'
  END AS static_source_state,
  COALESCE(latest_static.canonical_high, 0) AS static_high,
  COALESCE(latest_static.canonical_med, 0) AS static_med,
  COALESCE(latest_static.canonical_low, 0) AS static_low,
  COALESCE(latest_static.canonical_info, 0) AS static_info,
  latest_risk.permission_audit_grade AS permission_audit_grade,
  latest_risk.permission_audit_score_capped AS permission_audit_score_capped,
  latest_risk.permission_audit_dangerous_count AS permission_audit_dangerous_count,
  latest_risk.permission_audit_signature_count AS permission_audit_signature_count,
  latest_risk.permission_audit_vendor_count AS permission_audit_vendor_count,
  latest_dynamic.dynamic_run_id AS latest_dynamic_run_id,
  latest_dynamic.started_at_utc AS latest_dynamic_started_at_utc,
  latest_dynamic.status AS latest_dynamic_status,
  latest_dynamic.grade AS latest_dynamic_grade,
  COALESCE(latest_dynamic.operator_run_profile, latest_nf.run_profile, latest_dynamic.profile_key, 'unknown') AS dynamic_run_profile,
  COALESCE(latest_dynamic.operator_interaction_level, latest_nf.interaction_level, 'unknown') AS dynamic_interaction_level,
  latest_feature_dynamic.dynamic_run_id AS latest_feature_dynamic_run_id,
  latest_feature_dynamic.started_at_utc AS latest_feature_dynamic_started_at_utc,
  latest_feature_dynamic.grade AS latest_feature_dynamic_grade,
  COALESCE(latest_feature_dynamic.operator_run_profile, latest_feature_nf.run_profile, latest_feature_dynamic.profile_key, 'unknown') AS latest_feature_run_profile,
  COALESCE(latest_feature_dynamic.operator_interaction_level, latest_feature_nf.interaction_level, 'unknown') AS latest_feature_interaction_level,
  latest_dynamic.valid_dataset_run AS dynamic_valid_dataset_run,
  latest_dynamic.invalid_reason_code AS dynamic_invalid_reason_code,
  CASE
    WHEN latest_dynamic.dynamic_run_id IS NULL THEN NULL
    WHEN latest_nf.dynamic_run_id IS NULL THEN 'missing_features'
    ELSE 'features_available'
  END AS dynamic_feature_state,
  CASE
    WHEN latest_dynamic.dynamic_run_id IS NULL THEN NULL
    WHEN latest_nf.dynamic_run_id IS NOT NULL THEN 'latest_run_has_features'
    WHEN latest_feature_dynamic.dynamic_run_id IS NOT NULL THEN 'latest_run_missing_features_older_features_exist'
    ELSE 'no_feature_rows_for_package'
  END AS dynamic_feature_recency_state,
  latest_nf.low_signal AS dynamic_low_signal,
  latest_nf.packet_count AS dynamic_packet_count,
  latest_nf.bytes_per_sec AS dynamic_bytes_per_sec,
  latest_nf.packets_per_sec AS dynamic_packets_per_sec,
  latest_feature_nf.low_signal AS latest_feature_dynamic_low_signal,
  latest_feature_nf.packet_count AS latest_feature_dynamic_packet_count,
  latest_feature_nf.bytes_per_sec AS latest_feature_dynamic_bytes_per_sec,
  latest_feature_nf.packets_per_sec AS latest_feature_dynamic_packets_per_sec,
  latest_regime.static_grade AS regime_static_grade,
  latest_regime.dynamic_grade_if AS regime_dynamic_grade,
  latest_regime.dynamic_score_if AS regime_dynamic_score,
  latest_regime.final_regime_if AS regime_final_label,
  latest_regime.created_at_utc AS regime_created_at_utc,
  CASE WHEN latest_static.package_name IS NOT NULL OR latest_risk.package_name IS NOT NULL OR latest_static_run.id IS NOT NULL THEN 1 ELSE 0 END AS has_static_data,
  CASE WHEN latest_dynamic.dynamic_run_id IS NOT NULL THEN 1 ELSE 0 END AS has_dynamic_data,
  CASE WHEN latest_regime.package_name IS NOT NULL THEN 1 ELSE 0 END AS has_regime_data,
  CASE
    WHEN (latest_static.package_name IS NOT NULL OR latest_risk.package_name IS NOT NULL OR latest_static_run.id IS NOT NULL)
         AND latest_dynamic.dynamic_run_id IS NOT NULL
         AND latest_regime.package_name IS NOT NULL THEN 'static+dynamic+regime'
    WHEN (latest_static.package_name IS NOT NULL OR latest_risk.package_name IS NOT NULL OR latest_static_run.id IS NOT NULL)
         AND latest_dynamic.dynamic_run_id IS NOT NULL THEN 'static+dynamic'
    WHEN (latest_static.package_name IS NOT NULL OR latest_risk.package_name IS NOT NULL OR latest_static_run.id IS NOT NULL) THEN 'static_only'
    WHEN latest_dynamic.dynamic_run_id IS NOT NULL THEN 'dynamic_only'
    ELSE 'catalog_only'
  END AS summary_state
FROM (
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name FROM apps
  UNION
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name FROM vw_static_finding_surfaces_latest
  UNION
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name FROM vw_static_risk_surfaces_latest
  UNION
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name FROM dynamic_sessions
  UNION
  SELECT package_name COLLATE utf8mb4_general_ci AS package_name FROM analysis_risk_regime_summary
) pkg
LEFT JOIN apps a
  ON a.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN android_app_categories cat
  ON cat.category_id = a.category_id
LEFT JOIN android_app_profiles ap
  ON ap.profile_key = a.profile_key
LEFT JOIN vw_latest_apk_per_package latest_apk
  ON latest_apk.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN vw_static_risk_surfaces_latest latest_risk
  ON latest_risk.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN vw_static_finding_surfaces_latest latest_static
  ON latest_static.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
-- Canonical preference contract:
-- UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
-- UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
-- UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'
-- UPPER(COALESCE(sar3.run_class, '')) = 'CANONICAL'
LEFT JOIN (
  SELECT sar2.*, a2.package_name AS package_name_lc
  FROM static_analysis_runs sar2
  JOIN app_versions av ON av.id = sar2.app_version_id
  JOIN apps a2 ON a2.id = av.app_id
  JOIN (
    SELECT a3.package_name,
           COALESCE(
             MAX(CASE
               WHEN UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'
                AND UPPER(COALESCE(sar3.run_class, '')) = 'CANONICAL'
               THEN sar3.id
             END),
             MAX(CASE
               WHEN UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'
               THEN sar3.id
             END),
             MAX(sar3.id)
           ) AS preferred_id
    FROM static_analysis_runs sar3
    JOIN app_versions av3 ON av3.id = sar3.app_version_id
    JOIN apps a3 ON a3.id = av3.app_id
    GROUP BY a3.package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_unicode_ci = a2.package_name COLLATE utf8mb4_unicode_ci
   AND latest.preferred_id = sar2.id
) latest_static_run
  ON latest_static_run.package_name_lc COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN (
  SELECT ds1.*
  FROM dynamic_sessions ds1
  JOIN (
    SELECT package_name, MAX(COALESCE(started_at_utc, created_at)) AS max_started
    FROM dynamic_sessions
    GROUP BY package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_unicode_ci = ds1.package_name COLLATE utf8mb4_unicode_ci
   AND latest.max_started = COALESCE(ds1.started_at_utc, ds1.created_at)
  JOIN (
    SELECT package_name, COALESCE(started_at_utc, created_at) AS started_marker, MAX(dynamic_run_id) AS max_run_id
    FROM dynamic_sessions
    GROUP BY package_name, COALESCE(started_at_utc, created_at)
  ) tie
    ON tie.package_name COLLATE utf8mb4_unicode_ci = ds1.package_name COLLATE utf8mb4_unicode_ci
   AND tie.started_marker = COALESCE(ds1.started_at_utc, ds1.created_at)
   AND tie.max_run_id = ds1.dynamic_run_id
) latest_dynamic
  ON latest_dynamic.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN dynamic_network_features latest_nf
  ON latest_nf.dynamic_run_id = latest_dynamic.dynamic_run_id
LEFT JOIN (
  SELECT dsf1.*
  FROM dynamic_sessions dsf1
  JOIN dynamic_network_features nff1
    ON nff1.dynamic_run_id = dsf1.dynamic_run_id
  JOIN (
    SELECT dsf.package_name, MAX(COALESCE(dsf.started_at_utc, dsf.created_at)) AS max_started
    FROM dynamic_sessions dsf
    JOIN dynamic_network_features nff
      ON nff.dynamic_run_id = dsf.dynamic_run_id
    GROUP BY dsf.package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_unicode_ci = dsf1.package_name COLLATE utf8mb4_unicode_ci
   AND latest.max_started = COALESCE(dsf1.started_at_utc, dsf1.created_at)
  JOIN (
    SELECT dsf.package_name, COALESCE(dsf.started_at_utc, dsf.created_at) AS started_marker, MAX(dsf.dynamic_run_id) AS max_run_id
    FROM dynamic_sessions dsf
    JOIN dynamic_network_features nff
      ON nff.dynamic_run_id = dsf.dynamic_run_id
    GROUP BY dsf.package_name, COALESCE(dsf.started_at_utc, dsf.created_at)
  ) tie
    ON tie.package_name COLLATE utf8mb4_unicode_ci = dsf1.package_name COLLATE utf8mb4_unicode_ci
   AND tie.started_marker = COALESCE(dsf1.started_at_utc, dsf1.created_at)
   AND tie.max_run_id = dsf1.dynamic_run_id
) latest_feature_dynamic
  ON latest_feature_dynamic.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN dynamic_network_features latest_feature_nf
  ON latest_feature_nf.dynamic_run_id = latest_feature_dynamic.dynamic_run_id
LEFT JOIN (
  SELECT rr.*
  FROM analysis_risk_regime_summary rr
  JOIN (
    SELECT package_name, MAX(created_at_utc) AS max_created
    FROM analysis_risk_regime_summary
    GROUP BY package_name
  ) latest
    ON latest.package_name COLLATE utf8mb4_unicode_ci = rr.package_name COLLATE utf8mb4_unicode_ci
   AND latest.max_created = rr.created_at_utc
) latest_regime
  ON latest_regime.package_name COLLATE utf8mb4_unicode_ci = pkg.package_name COLLATE utf8mb4_unicode_ci;
"""

__all__ = [
    "CREATE_V_WEB_APP_DIRECTORY",
    "CREATE_V_WEB_RUNTIME_RUN_INDEX",
    "CREATE_V_WEB_RUNTIME_RUN_DETAIL",
    "CREATE_V_WEB_STATIC_SESSION_HEALTH",
    "CREATE_V_WEB_APP_SESSIONS",
    "CREATE_V_WEB_APP_FINDINGS",
    "CREATE_V_WEB_APP_PERMISSIONS",
    "CREATE_V_WEB_APP_PERMISSION_SUMMARY",
    "CREATE_V_WEB_APP_STRING_SUMMARY",
    "CREATE_V_WEB_APP_STRING_SAMPLES",
    "CREATE_V_WEB_APP_COMPONENTS",
    "CREATE_V_WEB_APP_COMPONENT_SUMMARY",
    "CREATE_V_WEB_APP_COMPONENT_ACL",
    "CREATE_V_WEB_APP_REPORT_SUMMARY",
    "CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY",
]
