"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

from .sql_typed_reads import resolved_dynamic_session_static_run_id

CREATE_VW_DYNLOAD_HOTSPOTS = """
CREATE OR REPLACE VIEW vw_dynload_hotspots AS
SELECT e.package_name,
       CONVERT(e.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci AS session_stamp,
       e.apk_id,
       SUM(CASE WHEN e.event_type = 'classloader' THEN 1 ELSE 0 END) AS classloader_events,
       SUM(CASE WHEN e.event_type = 'native' THEN 1 ELSE 0 END) AS native_loads,
       COUNT(DISTINCT r.id) AS reflection_calls
FROM static_dynload_events AS e
LEFT JOIN static_reflection_calls AS r
  ON e.package_name = r.package_name
 AND CONVERT(e.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
   = CONVERT(r.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
 AND (e.apk_id = r.apk_id OR (e.apk_id IS NULL AND r.apk_id IS NULL))
GROUP BY e.package_name, e.session_stamp, e.apk_id
HAVING classloader_events > 0 AND reflection_calls > 0;
"""

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

CREATE_V_DYNAMIC_RUN_CONTEXT_V1 = """
CREATE OR REPLACE VIEW v_dynamic_run_context_v1 AS
SELECT
  ds.dynamic_run_id,
  ds.package_name,
  LOWER(TRIM(COALESCE(ds.package_name, ''))) AS package_name_lc,
  COALESCE(NULLIF(a.display_name, ''), ds.package_name) AS app_label,
  ds.device_serial,
  ds.profile_key,
  COALESCE(ds.operator_run_profile, nf.run_profile, ds.profile_key, 'unknown') AS effective_run_profile,
  COALESCE(ds.operator_interaction_level, nf.interaction_level, 'unknown') AS effective_interaction_level,
  ds.operator_messaging_activity,
  ds.scenario_id,
  ds.tier,
  ds.status AS workflow_status,
  ds.countable,
  ds.valid_dataset_run,
  ds.invalid_reason_code,
  adcs.paper_eligible AS cohort_paper_eligible,
  adcs.status AS cohort_status,
  adcs.reason_code AS cohort_reason_code,
  ds.duration_seconds,
  ds.started_at_utc,
  ds.ended_at_utc,
  ds.created_at,
  ds.static_run_id,
  {resolved_dynamic_static_run_id} AS effective_static_run_id,
  CASE
    WHEN {resolved_dynamic_static_run_id} IS NULL THEN 'missing_static_run_id'
    WHEN sar.id IS NULL THEN 'dangling_static_run_id'
    ELSE 'static_linked'
  END AS static_link_state,
  ds.static_handoff_hash,
  ds.apk_set_id,
  ds.base_apk_sha256,
  ds.artifact_set_hash,
  ds.version_name,
  ds.version_code,
  ds.pcap_relpath,
  ds.pcap_bytes,
  ds.pcap_valid,
  ds.network_signal_quality,
  nf.feature_schema_version,
  nf.low_signal,
  nf.low_signal_reasons_json,
  nf.capture_duration_s,
  nf.packet_count,
  nf.data_size_bytes,
  nf.bytes_per_sec,
  nf.packets_per_sec,
  nf.domains_per_min,
  nf.new_domain_rate_per_min,
  nf.new_sni_rate_per_min,
  nf.new_dns_rate_per_min,
  COALESCE(ctx.domain_observation_rows, 0) AS domain_observation_rows,
  COALESCE(ctx.distinct_observed_domains, 0) AS distinct_observed_domains,
  COALESCE(ctx.distinct_root_domains, 0) AS distinct_root_domains,
  COALESCE(ctx.first_party_domain_rows, 0) AS first_party_domain_rows,
  COALESCE(ctx.third_party_domain_rows, 0) AS third_party_domain_rows,
  COALESCE(ctx.unknown_domain_rows, 0) AS unknown_domain_rows,
  COALESCE(ctx.matched_service_count, 0) AS matched_service_count,
  COALESCE(ctx.matched_signal_count, 0) AS matched_signal_count,
  ctx.owner_classes_csv,
  ctx.role_classes_csv,
  ctx.service_keys_csv,
  ctx.signal_keys_csv
FROM dynamic_sessions ds
LEFT JOIN apps a
  ON CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_general_ci =
     CONVERT(ds.package_name USING utf8mb4) COLLATE utf8mb4_general_ci
LEFT JOIN dynamic_network_features nf
  ON nf.dynamic_run_id = ds.dynamic_run_id
LEFT JOIN analysis_dynamic_cohort_status adcs
  ON adcs.dynamic_run_id = ds.dynamic_run_id
LEFT JOIN static_analysis_runs sar
  ON sar.id = {resolved_dynamic_static_run_id}
LEFT JOIN (
  SELECT
    obs.dynamic_run_id,
    COUNT(*) AS domain_observation_rows,
    COUNT(DISTINCT obs.observed_domain) AS distinct_observed_domains,
    COUNT(DISTINCT obs.root_domain) AS distinct_root_domains,
    SUM(CASE WHEN LOWER(TRIM(COALESCE(obs.owner_class, ''))) = 'first_party' THEN 1 ELSE 0 END) AS first_party_domain_rows,
    SUM(CASE WHEN LOWER(TRIM(COALESCE(obs.owner_class, ''))) = 'third_party' THEN 1 ELSE 0 END) AS third_party_domain_rows,
    SUM(CASE
          WHEN LOWER(TRIM(COALESCE(obs.owner_class, ''))) IN ('first_party', 'third_party') THEN 0
          ELSE 1
        END) AS unknown_domain_rows,
    COUNT(DISTINCT svc.service_id) AS matched_service_count,
    COUNT(DISTINCT sig.signal_id) AS matched_signal_count,
    GROUP_CONCAT(DISTINCT obs.owner_class ORDER BY obs.owner_class SEPARATOR ',') AS owner_classes_csv,
    GROUP_CONCAT(DISTINCT obs.role_class ORDER BY obs.role_class SEPARATOR ',') AS role_classes_csv,
    GROUP_CONCAT(DISTINCT svc.service_key ORDER BY svc.service_key SEPARATOR ',') AS service_keys_csv,
    GROUP_CONCAT(DISTINCT sig.signal_key ORDER BY sig.signal_key SEPARATOR ',') AS signal_keys_csv
  FROM dynamic_domain_observations obs
  LEFT JOIN dynamic_service_domain_map sdm
    ON sdm.is_active = 1
   AND (
        LOWER(TRIM(COALESCE(sdm.package_name_scope, ''))) = ''
        OR CONVERT(sdm.package_name_scope USING utf8mb4) COLLATE utf8mb4_general_ci =
           CONVERT(obs.package_name USING utf8mb4) COLLATE utf8mb4_general_ci
   )
   AND (
        (
          UPPER(TRIM(COALESCE(sdm.match_type, ''))) = 'EXACT'
          AND LOWER(TRIM(COALESCE(obs.observed_domain, ''))) = LOWER(TRIM(COALESCE(sdm.domain_pattern, '')))
        )
        OR
        (
          UPPER(TRIM(COALESCE(sdm.match_type, ''))) = 'SUFFIX'
          AND (
            LOWER(TRIM(COALESCE(obs.observed_domain, ''))) = LOWER(TRIM(COALESCE(sdm.domain_pattern, '')))
            OR LOWER(TRIM(COALESCE(obs.observed_domain, ''))) LIKE
               CONCAT('%.', LOWER(TRIM(COALESCE(sdm.domain_pattern, ''))))
          )
        )
   )
  LEFT JOIN dynamic_service_catalog svc
    ON svc.service_id = sdm.service_id
   AND svc.is_active = 1
  LEFT JOIN dynamic_service_signal_map ssm
    ON ssm.service_id = svc.service_id
   AND ssm.is_active = 1
  LEFT JOIN dynamic_signal_catalog sig
    ON sig.signal_id = ssm.signal_id
   AND sig.is_active = 1
  GROUP BY obs.dynamic_run_id
) ctx
  ON ctx.dynamic_run_id = ds.dynamic_run_id;
""".format(
    resolved_dynamic_static_run_id=resolved_dynamic_session_static_run_id("ds"),
)

__all__ = [
    "CREATE_VW_DYNLOAD_HOTSPOTS",
    "CREATE_V_RUNTIME_DYNAMIC_COHORT_STATUS_V1",
    "CREATE_V_PAPER_DYNAMIC_COHORT_V1",
    "CREATE_V_DYNAMIC_RUN_CONTEXT_V1",
]
