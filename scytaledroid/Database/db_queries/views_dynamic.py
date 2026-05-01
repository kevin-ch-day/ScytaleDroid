"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

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

__all__ = [
    "CREATE_VW_DYNLOAD_HOTSPOTS",
    "CREATE_V_RUNTIME_DYNAMIC_COHORT_STATUS_V1",
    "CREATE_V_PAPER_DYNAMIC_COHORT_V1",
]
