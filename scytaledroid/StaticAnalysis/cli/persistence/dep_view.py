"""DEP canonical view helpers."""

from __future__ import annotations

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.LoggingUtils import logging_utils as log

CREATE_DEP_VIEW = """
CREATE OR REPLACE VIEW v_dep_static_profile AS
SELECT
  sar.id AS static_run_id,
  a.package_name,
  a.display_name,
  a.profile_key,
  av.version_code,
  av.version_name,
  av.min_sdk,
  av.target_sdk,
  sar.session_stamp,
  sar.scope_label,
  sar.category,
  sar.profile,
  sar.sha256,
  sar.base_apk_sha256,
  sar.artifact_set_hash,
  sar.run_signature,
  sar.run_signature_version,
  sar.identity_valid,
  sar.identity_error_reason,
  sar.findings_total,
  sar.status,
  sar.ended_at_utc,
  rs.risk_score,
  rs.risk_grade,
  rs.dangerous AS risk_dangerous,
  rs.signature AS risk_signature,
  rs.vendor AS risk_vendor,
  mtr.exports_total,
  mtr.exports_activities,
  mtr.exports_services,
  mtr.exports_receivers,
  mtr.exports_providers,
  masvs.masvs_total,
  masvs.masvs_pass,
  masvs.masvs_fail,
  masvs.masvs_inconclusive,
  perms.dangerous_permissions,
  perms.signature_permissions,
  perms.custom_permissions,
  perms.permissions_total
FROM static_analysis_runs sar
JOIN app_versions av ON av.id = sar.app_version_id
JOIN apps a ON a.id = av.app_id
LEFT JOIN (
  SELECT
    run_id,
    MAX(CASE WHEN feature_key = 'exports.total' THEN value_num ELSE NULL END) AS exports_total,
    MAX(CASE WHEN feature_key = 'exports.activities' THEN value_num ELSE NULL END) AS exports_activities,
    MAX(CASE WHEN feature_key = 'exports.services' THEN value_num ELSE NULL END) AS exports_services,
    MAX(CASE WHEN feature_key = 'exports.receivers' THEN value_num ELSE NULL END) AS exports_receivers,
    MAX(CASE WHEN feature_key = 'exports.providers' THEN value_num ELSE NULL END) AS exports_providers
  FROM metrics
  GROUP BY run_id
) mtr ON mtr.run_id = sar.id
LEFT JOIN (
  SELECT
    run_id,
    COUNT(*) AS masvs_total,
    SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) AS masvs_pass,
    SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) AS masvs_fail,
    SUM(CASE WHEN status = 'INCONCLUSIVE' THEN 1 ELSE 0 END) AS masvs_inconclusive
  FROM masvs_control_coverage
  GROUP BY run_id
) masvs ON masvs.run_id = sar.id
LEFT JOIN (
  SELECT
    run_id,
    SUM(is_runtime_dangerous) AS dangerous_permissions,
    SUM(is_signature) AS signature_permissions,
    SUM(is_custom) AS custom_permissions,
    COUNT(*) AS permissions_total
  FROM static_permission_matrix
  GROUP BY run_id
) perms ON perms.run_id = sar.id
LEFT JOIN risk_scores rs
  ON rs.package_name = a.package_name
 AND rs.session_stamp = sar.session_stamp
 AND rs.scope_label = sar.scope_label
"""


def ensure_dep_view() -> bool:
    try:
        core_q.run_sql(CREATE_DEP_VIEW)
        return True
    except Exception as exc:
        log.warning(f"Failed to create DEP view: {exc}", category="static_analysis")
        return False


__all__ = ["ensure_dep_view"]