"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

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

__all__ = [
    "CREATE_V_ARTIFACT_REGISTRY_INTEGRITY",
    "CREATE_V_CURRENT_ARTIFACT_REGISTRY",
]
