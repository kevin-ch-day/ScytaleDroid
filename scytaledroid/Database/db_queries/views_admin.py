"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_V_ARTIFACT_REGISTRY_INTEGRITY = """
CREATE OR REPLACE VIEW v_artifact_registry_integrity AS
SELECT
  ar.artifact_id,
  ar.run_id,
  ar.run_type,
  ar.session_stamp,
  ar.static_run_id,
  ar.dynamic_run_id,
  ar.linkage_migration_status,
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
  COALESCE(
    ar.static_run_id,
    CASE
      WHEN ar.run_type = 'static' AND ar.run_id REGEXP '^[0-9]+$'
        THEN CAST(ar.run_id AS UNSIGNED)
      ELSE NULL
    END
  ) AS resolved_static_run_id,
  COALESCE(
    ar.dynamic_run_id,
    CASE
      WHEN ar.run_type = 'dynamic' AND TRIM(COALESCE(ar.run_id, '')) <> ''
        THEN ar.run_id
      ELSE NULL
    END
  ) AS resolved_dynamic_run_id,
  CASE
    WHEN ar.run_type = 'dynamic' AND ar.dynamic_run_id IS NOT NULL THEN 'typed_dynamic'
    WHEN ar.run_type = 'dynamic' AND TRIM(COALESCE(ar.run_id, '')) <> '' THEN 'legacy_dynamic_fallback'
    WHEN ar.run_type = 'static' AND ar.static_run_id IS NOT NULL THEN 'typed_static'
    WHEN ar.run_type = 'static' AND ar.run_id REGEXP '^[0-9]+$' THEN 'legacy_static_fallback'
    WHEN ar.run_type = 'static' THEN 'legacy_static_untyped'
    ELSE 'unclassified'
  END AS linkage_resolution_path,
  CASE
    WHEN ar.run_type = 'dynamic'
     AND (ds_typed.dynamic_run_id IS NOT NULL OR ds_legacy.dynamic_run_id IS NOT NULL)
      THEN 'linked'
    WHEN ar.run_type = 'dynamic' THEN 'dangling_dynamic_run'
    WHEN ar.run_type = 'static'
     AND (sar_typed.id IS NOT NULL OR sar_legacy.id IS NOT NULL)
      THEN 'linked'
    WHEN ar.run_type = 'static' THEN 'dangling_static_run'
    ELSE 'unknown_run_type'
  END AS link_state
FROM artifact_registry ar
LEFT JOIN dynamic_sessions ds_typed
  ON ar.run_type = 'dynamic'
 AND ar.dynamic_run_id IS NOT NULL
 AND ds_typed.dynamic_run_id = ar.dynamic_run_id
LEFT JOIN dynamic_sessions ds_legacy
  ON ar.run_type = 'dynamic'
 AND ar.dynamic_run_id IS NULL
 AND TRIM(COALESCE(ar.run_id, '')) <> ''
 AND ds_legacy.dynamic_run_id = ar.run_id
LEFT JOIN static_analysis_runs sar_typed
  ON ar.run_type = 'static'
 AND ar.static_run_id IS NOT NULL
 AND sar_typed.id = ar.static_run_id
LEFT JOIN static_analysis_runs sar_legacy
  ON ar.run_type = 'static'
 AND ar.static_run_id IS NULL
 AND ar.run_id REGEXP '^[0-9]+$'
 AND sar_legacy.id = CAST(ar.run_id AS UNSIGNED);
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
