"""Canonical database schema for static-analysis results.

The schema is designed for idempotent UPSERT ingestion and de-duplicated
records keyed by app version.
"""

from __future__ import annotations

from typing import Iterable

from ...db_core import db_queries as core_q


_DDL_STATEMENTS: list[str] = [
    # Apps and Versions
    """
    CREATE TABLE IF NOT EXISTS apps (
      id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      package_name  VARCHAR(191)    NOT NULL,
      display_name  VARCHAR(191)    DEFAULT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY ux_apps_package (package_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS app_versions (
      id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_id        BIGINT UNSIGNED NOT NULL,
      version_name  VARCHAR(191)    DEFAULT NULL,
      version_code  BIGINT          DEFAULT NULL,
      min_sdk       INT             DEFAULT NULL,
      target_sdk    INT             DEFAULT NULL,
      analyzed_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY ux_app_versions (app_id, version_name, version_code),
      KEY ix_app_versions_app_id (app_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS static_analysis_runs (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_version_id   BIGINT UNSIGNED NOT NULL,
      session_stamp    VARCHAR(64)    DEFAULT NULL,
      scope_label      VARCHAR(191)   DEFAULT NULL,
      sha256           CHAR(64)       DEFAULT NULL,
      analysis_version VARCHAR(32)    DEFAULT NULL,
      profile          VARCHAR(32)    DEFAULT NULL,
      findings_total   INT UNSIGNED   NOT NULL DEFAULT 0,
      detector_metrics JSON           DEFAULT NULL,
      repro_bundle     JSON           DEFAULT NULL,
      analysis_matrices JSON          DEFAULT NULL,
      analysis_indicators JSON        DEFAULT NULL,
      workload_profile JSON           DEFAULT NULL,
      created_at       TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_static_runs_version (app_version_id),
      KEY ix_static_runs_session (session_stamp),
      KEY ix_static_runs_sha (sha256),
      CONSTRAINT fk_static_runs_version FOREIGN KEY (app_version_id)
        REFERENCES app_versions (id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS analysis_matrices JSON DEFAULT NULL;
    """,
    """
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS analysis_indicators JSON DEFAULT NULL;
    """,
    """
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS workload_profile JSON DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_session_version
    ON static_analysis_runs (session_stamp, app_version_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS static_analysis_findings (
      id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      run_id      BIGINT UNSIGNED NOT NULL,
      finding_id  VARCHAR(128)    DEFAULT NULL,
      status      VARCHAR(32)     DEFAULT NULL,
      severity    VARCHAR(32)     DEFAULT NULL,
      category    VARCHAR(64)     DEFAULT NULL,
      title       VARCHAR(512)    DEFAULT NULL,
      tags        JSON            DEFAULT NULL,
      evidence    JSON            DEFAULT NULL,
      fix         TEXT            DEFAULT NULL,
      rule_id     VARCHAR(128)    DEFAULT NULL,
      cvss_score  DECIMAL(4,1)    DEFAULT NULL,
      masvs_control VARCHAR(32)   DEFAULT NULL,
      detector    VARCHAR(64)     DEFAULT NULL,
      module      VARCHAR(64)     DEFAULT NULL,
      evidence_refs JSON          DEFAULT NULL,
      created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_static_findings_run (run_id),
      KEY ix_static_findings_severity (run_id, severity),
      KEY ix_static_findings_rule (run_id, rule_id),
      CONSTRAINT fk_static_findings_run FOREIGN KEY (run_id)
        REFERENCES static_analysis_runs (id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE static_analysis_findings
      ADD COLUMN IF NOT EXISTS cvss_score DECIMAL(4,1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS masvs_control VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS detector VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS module VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS evidence_refs JSON DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_findings_rule_severity
    ON static_analysis_findings (rule_id, severity, run_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS static_fileproviders (
      id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      run_id             BIGINT UNSIGNED NOT NULL,
      component_name     VARCHAR(191)    NOT NULL,
      authorities        JSON            DEFAULT NULL,
      exported           TINYINT(1)      NOT NULL DEFAULT 0,
      base_permission    VARCHAR(191)    DEFAULT NULL,
      read_permission    VARCHAR(191)    DEFAULT NULL,
      write_permission   VARCHAR(191)    DEFAULT NULL,
      base_guard         VARCHAR(32)     DEFAULT NULL,
      read_guard         VARCHAR(32)     DEFAULT NULL,
      write_guard        VARCHAR(32)     DEFAULT NULL,
      effective_guard    VARCHAR(32)     DEFAULT NULL,
      grant_uri_permissions TINYINT(1)   DEFAULT 0,
      metrics            JSON            DEFAULT NULL,
      created_at         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_static_fileproviders_run (run_id),
      KEY ix_static_fileproviders_guard (effective_guard),
      KEY ix_static_fileproviders_component (component_name),
      CONSTRAINT fk_static_fileproviders_run FOREIGN KEY (run_id)
        REFERENCES static_analysis_runs (id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS static_provider_acl (
      id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      provider_id     BIGINT UNSIGNED NOT NULL,
      path            VARCHAR(191)    DEFAULT NULL,
      path_prefix     VARCHAR(191)    DEFAULT NULL,
      path_pattern    VARCHAR(191)    DEFAULT NULL,
      read_permission VARCHAR(191)    DEFAULT NULL,
      write_permission VARCHAR(191)   DEFAULT NULL,
      read_guard      VARCHAR(32)     DEFAULT NULL,
      write_guard     VARCHAR(32)     DEFAULT NULL,
      metadata        JSON            DEFAULT NULL,
      created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_provider_acl_provider (provider_id),
      KEY ix_provider_acl_path (path),
      KEY ix_provider_acl_prefix (path_prefix),
      CONSTRAINT fk_provider_acl_provider FOREIGN KEY (provider_id)
        REFERENCES static_fileproviders (id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    # Ingest/Audit
    """
    CREATE TABLE IF NOT EXISTS analysis_runs (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_version_id   BIGINT UNSIGNED NOT NULL,
      profile          VARCHAR(32)     DEFAULT NULL,
      scope_label      VARCHAR(191)    DEFAULT NULL,
      raw_artifact_uri VARCHAR(512)    DEFAULT NULL,
      created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_analysis_runs_version (app_version_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ingest_audit (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      analysis_run_id  BIGINT UNSIGNED DEFAULT NULL,
      status           VARCHAR(32)     NOT NULL,
      stats            JSON            DEFAULT NULL,
      created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_ingest_audit_run (analysis_run_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    # Canonical Observations
    """
    CREATE TABLE IF NOT EXISTS endpoints (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_version_id   BIGINT UNSIGNED NOT NULL,
      scheme           VARCHAR(8)      NOT NULL,
      host_root        VARCHAR(191)    NOT NULL,
      normalized_path  VARCHAR(512)    NOT NULL,
      source_types     JSON            DEFAULT NULL,
      occurrences      INT             NOT NULL DEFAULT 1,
      PRIMARY KEY (id),
      UNIQUE KEY ux_endpoints (app_version_id, scheme, host_root, normalized_path),
      KEY ix_endpoints_host (app_version_id, host_root)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS secret_candidates (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_version_id   BIGINT UNSIGNED NOT NULL,
      value_hash       VARCHAR(191)    NOT NULL,
      format_tag       VARCHAR(64)     DEFAULT NULL,
      confidence       VARCHAR(16)     DEFAULT NULL,
      evidence_types   JSON            DEFAULT NULL,
      occurrences      INT             NOT NULL DEFAULT 1,
      PRIMARY KEY (id),
      UNIQUE KEY ux_secret_candidates (app_version_id, value_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS analytics_ids (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_version_id   BIGINT UNSIGNED NOT NULL,
      vendor           VARCHAR(64)     NOT NULL,
      id_hash          VARCHAR(191)    NOT NULL,
      occurrences      INT             NOT NULL DEFAULT 1,
      sources          JSON            DEFAULT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY ux_analytics_ids (app_version_id, vendor, id_hash),
      KEY ix_analytics_lookup (vendor, id_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      app_version_id   BIGINT UNSIGNED NOT NULL,
      rule_id          VARCHAR(32)     NOT NULL,
      severity         VARCHAR(16)     NOT NULL,
      category         VARCHAR(32)     DEFAULT NULL,
      reason_codes     JSON            DEFAULT NULL,
      evidence_ref     VARCHAR(512)    DEFAULT NULL,
      occurrences      INT             NOT NULL DEFAULT 1,
      PRIMARY KEY (id),
      KEY ix_findings_rule (app_version_id, rule_id, severity)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE OR REPLACE VIEW v_provider_exposure AS
    SELECT
      fp.id AS provider_id,
      fp.run_id,
      r.app_version_id,
      r.session_stamp,
      r.scope_label,
      a.package_name,
      fp.component_name,
      fp.authorities,
      fp.exported,
      fp.base_permission,
      fp.read_permission,
      fp.write_permission,
      fp.base_guard,
      fp.read_guard,
      fp.write_guard,
      fp.effective_guard,
      fp.grant_uri_permissions,
      fp.metrics
    FROM static_fileproviders fp
    JOIN static_analysis_runs r ON fp.run_id = r.id
    JOIN app_versions av ON r.app_version_id = av.id
    JOIN apps a ON av.app_id = a.id;
    """,
    """
    CREATE OR REPLACE VIEW v_base002_candidates AS
    SELECT
      v.provider_id,
      v.run_id,
      v.app_version_id,
      v.session_stamp,
      v.scope_label,
      v.package_name,
      v.component_name,
      v.authorities,
      v.effective_guard,
      v.read_guard,
      v.write_guard,
      v.base_permission,
      v.read_permission,
      v.write_permission,
      v.grant_uri_permissions
    FROM v_provider_exposure v
    WHERE COALESCE(v.effective_guard, 'none') IN ('none','weak','unknown')
       OR COALESCE(v.read_guard, 'none') IN ('none','weak','unknown')
       OR COALESCE(v.write_guard, 'none') IN ('none','weak','unknown');
    """,
    """
    CREATE OR REPLACE VIEW v_session_string_samples AS
    SELECT
      r.id AS run_id,
      r.session_stamp,
      r.scope_label,
      a.package_name,
      s.session_stamp AS summary_session,
      s.scope_label AS summary_scope,
      sm.bucket,
      sm.value_masked,
      sm.src,
      sm.tag,
      sm.source_type,
      sm.finding_type,
      sm.provider,
      sm.risk_tag,
      sm.confidence,
      sm.sample_hash,
      sm.root_domain,
      sm.resource_name,
      sm.scheme,
      sm.created_at AS sample_created_at
    FROM static_analysis_runs r
    JOIN app_versions av ON r.app_version_id = av.id
    JOIN apps a ON av.app_id = a.id
    JOIN static_string_summary s
      ON s.package_name = a.package_name
     AND (
          (r.session_stamp IS NOT NULL AND s.session_stamp = r.session_stamp)
          OR (
              ABS(TIMESTAMPDIFF(SECOND, s.created_at, r.created_at)) <= 3600
          )
        )
    JOIN static_string_samples sm ON sm.summary_id = s.id;
    """,
    # Allowlist
    """
    CREATE TABLE IF NOT EXISTS allowlist (
      id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      type          ENUM('host','path','rule','source') NOT NULL,
      pattern       VARCHAR(255)    NOT NULL,
      vendor        VARCHAR(64)     DEFAULT NULL,
      notes         VARCHAR(255)    DEFAULT NULL,
      default_risk  VARCHAR(16)     DEFAULT NULL,
      PRIMARY KEY (id),
      KEY ix_allowlist_type (type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]


def ensure_all() -> bool:
    """Create all canonical tables if missing.

    Returns True when all statements executed without error.
    """
    try:
        for stmt in _DDL_STATEMENTS:
            core_q.run_sql(stmt)
        return True
    except Exception:
        return False


__all__ = ["ensure_all"]

