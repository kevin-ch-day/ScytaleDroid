"""Canonical database schema for static-analysis results.

The schema is designed for idempotent UPSERT ingestion and de-duplicated
records keyed by app version.
"""

from __future__ import annotations

from typing import Iterable

import re

from ...db_core import db_queries as core_q


_DDL_STATEMENTS: list[str] = [
    # Apps and Versions
    """
    CREATE TABLE IF NOT EXISTS apps (
      id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      package_name  VARCHAR(255)    NOT NULL,
      display_name  VARCHAR(255)    DEFAULT NULL,
      category_id   INT             DEFAULT NULL,
      profile_key   VARCHAR(64)     NOT NULL DEFAULT 'UNCLASSIFIED',
      created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY ux_apps_package (package_name),
      KEY idx_app_category_id (category_id),
      KEY idx_apps_profile_key (profile_key),
      CONSTRAINT fk_app_category FOREIGN KEY (category_id)
        REFERENCES android_app_categories (category_id)
        ON DELETE SET NULL ON UPDATE CASCADE
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
      session_stamp    VARCHAR(128)   DEFAULT NULL,
      scope_label      VARCHAR(191)   DEFAULT NULL,
      category         VARCHAR(64)    DEFAULT NULL,
      sha256           CHAR(64)       DEFAULT NULL,
      base_apk_sha256  CHAR(64)       DEFAULT NULL,
      artifact_set_hash CHAR(64)      DEFAULT NULL,
      run_signature    CHAR(64)       DEFAULT NULL,
      run_signature_version VARCHAR(16) DEFAULT NULL,
      identity_valid   TINYINT(1)     DEFAULT NULL,
      identity_error_reason VARCHAR(128) DEFAULT NULL,
      analysis_version VARCHAR(32)    DEFAULT NULL,
      pipeline_version VARCHAR(32)    DEFAULT NULL,
      catalog_versions VARCHAR(128)   DEFAULT NULL,
      config_hash      CHAR(64)       DEFAULT NULL,
      study_tag        VARCHAR(128)   DEFAULT NULL,
      run_started_utc  VARCHAR(64)    DEFAULT NULL,
      status           VARCHAR(16)    DEFAULT 'RUNNING',
      ended_at_utc     DATETIME       DEFAULT NULL,
      abort_reason     VARCHAR(64)    DEFAULT NULL,
      abort_signal     VARCHAR(16)    DEFAULT NULL,
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
      ADD COLUMN IF NOT EXISTS category VARCHAR(64) DEFAULT NULL;
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
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS pipeline_version VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS catalog_versions VARCHAR(128) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS config_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS study_tag VARCHAR(128) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_started_utc VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'RUNNING',
      ADD COLUMN IF NOT EXISTS ended_at_utc DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS abort_reason VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS abort_signal VARCHAR(16) DEFAULT NULL;
    """,
    """
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS base_apk_sha256 CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS artifact_set_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_signature CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_signature_version VARCHAR(16) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_valid TINYINT(1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_error_reason VARCHAR(128) DEFAULT NULL;
    """,
    """
    ALTER TABLE static_analysis_runs
      MODIFY config_hash CHAR(64) DEFAULT NULL;
    """,
    """
    ALTER TABLE static_analysis_runs
      MODIFY session_stamp VARCHAR(128) DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_session_version
    ON static_analysis_runs (session_stamp, app_version_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_category
    ON static_analysis_runs (category);
    """,
    """
    CREATE TABLE IF NOT EXISTS static_session_rollups (
      session_stamp VARCHAR(128) NOT NULL,
      scope_label   VARCHAR(191) NOT NULL DEFAULT '',
      apps_total    INT UNSIGNED NOT NULL DEFAULT 0,
      completed     INT UNSIGNED NOT NULL DEFAULT 0,
      failed        INT UNSIGNED NOT NULL DEFAULT 0,
      aborted       INT UNSIGNED NOT NULL DEFAULT 0,
      running       INT UNSIGNED NOT NULL DEFAULT 0,
      created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (session_stamp, scope_label),
      KEY ix_static_rollup_scope (scope_label)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS static_session_run_links (
      link_id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      session_stamp       VARCHAR(128) NOT NULL,
      package_name        VARCHAR(255) NOT NULL,
      static_run_id       BIGINT UNSIGNED NOT NULL,
      run_origin          VARCHAR(16) NOT NULL DEFAULT 'created',
      origin_session_stamp VARCHAR(128) DEFAULT NULL,
      pipeline_version    VARCHAR(32) NOT NULL,
      base_apk_sha256     CHAR(64) NOT NULL,
      artifact_set_hash   CHAR(64) NOT NULL,
      run_signature       CHAR(64) NOT NULL,
      run_signature_version VARCHAR(16) NOT NULL,
      identity_valid      TINYINT(1) NOT NULL,
      identity_error_reason VARCHAR(128) DEFAULT NULL,
      linked_at_utc       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (link_id),
      UNIQUE KEY ux_static_session_run (session_stamp, package_name),
      KEY ix_static_session_run_static (static_run_id),
      KEY ix_static_session_run_origin (origin_session_stamp),
      CONSTRAINT fk_static_session_run_static
        FOREIGN KEY (static_run_id)
        REFERENCES static_analysis_runs (id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE static_session_run_links
      MODIFY run_origin VARCHAR(16) NOT NULL DEFAULT 'created';
    """,
    """
    ALTER TABLE static_session_run_links
      ADD COLUMN IF NOT EXISTS pipeline_version VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS base_apk_sha256 CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS artifact_set_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_signature CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_signature_version VARCHAR(16) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_valid TINYINT(1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_error_reason VARCHAR(128) DEFAULT NULL;
    """,
    """
    ALTER TABLE static_session_run_links
      MODIFY pipeline_version VARCHAR(32) NOT NULL,
      MODIFY base_apk_sha256 CHAR(64) NOT NULL,
      MODIFY artifact_set_hash CHAR(64) NOT NULL,
      MODIFY run_signature CHAR(64) NOT NULL,
      MODIFY run_signature_version VARCHAR(16) NOT NULL,
      MODIFY identity_valid TINYINT(1) NOT NULL;
    """,
    """
    CREATE TABLE IF NOT EXISTS static_correlation_results (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      static_run_id    BIGINT UNSIGNED NOT NULL,
      package_name     VARCHAR(255)    NOT NULL,
      correlation_key  VARCHAR(128)    NOT NULL,
      severity_band    ENUM('INFO','WARN','FAIL') NOT NULL,
      score            INT             NOT NULL DEFAULT 0,
      rationale        TEXT            NOT NULL,
      evidence_path    VARCHAR(1024)   DEFAULT NULL,
      evidence_preview TEXT            DEFAULT NULL,
      created_at_utc   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_static_corr (static_run_id, package_name, correlation_key),
      KEY ix_static_corr_run_pkg (static_run_id, package_name),
      KEY ix_static_corr_key (correlation_key),
      KEY ix_static_corr_sev (severity_band)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS permission_signal_observations (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      static_run_id BIGINT UNSIGNED NOT NULL,
      package_name VARCHAR(255) NOT NULL,
      signal_key VARCHAR(128) NOT NULL,
      severity_band ENUM('INFO','WARN','FAIL') NOT NULL DEFAULT 'INFO',
      score INT NOT NULL DEFAULT 0,
      trigger_permissions_json JSON NOT NULL,
      primary_permission VARCHAR(255) DEFAULT NULL,
      rationale TEXT DEFAULT NULL,
      evidence_path VARCHAR(1024) DEFAULT NULL,
      observed_at_utc DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_perm_sig (static_run_id, package_name, signal_key),
      KEY ix_perm_sig_run_pkg (static_run_id, package_name),
      KEY ix_perm_sig_key (signal_key),
      KEY ix_perm_sig_sev (severity_band)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
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
    ALTER TABLE static_fileproviders
      ADD COLUMN IF NOT EXISTS run_id BIGINT UNSIGNED DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS component_name VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS authorities JSON DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS base_permission VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS read_permission VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS write_permission VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS base_guard VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS read_guard VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS write_guard VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS effective_guard VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS metrics JSON DEFAULT NULL;
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
    """
    ALTER TABLE static_provider_acl
      ADD COLUMN IF NOT EXISTS provider_id BIGINT UNSIGNED DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS path VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS path_prefix VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS path_pattern VARCHAR(191) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS read_guard VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS write_guard VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS metadata JSON DEFAULT NULL;
    """,
    # Canonical Observations
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
    """
    CREATE OR REPLACE VIEW v_static_run_category_summary AS
    SELECT
      COALESCE(r.category, 'Uncategorized') AS category,
      COUNT(*) AS run_count,
      MAX(r.created_at) AS latest_run,
      AVG(spr.risk_score) AS avg_risk_score,
      COUNT(spr.id) AS risk_rows
    FROM static_analysis_runs r
    JOIN app_versions av ON r.app_version_id = av.id
    JOIN apps a ON av.app_id = a.id
    LEFT JOIN static_permission_risk spr
      ON spr.session_stamp = r.session_stamp
     AND spr.package_name = a.package_name
    GROUP BY COALESCE(r.category, 'Uncategorized');
    """,
]


_TABLE_NAME_PATTERN = re.compile(r"CREATE TABLE IF NOT EXISTS\\s+`?([a-zA-Z0-9_]+)`?", re.IGNORECASE)


def ensure_all() -> bool:
    """Verify canonical tables exist; no runtime DDL is executed."""
    tables = set()
    for stmt in _DDL_STATEMENTS:
        match = _TABLE_NAME_PATTERN.search(stmt)
        if match:
            tables.add(match.group(1))
    if not tables:
        return True
    ok = True
    for table in sorted(tables):
        try:
            row = core_q.run_sql(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
                (table,),
                fetch="one",
            )
            present = bool(row and int(row[0]) > 0)
        except Exception:
            present = False
        if not present:
            ok = False
            try:
                core_q.run_sql("/* canonical schema missing */ SELECT 1")
            except Exception:
                pass
    return ok


__all__ = ["ensure_all"]
