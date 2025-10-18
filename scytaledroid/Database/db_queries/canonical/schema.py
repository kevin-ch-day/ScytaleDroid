"""Canonical database schema for static-analysis results.

The schema is designed for idempotent UPSERT ingestion and de-duplicated
records keyed by app version.
"""

from __future__ import annotations

from typing import Iterable

from ..db_core import db_queries as core_q


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

