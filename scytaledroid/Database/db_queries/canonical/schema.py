"""Canonical database schema for static-analysis results.

The schema is designed for idempotent UPSERT ingestion and de-duplicated
records keyed by app version.
"""

from __future__ import annotations

import re

from ...db_core import db_queries as core_q

CREATE_EXTERNAL_SDK_TRACKER_INTEL = """
CREATE TABLE IF NOT EXISTS external_sdk_tracker_intel (
  intel_id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  intel_source         VARCHAR(64)     NOT NULL,
  tracker_id_external  VARCHAR(64)     NOT NULL,
  tracker_name         VARCHAR(191)    NOT NULL,
  code_signature       VARCHAR(255)    DEFAULT NULL,
  network_signature    TEXT            DEFAULT NULL,
  website              TEXT            DEFAULT NULL,
  description          LONGTEXT        DEFAULT NULL,
  categories_json      JSON            DEFAULT NULL,
  documentation_json   JSON            DEFAULT NULL,
  creation_date        DATE            DEFAULT NULL,
  snapshot_date        DATE            NOT NULL,
  source_url           TEXT            DEFAULT NULL,
  source_terms_note    VARCHAR(255)    DEFAULT NULL,
  fetched_at_utc       DATETIME        DEFAULT NULL,
  is_active            TINYINT(1)      NOT NULL DEFAULT 1,
  created_at           TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at           TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (intel_id),
  UNIQUE KEY ux_external_sdk_tracker_snapshot (intel_source, tracker_id_external, snapshot_date),
  KEY ix_external_sdk_tracker_name (tracker_name),
  KEY ix_external_sdk_tracker_code_signature (code_signature),
  KEY ix_external_sdk_tracker_snapshot (snapshot_date),
  KEY ix_external_sdk_tracker_source_snapshot (intel_source, snapshot_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_DYNAMIC_DOMAIN_REFERENCE = """
CREATE TABLE IF NOT EXISTS dynamic_domain_reference (
  reference_id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  package_name_scope     VARCHAR(255)    NOT NULL DEFAULT '',
  domain_pattern         VARCHAR(255)    NOT NULL,
  match_type             VARCHAR(16)     NOT NULL,
  owner_class            VARCHAR(32)     NOT NULL,
  role_class             VARCHAR(64)     NOT NULL,
  confidence             VARCHAR(16)     NOT NULL,
  classification_basis   VARCHAR(64)     NOT NULL,
  source_label           VARCHAR(64)     NOT NULL DEFAULT 'repo_seed',
  source_url             TEXT            DEFAULT NULL,
  notes                  TEXT            DEFAULT NULL,
  is_active              TINYINT(1)      NOT NULL DEFAULT 1,
  created_at_utc         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (reference_id),
  UNIQUE KEY uq_dynamic_domain_reference (package_name_scope, domain_pattern, match_type),
  KEY ix_dynamic_domain_reference_active (is_active, match_type),
  KEY ix_dynamic_domain_reference_pattern (domain_pattern),
  KEY ix_dynamic_domain_reference_scope (package_name_scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_DYNAMIC_SERVICE_CATALOG = """
CREATE TABLE IF NOT EXISTS dynamic_service_catalog (
  service_id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  service_key           VARCHAR(128)    NOT NULL,
  display_name          VARCHAR(191)    NOT NULL,
  owner_name            VARCHAR(191)    NOT NULL,
  owner_class           VARCHAR(32)     NOT NULL,
  service_category      VARCHAR(64)     NOT NULL,
  primary_use_case      VARCHAR(128)    DEFAULT NULL,
  documentation_url     TEXT            DEFAULT NULL,
  privacy_policy_url    TEXT            DEFAULT NULL,
  source_label          VARCHAR(64)     NOT NULL DEFAULT 'repo_seed',
  source_url            TEXT            DEFAULT NULL,
  confidence            VARCHAR(16)     NOT NULL,
  notes                 TEXT            DEFAULT NULL,
  is_active             TINYINT(1)      NOT NULL DEFAULT 1,
  created_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (service_id),
  UNIQUE KEY uq_dynamic_service_catalog_key (service_key),
  KEY ix_dynamic_service_catalog_active (is_active, owner_class, service_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_DYNAMIC_SERVICE_DOMAIN_MAP = """
CREATE TABLE IF NOT EXISTS dynamic_service_domain_map (
  service_domain_map_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  service_id            BIGINT UNSIGNED NOT NULL,
  package_name_scope    VARCHAR(255)    NOT NULL DEFAULT '',
  domain_pattern        VARCHAR(255)    NOT NULL,
  match_type            VARCHAR(16)     NOT NULL,
  role_class            VARCHAR(64)     DEFAULT NULL,
  source_label          VARCHAR(64)     NOT NULL DEFAULT 'repo_seed',
  source_url            TEXT            DEFAULT NULL,
  confidence            VARCHAR(16)     NOT NULL,
  notes                 TEXT            DEFAULT NULL,
  is_active             TINYINT(1)      NOT NULL DEFAULT 1,
  created_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (service_domain_map_id),
  UNIQUE KEY uq_dynamic_service_domain_map (service_id, package_name_scope, domain_pattern, match_type),
  KEY ix_dynamic_service_domain_map_active (is_active, match_type, package_name_scope),
  KEY ix_dynamic_service_domain_map_pattern (domain_pattern),
  CONSTRAINT fk_dynamic_service_domain_map_service FOREIGN KEY (service_id)
    REFERENCES dynamic_service_catalog (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_DYNAMIC_SIGNAL_CATALOG = """
CREATE TABLE IF NOT EXISTS dynamic_signal_catalog (
  signal_id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  signal_key            VARCHAR(128)    NOT NULL,
  display_name          VARCHAR(191)    NOT NULL,
  signal_family         VARCHAR(64)     NOT NULL,
  focus_area            VARCHAR(32)     NOT NULL,
  severity_hint         VARCHAR(16)     NOT NULL,
  description           TEXT            DEFAULT NULL,
  analyst_guidance      TEXT            DEFAULT NULL,
  source_label          VARCHAR(64)     NOT NULL DEFAULT 'repo_seed',
  source_url            TEXT            DEFAULT NULL,
  notes                 TEXT            DEFAULT NULL,
  is_active             TINYINT(1)      NOT NULL DEFAULT 1,
  created_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (signal_id),
  UNIQUE KEY uq_dynamic_signal_catalog_key (signal_key),
  KEY ix_dynamic_signal_catalog_active (is_active, focus_area, severity_hint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_DYNAMIC_SERVICE_SIGNAL_MAP = """
CREATE TABLE IF NOT EXISTS dynamic_service_signal_map (
  service_signal_map_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  service_id            BIGINT UNSIGNED NOT NULL,
  signal_id             BIGINT UNSIGNED NOT NULL,
  signal_strength       VARCHAR(16)     NOT NULL,
  confidence            VARCHAR(16)     NOT NULL,
  rationale             TEXT            DEFAULT NULL,
  source_label          VARCHAR(64)     NOT NULL DEFAULT 'repo_seed',
  source_url            TEXT            DEFAULT NULL,
  notes                 TEXT            DEFAULT NULL,
  is_active             TINYINT(1)      NOT NULL DEFAULT 1,
  created_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (service_signal_map_id),
  UNIQUE KEY uq_dynamic_service_signal_map (service_id, signal_id),
  KEY ix_dynamic_service_signal_map_active (is_active, signal_strength, confidence),
  CONSTRAINT fk_dynamic_service_signal_map_service FOREIGN KEY (service_id)
    REFERENCES dynamic_service_catalog (service_id),
  CONSTRAINT fk_dynamic_service_signal_map_signal FOREIGN KEY (signal_id)
    REFERENCES dynamic_signal_catalog (signal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_RESEARCH_COHORTS = """
CREATE TABLE IF NOT EXISTS research_cohorts (
  cohort_id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cohort_key       VARCHAR(128)    NOT NULL,
  display_name     VARCHAR(191)    NOT NULL,
  description      TEXT            DEFAULT NULL,
  intended_use     VARCHAR(64)     NOT NULL DEFAULT 'research',
  selection_rule   VARCHAR(64)     NOT NULL DEFAULT 'newest_harvest_capture_per_package',
  is_active        TINYINT(1)      NOT NULL DEFAULT 1,
  created_at_utc   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (cohort_id),
  UNIQUE KEY uq_research_cohorts_key (cohort_key),
  KEY idx_research_cohorts_active (is_active),
  KEY idx_research_cohorts_use (intended_use)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_RESEARCH_COHORT_MEMBERS = """
CREATE TABLE IF NOT EXISTS research_cohort_members (
  member_id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cohort_id          BIGINT UNSIGNED NOT NULL,
  package_name       VARCHAR(255)    NOT NULL,
  member_source      VARCHAR(64)     NOT NULL DEFAULT 'manual',
  source_cohort_key  VARCHAR(128)    DEFAULT NULL,
  sort_order         INT UNSIGNED    NOT NULL DEFAULT 0,
  is_active          TINYINT(1)      NOT NULL DEFAULT 1,
  notes              TEXT            DEFAULT NULL,
  created_at_utc     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (member_id),
  UNIQUE KEY uq_research_cohort_member (cohort_id, package_name),
  KEY idx_research_cohort_members_package (package_name),
  KEY idx_research_cohort_members_active (cohort_id, is_active, sort_order, package_name),
  CONSTRAINT fk_research_cohort_members_cohort FOREIGN KEY (cohort_id)
    REFERENCES research_cohorts (cohort_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

_DDL_STATEMENTS: list[str] = [
    # Core dictionaries used by many flows (device inventory, profiles, publishers).
    """
    CREATE TABLE IF NOT EXISTS android_app_categories (
      category_id   INT            NOT NULL AUTO_INCREMENT,
      category_name VARCHAR(191)   NOT NULL,
      created_at    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (category_id),
      UNIQUE KEY ux_app_categories_name (category_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS android_app_profiles (
      profile_key   VARCHAR(64)    NOT NULL,
      display_name  VARCHAR(191)   NOT NULL,
      description   TEXT           DEFAULT NULL,
      scope_group   VARCHAR(64)    DEFAULT NULL,
      sort_order    INT            DEFAULT 0,
      is_active     TINYINT(1)     NOT NULL DEFAULT 1,
      created_at    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (profile_key),
      KEY idx_profiles_active (is_active),
      KEY idx_profiles_sort (sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS android_app_publishers (
      publisher_key VARCHAR(64)    NOT NULL,
      display_name  VARCHAR(191)   NOT NULL,
      description   TEXT           DEFAULT NULL,
      sort_order    INT            DEFAULT 0,
      is_active     TINYINT(1)     NOT NULL DEFAULT 1,
      created_at    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (publisher_key),
      KEY idx_publishers_active (is_active),
      KEY idx_publishers_sort (sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS android_publisher_prefix_rules (
      rule_id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      publisher_key VARCHAR(64)     NOT NULL,
      match_type    VARCHAR(16)     NOT NULL, -- EXACT|PREFIX
      pattern       VARCHAR(255)    NOT NULL,
      priority      INT             NOT NULL DEFAULT 100,
      is_active     TINYINT(1)      NOT NULL DEFAULT 1,
      created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (rule_id),
      KEY idx_pub_rules_active (is_active, priority),
      KEY idx_pub_rules_publisher (publisher_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    CREATE_RESEARCH_COHORTS,
    CREATE_RESEARCH_COHORT_MEMBERS,
    CREATE_EXTERNAL_SDK_TRACKER_INTEL,
    CREATE_DYNAMIC_DOMAIN_REFERENCE,
    CREATE_DYNAMIC_SERVICE_CATALOG,
    CREATE_DYNAMIC_SERVICE_DOMAIN_MAP,
    CREATE_DYNAMIC_SIGNAL_CATALOG,
    CREATE_DYNAMIC_SERVICE_SIGNAL_MAP,
    # Apps and Versions
    """
    CREATE TABLE IF NOT EXISTS apps (
      id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      package_name  VARCHAR(255)    NOT NULL,
      display_name  VARCHAR(255)    DEFAULT NULL,
      category_id   INT             DEFAULT NULL,
      profile_key   VARCHAR(64)     NOT NULL DEFAULT 'UNCLASSIFIED',
      publisher_key VARCHAR(64)     NOT NULL DEFAULT 'UNKNOWN',
      created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY ux_apps_package (package_name),
      KEY idx_app_category_id (category_id),
      KEY idx_apps_profile_key (profile_key),
      KEY idx_apps_publisher_key (publisher_key),
      CONSTRAINT fk_app_category FOREIGN KEY (category_id)
        REFERENCES android_app_categories (category_id)
        ON DELETE SET NULL ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS publisher_key VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN';
    """,
    """
    CREATE TABLE IF NOT EXISTS app_display_orderings (
      ordering_key  VARCHAR(64)   NOT NULL,
      package_name  VARCHAR(255)  NOT NULL,
      sort_order    INT           NOT NULL,
      created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (ordering_key, package_name),
      KEY idx_app_orderings_key_order (ordering_key, sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    -- Context-specific display aliases (e.g., publication shortening) without overwriting
    -- apps.display_name (canonical).
    CREATE TABLE IF NOT EXISTS app_display_aliases (
      alias_key     VARCHAR(64)   NOT NULL,
      package_name  VARCHAR(255)  NOT NULL,
      display_name  VARCHAR(255)  NOT NULL,
      created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (alias_key, package_name),
      KEY idx_app_aliases_key_name (alias_key, display_name)
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
      apk_set_id       BIGINT UNSIGNED DEFAULT NULL,
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
      findings_runtime_total INT UNSIGNED DEFAULT NULL,
      findings_capped_total INT UNSIGNED DEFAULT NULL,
      findings_capped_by_detector_json JSON DEFAULT NULL,
      detector_metrics JSON           DEFAULT NULL,
      repro_bundle     JSON           DEFAULT NULL,
      analysis_matrices JSON          DEFAULT NULL,
      analysis_indicators JSON        DEFAULT NULL,
      workload_profile JSON           DEFAULT NULL,
      created_at       TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_static_runs_version (app_version_id),
      KEY ix_static_runs_apk_set_id (apk_set_id),
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
      ADD COLUMN IF NOT EXISTS apk_set_id BIGINT UNSIGNED DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_apk_set_id
      ON static_analysis_runs (apk_set_id);
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
      ADD COLUMN IF NOT EXISTS profile_key VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS scenario_id VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS device_serial VARCHAR(128) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS tool_semver VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS tool_git_commit VARCHAR(40) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS schema_version VARCHAR(64) DEFAULT NULL;
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
      ADD COLUMN IF NOT EXISTS session_label VARCHAR(128) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS is_canonical TINYINT(1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS canonical_set_at_utc DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS canonical_reason VARCHAR(64) DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_session_label
      ON static_analysis_runs (session_label);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_canonical
      ON static_analysis_runs (session_label, is_canonical);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_runs_base_hash_contract
      ON static_analysis_runs (base_apk_sha256, status, run_class, identity_valid);
    """,
    """
    CREATE TABLE IF NOT EXISTS artifact_registry (
      artifact_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      run_id        VARCHAR(64)     NOT NULL,
      run_type      VARCHAR(16)     NOT NULL,
      session_stamp VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
      static_run_id BIGINT UNSIGNED DEFAULT NULL,
      dynamic_run_id VARCHAR(64)    DEFAULT NULL,
      linkage_migration_status VARCHAR(32) NOT NULL DEFAULT 'legacy_unclassified',
      artifact_type VARCHAR(64)     NOT NULL,
      origin        VARCHAR(16)     NOT NULL,
      device_path   TEXT            DEFAULT NULL,
      host_path     TEXT            DEFAULT NULL,
      pull_status   VARCHAR(16)     DEFAULT NULL,
      sha256        CHAR(64)        DEFAULT NULL,
      size_bytes    BIGINT          DEFAULT NULL,
      created_at_utc DATETIME       DEFAULT NULL,
      pulled_at_utc DATETIME        DEFAULT NULL,
      status_reason VARCHAR(191)    DEFAULT NULL,
      meta_json     JSON            DEFAULT NULL,
      PRIMARY KEY (artifact_id),
      KEY ix_artifact_run (run_id, run_type),
      KEY ix_artifact_run_type_created (run_type, created_at_utc),
      KEY ix_artifact_static_run_id (static_run_id),
      KEY ix_artifact_dynamic_run_id (dynamic_run_id),
      KEY ix_artifact_type (artifact_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE artifact_registry
      ADD COLUMN IF NOT EXISTS static_run_id BIGINT UNSIGNED DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS dynamic_run_id VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS session_stamp VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS linkage_migration_status VARCHAR(32) NOT NULL DEFAULT 'legacy_unclassified';
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_run_type_created
      ON artifact_registry (run_type, created_at_utc);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_static_run_id
      ON artifact_registry (static_run_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_dynamic_run_id
      ON artifact_registry (dynamic_run_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_session_stamp
      ON artifact_registry (session_stamp);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_run_type_session_created
      ON artifact_registry (run_type, session_stamp, created_at_utc);
    """,
    """
    -- Durable failure records for static persistence. Written outside the main
    -- persistence transaction so we don't lose the root cause on rollback.
    CREATE TABLE IF NOT EXISTS static_persistence_failures (
      id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      static_run_id     BIGINT UNSIGNED NOT NULL,
      stage             VARCHAR(64)     DEFAULT NULL,
      exception_class   VARCHAR(128)    DEFAULT NULL,
      exception_message VARCHAR(1024)   DEFAULT NULL,
      errors_tail       TEXT            DEFAULT NULL,
      occurred_at_utc   DATETIME        NOT NULL,
      PRIMARY KEY (id),
      KEY ix_static_persist_fail_run (static_run_id, occurred_at_utc)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ml_feature_windows (
      window_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      run_id        VARCHAR(64)     NOT NULL,
      run_type      VARCHAR(16)     NOT NULL DEFAULT 'dynamic',
      window_idx    INT             NOT NULL,
      start_utc     DATETIME        DEFAULT NULL,
      end_utc       DATETIME        DEFAULT NULL,
      features_json JSON            DEFAULT NULL,
      feature_version VARCHAR(32)   DEFAULT NULL,
      window_params_json JSON       DEFAULT NULL,
      created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (window_id),
      KEY ix_ml_windows_run (run_id, run_type),
      KEY ix_ml_windows_idx (run_id, window_idx)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ml_scores (
      score_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      run_id        VARCHAR(64)     NOT NULL,
      run_type      VARCHAR(16)     NOT NULL DEFAULT 'dynamic',
      model_name    VARCHAR(64)     NOT NULL,
      model_version VARCHAR(32)     DEFAULT NULL,
      window_id     BIGINT UNSIGNED DEFAULT NULL,
      score         DOUBLE          DEFAULT NULL,
      threshold     DOUBLE          DEFAULT NULL,
      is_anomaly    TINYINT(1)      DEFAULT NULL,
      params_json   JSON            DEFAULT NULL,
      trained_on_ref VARCHAR(191)   DEFAULT NULL,
      created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (score_id),
      KEY ix_ml_scores_run (run_id, run_type),
      KEY ix_ml_scores_model (model_name),
      KEY ix_ml_scores_window (window_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS base_apk_sha256 CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS artifact_set_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_signature CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_signature_version VARCHAR(16) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_valid TINYINT(1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_error_reason VARCHAR(128) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_mode VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS identity_conflict_flag TINYINT(1) DEFAULT 0,
      ADD COLUMN IF NOT EXISTS static_handoff_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS static_handoff_json JSON DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS static_handoff_json_path TEXT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS masvs_mapping_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS run_class VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS non_canonical_reasons JSON DEFAULT NULL;
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
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS findings_runtime_total INT UNSIGNED NULL,
      ADD COLUMN IF NOT EXISTS findings_capped_total INT UNSIGNED NULL,
      ADD COLUMN IF NOT EXISTS findings_capped_by_detector_json JSON DEFAULT NULL;
    """,
    """
    ALTER TABLE static_analysis_runs
      ADD COLUMN IF NOT EXISTS static_session_id BIGINT UNSIGNED DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_analysis_runs_static_session_id
      ON static_analysis_runs (static_session_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS static_analysis_sessions (
      static_session_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      session_stamp VARCHAR(128) NOT NULL,
      scope_label VARCHAR(191) NOT NULL DEFAULT '',
      session_label VARCHAR(191) DEFAULT NULL,
      session_status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
      session_disposition VARCHAR(64) NOT NULL DEFAULT 'unknown_needs_review',
      disposition_confidence VARCHAR(16) NOT NULL DEFAULT 'medium',
      total_run_count INT UNSIGNED NOT NULL DEFAULT 0,
      completed_run_count INT UNSIGNED NOT NULL DEFAULT 0,
      failed_run_count INT UNSIGNED NOT NULL DEFAULT 0,
      interrupted_run_count INT UNSIGNED NOT NULL DEFAULT 0,
      persist_error_run_count INT UNSIGNED NOT NULL DEFAULT 0,
      missing_artifacts_run_count INT UNSIGNED NOT NULL DEFAULT 0,
      total_findings_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      total_permission_matrix_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      total_permission_risk_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      total_string_summary_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      total_string_sample_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      session_link_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      rollup_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      persistence_failure_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
      expected_package_count INT UNSIGNED DEFAULT NULL,
      reconciled_package_count INT UNSIGNED DEFAULT NULL,
      completion_reconciliation_status VARCHAR(32) DEFAULT NULL,
      selection_artifact_manifest_sha256 CHAR(64) DEFAULT NULL,
      completion_reconciled_at_utc DATETIME DEFAULT NULL,
      web_visibility_default VARCHAR(16) NOT NULL DEFAULT 'operator',
      cleanup_status VARCHAR(32) NOT NULL DEFAULT 'none',
      superseded_by_session_id BIGINT UNSIGNED DEFAULT NULL,
      tool_semver VARCHAR(32) DEFAULT NULL,
      tool_git_commit VARCHAR(40) DEFAULT NULL,
      schema_version VARCHAR(64) DEFAULT NULL,
      first_created_at DATETIME DEFAULT NULL,
      last_ended_at DATETIME DEFAULT NULL,
      refreshed_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
      created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (static_session_id),
      UNIQUE KEY ux_static_session_natural (session_stamp, scope_label),
      KEY ix_static_session_disposition (session_disposition, web_visibility_default),
      KEY ix_static_session_cleanup (cleanup_status),
      KEY ix_static_session_stamp (session_stamp),
      CONSTRAINT fk_static_session_superseded
        FOREIGN KEY (superseded_by_session_id)
        REFERENCES static_analysis_sessions(static_session_id)
        ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
    """,
    """
    ALTER TABLE static_analysis_sessions
      ADD COLUMN IF NOT EXISTS expected_package_count INT UNSIGNED DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS reconciled_package_count INT UNSIGNED DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS completion_reconciliation_status VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS selection_artifact_manifest_sha256 CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS completion_reconciled_at_utc DATETIME DEFAULT NULL;
    """,
    """
    CREATE TABLE IF NOT EXISTS static_session_disposition_history (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      static_session_id BIGINT UNSIGNED NOT NULL,
      from_disposition VARCHAR(64) DEFAULT NULL,
      to_disposition VARCHAR(64) NOT NULL,
      reason VARCHAR(512) DEFAULT NULL,
      actor VARCHAR(128) NOT NULL DEFAULT 'manual_sql',
      detail_json LONGTEXT DEFAULT NULL,
      created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY ix_sess_disp_hist_session (static_session_id, created_at_utc),
      CONSTRAINT fk_sess_disp_hist_session
        FOREIGN KEY (static_session_id)
        REFERENCES static_analysis_sessions(static_session_id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
      severity_raw VARCHAR(32)   DEFAULT NULL,
      category    VARCHAR(64)     DEFAULT NULL,
      title       VARCHAR(512)    DEFAULT NULL,
      tags        JSON            DEFAULT NULL,
      evidence    JSON            DEFAULT NULL,
      fix         TEXT            DEFAULT NULL,
      rule_id     VARCHAR(128)    DEFAULT NULL,
      cvss_score  DECIMAL(4,1)    DEFAULT NULL,
      masvs_area  VARCHAR(32)     DEFAULT NULL,
      masvs_control_id VARCHAR(32) DEFAULT NULL,
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
      ADD COLUMN IF NOT EXISTS masvs_area VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS masvs_control_id VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS masvs_control VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS detector VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS module VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS evidence_refs JSON DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS severity_raw VARCHAR(32) DEFAULT NULL;
    """,
    """
    CREATE TABLE IF NOT EXISTS static_finding_evidence_payloads (
      evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
      evidence_json LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
      evidence_chars INT UNSIGNED NOT NULL,
      first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (evidence_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    ALTER TABLE static_analysis_findings
      ADD COLUMN IF NOT EXISTS evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL AFTER evidence_refs;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_findings_evidence_hash
    ON static_analysis_findings (evidence_hash);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_findings_rule_severity
    ON static_analysis_findings (rule_id, severity, run_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_static_findings_run_detector
    ON static_analysis_findings (run_id, detector);
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
    ALTER TABLE findings
      ADD COLUMN IF NOT EXISTS static_run_id BIGINT UNSIGNED DEFAULT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_findings_static_run
    ON findings (static_run_id);
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
      -- Explicit collation to prevent MariaDB "illegal mix of collations" when schemas evolve.
      ON s.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
     AND (
          (r.session_stamp IS NOT NULL AND s.session_stamp COLLATE utf8mb4_unicode_ci = r.session_stamp COLLATE utf8mb4_unicode_ci)
          OR (
              ABS(TIMESTAMPDIFF(SECOND, s.created_at, r.created_at)) <= 3600
          )
        )
    JOIN static_string_selected_samples sm ON sm.summary_id = s.id;
    """,
    """
    CREATE OR REPLACE VIEW v_static_run_category_summary AS
    SELECT
      COALESCE(r.category, 'Uncategorized') AS category,
      COUNT(*) AS run_count,
      MAX(r.created_at) AS latest_run,
      AVG(rs.risk_score) AS avg_risk_score,
      COUNT(rs.id) AS risk_rows
    FROM static_analysis_runs r
    JOIN app_versions av ON r.app_version_id = av.id
    JOIN apps a ON av.app_id = a.id
    LEFT JOIN risk_scores rs
      ON rs.session_stamp COLLATE utf8mb4_unicode_ci = r.session_stamp COLLATE utf8mb4_unicode_ci
     AND rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
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
