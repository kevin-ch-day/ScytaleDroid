"""Post-paper analysis registry + derived-facts schema (Phase H, tables-only).

These tables make the DB authoritative for:
- cohort selection and run membership (no more "rogue JSON discovery")
- derived aggregate facts used in reports (RDI, deltas, exposure, regimes)

Evidence packs remain immutable ground truth; these tables store *indices* and
*derived aggregates* with full provenance (receipt_id).
"""

from __future__ import annotations

_DDL_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS analysis_cohorts (
      cohort_id        VARCHAR(64)  NOT NULL,
      name             VARCHAR(191) NOT NULL,
      selector_type    VARCHAR(16)  NOT NULL,   -- freeze|query|manual
      freeze_sha256    CHAR(64)     DEFAULT NULL,
      selection_manifest_sha256 CHAR(64) DEFAULT NULL,
      toolchain_fingerprint CHAR(64) DEFAULT NULL,
      pipeline_git_sha VARCHAR(40)  DEFAULT NULL,
      created_at_utc   DATETIME     NOT NULL,
      notes_json       JSON         DEFAULT NULL,
      PRIMARY KEY (cohort_id),
      KEY idx_analysis_cohorts_created (created_at_utc)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_derivation_receipts (
      receipt_id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      cohort_id        VARCHAR(64)     NOT NULL,
      freeze_sha256    CHAR(64)        DEFAULT NULL,
      selection_manifest_sha256 CHAR(64) DEFAULT NULL,
      toolchain_fingerprint CHAR(64)   DEFAULT NULL,
      pipeline_git_sha VARCHAR(40)     DEFAULT NULL,
      params_json      JSON            DEFAULT NULL, -- windowing, percentile method, model params, etc.
      status           VARCHAR(16)     NOT NULL DEFAULT 'RUNNING', -- RUNNING|OK|FAIL
      finished_at_utc  DATETIME        DEFAULT NULL,
      error_text       TEXT            DEFAULT NULL,
      created_at_utc   DATETIME        NOT NULL,
      PRIMARY KEY (receipt_id),
      KEY idx_analysis_receipts_cohort (cohort_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    ALTER TABLE analysis_derivation_receipts
      ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'RUNNING',
      ADD COLUMN IF NOT EXISTS finished_at_utc DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS error_text TEXT DEFAULT NULL;
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_cohort_runs (
      cohort_id        VARCHAR(64)  NOT NULL,
      dynamic_run_id   CHAR(36)     NOT NULL,
      package_name     VARCHAR(255) NOT NULL,
      base_apk_sha256  CHAR(64)     DEFAULT NULL,
      run_role         VARCHAR(16)  NOT NULL,  -- baseline|interactive|unknown
      included         TINYINT(1)   NOT NULL DEFAULT 1,
      exclude_reason   VARCHAR(64)  DEFAULT NULL,
      evidence_pack_sha256 CHAR(64) DEFAULT NULL,
      pcap_sha256      CHAR(64)     DEFAULT NULL,
      created_at_utc   DATETIME     NOT NULL,
      PRIMARY KEY (cohort_id, dynamic_run_id),
      KEY idx_analysis_cohort_runs_pkg (cohort_id, package_name),
      KEY idx_analysis_cohort_runs_role (cohort_id, run_role)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_ml_app_phase_model_metrics (
      receipt_id       BIGINT UNSIGNED NOT NULL,
      cohort_id        VARCHAR(64)  NOT NULL,
      package_name     VARCHAR(255) NOT NULL,
      phase            VARCHAR(16)  NOT NULL,  -- idle|interactive
      model_key        VARCHAR(32)  NOT NULL,  -- isolation_forest|one_class_svm
      windows_total    INT          NOT NULL,
      windows_flagged  INT          NOT NULL,
      flagged_pct      DOUBLE       NOT NULL,
      threshold_value  DOUBLE       DEFAULT NULL,
      training_mode    VARCHAR(32)  DEFAULT NULL, -- baseline_only|union_fallback
      train_samples    INT          DEFAULT NULL,
      np_percentile_method VARCHAR(32) DEFAULT NULL,
      ml_schema_version VARCHAR(32) DEFAULT NULL,
      pipeline_git_sha VARCHAR(40)  DEFAULT NULL,
      created_at_utc   DATETIME     NOT NULL,
      PRIMARY KEY (cohort_id, package_name, phase, model_key),
      KEY idx_analysis_ml_metrics_receipt (receipt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_signature_deltas (
      receipt_id       BIGINT UNSIGNED NOT NULL,
      cohort_id        VARCHAR(64)  NOT NULL,
      package_name     VARCHAR(255) NOT NULL,
      bytes_p50_delta  DOUBLE       DEFAULT NULL,
      bytes_p95_delta  DOUBLE       DEFAULT NULL,
      pps_p50_delta    DOUBLE       DEFAULT NULL,
      pps_p95_delta    DOUBLE       DEFAULT NULL,
      pkt_size_p50_delta DOUBLE     DEFAULT NULL,
      pkt_size_p95_delta DOUBLE     DEFAULT NULL,
      idle_windows     INT          DEFAULT NULL,
      interactive_windows INT       DEFAULT NULL,
      created_at_utc   DATETIME     NOT NULL,
      PRIMARY KEY (cohort_id, package_name),
      KEY idx_analysis_sig_receipt (receipt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_static_exposure (
      receipt_id       BIGINT UNSIGNED NOT NULL,
      cohort_id        VARCHAR(64)  NOT NULL,
      package_name     VARCHAR(255) NOT NULL,
      exported_components_raw INT    DEFAULT NULL,
      dangerous_permissions_raw INT  DEFAULT NULL,
      uses_cleartext_traffic TINYINT(1) DEFAULT NULL,
      sdk_indicators_score DOUBLE    DEFAULT NULL,
      exported_components_norm DOUBLE DEFAULT NULL,
      dangerous_permissions_norm DOUBLE DEFAULT NULL,
      static_posture_score DOUBLE    NOT NULL,
      exposure_grade   VARCHAR(16)   DEFAULT NULL, -- L/M/H (interpretive)
      notes_json       JSON          DEFAULT NULL,
      created_at_utc   DATETIME      NOT NULL,
      PRIMARY KEY (cohort_id, package_name),
      KEY idx_analysis_exposure_receipt (receipt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_risk_regime_summary (
      receipt_id       BIGINT UNSIGNED NOT NULL,
      cohort_id        VARCHAR(64)  NOT NULL,
      package_name     VARCHAR(255) NOT NULL,
      static_score     DOUBLE       DEFAULT NULL,
      static_grade     VARCHAR(16)  DEFAULT NULL,
      dynamic_score_if DOUBLE       DEFAULT NULL,
      dynamic_grade_if VARCHAR(16)  DEFAULT NULL,
      final_regime_if  VARCHAR(32)  DEFAULT NULL,
      notes_json       JSON         DEFAULT NULL,
      created_at_utc   DATETIME     NOT NULL,
      PRIMARY KEY (cohort_id, package_name),
      KEY idx_analysis_regime_receipt (receipt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]
