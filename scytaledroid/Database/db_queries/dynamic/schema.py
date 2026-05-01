"""Dynamic-analysis schema for sessions and telemetry."""

from __future__ import annotations

import re

from ...db_core import db_queries as core_q

_DDL_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS dynamic_sessions (
      dynamic_run_id     CHAR(36)     NOT NULL,
      package_name       VARCHAR(255) NOT NULL,
      device_serial      VARCHAR(128) DEFAULT NULL,
      profile_key        VARCHAR(64)  DEFAULT NULL,
      operator_run_profile VARCHAR(64) DEFAULT NULL,
      operator_interaction_level VARCHAR(32) DEFAULT NULL,
      operator_messaging_activity VARCHAR(32) DEFAULT NULL,
      scenario_id        VARCHAR(64)  DEFAULT NULL,
      tier               VARCHAR(32)  DEFAULT NULL,
      countable          TINYINT(1)   DEFAULT NULL,
      valid_dataset_run  TINYINT(1)   DEFAULT NULL,
      invalid_reason_code VARCHAR(64) DEFAULT NULL,
      duration_seconds   INT          DEFAULT NULL,
      sampling_duration_seconds DOUBLE DEFAULT NULL,
      clock_alignment_delta_s DOUBLE DEFAULT NULL,
      sampling_rate_s    INT          DEFAULT NULL,
      started_at_utc     DATETIME     DEFAULT NULL,
      ended_at_utc       DATETIME     DEFAULT NULL,
      host_time_utc_start DATETIME    DEFAULT NULL,
      host_time_utc_end   DATETIME    DEFAULT NULL,
      device_time_utc_start DATETIME  DEFAULT NULL,
      device_time_utc_end   DATETIME  DEFAULT NULL,
      device_uptime_ms_start BIGINT   DEFAULT NULL,
      device_uptime_ms_end   BIGINT   DEFAULT NULL,
      drift_ms_start     BIGINT       DEFAULT NULL,
      drift_ms_end       BIGINT       DEFAULT NULL,
      status             VARCHAR(16)  DEFAULT NULL,
      evidence_path      TEXT         DEFAULT NULL,
      static_run_id      BIGINT       DEFAULT NULL,
      static_handoff_hash CHAR(64)    DEFAULT NULL,
      run_signature      CHAR(64)     DEFAULT NULL,
      run_signature_version VARCHAR(16) DEFAULT NULL,
      base_apk_sha256    CHAR(64)     DEFAULT NULL,
      apk_sha256         CHAR(64)     DEFAULT NULL,
      artifact_set_hash  CHAR(64)     DEFAULT NULL,
      version_name       VARCHAR(191) DEFAULT NULL,
      version_code       BIGINT       DEFAULT NULL,
      expected_samples   INT          DEFAULT NULL,
      captured_samples   INT          DEFAULT NULL,
      sample_min_delta_s FLOAT        DEFAULT NULL,
      sample_avg_delta_s FLOAT        DEFAULT NULL,
      sample_max_delta_s FLOAT        DEFAULT NULL,
      sample_max_gap_s   FLOAT        DEFAULT NULL,
      sample_first_gap_s FLOAT        DEFAULT NULL,
      sample_max_gap_excluding_first_s FLOAT DEFAULT NULL,
      netstats_available TINYINT(1)   DEFAULT NULL,
      network_signal_quality VARCHAR(32) DEFAULT NULL,
      netstats_rows     INT          DEFAULT NULL,
      netstats_missing_rows INT      DEFAULT NULL,
      pcap_relpath      VARCHAR(512) DEFAULT NULL,
      pcap_bytes        BIGINT       DEFAULT NULL,
      pcap_sha256       CHAR(64)     DEFAULT NULL,
      pcap_valid        TINYINT(1)   DEFAULT NULL,
      pcap_validated_at_utc DATETIME DEFAULT NULL,
      tool_semver        VARCHAR(32)  DEFAULT NULL,
      tool_git_commit    VARCHAR(40)  DEFAULT NULL,
      schema_version     VARCHAR(32)  DEFAULT NULL,
      grade              VARCHAR(16)  DEFAULT NULL,
      grade_reasons_json JSON         DEFAULT NULL,
      created_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (dynamic_run_id),
      KEY idx_dyn_sessions_pkg_scenario_started (package_name, scenario_id, started_at_utc),
      KEY idx_dyn_sessions_pkg_bundle_scenario (package_name, artifact_set_hash, scenario_id),
      KEY idx_dyn_sessions_device_started (device_serial, started_at_utc)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    ALTER TABLE dynamic_sessions
      ADD COLUMN IF NOT EXISTS profile_key VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS operator_run_profile VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS operator_interaction_level VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS operator_messaging_activity VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS countable TINYINT(1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS valid_dataset_run TINYINT(1) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS invalid_reason_code VARCHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS host_time_utc_start DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS host_time_utc_end DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS device_time_utc_start DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS device_time_utc_end DATETIME DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS device_uptime_ms_start BIGINT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS device_uptime_ms_end BIGINT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS drift_ms_start BIGINT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS drift_ms_end BIGINT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS apk_sha256 CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS static_handoff_hash CHAR(64) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS tool_semver VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS tool_git_commit VARCHAR(40) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS schema_version VARCHAR(32) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS grade VARCHAR(16) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS grade_reasons_json JSON DEFAULT NULL;
    """,
    """
    CREATE TABLE IF NOT EXISTS dynamic_session_issues (
      id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      dynamic_run_id CHAR(36)        NOT NULL,
      issue_code     VARCHAR(64)     NOT NULL,
      details_json   JSON            DEFAULT NULL,
      created_at     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_dyn_issues_run (dynamic_run_id),
      KEY idx_dyn_issues_code (issue_code),
      CONSTRAINT fk_dyn_issues_run
        FOREIGN KEY (dynamic_run_id)
        REFERENCES dynamic_sessions (dynamic_run_id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    CREATE TABLE IF NOT EXISTS dynamic_telemetry_process (
      id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      dynamic_run_id  CHAR(36)        NOT NULL,
      sample_index    INT             NOT NULL,
      timestamp_utc   DATETIME        NOT NULL,
      uid             VARCHAR(64)     DEFAULT NULL,
      pid             INT             DEFAULT NULL,
      cpu_pct         FLOAT           DEFAULT NULL,
      rss_kb          FLOAT           DEFAULT NULL,
      pss_kb          FLOAT           DEFAULT NULL,
      threads         INT             DEFAULT NULL,
      proc_name       VARCHAR(191)    DEFAULT NULL,
      best_effort     TINYINT(1)      DEFAULT NULL,
      collector_status VARCHAR(64)    DEFAULT NULL,
      PRIMARY KEY (id),
      KEY idx_dyn_proc_run_ts (dynamic_run_id, timestamp_utc),
      CONSTRAINT fk_dyn_proc_run
        FOREIGN KEY (dynamic_run_id)
        REFERENCES dynamic_sessions (dynamic_run_id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS dynamic_telemetry_network (
      id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      dynamic_run_id  CHAR(36)        NOT NULL,
      sample_index    INT             NOT NULL,
      timestamp_utc   DATETIME        NOT NULL,
      uid             VARCHAR(64)     DEFAULT NULL,
      bytes_in        DOUBLE          DEFAULT NULL,
      bytes_out       DOUBLE          DEFAULT NULL,
      conn_count      DOUBLE          DEFAULT NULL,
      source          VARCHAR(64)     DEFAULT NULL,
      best_effort     TINYINT(1)      DEFAULT NULL,
      collector_status VARCHAR(64)    DEFAULT NULL,
      PRIMARY KEY (id),
      KEY idx_dyn_net_run_ts (dynamic_run_id, timestamp_utc),
      CONSTRAINT fk_dyn_net_run
        FOREIGN KEY (dynamic_run_id)
        REFERENCES dynamic_sessions (dynamic_run_id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS dynamic_network_indicators (
      id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      dynamic_run_id  CHAR(36)        NOT NULL,
      indicator_type  VARCHAR(32)     NOT NULL,
      indicator_value VARCHAR(255)    NOT NULL,
      indicator_count INT             DEFAULT NULL,
      indicator_source VARCHAR(32)    DEFAULT NULL,
      meta_json       JSON            DEFAULT NULL,
      created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY ux_dyn_net_ind (dynamic_run_id, indicator_type, indicator_value, indicator_source),
      KEY idx_dyn_net_ind_type_value (indicator_type, indicator_value),
      CONSTRAINT fk_dyn_net_ind_run
        FOREIGN KEY (dynamic_run_id)
        REFERENCES dynamic_sessions (dynamic_run_id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    -- Derived (rebuildable) per-run network feature index.
    --
    -- Paper #2 contract: evidence packs remain authoritative. This table exists
    -- purely to accelerate SQL pulls for ML/reporting without JSON scanning.
    CREATE TABLE IF NOT EXISTS dynamic_network_features (
      dynamic_run_id     CHAR(36)        NOT NULL,
      package_name       VARCHAR(255)    NOT NULL,
      run_profile        VARCHAR(64)     DEFAULT NULL,
      interaction_level  VARCHAR(32)     DEFAULT NULL,
      tier               VARCHAR(32)     DEFAULT NULL,
      valid_dataset_run  TINYINT(1)      DEFAULT NULL,
      invalid_reason_code VARCHAR(64)    DEFAULT NULL,
      countable          TINYINT(1)      DEFAULT NULL,
      low_signal         TINYINT(1)      DEFAULT NULL,
      low_signal_reasons_json JSON       DEFAULT NULL,
      min_pcap_bytes     INT             DEFAULT NULL,
      min_duration_s     INT             DEFAULT NULL,
      feature_schema_version VARCHAR(32) NOT NULL,
      host_tools_json    JSON            DEFAULT NULL,

      -- Metrics (from analysis/pcap_features.json:metrics)
      capture_duration_s DOUBLE          DEFAULT NULL,
      packet_count       BIGINT          DEFAULT NULL,
      data_size_bytes    BIGINT          DEFAULT NULL,
      bytes_per_sec      DOUBLE          DEFAULT NULL,
      packets_per_sec    DOUBLE          DEFAULT NULL,
      avg_packet_size_bytes DOUBLE       DEFAULT NULL,
      avg_packet_rate_pps DOUBLE         DEFAULT NULL,
      bytes_per_second_p50 DOUBLE        DEFAULT NULL,
      bytes_per_second_p95 DOUBLE        DEFAULT NULL,
      bytes_per_second_max DOUBLE        DEFAULT NULL,
      packets_per_second_p50 DOUBLE      DEFAULT NULL,
      packets_per_second_p95 DOUBLE      DEFAULT NULL,
      packets_per_second_max DOUBLE      DEFAULT NULL,
      burstiness_bytes_p95_over_p50 DOUBLE DEFAULT NULL,
      burstiness_packets_p95_over_p50 DOUBLE DEFAULT NULL,

      -- Proxies (from analysis/pcap_features.json:proxies)
      tls_ratio          FLOAT           DEFAULT NULL,
      quic_ratio         FLOAT           DEFAULT NULL,
      tcp_ratio          FLOAT           DEFAULT NULL,
      udp_ratio          FLOAT           DEFAULT NULL,
      unique_dns_topn    INT             DEFAULT NULL,
      unique_sni_topn    INT             DEFAULT NULL,
      unique_domains_topn INT            DEFAULT NULL,
      unique_dst_ip_count INT            DEFAULT NULL,
      unique_dst_port_count INT          DEFAULT NULL,
      sni_observation_count INT          DEFAULT NULL,
      dns_observation_count INT          DEFAULT NULL,
      unique_sni_count     INT           DEFAULT NULL,
      unique_dns_qname_count INT         DEFAULT NULL,
      top1_sni_share      FLOAT          DEFAULT NULL,
      top1_dns_share      FLOAT          DEFAULT NULL,
      domains_per_min     FLOAT          DEFAULT NULL,
      new_domain_rate_per_min FLOAT      DEFAULT NULL,
      new_sni_rate_per_min FLOAT         DEFAULT NULL,
      new_dns_rate_per_min FLOAT         DEFAULT NULL,
      top_dns_total      INT             DEFAULT NULL,
      top_sni_total      INT             DEFAULT NULL,
      dns_concentration  FLOAT           DEFAULT NULL,
      sni_concentration  FLOAT           DEFAULT NULL,

      created_at         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (dynamic_run_id),
      KEY idx_dyn_net_feat_pkg_profile (package_name, run_profile),
      KEY idx_dyn_net_feat_pkg_valid (package_name, valid_dataset_run),
      CONSTRAINT fk_dyn_net_feat_run
        FOREIGN KEY (dynamic_run_id)
        REFERENCES dynamic_sessions (dynamic_run_id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
    """
    -- Best-effort forward schema extension (derived table only).
    ALTER TABLE dynamic_network_features
      ADD COLUMN IF NOT EXISTS bytes_per_second_p50 DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS bytes_per_second_p95 DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS bytes_per_second_max DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS packets_per_second_p50 DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS packets_per_second_p95 DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS packets_per_second_max DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS burstiness_bytes_p95_over_p50 DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS burstiness_packets_p95_over_p50 DOUBLE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS unique_dst_ip_count INT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS unique_dst_port_count INT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS sni_observation_count INT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS dns_observation_count INT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS unique_sni_count INT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS unique_dns_qname_count INT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS top1_sni_share FLOAT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS top1_dns_share FLOAT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS domains_per_min FLOAT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS new_domain_rate_per_min FLOAT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS new_sni_rate_per_min FLOAT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS new_dns_rate_per_min FLOAT DEFAULT NULL;
    """,
]


_TABLE_NAME_PATTERN = re.compile(r"CREATE TABLE IF NOT EXISTS\\s+`?([a-zA-Z0-9_]+)`?", re.IGNORECASE)

_REQUIRED_TABLES: tuple[str, ...] = (
    # Core persistence tables. These are required for DB-backed indexing, but DB
    # must remain optional for evidence-pack-based workflows.
    "dynamic_sessions",
    "dynamic_session_issues",
    "dynamic_telemetry_process",
    "dynamic_telemetry_network",
)


def ensure_all() -> bool:
    """Verify required dynamic tables exist; no runtime DDL is executed.

    Important: this must be an explicit allowlist so derived/index tables don't
    accidentally become required just because DDL was added.
    """
    tables = set(_REQUIRED_TABLES)
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
                core_q.run_sql("/* dynamic schema missing */ SELECT 1")
            except Exception:
                pass
    return ok


__all__ = ["ensure_all", "_DDL_STATEMENTS"]
