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
      scenario_id        VARCHAR(64)  DEFAULT NULL,
      tier               VARCHAR(32)  DEFAULT NULL,
      duration_seconds   INT          DEFAULT NULL,
      sampling_rate_s    INT          DEFAULT NULL,
      started_at_utc     DATETIME     DEFAULT NULL,
      ended_at_utc       DATETIME     DEFAULT NULL,
      status             VARCHAR(16)  DEFAULT NULL,
      evidence_path      TEXT         DEFAULT NULL,
      static_run_id      BIGINT       DEFAULT NULL,
      run_signature      CHAR(64)     DEFAULT NULL,
      run_signature_version VARCHAR(16) DEFAULT NULL,
      base_apk_sha256    CHAR(64)     DEFAULT NULL,
      artifact_set_hash  CHAR(64)     DEFAULT NULL,
      version_name       VARCHAR(191) DEFAULT NULL,
      version_code       BIGINT       DEFAULT NULL,
      expected_samples   INT          DEFAULT NULL,
      captured_samples   INT          DEFAULT NULL,
      sample_min_delta_s FLOAT        DEFAULT NULL,
      sample_avg_delta_s FLOAT        DEFAULT NULL,
      sample_max_delta_s FLOAT        DEFAULT NULL,
      sample_max_gap_s   FLOAT        DEFAULT NULL,
      netstats_available TINYINT(1)   DEFAULT NULL,
      network_signal_quality VARCHAR(32) DEFAULT NULL,
      created_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (dynamic_run_id),
      KEY idx_dyn_sessions_pkg_scenario_started (package_name, scenario_id, started_at_utc),
      KEY idx_dyn_sessions_pkg_bundle_scenario (package_name, artifact_set_hash, scenario_id),
      KEY idx_dyn_sessions_device_started (device_serial, started_at_utc)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
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
]


_TABLE_NAME_PATTERN = re.compile(r"CREATE TABLE IF NOT EXISTS\\s+`?([a-zA-Z0-9_]+)`?", re.IGNORECASE)


def ensure_all() -> bool:
    """Verify dynamic tables exist; no runtime DDL is executed."""
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
                core_q.run_sql("/* dynamic schema missing */ SELECT 1")
            except Exception:
                pass
    return ok


__all__ = ["ensure_all", "_DDL_STATEMENTS"]
