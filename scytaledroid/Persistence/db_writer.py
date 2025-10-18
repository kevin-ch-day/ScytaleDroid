"""DB writer for run-level metrics, buckets, correlations, findings, contributors.

Best-effort: functions return None/False if DB not reachable. Tables are
created if missing. This writer is intentionally minimal and safe.
"""

from __future__ import annotations

from typing import Mapping, Optional, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_queries import views as _views


_DDL = [
    """
    CREATE TABLE IF NOT EXISTS runs (
      run_id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      package       VARCHAR(191)    NOT NULL,
      version_code  BIGINT          NULL,
      version_name  VARCHAR(191)    NULL,
      target_sdk    INT             NULL,
      schema_version VARCHAR(32)    NULL,
      ts            TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
      session_stamp VARCHAR(32)     NULL,
      prefs_hash    VARCHAR(64)     NULL,
      installer     VARCHAR(191)    NULL,
      confidence    VARCHAR(32)     NULL,
      PRIMARY KEY (run_id),
      KEY ix_runs_session (session_stamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS metrics (
      run_id     BIGINT UNSIGNED NOT NULL,
      feature_key VARCHAR(191)   NOT NULL,
      value_num  DECIMAL(12,4)   NULL,
      value_text VARCHAR(512)    NULL,
      module_id  VARCHAR(64)     NULL,
      KEY ix_metrics_run (run_id),
      KEY ix_metrics_key (feature_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS buckets (
      run_id   BIGINT UNSIGNED NOT NULL,
      bucket   VARCHAR(64)     NOT NULL,
      points   DECIMAL(8,3)    NOT NULL,
      cap      DECIMAL(8,3)    NULL,
      KEY ix_buckets (run_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS correlations (
      run_id   BIGINT UNSIGNED NOT NULL,
      rule_id  VARCHAR(64)     NOT NULL,
      points   DECIMAL(8,3)    NOT NULL,
      rationale VARCHAR(512)   NULL,
      KEY ix_corr (run_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
      run_id   BIGINT UNSIGNED NOT NULL,
      severity VARCHAR(16)     NOT NULL,
      masvs    VARCHAR(32)     NULL,
      cvss     VARCHAR(128)    NULL,
      kind     VARCHAR(64)     NULL,
      evidence VARCHAR(512)    NULL,
      module_id VARCHAR(64)    NULL,
      KEY ix_findings (run_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS contributors (
      run_id   BIGINT UNSIGNED NOT NULL,
      feature  VARCHAR(128)    NOT NULL,
      points   DECIMAL(8,3)    NOT NULL,
      explanation VARCHAR(512) NULL,
      rank     INT             NULL,
      KEY ix_contrib (run_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]


def ensure_schema() -> bool:
    try:
        for stmt in _DDL:
            core_q.run_sql(stmt)
        _ensure_runs_session_column()
        _ensure_buckets_foreign_key()
        _ensure_views()
        return True
    except Exception:
        return False


def create_run(
    *,
    package: str,
    version_code: Optional[int],
    version_name: Optional[str],
    target_sdk: Optional[int],
    schema_version: str = "v1",
    prefs_hash: Optional[str] = None,
    installer: Optional[str] = None,
    confidence: Optional[str] = None,
    session_stamp: Optional[str] = None,
) -> Optional[int]:
    try:
        ensure_schema()
        run_id = core_q.run_sql(
            (
                "INSERT INTO runs (package, version_code, version_name, target_sdk, schema_version, ts, session_stamp, prefs_hash, installer, confidence) "
                "VALUES (%s,%s,%s,%s,%s,CURRENT_TIMESTAMP,%s,%s,%s,%s)"
            ),
            (
                package,
                version_code,
                version_name,
                target_sdk,
                schema_version,
                session_stamp,
                prefs_hash,
                installer,
                confidence,
            ),
            return_lastrowid=True,
        )
        return int(run_id) if run_id else None
    except Exception:
        return None


def write_metrics(run_id: int, entries: Mapping[str, tuple[Optional[float], Optional[str]]], module_id: Optional[str] = None) -> bool:
    try:
        for key, (num, text) in entries.items():
            core_q.run_sql(
                "INSERT INTO metrics (run_id, feature_key, value_num, value_text, module_id) VALUES (%s,%s,%s,%s,%s)",
                (run_id, key, num, text, module_id),
            )
        return True
    except Exception:
        return False


def write_buckets(run_id: int, buckets: Mapping[str, tuple[float, Optional[float]]]) -> bool:
    try:
        for name, (points, cap) in buckets.items():
            core_q.run_sql(
                "INSERT INTO buckets (run_id, bucket, points, cap) VALUES (%s,%s,%s,%s)",
                (run_id, name, points, cap),
            )
        return True
    except Exception:
        return False


def write_correlations(run_id: int, rows: Sequence[tuple[str, float, str]]) -> bool:
    try:
        for rule_id, points, rationale in rows:
            core_q.run_sql(
                "INSERT INTO correlations (run_id, rule_id, points, rationale) VALUES (%s,%s,%s,%s)",
                (run_id, rule_id, points, rationale),
            )
        return True
    except Exception:
        return False


def write_findings(run_id: int, rows: Sequence[tuple[str, str, str, str, str]]) -> bool:
    try:
        for severity, masvs, cvss, kind, evidence in rows:
            core_q.run_sql(
                "INSERT INTO findings (run_id, severity, masvs, cvss, kind, evidence, module_id) VALUES (%s,%s,%s,%s,%s,%s)",
                (run_id, severity, masvs, cvss, kind, evidence, None),
            )
        return True
    except Exception:
        return False


def write_contributors(run_id: int, rows: Sequence[tuple[str, float, str, int]]) -> bool:
    try:
        for feature, points, explanation, rank in rows:
            core_q.run_sql(
                "INSERT INTO contributors (run_id, feature, points, explanation, rank) VALUES (%s,%s,%s,%s,%s)",
                (run_id, feature, points, explanation, rank),
            )
        return True
    except Exception:
        return False


__all__ = [
    "ensure_schema",
    "create_run",
    "write_metrics",
    "write_buckets",
    "write_correlations",
    "write_findings",
    "write_contributors",
]


def _ensure_runs_session_column() -> None:
    try:
        column = core_q.run_sql(
            "SHOW COLUMNS FROM runs LIKE 'session_stamp';",
            fetch="one",
        )
        if not column:
            core_q.run_sql(
                "ALTER TABLE runs ADD COLUMN session_stamp VARCHAR(32) NULL AFTER ts;",
            )
    except Exception:
        pass

    try:
        core_q.run_sql("ALTER TABLE runs ADD INDEX ix_runs_session (session_stamp);")
    except Exception:
        pass


def _ensure_buckets_foreign_key() -> None:
    try:
        fk_exists = core_q.run_sql(
            """
            SELECT CONSTRAINT_NAME
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE table_schema = DATABASE()
              AND table_name = 'buckets'
              AND referenced_table_name = 'runs'
              AND referenced_column_name = 'run_id';
            """,
            fetch="one",
        )
        if not fk_exists:
            core_q.run_sql(
                """
                ALTER TABLE buckets
                ADD CONSTRAINT fk_buckets_run
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                    ON DELETE CASCADE;
                """
            )
    except Exception:
        pass


def _ensure_views() -> None:
    try:
        core_q.run_sql(_views.CREATE_V_RUN_OVERVIEW)
    except Exception:
        pass

