"""DB writer for run-level metrics, buckets, correlations, findings, contributors.

Best-effort: functions return None/False if DB not reachable. Tables are
created if missing. This writer is intentionally minimal and safe.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Optional, Sequence, Union

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
      threat_profile VARCHAR(32)    NOT NULL DEFAULT 'Unknown',
      env_profile   VARCHAR(32)     NOT NULL DEFAULT 'consumer',
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
      KEY ix_metrics_feature (feature_key),
      KEY ix_metrics_run_feature (run_id, feature_key),
      UNIQUE KEY uq_metrics_run_key (run_id, feature_key)
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
      evidence_path   VARCHAR(512)   NULL,
      evidence_offset VARCHAR(64)    NULL,
      evidence_preview VARCHAR(256)  NULL,
      rule_id         VARCHAR(64)    NULL,
      cvss_v40_b_score   DECIMAL(4,1) NULL,
      cvss_v40_bt_score  DECIMAL(4,1) NULL,
      cvss_v40_be_score  DECIMAL(4,1) NULL,
      cvss_v40_bte_score DECIMAL(4,1) NULL,
      cvss_v40_b_vector   VARCHAR(128) NULL,
      cvss_v40_bt_vector  VARCHAR(128) NULL,
      cvss_v40_be_vector  VARCHAR(128) NULL,
      cvss_v40_bte_vector VARCHAR(128) NULL,
      cvss_v40_meta LONGTEXT NULL,
      KEY ix_findings_run (run_id),
      KEY ix_findings_rule (rule_id),
      KEY ix_findings_masvs (masvs)
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
        _ensure_run_profiles_columns()
        _ensure_metrics_unique_key()
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
    threat_profile: str = "Unknown",
    env_profile: str = "consumer",
) -> Optional[int]:
    try:
        ensure_schema()
        run_id = core_q.run_sql(
            (
                "INSERT INTO runs (package, version_code, version_name, target_sdk, schema_version, ts, session_stamp, prefs_hash, installer, confidence, threat_profile, env_profile) "
                "VALUES (%s,%s,%s,%s,%s,CURRENT_TIMESTAMP,%s,%s,%s,%s,%s,%s)"
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
                threat_profile,
                env_profile,
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
                (
                    "INSERT INTO metrics (run_id, feature_key, value_num, value_text, module_id) "
                    "VALUES (%s,%s,%s,%s,%s) "
                    "ON DUPLICATE KEY UPDATE value_num=VALUES(value_num), value_text=VALUES(value_text), module_id=VALUES(module_id)"
                ),
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


FindingRow = Union[
    tuple[str, str, str, str, Union[str, Mapping[str, Any]]],
    tuple[str, str, str, str, Union[str, Mapping[str, Any]], Optional[str]],
    Mapping[str, Any],
]


def write_findings(run_id: int, rows: Sequence[FindingRow]) -> bool:
    try:
        for row in rows:
            if isinstance(row, Mapping):
                severity = row.get("severity")
                masvs = row.get("masvs")
                cvss = row.get("cvss") or row.get("legacy_cvss")
                kind = row.get("kind")
                module_id = row.get("module_id")
                evidence_payload = row.get("evidence")
            else:
                if len(row) == 6:
                    severity, masvs, cvss, kind, evidence_payload, module_id = row
                else:
                    severity, masvs, cvss, kind, evidence_payload = row[:5]
                    module_id = None
            evidence = _serialise_evidence(evidence_payload)
            core_q.run_sql(
                "INSERT INTO findings (run_id, severity, masvs, cvss, kind, evidence, module_id) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (run_id, severity, masvs, cvss, kind, evidence, module_id),
            )
        return True
    except Exception:
        return False


def _serialise_evidence(payload: Any) -> Optional[str]:
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return json.dumps({}, ensure_ascii=False)


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


def _ensure_run_profiles_columns() -> None:
    for column_name, ddl in (
        (
            "threat_profile",
            "ALTER TABLE runs ADD COLUMN threat_profile VARCHAR(32) NOT NULL DEFAULT 'Unknown' AFTER confidence;",
        ),
        (
            "env_profile",
            "ALTER TABLE runs ADD COLUMN env_profile VARCHAR(32) NOT NULL DEFAULT 'consumer' AFTER threat_profile;",
        ),
    ):
        try:
            column = core_q.run_sql(
                "SHOW COLUMNS FROM runs LIKE %s;",
                (column_name,),
                fetch="one",
            )
            if not column:
                core_q.run_sql(ddl)
        except Exception:
            pass


def _ensure_metrics_unique_key() -> None:
    try:
        existing = core_q.run_sql(
            "SHOW INDEX FROM metrics WHERE Key_name=%s;",
            ("uq_metrics_run_key",),
            fetch="one",
        )
        if existing:
            _ensure_metrics_indexes()
            return
    except Exception:
        return

    duplicates_present = False
    try:
        duplicate = core_q.run_sql(
            """
            SELECT run_id, feature_key
            FROM metrics
            GROUP BY run_id, feature_key
            HAVING COUNT(*) > 1
            LIMIT 1;
            """,
            fetch="one",
            dictionary=True,
        )
        duplicates_present = bool(duplicate)
    except Exception:
        duplicates_present = False

    if duplicates_present:
        _deduplicate_metrics_table()

    try:
        core_q.run_sql(
            "ALTER TABLE metrics ADD UNIQUE KEY uq_metrics_run_key (run_id, feature_key);"
        )
    except Exception:
        pass

    _ensure_metrics_indexes()


def _ensure_metrics_indexes() -> None:
    statements = (
        "ALTER TABLE metrics ADD INDEX ix_metrics_run (run_id);",
        "ALTER TABLE metrics ADD INDEX ix_metrics_feature (feature_key);",
        "ALTER TABLE metrics ADD INDEX ix_metrics_run_feature (run_id, feature_key);",
    )
    for stmt in statements:
        try:
            core_q.run_sql(stmt)
        except Exception:
            continue


def _deduplicate_metrics_table() -> None:
    try:
        core_q.run_sql("DROP TABLE IF EXISTS metrics_tmp;")
        core_q.run_sql(
            """
            CREATE TABLE metrics_tmp (
              run_id      BIGINT UNSIGNED NOT NULL,
              feature_key VARCHAR(191)    NOT NULL,
              value_num   DECIMAL(12,4)   NULL,
              value_text  VARCHAR(512)    NULL,
              module_id   VARCHAR(64)     NULL,
              UNIQUE KEY uq_metrics_run_key (run_id, feature_key),
              KEY ix_metrics_run (run_id),
              KEY ix_metrics_feature (feature_key),
              KEY ix_metrics_run_feature (run_id, feature_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        )
        core_q.run_sql(
            """
            INSERT INTO metrics_tmp (run_id, feature_key, value_num, value_text, module_id)
            SELECT
              run_id,
              feature_key,
              MAX(value_num) AS value_num,
              SUBSTRING_INDEX(
                GROUP_CONCAT(COALESCE(value_text, '') ORDER BY LENGTH(value_text) DESC SEPARATOR '\\x1D'),
                '\\x1D', 1
              ) AS value_text,
              SUBSTRING_INDEX(
                GROUP_CONCAT(COALESCE(module_id, '') ORDER BY LENGTH(module_id) DESC SEPARATOR '\\x1D'),
                '\\x1D', 1
              ) AS module_id
            FROM metrics
            GROUP BY run_id, feature_key;
            """
        )
        core_q.run_sql(
            "RENAME TABLE metrics TO metrics_backup_tmp, metrics_tmp TO metrics;"
        )
        core_q.run_sql("DROP TABLE IF EXISTS metrics_backup_tmp;")
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
    try:
        core_q.run_sql(_views.CREATE_V_MASVS_MATRIX)
    except Exception:
        pass
