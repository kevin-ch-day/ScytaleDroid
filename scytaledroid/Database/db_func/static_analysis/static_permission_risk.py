"""DB helpers for per-APK permission risk persistence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import db_config, run_sql
from ...db_queries.static_analysis import static_permission_risk as queries

_IS_SQLITE = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower() == "sqlite"

SQLITE_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS static_permission_risk (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  apk_id INTEGER NOT NULL,
  app_id INTEGER NULL,
  package_name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  session_stamp TEXT NOT NULL,
  scope_label TEXT NOT NULL,
  risk_score REAL NOT NULL,
  risk_grade TEXT NOT NULL,
  dangerous INTEGER NOT NULL DEFAULT 0,
  signature INTEGER NOT NULL DEFAULT 0,
  vendor INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(apk_id)
);
"""

SQLITE_CREATE_TABLE_VNEXT = """
CREATE TABLE IF NOT EXISTS static_permission_risk_vnext (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  permission_name TEXT NOT NULL,
  risk_score REAL NOT NULL,
  risk_class TEXT NULL,
  rationale_code TEXT NULL,
  created_at_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(run_id, permission_name)
);
"""

SQLITE_UPSERT = """
INSERT INTO static_permission_risk (
  apk_id, app_id, package_name, sha256,
  session_stamp, scope_label,
  risk_score, risk_grade,
  dangerous, signature, vendor
) VALUES (
  %(apk_id)s, %(app_id)s, %(package_name)s, %(sha256)s,
  %(session_stamp)s, %(scope_label)s,
  %(risk_score)s, %(risk_grade)s,
  %(dangerous)s, %(signature)s, %(vendor)s
)
ON CONFLICT(apk_id) DO UPDATE SET
  app_id=excluded.app_id,
  package_name=excluded.package_name,
  sha256=excluded.sha256,
  session_stamp=excluded.session_stamp,
  scope_label=excluded.scope_label,
  risk_score=excluded.risk_score,
  risk_grade=excluded.risk_grade,
  dangerous=excluded.dangerous,
  signature=excluded.signature,
  vendor=excluded.vendor,
  created_at=CURRENT_TIMESTAMP
"""

SQLITE_UPSERT_VNEXT = """
INSERT INTO static_permission_risk_vnext (
  run_id, permission_name, risk_score, risk_class, rationale_code
) VALUES (
  %(run_id)s, %(permission_name)s, %(risk_score)s, %(risk_class)s, %(rationale_code)s
)
ON CONFLICT(run_id, permission_name) DO UPDATE SET
  risk_score=excluded.risk_score,
  risk_class=excluded.risk_class,
  rationale_code=excluded.rationale_code,
  created_at_utc=CURRENT_TIMESTAMP
"""


def ensure_table() -> bool:
    try:
        ok = table_exists()
        if not ok:
            log.warning(
                "static_permission_risk missing; load a DB snapshot or apply migrations.",
                category="database",
            )
        return ok
    except Exception:
        return False


def table_exists() -> bool:
    try:
        if _IS_SQLITE:
            row = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_permission_risk'",
                fetch="one",
            )
            return bool(row)
        row = run_sql(queries.TABLE_EXISTS, fetch="one")
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def upsert(payload: Mapping[str, object]) -> None:
    if _IS_SQLITE:
        try:
            run_sql(SQLITE_UPSERT, payload)
        except Exception:
            run_sql("DELETE FROM static_permission_risk WHERE apk_id = %s", (payload.get("apk_id"),))
            insert_stmt = """
            INSERT INTO static_permission_risk (
              apk_id, app_id, package_name, sha256,
              session_stamp, scope_label,
              risk_score, risk_grade,
              dangerous, signature, vendor
            ) VALUES (
              %(apk_id)s, %(app_id)s, %(package_name)s, %(sha256)s,
              %(session_stamp)s, %(scope_label)s,
              %(risk_score)s, %(risk_grade)s,
              %(dangerous)s, %(signature)s, %(vendor)s
            )
            """
            run_sql(insert_stmt, payload)
    else:
        run_sql(queries.UPSERT_RISK, payload)


def table_exists_vnext() -> bool:
    try:
        if _IS_SQLITE:
            row = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_permission_risk_vnext'",
                fetch="one",
            )
            return bool(row)
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'static_permission_risk_vnext'",
            fetch="one",
        )
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def ensure_table_vnext() -> bool:
    try:
        if _IS_SQLITE:
            run_sql(SQLITE_CREATE_TABLE_VNEXT)
        else:
            run_sql(
                """
                CREATE TABLE IF NOT EXISTS static_permission_risk_vnext (
                  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                  run_id BIGINT UNSIGNED NOT NULL,
                  permission_name VARCHAR(255) NOT NULL,
                  risk_score DECIMAL(7,3) NOT NULL,
                  risk_class VARCHAR(32) NULL,
                  rationale_code VARCHAR(64) NULL,
                  created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (id),
                  UNIQUE KEY ux_spr_vnext_run_perm (run_id, permission_name),
                  KEY ix_spr_vnext_run (run_id),
                  CONSTRAINT fk_spr_vnext_run
                    FOREIGN KEY (run_id) REFERENCES static_analysis_runs(id)
                    ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        return table_exists_vnext()
    except Exception:
        return False


def upsert_vnext(payload: Mapping[str, object]) -> None:
    if _IS_SQLITE:
        run_sql(SQLITE_UPSERT_VNEXT, payload)
        return
    run_sql(
        """
        INSERT INTO static_permission_risk_vnext (
          run_id, permission_name, risk_score, risk_class, rationale_code
        ) VALUES (
          %(run_id)s, %(permission_name)s, %(risk_score)s, %(risk_class)s, %(rationale_code)s
        )
        ON DUPLICATE KEY UPDATE
          risk_score = VALUES(risk_score),
          risk_class = VALUES(risk_class),
          rationale_code = VALUES(rationale_code),
          created_at_utc = CURRENT_TIMESTAMP
        """,
        payload,
    )


def bulk_upsert(rows: Iterable[Mapping[str, object]]) -> int:
    count = 0
    for row in rows:
        try:
            upsert(row)
            count += 1
        except Exception:
            continue
    return count


__all__ = [
    "ensure_table",
    "ensure_table_vnext",
    "table_exists",
    "upsert",
    "bulk_upsert",
    "table_exists_vnext",
    "upsert_vnext",
]
