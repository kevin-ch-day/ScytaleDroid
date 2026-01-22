"""DB helpers for per-APK permission risk persistence."""

from __future__ import annotations

from typing import Iterable, Mapping

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


def ensure_table() -> bool:
    try:
        if _IS_SQLITE:
            run_sql(SQLITE_CREATE_TABLE)
            run_sql("CREATE UNIQUE INDEX IF NOT EXISTS ux_spr_apk ON static_permission_risk(apk_id)")
        else:
            run_sql(queries.CREATE_TABLE)
            try:
                row = run_sql(
                    """
                    SELECT character_maximum_length
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE()
                      AND table_name = 'static_permission_risk'
                      AND column_name = 'session_stamp'
                    """,
                    fetch="one",
                )
                if row and row[0] and int(row[0]) < 128:
                    run_sql("ALTER TABLE static_permission_risk MODIFY session_stamp VARCHAR(128) NOT NULL")
            except Exception:
                pass
        return True
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
        run_sql(SQLITE_UPSERT, payload)
    else:
        run_sql(queries.UPSERT_RISK, payload)


def bulk_upsert(rows: Iterable[Mapping[str, object]]) -> int:
    count = 0
    for row in rows:
        try:
            upsert(row)
            count += 1
        except Exception:
            continue
    return count


__all__ = ["ensure_table", "table_exists", "upsert", "bulk_upsert"]
