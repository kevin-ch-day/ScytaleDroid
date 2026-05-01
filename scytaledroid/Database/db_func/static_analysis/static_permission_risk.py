"""DB helpers for canonical permission-level risk persistence."""

from __future__ import annotations

from collections.abc import Mapping

from ...db_core import db_config, run_sql

_ENGINE = str(db_config.DB_CONFIG.get("engine", "")).strip().lower()
_IS_SQLITE = _ENGINE == "sqlite"
if _IS_SQLITE and not db_config.is_test_env():
    raise RuntimeError("SQLite backend is test-only; configure MySQL/MariaDB or disable DB.")

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


__all__ = [
    "ensure_table_vnext",
    "table_exists_vnext",
    "upsert_vnext",
]
