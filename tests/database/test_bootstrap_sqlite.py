from __future__ import annotations

from scytaledroid.Database.tools import bootstrap


def test_normalize_sqlite_removes_on_update_current_timestamp() -> None:
    sql = """
    CREATE TABLE IF NOT EXISTS example (
      refreshed_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    normalized = bootstrap._normalize_sqlite(sql)  # noqa: SLF001 - targeted contract test

    assert "ON UPDATE CURRENT_TIMESTAMP" not in normalized
    assert "DEFAULT CURRENT_TIMESTAMP" in normalized


def test_normalize_sqlite_strips_charset_and_collation_clauses() -> None:
    sql = """
    CREATE TABLE IF NOT EXISTS demo (
      payload JSON CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
      note LONGTEXT COLLATE utf8mb4_unicode_ci NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    normalized = bootstrap._normalize_sqlite(sql)  # noqa: SLF001 - targeted contract test

    assert "CHARACTER SET" not in normalized
    assert "COLLATE" not in normalized
    assert "TEXT" in normalized


def test_execute_statements_skips_mysql_only_sqlite_statements(monkeypatch) -> None:
    executed: list[str] = []
    monkeypatch.setattr(bootstrap, "run_sql", lambda sql, *args, **kwargs: executed.append(sql))

    bootstrap._execute_statements(  # noqa: SLF001 - targeted contract test
        [
            "CREATE INDEX IF NOT EXISTS ix_static_analysis_runs_static_session_id ON static_analysis_runs (static_session_id);",
            "CREATE OR REPLACE VIEW v_demo AS SELECT 1;",
            "ALTER TABLE demo ADD COLUMN added_later VARCHAR(64) NULL;",
            "CREATE TABLE IF NOT EXISTS demo (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, refreshed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP);",
        ],
        dialect="sqlite",
    )

    assert len(executed) == 1
    assert "CREATE TABLE IF NOT EXISTS demo" in executed[0]
    assert "ON UPDATE CURRENT_TIMESTAMP" not in executed[0]
