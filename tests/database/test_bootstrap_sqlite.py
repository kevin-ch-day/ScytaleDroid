from __future__ import annotations

import sqlite3

import pytest
from scytaledroid.Database.db_queries.harvest.install_sets import CREATE_HARVEST_APK_OBSERVATIONS
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


def test_normalize_sqlite_preserves_unique_constraint_columns() -> None:
    normalized = bootstrap._normalize_sqlite(CREATE_HARVEST_APK_OBSERVATIONS)  # noqa: SLF001

    assert "UNIQUE (" in normalized
    assert "harvest_session_id" in normalized
    assert "package_name" in normalized
    assert "split_name" in normalized
    assert "sha256" in normalized
    assert "UNIQUE KEY" not in normalized


def test_normalized_harvest_observations_sql_executes_in_sqlite() -> None:
    normalized = bootstrap._normalize_sqlite(CREATE_HARVEST_APK_OBSERVATIONS)  # noqa: SLF001

    conn = sqlite3.connect(":memory:")
    conn.execute(normalized)


def test_bootstrap_database_rejects_sqlite_outside_tests(monkeypatch) -> None:
    monkeypatch.setitem(bootstrap.DB_CONFIG, "engine", "sqlite")
    monkeypatch.setattr(bootstrap.db_config, "is_test_env", lambda: False)

    with pytest.raises(RuntimeError, match="SQLite bootstrap is test-only"):
        bootstrap.bootstrap_database()


def test_bootstrap_module_help_is_side_effect_free(monkeypatch) -> None:
    monkeypatch.setattr(
        bootstrap,
        "bootstrap_database",
        lambda: (_ for _ in ()).throw(AssertionError("bootstrap must not run for --help")),
    )

    with pytest.raises(SystemExit) as exc_info:
        bootstrap.main(["--help"])

    assert exc_info.value.code == 0
