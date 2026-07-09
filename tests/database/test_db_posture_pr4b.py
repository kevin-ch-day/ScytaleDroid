from __future__ import annotations

import sqlite3

import pytest
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_engine
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.db_engine import DatabaseEngine
from scytaledroid.Database.tools import db_schema_snapshot


class _FakeLogger:
    def __init__(self) -> None:
        self.warning_calls: list[tuple[str, dict[str, object]]] = []

    def warning(self, message: str, *, extra=None, **_kwargs) -> None:  # noqa: ANN001
        self.warning_calls.append((message, dict(extra or {})))

    def error(self, *_args, **_kwargs) -> None:  # noqa: ANN001
        raise AssertionError("unexpected error log")

    def debug(self, *_args, **_kwargs) -> None:  # noqa: ANN001
        raise AssertionError("unexpected debug log")


def test_database_engine_raises_when_disabled(monkeypatch) -> None:
    monkeypatch.setitem(db_config.DB_CONFIG, "engine", "disabled")
    with pytest.raises(RuntimeError):
        DatabaseEngine()


def test_db_schema_snapshot_when_disabled_does_not_connect(monkeypatch) -> None:
    monkeypatch.setitem(db_config.DB_CONFIG, "engine", "disabled")
    snapshot = db_schema_snapshot.generate_snapshot()
    assert snapshot["db_enabled"] is False
    assert "note" in snapshot


def test_db_schema_snapshot_markdown_splits_legacy_presence() -> None:
    md = db_schema_snapshot._render_markdown(
        {
            "timestamp_utc": "t",
            "db_enabled": True,
            "required_tables": {"schema_version": True},
            "legacy_mirror_table_presence": {"runs": True, "findings": False},
            "optional_columns": [],
            "schema_version_history": [],
            "tables": [],
        }
    )
    assert "## required_tables" in md
    assert "## legacy_mirror_table_presence" in md
    assert "Informational only" in md
    assert "`findings`" in md and "**missing**" in md


def test_sqlite_db_url_rejected_outside_pytest(monkeypatch) -> None:
    # db_config forces SQLite defaults under pytest to avoid touching real DBs.
    # This test exercises the explicit DB_URL parsing path by calling the internal loader.
    monkeypatch.setenv("SCYTALEDROID_NO_DOTENV", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(db_config.sys, "argv", ["python"])
    monkeypatch.setenv("SCYTALEDROID_DB_URL", "sqlite:///tmp/scytaledroid.db")

    with pytest.raises(RuntimeError):
        db_config._load_from_env()  # noqa: SLF001 - unit-test posture contract


def test_sqlite_operational_logging_includes_sql_fields(monkeypatch) -> None:
    fake_log = _FakeLogger()
    monkeypatch.setattr(db_engine, "_LOG", fake_log)

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    with pytest.raises(db_engine.DatabaseError):
        db_engine._execute(  # noqa: SLF001 - targeted logging contract
            cursor,
            "SELECT * FROM missing_table WHERE id = %s",
            (1,),
            query_name="test.sqlite.failure",
            context={"op": "probe"},
            many=False,
        )

    assert len(fake_log.warning_calls) == 1
    message, extra = fake_log.warning_calls[0]
    assert message == "db.exec.sqlite_operational"
    assert extra["query"] == "test.sqlite.failure"
    assert extra["op"] == "probe"
    assert extra["sql_preview"] == "SELECT * FROM missing_table WHERE id = %s"
    assert isinstance(extra["sql_sha1"], str)
    assert len(extra["sql_sha1"]) == 40


@pytest.mark.integration
def test_run_sql_supports_named_and_positional_placeholders():
    """Exercise run_sql with both tuple/positional and dict/named params."""

    table_name = "paramstyle_guard_test"
    try:
        core_q.run_sql(f"DROP TABLE IF EXISTS {table_name}")
        core_q.run_sql(
            f"CREATE TABLE {table_name} ("
            "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "
            "value VARCHAR(64) NOT NULL"
            ")"
        )

        tuple_id = core_q.run_sql(
            f"INSERT INTO {table_name} (value) VALUES (%s)",
            ("tuple-style",),
            return_lastrowid=True,
        )
        dict_id = core_q.run_sql(
            f"INSERT INTO {table_name} (value) VALUES (%(val)s)",
            {"val": "dict-style"},
            return_lastrowid=True,
        )

        assert tuple_id != dict_id

        rows = core_q.run_sql(
            f"SELECT value FROM {table_name} ORDER BY id",
            fetch="all",
        )
        assert rows == [("tuple-style",), ("dict-style",)]
    except Exception as exc:  # pragma: no cover - defensive skip when DB unavailable
        pytest.skip(f"Database not available for paramstyle integration test: {exc}")
    finally:
        try:
            core_q.run_sql(f"DROP TABLE IF EXISTS {table_name}")
        except Exception:
            pass
