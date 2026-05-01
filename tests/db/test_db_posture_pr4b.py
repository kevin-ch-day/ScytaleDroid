from __future__ import annotations

import pytest

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine
from scytaledroid.Database.tools import db_schema_snapshot


def test_database_engine_raises_when_disabled(monkeypatch) -> None:
    monkeypatch.setitem(db_config.DB_CONFIG, "engine", "disabled")
    with pytest.raises(RuntimeError):
        DatabaseEngine()


def test_db_schema_snapshot_when_disabled_does_not_connect(monkeypatch) -> None:
    monkeypatch.setitem(db_config.DB_CONFIG, "engine", "disabled")
    snapshot = db_schema_snapshot.generate_snapshot()
    assert snapshot["db_enabled"] is False
    assert "note" in snapshot


def test_sqlite_db_url_rejected_outside_pytest(monkeypatch) -> None:
    # db_config forces SQLite defaults under pytest to avoid touching real DBs.
    # This test exercises the explicit DB_URL parsing path by calling the internal loader.
    monkeypatch.setenv("SCYTALEDROID_NO_DOTENV", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(db_config.sys, "argv", ["python"])
    monkeypatch.setenv("SCYTALEDROID_DB_URL", "sqlite:///tmp/scytaledroid.db")

    with pytest.raises(RuntimeError):
        db_config._load_from_env()  # noqa: SLF001 - unit-test posture contract

