from __future__ import annotations

import pytest
from scytaledroid.Database.db_core import optional


def test_maybe_get_database_returns_none_when_database_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(optional.db_config, "DB_CONFIG", {"engine": "disabled", "database": ""})
    monkeypatch.setattr(optional.db_config, "DB_CONFIG_SOURCE", "disabled")

    assert optional.maybe_get_database() is None
    availability = optional.database_availability()
    assert availability.state == "disabled"
    assert "database disabled" in availability.message


def test_require_database_fails_explicitly_when_database_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(optional.db_config, "DB_CONFIG", {"engine": "disabled", "database": ""})
    monkeypatch.setattr(optional.db_config, "DB_CONFIG_SOURCE", "disabled")

    with pytest.raises(optional.DatabaseUnavailableError) as excinfo:
        optional.require_database()

    assert excinfo.value.availability.state == "disabled"
    assert "SCYTALEDROID_DB_URL" in str(excinfo.value)


def test_maybe_get_database_classifies_connection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(optional.db_config, "DB_CONFIG", {"engine": "mysql", "database": "scytale"})
    monkeypatch.setattr(optional.db_config, "DB_CONFIG_SOURCE", "env:SCYTALEDROID_DB_URL")

    class BrokenDatabaseEngine:
        def __init__(self) -> None:
            raise RuntimeError("network down")

    import scytaledroid.Database.db_core.db_engine as db_engine

    monkeypatch.setattr(db_engine, "DatabaseEngine", BrokenDatabaseEngine)

    with pytest.raises(optional.DatabaseUnavailableError) as excinfo:
        optional.maybe_get_database()

    assert excinfo.value.availability.state == "connection_failed"
    assert "database connection failed" in str(excinfo.value)


def test_optional_database_boundary_does_not_mask_required_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(optional.db_config, "DB_CONFIG", {"engine": "disabled", "database": ""})

    with pytest.raises(optional.DatabaseUnavailableError):
        optional.require_database()
