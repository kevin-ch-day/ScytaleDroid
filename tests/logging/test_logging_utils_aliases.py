from __future__ import annotations

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_utils


def test_static_analysis_alias_routes_to_static_logger(monkeypatch) -> None:
    seen: list[str] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            return None

    monkeypatch.setattr(
        logging_utils.logging_engine,
        "get_logger",
        lambda category: seen.append(category) or _Logger(),
    )

    logging_utils.info("hello", category="static_analysis")

    assert seen == ["static"]


def test_db_alias_routes_to_database_logger(monkeypatch) -> None:
    seen: list[str] = []
    err_calls: list[str] = []

    class _Logger:
        def warning(self, _message, *, extra=None):
            return None

    class _ErrLogger:
        def warning(self, _message, *, extra=None):
            err_calls.append(_message)

    monkeypatch.setattr(
        logging_utils.logging_engine,
        "get_logger",
        lambda category: seen.append(category) or _Logger(),
    )
    monkeypatch.setattr(logging_utils.logging_engine, "get_error_logger", lambda: _ErrLogger())

    logging_utils.warning("hello", category="db")

    assert seen == ["database"]
    assert err_calls == []


def test_emit_environment_snapshot_includes_environment_identity(monkeypatch) -> None:
    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    monkeypatch.setattr(app_config, "DEBUG_MODE", True)
    monkeypatch.setattr(app_config, "SYS_TEST", False)
    monkeypatch.setattr(app_config, "RUNTIME_PRESET", "virtual")
    monkeypatch.setattr(app_config, "EXECUTION_MODE", "DEV")
    monkeypatch.setattr(app_config, "SYS_ENV", "VIRTUAL")

    logging_engine.emit_environment_snapshot(_Logger())

    assert records
    record = records[0]
    assert record["event"] == "app.env"
    assert record["debug_mode"] is True
    assert record["sys_test"] is False
    assert record["runtime_preset"] == "virtual"
    assert record["execution_mode"] == "DEV"
    assert record["sys_env"] == "VIRTUAL"
