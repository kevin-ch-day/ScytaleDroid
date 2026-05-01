import os
import pathlib
import sys
from collections.abc import Iterator

import pymysql
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Database.db_core import db_config  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def bootstrap_sqlite_schema() -> None:
    """Ensure SQLite schema exists for unit/persistence tests."""

    if db_config.DB_CONFIG.get("engine", "sqlite") != "sqlite":
        return
    try:
        from scytaledroid.Database.tools.bootstrap import bootstrap_database

        bootstrap_database()
    except Exception as exc:  # pragma: no cover - defensive
        pytest.skip(f"SQLite bootstrap failed: {exc}")


@pytest.fixture(scope="session", autouse=True)
def isolate_test_logs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Redirect test logging away from the shared workspace log directory."""

    from scytaledroid.Utils.LoggingUtils import logging_core, logging_engine

    monkeypatch = pytest.MonkeyPatch()
    log_root = tmp_path_factory.mktemp("logs")

    def _reset_loggers() -> None:
        for adapter in list(logging_engine._HARVEST_LOGGERS.values()):  # noqa: SLF001 - test cleanup
            logger = adapter.logger
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    pass
        logging_engine._HARVEST_LOGGERS.clear()  # noqa: SLF001 - test cleanup

        for logger in list(logging_engine._LOGGERS.values()):  # noqa: SLF001 - test cleanup
            logging_engine._clear_handlers(logger)  # noqa: SLF001 - test cleanup
        logging_engine._LOGGERS.clear()  # noqa: SLF001 - test cleanup

    _reset_loggers()
    monkeypatch.setattr(logging_core, "LOG_DIR", log_root)
    monkeypatch.setattr(logging_engine, "LOG_DIR", log_root)

    try:
        yield
    finally:
        _reset_loggers()
        monkeypatch.undo()


@pytest.fixture(autouse=True)
def isolate_integration_db(request: pytest.FixtureRequest) -> Iterator[None]:
    """Point integration tests at the dedicated test schema and truncate it."""

    if "integration" not in request.keywords:
        yield
        return

    # Integration tests are opt-in. Require an explicit DSN to avoid accidental
    # connections to local/prod databases.
    if not (os.environ.get("SCYTALEDROID_TEST_DB_URL") or os.environ.get("SCYTALEDROID_DB_URL")):
        pytest.skip("Integration DB tests are opt-in. Set SCYTALEDROID_TEST_DB_URL (recommended) or SCYTALEDROID_DB_URL.")

    test_db = os.environ.get("SCYTALEDROID_TEST_DB", "scytaledroid_droid_intel_db_test")
    original_db = db_config.DB_CONFIG["database"]
    db_config.override_database(test_db)

    config = db_config.DB_CONFIG
    if "host" not in config:
        db_config.override_database(original_db)
        pytest.skip("Integration DB not configured (missing host).")
    try:
        connection = pymysql.connect(
            host=config["host"],
            port=int(config["port"]),
            user=config["user"],
            password=config["password"],
            database=config["database"],
            charset=config.get("charset", "utf8mb4"),
            autocommit=True,
        )
    except pymysql.err.OperationalError as exc:
        db_config.override_database(original_db)
        pytest.skip(f"Cannot connect to test database '{test_db}': {exc}")
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET FOREIGN_KEY_CHECKS=0")
            cursor.execute("SHOW FULL TABLES WHERE Table_Type='BASE TABLE'")
            tables = [row[0] for row in cursor.fetchall()]
            for table in tables:
                cursor.execute(f"TRUNCATE TABLE `{table}`")
            cursor.execute("SET FOREIGN_KEY_CHECKS=1")
    finally:
        connection.close()

    try:
        yield
    finally:
        db_config.override_database(original_db)
