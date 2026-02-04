import os
from collections.abc import Iterator

import pymysql
import pytest
from scytaledroid.Database.db_core import db_config


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


@pytest.fixture(autouse=True)
def isolate_integration_db(request: pytest.FixtureRequest) -> Iterator[None]:
    """Point integration tests at the dedicated test schema and truncate it."""

    if "integration" not in request.keywords:
        yield
        return

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
