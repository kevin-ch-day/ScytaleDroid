import os
import pathlib
import sys
from typing import Iterator

import pymysql
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Database.db_core import db_config


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
