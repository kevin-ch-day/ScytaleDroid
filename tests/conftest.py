import os
from typing import Iterator

import pymysql
import pytest


def _parse_env_url() -> dict[str, str | int]:
    from urllib.parse import urlparse, unquote

    url = os.environ.get("SCYTALEDROID_DB_URL")
    if not url:
        raise RuntimeError("SCYTALEDROID_DB_URL must be set for integration tests.")
    parsed = urlparse(url)
    if not parsed.path or parsed.path == "/":
        raise RuntimeError("SCYTALEDROID_DB_URL must include a database name.")
    return {
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 3306,
        "user": unquote(parsed.username) if parsed.username else "",
        "password": unquote(parsed.password) if parsed.password else "",
        "database": parsed.path.lstrip("/"),
        "charset": "utf8mb4",
    }


@pytest.fixture(autouse=True)
def truncate_database(request: pytest.FixtureRequest) -> Iterator[None]:
    if "integration" not in request.keywords:
        yield
        return

    if "SCYTALEDROID_DB_URL" not in os.environ:
        pytest.skip("SCYTALEDROID_DB_URL not set; integration tests skipped.")

    config = _parse_env_url()
    connection = pymysql.connect(
        host=config["host"],
        port=int(config["port"]),
        user=config["user"],
        password=config["password"],
        database=config["database"],
        charset=config.get("charset", "utf8mb4"),
        autocommit=True,
    )
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
    yield
