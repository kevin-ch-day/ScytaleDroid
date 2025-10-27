"""db_config.py - Simple hardcoded database configuration.

This module intentionally contains only static values. Connection handling and
all runtime logic live in db_engine.py.
"""

from typing import Dict, Union

DB_CONFIG: Dict[str, Union[str, int]] = {
    "host": "localhost",
    "port": 3306,
    "user": "scytale",
    "password": "StrongPass!",
    "database": "scytaledroid_droid_intel_db_dev",
    "charset": "utf8mb4",
}

# For display purposes in menus/tools
DB_CONFIG_SOURCE: str = "hardcoded"

_DEFAULT_DATABASE = DB_CONFIG["database"]


def override_database(database: str | None) -> None:
    """Temporarily override the target database schema.

    Passing ``None`` restores the default development schema.  This is primarily
    used by integration tests to isolate work in the shared MariaDB instance.
    """

    global DB_CONFIG
    if database:
        DB_CONFIG["database"] = database
    else:
        DB_CONFIG["database"] = _DEFAULT_DATABASE


__all__ = ["DB_CONFIG", "DB_CONFIG_SOURCE", "override_database"]
