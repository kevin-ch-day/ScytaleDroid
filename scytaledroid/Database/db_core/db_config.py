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

__all__ = ["DB_CONFIG", "DB_CONFIG_SOURCE"]
