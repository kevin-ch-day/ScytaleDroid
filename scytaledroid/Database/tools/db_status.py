"""Report database backend status, connection, and schema version.

OSS vNext posture:
- DB is optional.
- When enabled, MySQL/MariaDB is required.
"""

from __future__ import annotations

import sys

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine


def main() -> int:
    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    host = str(cfg.get("host", "<unknown>"))
    port = str(cfg.get("port", "<unknown>"))
    database = str(cfg.get("database", "<unknown>"))
    user = str(cfg.get("user", "<unknown>"))

    print("Database Status")
    print("================")
    print(f"Backend : {backend}")
    print(f"Host    : {host}")
    print(f"Port    : {port}")
    print(f"Database: {database}")
    print(f"User    : {user}")
    print(f"Config  : {getattr(db_config, 'DB_CONFIG_SOURCE', 'default')}")
    print("")

    if not db_config.db_enabled():
        print("Connection: DISABLED (DB not configured)")
        print("Schema version: n/a")
        return 0

    engine = None
    try:
        engine = DatabaseEngine()
        engine.fetch_one("SELECT 1")
        print("Connection: OK")
    except Exception as exc:
        print(f"Connection: FAILED ({exc})")
        return 1

    try:
        row = engine.fetch_one(
            "SELECT version, applied_at_utc FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1"
        )
        if row:
            print(f"Schema version: {row[0]} (applied {row[1]})")
        else:
            print("Schema version: MISSING")
            return 2
    except Exception as exc:
        print(f"Schema check failed: {exc}")
        return 2

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
