"""Bootstrap the database schema for the active backend (MySQL/MariaDB).

Usage:
    python -m scytaledroid.Database.tools.db_init

Note: SQLite is supported for unit tests only. OSS vNext requires MySQL/MariaDB
when DB features are enabled.
"""

from __future__ import annotations

import sys

from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def main() -> int:
    backend = str(DB_CONFIG.get("engine", "disabled"))
    db = str(DB_CONFIG.get("database", "<unknown>"))
    host = str(DB_CONFIG.get("host", "<local>"))
    log.info(f"Initializing schema for backend={backend} db={db} host={host}", category="database")
    if backend.lower() == "disabled":
        log.error(
            "DB init requested but DB is disabled. Configure SCYTALEDROID_DB_URL (mysql/mariadb) to enable DB features.",
            category="database",
        )
        return 1
    try:
        bootstrap_database()
    except SystemExit:
        raise
    except Exception as exc:
        log.error(f"DB init failed: {exc}", category="database")
        return 1
    log.info("DB init completed.", category="database")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
