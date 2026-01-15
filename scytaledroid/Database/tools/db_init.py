"""Bootstrap the database schema for the active backend (MariaDB or SQLite).

Usage:
    python -m scytaledroid.Database.tools.db_init
"""

from __future__ import annotations

import sys

from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def main() -> int:
    backend = str(DB_CONFIG.get("engine", "sqlite"))
    db = str(DB_CONFIG.get("database", "<unknown>"))
    host = str(DB_CONFIG.get("host", "<local>"))
    log.info(f"Initializing schema for backend={backend} db={db} host={host}", category="database")
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
