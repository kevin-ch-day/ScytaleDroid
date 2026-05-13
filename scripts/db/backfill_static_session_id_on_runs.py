#!/usr/bin/env python3
"""Backfill ``static_analysis_runs.static_session_id`` from ``static_analysis_sessions``.

Resolves matching headers on (session_stamp, COALESCE(TRIM(scope_label),'')).
Uses the same connection resolution as ``recreate_web_consumer_views.py``.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_PREVIEW_COUNT_SQL = """
SELECT COUNT(*)
FROM static_analysis_runs sar
INNER JOIN static_analysis_sessions sas
  ON sas.session_stamp = sar.session_stamp
 AND sas.scope_label = COALESCE(TRIM(BOTH FROM sar.scope_label), '')
WHERE sar.static_session_id IS NULL
  AND sar.session_stamp IS NOT NULL
  AND LENGTH(TRIM(BOTH FROM sar.session_stamp)) > 0
"""

_UPDATE_SQL = """
UPDATE static_analysis_runs sar
INNER JOIN static_analysis_sessions sas
  ON sas.session_stamp = sar.session_stamp
 AND sas.scope_label = COALESCE(TRIM(BOTH FROM sar.scope_label), '')
SET sar.static_session_id = sas.static_session_id
WHERE sar.static_session_id IS NULL
  AND sar.session_stamp IS NOT NULL
  AND LENGTH(TRIM(BOTH FROM sar.session_stamp)) > 0
"""


def _connect():  # pragma: no cover — thin copy of recreate_web_consumer_views helpers
    try:
        import pymysql  # type: ignore[import-untyped]
    except ImportError as e:
        raise RuntimeError("pymysql is required. pip install pymysql") from e

    from scytaledroid.Database.db_core import db_config

    cfg = db_config.DB_CONFIG
    engine = str(cfg.get("engine", "")).lower()
    host = cfg.get("host") or os.environ.get("SCYTALEDROID_DB_HOST", "localhost")
    port = int(cfg.get("port") or os.environ.get("SCYTALEDROID_DB_PORT", "3306"))
    user = (
        str(cfg.get("user") or "")
        .strip()
        or (os.environ.get("SCYTALEDROID_DB_USER") or os.environ.get("MYSQL_USER") or "").strip()
    )
    password = str(
        cfg.get("password")
        or os.environ.get("SCYTALEDROID_DB_PASSWD")
        or os.environ.get("SCYTALEDROID_DB_PASS")
        or os.environ.get("MYSQL_PASSWORD", "")
        or ""
    )
    database = str(
        cfg.get("database")
        or os.environ.get("SCYTALEDROID_DB_NAME")
        or os.environ.get("MYSQL_DATABASE")
        or ""
    ).strip()

    if engine == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        sys.exit(2)
    if not user or not database:
        sys.stderr.write("Operational DB not resolved (set SCYTALEDROID_DB_URL or SCYTALEDROID_DB_*).\n")
        sys.exit(2)

    return pymysql.connect(
        host=str(host),
        port=port,
        user=user,
        password=password,
        database=database,
        charset="utf8mb4",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Execute UPDATE (default is dry-run: count only).",
    )
    args = parser.parse_args()

    conn = _connect()
    conn.autocommit(True)
    try:
        with conn.cursor() as cur:
            cur.execute(_PREVIEW_COUNT_SQL)
            row = cur.fetchone()
            preview = int(row[0]) if row and row[0] is not None else 0
            print(f"matchable_null_static_session_id_rows={preview}")
            if not args.apply:
                print("(dry-run; pass --apply to run UPDATE)")
                return 0
            cur.execute(_UPDATE_SQL)
            print(f"rows_affected={cur.rowcount}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
