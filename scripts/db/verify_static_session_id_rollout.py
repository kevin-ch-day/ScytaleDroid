#!/usr/bin/env python3
"""Print scalar verification counts for static_session_id rollout (read-only)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_QUERIES: tuple[tuple[str, str], ...] = (
    (
        "sar_with_stamp_null_static_session_id",
        """
        SELECT COUNT(*)
        FROM static_analysis_runs sar
        WHERE sar.session_stamp IS NOT NULL
          AND LENGTH(TRIM(BOTH FROM sar.session_stamp)) > 0
          AND sar.static_session_id IS NULL
        """,
    ),
    (
        "session_headers_with_zero_runs",
        """
        SELECT COUNT(*)
        FROM static_analysis_sessions sas
        LEFT JOIN static_analysis_runs sar
          ON TRIM(BOTH FROM sar.session_stamp) = TRIM(BOTH FROM sas.session_stamp)
         AND COALESCE(TRIM(BOTH FROM sar.scope_label), '') = COALESCE(TRIM(BOTH FROM sas.scope_label), '')
        WHERE sar.id IS NULL
        """,
    ),
    (
        "dynamic_dangling_static_run_id",
        """
        SELECT COUNT(*)
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar ON sar.id = ds.static_run_id
        WHERE ds.static_run_id IS NOT NULL
          AND sar.id IS NULL
        """,
    ),
    (
        "artifact_static_numeric_dangling",
        """
        SELECT COUNT(*)
        FROM v_artifact_registry_integrity ar
        WHERE ar.run_type = 'static'
          AND ar.link_state = 'dangling_static_run'
        """,
    ),
)


def _connect():
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    conn = _connect()
    conn.autocommit(True)
    try:
        with conn.cursor() as cur:
            for label, sql in _QUERIES:
                cur.execute(sql)
                row = cur.fetchone()
                value = int(row[0]) if row and row[0] is not None else 0
                print(f"{label}={value}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
