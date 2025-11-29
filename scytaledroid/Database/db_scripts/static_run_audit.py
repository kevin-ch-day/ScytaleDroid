#!/usr/bin/env python3
"""
static_run_audit.py

Diagnose static-analysis runs by enumerating counts across core tables for a
given run_id or session_stamp. This is meant to help reconcile CLI output with
the database.

Usage:
  python -m scytaledroid.Database.db_scripts.static_run_audit --session 20251128-203341
  python -m scytaledroid.Database.db_scripts.static_run_audit --run-id 46
"""

from __future__ import annotations

import argparse
from typing import Dict, Iterable, Optional, Tuple

from scytaledroid.Database.db_core import db_engine


def _fetch_columns(cursor, table: str) -> set[str]:
    cursor.execute(f"SHOW COLUMNS FROM {table}")
    return {row[0] for row in cursor.fetchall()}


def _resolve_run(cursor, session_stamp: Optional[str], run_id: Optional[int]) -> Tuple[Optional[int], Optional[str]]:
    if run_id:
        cursor.execute(
            "SELECT session_stamp FROM static_analysis_runs WHERE id=%s",
            (run_id,),
        )
        row = cursor.fetchone()
        return run_id, row[0] if row else None

    if session_stamp:
        cursor.execute(
            "SELECT id FROM static_analysis_runs WHERE session_stamp=%s",
            (session_stamp,),
        )
        row = cursor.fetchone()
        return (row[0] if row else None), session_stamp

    return None, None


def _count_for_table(cursor, table: str, run_id: Optional[int], session: Optional[str]) -> Tuple[str, Optional[int], str]:
    cols = _fetch_columns(cursor, table)
    where = None
    params: tuple = ()
    if "static_run_id" in cols and run_id is not None:
        where = "static_run_id=%s"
        params = (run_id,)
    elif "run_id" in cols and run_id is not None:
        where = "run_id=%s"
        params = (run_id,)
    elif "session_stamp" in cols and session is not None:
        where = "session_stamp=%s"
        params = (session,)
    else:
        return table, None, "SKIP (no run_id/session_stamp column)"

    try:
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params)
        (count,) = cursor.fetchone()
        return table, int(count), "OK"
    except Exception as exc:  # pragma: no cover - defensive diagnostics
        return table, None, f"ERROR: {exc}"


def audit_run(session_stamp: Optional[str], run_id: Optional[int]) -> None:
    tables = [
        "static_analysis_runs",
        "findings",  # normalized findings (legacy name in some deployments)
        "static_analysis_findings",
        "static_findings",
        "static_findings_summary",
        "static_string_summary",
        "static_string_samples",
        "buckets",
        "metrics",
        "permission_audit_snapshots",
        "permission_audit_apps",
    ]
    with db_engine.connect() as conn:
        cur = conn.cursor()
        resolved_run_id, resolved_session = _resolve_run(cur, session_stamp, run_id)
        print(f"Resolved run: id={resolved_run_id} session={resolved_session}")
        if resolved_run_id is None and resolved_session is None:
            print("No matching static_analysis_runs row found.")
            return

        for table in tables:
            table_name, count, status = _count_for_table(cur, table, resolved_run_id, resolved_session)
            print(f"{table_name:28} -> {count!s:>5} ({status})")

        # Per-app severity from findings if possible
        if resolved_run_id is not None:
            try:
                cur.execute(
                    """
                    SELECT a.package_name, saf.severity, COUNT(*) as cnt
                    FROM static_analysis_findings saf
                    JOIN static_analysis_runs r ON r.id = saf.run_id
                    JOIN app_versions av ON av.id = r.app_version_id
                    JOIN apps a ON a.id = av.app_id
                    WHERE saf.run_id=%s
                    GROUP BY a.package_name, saf.severity
                    ORDER BY a.package_name, saf.severity
                    """,
                    (resolved_run_id,),
                )
                rows = cur.fetchall()
                if rows:
                    print("\nPer-app severity (from findings):")
                    for pkg, sev, cnt in rows:
                        print(f"  {pkg:35} {sev:<6} {cnt}")
            except Exception as exc:
                print(f"\nPer-app severity query failed: {exc}")

        cur.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit static-analysis run counts across tables.")
    ap.add_argument("--session", help="session_stamp (e.g., 20251128-203341)")
    ap.add_argument("--run-id", type=int, help="static_analysis_runs.id")
    args = ap.parse_args()
    audit_run(args.session, args.run_id)


if __name__ == "__main__":
    main()
