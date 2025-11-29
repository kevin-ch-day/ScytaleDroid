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
import sys
from dataclasses import dataclass
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
            "SELECT id FROM static_analysis_runs WHERE session_stamp=%s ORDER BY id DESC LIMIT 1",
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


@dataclass
class RunAudit:
    static_run_id: int
    session_stamp: Optional[str]
    counts: Dict[str, Tuple[Optional[int], str]]
    severity_rows: Iterable[Tuple[str, str, int]]


def collect_static_run_counts(
    *, session_stamp: Optional[str] = None, static_run_id: Optional[int] = None
) -> Optional[RunAudit]:
    with db_engine.connect() as conn:
        cur = conn.cursor()
        resolved_run_id, resolved_session = _resolve_run(cur, session_stamp, static_run_id)
        if resolved_run_id is None:
            return None

        tables = [
            "static_analysis_runs",
            "findings",
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
        counts: Dict[str, Tuple[Optional[int], str]] = {}
        for table in tables:
            table_name, count, status = _count_for_table(
                cur, table, resolved_run_id, resolved_session
            )
            counts[table_name] = (count, status)

        severity_rows: list[tuple[str, str, int]] = []
        try:
            cur.execute(
                """
                SELECT a.package_name, f.severity, COUNT(*) as cnt
                FROM findings f
                JOIN static_analysis_runs r ON r.id = f.static_run_id
                JOIN app_versions av ON av.id = r.app_version_id
                JOIN apps a ON a.id = av.app_id
                WHERE f.static_run_id=%s
                GROUP BY a.package_name, f.severity
                ORDER BY a.package_name, f.severity
                """,
                (resolved_run_id,),
            )
            severity_rows = [(pkg, sev, int(cnt)) for pkg, sev, cnt in cur.fetchall()]
        except Exception:
            severity_rows = []

        cur.close()
    return RunAudit(
        static_run_id=resolved_run_id,
        session_stamp=resolved_session,
        counts=counts,
        severity_rows=severity_rows,
    )


def audit_run(session_stamp: Optional[str], run_id: Optional[int]) -> int:
    audit = collect_static_run_counts(session_stamp=session_stamp, static_run_id=run_id)
    if audit is None:
        print("Resolved run: id=None session=None")
        print("No matching static_analysis_runs row found.")
        return 1

    print(f"Resolved run: id={audit.static_run_id} session={audit.session_stamp}")

    required = {
        "findings",
        "static_string_summary",
        "static_string_samples",
        "buckets",
        "metrics",
        "permission_audit_snapshots",
        "permission_audit_apps",
    }
    missing = []

    for table, (count, status) in audit.counts.items():
        print(f"{table:28} -> {count!s:>5} ({status})")
        if table in required:
            if count is None or int(count) == 0:
                missing.append(table)

    if audit.severity_rows:
        print("\nPer-app severity (from findings):")
        for pkg, sev, cnt in audit.severity_rows:
            print(f"  {pkg:35} {sev:<6} {cnt}")

    if missing:
        print("\nDB verification: ERROR (missing: " + ", ".join(sorted(missing)) + ")")
        return 2
    print("\nDB verification: OK (canonical tables populated)")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit static-analysis run counts across tables.")
    ap.add_argument("--session", help="session_stamp (e.g., 20251128-203341)")
    ap.add_argument("--run-id", type=int, help="static_analysis_runs.id")
    args = ap.parse_args()
    exit_code = audit_run(args.session, args.run_id)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
