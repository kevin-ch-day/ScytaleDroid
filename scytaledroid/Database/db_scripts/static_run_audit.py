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
from datetime import datetime
from typing import Dict, Iterable, Optional, Tuple

from scytaledroid.Database.db_core import db_engine


def _fetch_columns(cursor, table: str) -> set[str]:
    cursor.execute(f"SHOW COLUMNS FROM {table}")
    return {row[0] for row in cursor.fetchall()}


def _derive_package(scope_label: Optional[str]) -> Optional[str]:
    if not scope_label:
        return None
    scope_label = scope_label.strip()
    if scope_label.startswith("com."):
        return scope_label
    if "(com." in scope_label:
        tail = scope_label.rsplit("(", 1)[-1]
        tail = tail.rstrip(")")
        if tail.startswith("com."):
            return tail
    return None


def _resolve_run(
    cursor,
    session_stamp: Optional[str],
    static_run_id: Optional[int],
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str], Optional[datetime], Optional[int]]:
    resolved_session = session_stamp
    scope_label = None
    created_at = None

    if static_run_id:
        cursor.execute(
            "SELECT session_stamp, scope_label, created_at FROM static_analysis_runs WHERE id=%s",
            (static_run_id,),
        )
        row = cursor.fetchone()
        if row:
            resolved_session = row[0]
            scope_label = row[1]
            created_at = row[2]
        static_run = static_run_id
    elif session_stamp:
        cursor.execute(
            """
            SELECT id, scope_label, created_at
            FROM static_analysis_runs
            WHERE session_stamp=%s
            ORDER BY id DESC
            LIMIT 1
            """,
            (session_stamp,),
        )
        row = cursor.fetchone()
        static_run = row[0] if row else None
        scope_label = row[1] if row else None
        created_at = row[2] if row else None
    else:
        return None, None, None, None, None, None

    derived_package = _derive_package(scope_label)
    resolved_run_id: Optional[int] = None
    if resolved_session and derived_package:
        cursor.execute(
            """
            SELECT run_id
            FROM runs
            WHERE session_stamp=%s AND package=%s
            ORDER BY run_id DESC
            LIMIT 1
            """,
            (resolved_session, derived_package),
        )
        row = cursor.fetchone()
        if row:
            resolved_run_id = row[0]

    return static_run, resolved_session, scope_label, derived_package, created_at, resolved_run_id


def _count_for_table(
    cursor,
    table: str,
    run_id: Optional[int],
    static_run_id: Optional[int],
    session: Optional[str],
    static_run_ids: Optional[Iterable[int]] = None,
    is_group_scope: bool = False,
) -> Tuple[str, Optional[int], str]:
    if is_group_scope and session:
        if table == "permission_audit_snapshots":
            try:
                cursor.execute(
                    "SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_key=%s",
                    (f"perm-audit:app:{session}",),
                )
                (count,) = cursor.fetchone()
                return table, int(count), "OK"
            except Exception as exc:
                return table, None, f"ERROR: {exc}"
        if table == "permission_audit_apps":
            try:
                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM permission_audit_apps a
                    JOIN permission_audit_snapshots s ON s.snapshot_id = a.snapshot_id
                    WHERE s.snapshot_key=%s
                    """,
                    (f"perm-audit:app:{session}",),
                )
                (count,) = cursor.fetchone()
                return table, int(count), "OK"
            except Exception as exc:
                return table, None, f"ERROR: {exc}"

    static_id_list = list(static_run_ids or [])
    cols = _fetch_columns(cursor, table)
    where = None
    params: tuple = ()
    if "static_run_id" in cols and static_id_list:
        where = f"static_run_id IN ({','.join(['%s'] * len(static_id_list))})"
        params = tuple(static_id_list)
    elif "static_run_id" in cols and static_run_id is not None:
        where = "static_run_id=%s"
        params = (static_run_id,)
    elif "run_id" in cols and run_id is not None:
        where = "run_id=%s"
        params = (run_id,)
    elif "run_id" in cols and session is not None and is_group_scope:
        where = "run_id IN (SELECT run_id FROM runs WHERE session_stamp=%s)"
        params = (session,)
    elif "run_id" in cols:
        return table, None, "SKIP (no run_id)"
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
    run_id: Optional[int]
    session_stamp: Optional[str]
    scope_label: Optional[str]
    derived_package: Optional[str]
    created_at: Optional[datetime]
    is_group_scope: bool
    is_legacy: bool
    is_orphan: bool
    counts: Dict[str, Tuple[Optional[int], str]]
    severity_rows: Iterable[Tuple[str, str, int]]


def collect_static_run_counts(
    *, session_stamp: Optional[str] = None, static_run_id: Optional[int] = None
) -> Optional[RunAudit]:
    with db_engine.connect() as conn:
        cur = conn.cursor()
        (
            resolved_static_run_id,
            resolved_session,
            scope_label,
            derived_package,
            created_at,
            resolved_run_id,
        ) = _resolve_run(cur, session_stamp, static_run_id)
        if resolved_static_run_id is None:
            return None

        is_group_scope = derived_package is None
        cutoff = datetime(2026, 1, 22)
        is_legacy = bool(created_at and created_at < cutoff)
        is_orphan = bool(derived_package and resolved_run_id is None and not is_legacy)
        static_run_ids: list[int] = []
        if resolved_session:
            try:
                cur.execute(
                    "SELECT id FROM static_analysis_runs WHERE session_stamp=%s",
                    (resolved_session,),
                )
                static_run_ids = [int(row[0]) for row in cur.fetchall() if row and row[0]]
            except Exception:
                static_run_ids = []

        tables = [
            "static_analysis_runs",
            "findings",
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
                cur,
                table,
                resolved_run_id,
                resolved_static_run_id,
                resolved_session,
                static_run_ids=static_run_ids,
                is_group_scope=is_group_scope,
            )
            counts[table_name] = (count, status)

        severity_rows: list[tuple[str, str, int]] = []
        try:
            findings_cols = _fetch_columns(cur, "findings")
            if "run_id" in findings_cols and resolved_run_id is not None:
                cur.execute(
                    """
                    SELECT r.package, f.severity, COUNT(*) as cnt
                    FROM findings f
                    JOIN runs r ON r.run_id = f.run_id
                    WHERE f.run_id=%s
                    GROUP BY r.package, f.severity
                    ORDER BY r.package, f.severity
                    """,
                    (resolved_run_id,),
                )
                severity_rows = [(pkg, sev, int(cnt)) for pkg, sev, cnt in cur.fetchall()]
            elif "static_run_id" in findings_cols and resolved_static_run_id is not None:
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
                    (resolved_static_run_id,),
                )
                severity_rows = [(pkg, sev, int(cnt)) for pkg, sev, cnt in cur.fetchall()]
        except Exception:
            severity_rows = []

        cur.close()
    return RunAudit(
        static_run_id=resolved_static_run_id,
        run_id=resolved_run_id,
        session_stamp=resolved_session,
        scope_label=scope_label,
        derived_package=derived_package,
        created_at=created_at,
        is_group_scope=is_group_scope,
        is_legacy=is_legacy,
        is_orphan=is_orphan,
        counts=counts,
        severity_rows=severity_rows,
    )


def audit_run(session_stamp: Optional[str], run_id: Optional[int]) -> int:
    audit = collect_static_run_counts(session_stamp=session_stamp, static_run_id=run_id)
    if audit is None:
        print("Resolved run: id=None session=None")
        print("No matching static_analysis_runs row found.")
        return 1

    print(
        "Resolved run: static_run_id="
        f"{audit.static_run_id} run_id={audit.run_id} session={audit.session_stamp}"
    )
    if audit.is_group_scope:
        print("Note: Group scope detected; per-package run mapping not applicable.")
    if audit.is_orphan:
        print("Note: ORPHAN static run (runs row missing).")
    elif audit.is_legacy:
        print("Note: LEGACY static run (pre-ledger era).")

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

    if missing and audit.run_id is not None:
        print("\nDB verification: ERROR (missing: " + ", ".join(sorted(missing)) + ")")
        return 2
    if audit.run_id is None:
        print("\nDB verification: SKIPPED (run_id missing)")
        return 0
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
