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
import os
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

# Allow running this file directly (e.g., `python scytaledroid/.../static_run_audit.py`)
# without requiring `python -m ...` from the repo root.
from pathlib import Path
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _configure_db_target(db_target: str) -> None:
    parsed = urlparse(db_target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"mysql", "mariadb"}:
        raise RuntimeError("Unsupported --db-target scheme. Use mysql://... (SQLite is not supported).")
    os.environ["SCYTALEDROID_DB_URL"] = db_target
    host = parsed.hostname or "localhost"
    port = parsed.port or 3306
    db_name = (parsed.path or "").lstrip("/")
    print(f"[DB TARGET] backend=mysql host={host} port={port} db={db_name}")

def _imports():  # noqa: ANN202 - small script helper
    # Local import so this script can be run both as `python ...` and with repo-root sys.path tweak.
    from scytaledroid.Database.db_core import db_engine

    return db_engine


def _fetch_columns(cursor, table: str) -> set[str]:
    cursor.execute(f"SHOW COLUMNS FROM {table}")
    return {row[0] for row in cursor.fetchall()}


_AUTHORITATIVE_STATES = frozenset({"STARTED", "COMPLETED", "FAILED"})
_RUN_STATE_ALIASES = {"RUNNING": "STARTED", "ABORTED": "FAILED", "DONE": "COMPLETED"}


def _normalize_static_run_status(status: str | None) -> str:
    token = str(status or "").strip().upper()
    if token in _AUTHORITATIVE_STATES:
        return token
    return _RUN_STATE_ALIASES.get(token, "FAILED")


@dataclass(frozen=True, slots=True)
class GroupSessionVerification:
    """Status-aware checks for group-scope (multi-app) static sessions."""

    completed_total: int
    failed_total: int
    started_total: int
    completed_missing_findings_summary: tuple[int, ...]
    completed_missing_string_summary: tuple[int, ...]
    failed_nonterminal: tuple[int, ...]
    overall: str
    notes: tuple[str, ...] = ()


def compute_group_session_verification(
    *,
    runs: Sequence[tuple[int, str | None, object | None, str | None, str | None]],
    findings_summary_ids: frozenset[int],
    string_summary_ids: frozenset[int],
) -> GroupSessionVerification:
    """
    Pure evaluation for tests and DB-backed audits.

    *runs* rows: (static_run_id, raw_status, ended_at_utc, abort_reason, abort_signal).
    """

    completed: list[int] = []
    failed_terminal: list[int] = []
    failed_nonterminal: list[int] = []
    started: list[int] = []
    for sid, raw_st, ended_at, _ar, _as in runs:
        st = _normalize_static_run_status(raw_st)
        if st == "COMPLETED":
            completed.append(int(sid))
        elif st == "FAILED":
            if ended_at is None:
                failed_nonterminal.append(int(sid))
            else:
                failed_terminal.append(int(sid))
        elif st == "STARTED":
            started.append(int(sid))
        else:
            failed_nonterminal.append(int(sid))

    missing_fss = tuple(sorted(i for i in completed if i not in findings_summary_ids))
    missing_sss = tuple(sorted(i for i in completed if i not in string_summary_ids))
    ftuple = tuple(sorted(failed_nonterminal))
    notes: list[str] = []
    if failed_terminal:
        notes.append(
            f"{len(failed_terminal)} FAILED terminal app run(s) — canonical summary/findings rows not required"
        )
    if started:
        notes.append(f"{len(started)} STARTED run(s) still without terminal status")

    if missing_fss or missing_sss or ftuple:
        overall = "ERROR"
    elif failed_terminal or started:
        overall = "PARTIAL"
    else:
        overall = "OK"

    return GroupSessionVerification(
        completed_total=len(completed),
        failed_total=len(failed_terminal),
        started_total=len(started),
        completed_missing_findings_summary=missing_fss,
        completed_missing_string_summary=missing_sss,
        failed_nonterminal=ftuple,
        overall=overall,
        notes=tuple(notes),
    )


def _collect_group_verification(
    cursor,
    *,
    session_stamp: str,
    static_run_ids: list[int],
) -> GroupSessionVerification | None:
    if not session_stamp or not static_run_ids:
        return None
    try:
        cursor.execute(
            """
            SELECT id, status, ended_at_utc,
                   COALESCE(abort_reason, ''), COALESCE(abort_signal, '')
            FROM static_analysis_runs
            WHERE session_stamp=%s
            ORDER BY id ASC
            """,
            (session_stamp,),
        )
        raw_rows = cursor.fetchall() or []
    except Exception:
        return None

    runs: list[tuple[int, str | None, object | None, str | None, str | None]] = []
    for row in raw_rows:
        if not row:
            continue
        try:
            sid = int(row[0])
        except Exception:
            continue
        runs.append((sid, row[1], row[2], row[3], row[4]))

    completed_ids = [
        sid
        for sid, st, _e, _a, _b in runs
        if _normalize_static_run_status(st) == "COMPLETED"
    ]
    findings_ids: frozenset[int] = frozenset()
    string_ids: frozenset[int] = frozenset()
    if completed_ids:
        ph = ",".join(["%s"] * len(completed_ids))
        try:
            cursor.execute(
                f"SELECT DISTINCT static_run_id FROM static_findings_summary WHERE static_run_id IN ({ph})",
                tuple(completed_ids),
            )
            findings_ids = frozenset(int(r[0]) for r in cursor.fetchall() if r and r[0] is not None)
        except Exception:
            findings_ids = frozenset()
        try:
            cursor.execute(
                f"SELECT DISTINCT static_run_id FROM static_string_summary WHERE static_run_id IN ({ph})",
                tuple(completed_ids),
            )
            string_ids = frozenset(int(r[0]) for r in cursor.fetchall() if r and r[0] is not None)
        except Exception:
            string_ids = frozenset()

    return compute_group_session_verification(
        runs=runs,
        findings_summary_ids=findings_ids,
        string_summary_ids=string_ids,
    )


def _derive_package(scope_label: str | None) -> str | None:
    if not scope_label:
        return None
    scope_label = scope_label.strip()
    matches = re.findall(
        r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)",
        scope_label,
    )
    if matches:
        return matches[-1]
    return None


def _resolve_run(
    cursor,
    session_stamp: str | None,
    static_run_id: int | None,
) -> tuple[int | None, str | None, str | None, str | None, datetime | None, int | None, str | None]:
    resolved_session = session_stamp
    scope_label = None
    created_at = None
    status = None

    if static_run_id:
        cursor.execute(
            "SELECT session_stamp, scope_label, created_at, status FROM static_analysis_runs WHERE id=%s",
            (static_run_id,),
        )
        row = cursor.fetchone()
        if row:
            resolved_session = row[0]
            scope_label = row[1]
            created_at = row[2]
            status = row[3]
        static_run = static_run_id
    elif session_stamp:
        cursor.execute(
            """
            SELECT id, scope_label, created_at, status
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
        status = row[3] if row else None
    else:
        return None, None, None, None, None, None, None

    derived_package = _derive_package(scope_label)
    resolved_run_id: int | None = None
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

    return static_run, resolved_session, scope_label, derived_package, created_at, resolved_run_id, status


def _count_for_table(
    cursor,
    table: str,
    run_id: int | None,
    static_run_id: int | None,
    session: str | None,
    static_run_ids: Iterable[int] | None = None,
    is_group_scope: bool = False,
) -> tuple[str, int | None, str]:
    static_id_list = list(static_run_ids or [])
    if table == "static_analysis_findings":
        if not static_id_list:
            return table, None, "SKIP (no static_run_ids)"
        try:
            placeholders = ",".join(["%s"] * len(static_id_list))
            cursor.execute(
                f"SELECT COUNT(*) FROM static_analysis_findings WHERE run_id IN ({placeholders})",
                tuple(static_id_list),
            )
            (count,) = cursor.fetchone()
            return table, int(count), "OK"
        except Exception as exc:
            return table, None, f"ERROR: {exc}"

    if table == "static_permission_matrix":
        try:
            if static_id_list:
                placeholders = ",".join(["%s"] * len(static_id_list))
                cursor.execute(
                    f"SELECT COUNT(*) FROM static_permission_matrix WHERE run_id IN ({placeholders})",
                    tuple(static_id_list),
                )
                (count,) = cursor.fetchone()
                return table, int(count), "OK"
            if static_run_id is not None:
                cursor.execute(
                    "SELECT COUNT(*) FROM static_permission_matrix WHERE run_id=%s",
                    (static_run_id,),
                )
                (count,) = cursor.fetchone()
                return table, int(count), "OK"
        except Exception as exc:
            return table, None, f"ERROR: {exc}"

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
    run_id: int | None
    session_stamp: str | None
    scope_label: str | None
    derived_package: str | None
    created_at: datetime | None
    status: str | None
    is_group_scope: bool
    is_orphan: bool
    counts: dict[str, tuple[int | None, str]]
    severity_rows: Iterable[tuple[str, str, int]]
    group_verification: GroupSessionVerification | None = None


def collect_static_run_counts(
    *, session_stamp: str | None = None, static_run_id: int | None = None
) -> RunAudit | None:
    db_engine = _imports()
    with db_engine.connect() as conn:
        cur = conn.cursor()
        (
            resolved_static_run_id,
            resolved_session,
            scope_label,
            derived_package,
            created_at,
            resolved_run_id,
            run_status,
        ) = _resolve_run(cur, session_stamp, static_run_id)
        if resolved_static_run_id is None:
            return None

        is_group_scope = derived_package is None
        is_orphan = bool(derived_package and resolved_run_id is None)
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
            "static_analysis_findings",
            "findings",
            "static_findings",
            "static_findings_summary",
            "static_string_summary",
            "static_string_samples",
            "buckets",
            "metrics",
            "static_permission_matrix",
            "permission_audit_snapshots",
            "permission_audit_apps",
        ]
        counts: dict[str, tuple[int | None, str]] = {}
        for table in tables:
            table_name, count, table_status = _count_for_table(
                cur,
                table,
                resolved_run_id,
                resolved_static_run_id,
                resolved_session,
                static_run_ids=static_run_ids,
                is_group_scope=is_group_scope,
            )
            counts[table_name] = (count, table_status)

        severity_rows: list[tuple[str, str, int]] = []
        try:
            canonical_cols = _fetch_columns(cur, "static_analysis_findings")
            if canonical_cols and resolved_static_run_id is not None:
                cur.execute(
                    """
                    SELECT a.package_name, f.severity, COUNT(*) as cnt
                    FROM static_analysis_findings f
                    JOIN static_analysis_runs r ON r.id = f.run_id
                    JOIN app_versions av ON av.id = r.app_version_id
                    JOIN apps a ON a.id = av.app_id
                    WHERE f.run_id=%s
                    GROUP BY a.package_name, f.severity
                    ORDER BY a.package_name, f.severity
                    """,
                    (resolved_static_run_id,),
                )
                severity_rows = [(pkg, sev, int(cnt)) for pkg, sev, cnt in cur.fetchall()]
            else:
                findings_cols = _fetch_columns(cur, "findings")
                if "static_run_id" not in findings_cols or resolved_static_run_id is None:
                    raise RuntimeError("legacy findings unavailable")
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

        group_verification: GroupSessionVerification | None = None
        if is_group_scope and resolved_session and static_run_ids:
            group_verification = _collect_group_verification(
                cur,
                session_stamp=resolved_session,
                static_run_ids=static_run_ids,
            )

        cur.close()
    return RunAudit(
        static_run_id=resolved_static_run_id,
        run_id=resolved_run_id,
        session_stamp=resolved_session,
        scope_label=scope_label,
        derived_package=derived_package,
        created_at=created_at,
        status=run_status,
        is_group_scope=is_group_scope,
        is_orphan=is_orphan,
        counts=counts,
        severity_rows=severity_rows,
        group_verification=group_verification,
    )


def audit_run(session_stamp: str | None, run_id: int | None) -> int:
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
    if audit.status:
        print(f"Status: {audit.status}")

    required_single = {
        "findings",
        "static_string_summary",
        "static_string_samples",
        "buckets",
        "metrics",
        "permission_audit_snapshots",
        "permission_audit_apps",
    }
    required_group = {
        "static_string_summary",
        "static_string_samples",
        "permission_audit_snapshots",
        "permission_audit_apps",
    }
    required = required_group if audit.is_group_scope else required_single
    missing = []
    partial_permission_contract = (
        not audit.is_group_scope
        and str(audit.status or "").upper() == "FAILED"
        and int(audit.counts.get("static_permission_matrix", (0, "OK"))[0] or 0) > 0
        and int(audit.counts.get("permission_audit_snapshots", (0, "OK"))[0] or 0) == 0
    )

    for table, (count, status) in audit.counts.items():
        print(f"{table:28} -> {count!s:>5} ({status})")
        if table in required:
            if partial_permission_contract and table in {"permission_audit_snapshots", "permission_audit_apps"}:
                continue
            if count is None or int(count) == 0:
                missing.append(table)

    if partial_permission_contract:
        print(
            "\nNote: interrupted/failed run contract detected — static_permission_matrix rows were persisted,"
            " but permission_audit snapshot refresh was skipped, so permission_audit_* counts may remain 0."
        )

    if audit.severity_rows:
        print("\nPer-app severity (canonical findings):")
        for pkg, sev, cnt in audit.severity_rows:
            print(f"  {pkg:35} {sev:<6} {cnt}")

    if audit.is_group_scope and audit.group_verification:
        gv = audit.group_verification
        print("\nGroup session verification:")
        print(
            f"  completed={gv.completed_total} failed_terminal={gv.failed_total} "
            f"started={gv.started_total} overall={gv.overall}"
        )
        for note in gv.notes:
            print(f"  note: {note}")
        if gv.completed_missing_findings_summary:
            prev = ", ".join(str(x) for x in gv.completed_missing_findings_summary[:12])
            more = len(gv.completed_missing_findings_summary) - 12
            tail = f" (+{more} more)" if more > 0 else ""
            print(f"  ERROR: COMPLETED missing static_findings_summary: {prev}{tail}")
        if gv.completed_missing_string_summary:
            prev = ", ".join(str(x) for x in gv.completed_missing_string_summary[:12])
            more = len(gv.completed_missing_string_summary) - 12
            tail = f" (+{more} more)" if more > 0 else ""
            print(f"  ERROR: COMPLETED missing static_string_summary: {prev}{tail}")
        if gv.failed_nonterminal:
            prev = ", ".join(str(x) for x in gv.failed_nonterminal[:12])
            more = len(gv.failed_nonterminal) - 12
            tail = f" (+{more} more)" if more > 0 else ""
            print(f"  ERROR: non-terminal FAILED static_run_id: {prev}{tail}")

    if audit.is_group_scope:
        if audit.group_verification and audit.group_verification.overall == "ERROR":
            parts = []
            if missing:
                parts.append("missing aggregates: " + ", ".join(sorted(missing)))
            gv = audit.group_verification
            if gv.completed_missing_findings_summary:
                parts.append(
                    f"{len(gv.completed_missing_findings_summary)} COMPLETED missing static_findings_summary"
                )
            if gv.completed_missing_string_summary:
                parts.append(f"{len(gv.completed_missing_string_summary)} COMPLETED missing static_string_summary")
            if gv.failed_nonterminal:
                parts.append(f"{len(gv.failed_nonterminal)} non-terminal FAILED")
            print("\nDB verification: ERROR (" + ("; ".join(parts) if parts else "group verification") + ")")
            return 2
        if missing:
            print("\nDB verification: ERROR (missing session aggregates: " + ", ".join(sorted(missing)) + ")")
            return 2
        if audit.group_verification and audit.group_verification.overall == "PARTIAL":
            print("\nDB verification: PARTIAL (group session; completed apps have required summary rows)")
            return 0
        if not audit.group_verification:
            print("\nDB verification: SKIPPED (group session verification unavailable)")
            return 0
        print("\nDB verification: OK (group session)")
        return 0

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
    ap.add_argument(
        "--db-target",
        required=True,
        help="Explicit DB target DSN (mysql://...). Required for audit safety (SQLite is not supported).",
    )
    ap.add_argument("--session", help="session_stamp (e.g., 20251128-203341)")
    ap.add_argument("--run-id", type=int, help="static_analysis_runs.id")
    args = ap.parse_args()
    _configure_db_target(str(args.db_target))
    exit_code = audit_run(args.session, args.run_id)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
