#!/usr/bin/env python3
"""Cohort/session audit: canonical row counts + Web views + legacy table counts (read-only).

Validates that a static analysis session wrote expected **canonical** rows and that
read-model views are queryable by ``session_stamp``. Intended for research cohort runs
(e.g. Research Dataset Alpha) before scaling to full-library scans.

Environment: same as CLI static persistence (``SCYTALEDROID_DB_*``). Run from repo root::

  export SCYTALEDROID_DB_USER=… SCYTALEDROID_DB_NAME=… SCYTALEDROID_DB_PASSWD=…
  PYTHONPATH=. python scripts/db/audit_static_session.py --session 20260502-rda-full

Static persistence writes **canonical** tables only (no legacy mirror). Empty legacy
``runs`` / ``metrics`` / ``buckets`` / ``findings`` counts are **not** treated as failure.

Exit codes:
  0 — audit completed; canonical session has at least one ``static_analysis_runs`` row
  1 — DB error or import failure
  2 — no rows in ``static_analysis_runs`` for the given session stamp
  3 — (only with ``--strict-masvs-views``) canonical MASVS views not deployed on this catalog
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence


def _sql_literal(session: str) -> str:
    return "'" + session.replace("'", "''") + "'"


def _safe_scalar(
    run_sql,
    sql: str,
    params: tuple[object, ...] = (),
) -> tuple[int | None, str]:
    try:
        row = run_sql(sql, params, fetch="one")
        if row is None:
            return 0, "OK"
        if isinstance(row, dict):
            val = next(iter(row.values()))
        else:
            val = row[0]
        return int(val), "OK"
    except Exception as exc:  # pragma: no cover - live DB
        return None, f"ERROR: {exc}"


def _print_table(title: str, rows: Sequence[tuple[str, int | None, str]]) -> None:
    print()
    print(title)
    print("-" * min(88, max(40, len(title) + 4)))
    label_w = 34
    for label, count, status in rows:
        c = "—" if count is None else str(count)
        print(f"  {label:<{label_w}} {c:>12}  {status}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit canonical static persistence + views for a session_stamp.",
    )
    parser.add_argument(
        "--session",
        required=True,
        help="session_stamp on static_analysis_runs (e.g. 20260502-rda-canonical-only)",
    )
    parser.add_argument(
        "--no-sql",
        action="store_true",
        help="Do not print the copyable SQL appendix.",
    )
    parser.add_argument(
        "--strict-masvs-views",
        action="store_true",
        help="Exit 3 when v_static_masvs_matrix_v1 / session summary views are missing (1146 etc.).",
    )
    args = parser.parse_args()
    session = str(args.session).strip()
    if not session:
        sys.stderr.write("Empty --session.\n")
        return 1

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import view_deploy_remediation as vdr
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    run_sql = core_q.run_sql
    lit = _sql_literal(session)
    bridge_on = False  # legacy Persistence/db_writer mirror removed

    print("Static session audit (research cohort)")
    print(f"  session_stamp     : {session}")
    print("  legacy DB mirror  : removed (canonical static_analysis_* only; runs/metrics/buckets no longer written)")

    n_runs, st_runs = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s",
        (session,),
    )
    if st_runs != "OK" or n_runs is None:
        print(f"\nCould not query static_analysis_runs: {st_runs}")
        return 1
    if n_runs == 0:
        print("\nNo rows in static_analysis_runs for this session_stamp.")
        print("  Fix session name or confirm persistence used this stamp.")
        return 2

    min_id, _ = _safe_scalar(
        run_sql,
        "SELECT MIN(id) FROM static_analysis_runs WHERE session_stamp=%s",
        (session,),
    )
    max_id, _ = _safe_scalar(
        run_sql,
        "SELECT MAX(id) FROM static_analysis_runs WHERE session_stamp=%s",
        (session,),
    )

    print(f"  static_run rows   : {n_runs} (id range {min_id} … {max_id})")

    # --- Canonical persistence
    canonical_rows: list[tuple[str, int | None, str]] = []

    c, st = _safe_scalar(run_sql, f"SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s", (session,))
    canonical_rows.append(("static_analysis_runs", c, st))

    c, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM static_analysis_findings f
        INNER JOIN static_analysis_runs r ON r.id = f.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    canonical_rows.append(("static_analysis_findings (via run_id)", c, st))

    c, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM static_permission_matrix m
        WHERE m.run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )
    canonical_rows.append(("static_permission_matrix", c, st))

    c, st = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp=%s",
        (session,),
    )
    canonical_rows.append(("static_string_summary", c, st))

    c, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM static_string_samples
        WHERE static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )
    canonical_rows.append(("static_string_samples", c, st))

    c, st = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM static_session_rollups WHERE session_stamp=%s",
        (session,),
    )
    canonical_rows.append(("static_session_rollups", c, st))

    _print_table("Canonical persistence", canonical_rows)

    # --- Canonical MASVS (requires v_static_masvs_* views deployed)
    mc_m, st_m = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM v_static_masvs_matrix_v1 m
        WHERE m.session_stamp=%s
        """,
        (session,),
    )
    print()
    print("Canonical MASVS (matrix rows for this session)")
    print("-" * 56)
    label_mm = "v_static_masvs_matrix_v1 rows"
    c_mm = "—" if mc_m is None else str(mc_m)
    print(f"  {label_mm:<34} {c_mm:>12}  {st_m}")

    masvs_session_exc: BaseException | None = None
    try:
        masvs_summary = run_sql(
            """
            SELECT *
            FROM v_static_masvs_session_summary_v1
            WHERE session_stamp=%s
            """,
            (session,),
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:
        masvs_session_exc = exc
        masvs_summary = None
        print()
        print(f"  v_static_masvs_session_summary_v1: unavailable ({exc.__class__.__name__})")
    else:
        print()
        print("Canonical MASVS (session summary)")
        print("-" * 56)
        if masvs_summary and isinstance(masvs_summary, dict):
            key_w = 40
            for key in sorted(masvs_summary.keys()):
                raw = masvs_summary.get(key)
                disp = "—" if raw is None else str(raw)
                print(f"  {str(key):<{key_w}} {disp}")
        else:
            print("  (no rollup row — views missing or session absent from matrix)")

    # --- Permission audit / parity
    perm_rows: list[tuple[str, int | None, str]] = []
    snap_key = f"perm-audit:app:{session}"
    c, st = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_key=%s",
        (snap_key,),
    )
    perm_rows.append(("permission_audit_snapshots", c, st))

    c, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM permission_audit_apps a
        INNER JOIN permission_audit_snapshots s ON s.snapshot_id = a.snapshot_id
        WHERE s.snapshot_key=%s
        """,
        (snap_key,),
    )
    perm_rows.append(("permission_audit_apps", c, st))

    _print_table("Permission audit / parity", perm_rows)

    # --- Derived / Web read views (session or static_run_id scoped)
    view_rows: list[tuple[str, int | None, str]] = []

    c, st = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM v_web_app_sessions WHERE session_stamp=%s",
        (session,),
    )
    view_rows.append(("v_web_app_sessions", c, st))

    c, st = _safe_scalar(
        run_sql,
        f"""
        SELECT COUNT(*) FROM v_web_app_permissions
        WHERE session_stamp=%s
        """,
        (session,),
    )
    view_rows.append(("v_web_app_permissions", c, st))

    c, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM v_web_app_findings
        WHERE static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )
    view_rows.append(("v_web_app_findings *", c, st))

    _print_table("Derived / Web read views", view_rows)

    # --- Static-to-dynamic handoff (strict filters inside view)
    handoff_rows: list[tuple[str, int | None, str]] = []
    c, st = _safe_scalar(
        run_sql,
        f"""
        SELECT COUNT(*) FROM v_static_handoff_v1 h
        INNER JOIN static_analysis_runs r ON r.id = h.static_run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    handoff_rows.append(("v_static_handoff_v1 **", c, st))
    _print_table("Static-to-dynamic handoff", handoff_rows)

    # --- Compatibility bridge (legacy mirror)
    legacy_rows: list[tuple[str, int | None, str]] = []
    lr, st = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM runs WHERE session_stamp=%s",
        (session,),
    )
    legacy_rows.append(("runs (legacy mirror)", lr, st))

    lm, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM metrics m
        INNER JOIN runs r ON r.run_id = m.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    legacy_rows.append(("metrics (legacy mirror)", lm, st))

    lb, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM buckets b
        INNER JOIN runs r ON r.run_id = b.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    legacy_rows.append(("buckets (legacy mirror)", lb, st))

    lf, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM findings f
        WHERE f.static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )
    legacy_rows.append(("findings (legacy mirror)", lf, st))

    legacy_note = "historical rows only (mirror writers removed)"
    _print_table(f"Legacy mirror tables ({legacy_note})", legacy_rows)

    # --- Interpretation
    print()
    print("Notes:")
    print(
        "  * v_web_app_findings is built from “latest” surfaces per package; "
        "row count can be lower than raw static_analysis_findings."
    )
    print(
        "  ** v_static_handoff_v1 only includes COMPLETED runs with handoff hashes populated; "
        "zero rows can mean incomplete runs or missing handoff fields — compare to static_analysis_runs.status."
    )
    if not bridge_on:
        print(
            "  Legacy mirror counts are informational only — static analysis no longer writes these tables "
            "(empty or stale rows from older toolchains are OK)."
        )

    warnings: list[str] = []
    fc = canonical_rows[1][1]  # findings count tuple
    if fc == 0:
        warnings.append("static_analysis_findings count is 0 — verify detectors/persistence for this session.")

    if not args.no_sql:
        print()
        print("Copyable SQL (same session; adjust catalog/database as needed)")
        print("=" * 72)
        print(f"-- session_stamp = {lit}")
        print(f"SELECT COUNT(*) AS static_run_rows FROM static_analysis_runs WHERE session_stamp = {lit};")
        print(
            "SELECT COUNT(*) AS finding_rows FROM static_analysis_findings f\n"
            "INNER JOIN static_analysis_runs r ON r.id = f.run_id\n"
            f"WHERE r.session_stamp = {lit};"
        )
        print(
            "SELECT COUNT(*) AS perm_rows FROM static_permission_matrix m\n"
            "WHERE m.run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp = "
            f"{lit});"
        )
        print(f"SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = {lit};")
        print(
            "SELECT COUNT(*) FROM static_string_samples\n"
            "WHERE static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp = "
            f"{lit});"
        )
        print(f"SELECT * FROM static_session_rollups WHERE session_stamp = {lit} LIMIT 20;")
        print(f"SELECT COUNT(*) FROM v_web_app_sessions WHERE session_stamp = {lit};")
        print(f"SELECT COUNT(*) FROM v_web_app_permissions WHERE session_stamp = {lit};")
        print(
            "SELECT COUNT(*) FROM v_web_app_findings\n"
            "WHERE static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp = "
            f"{lit});"
        )
        print(
            "SELECT COUNT(*) FROM v_static_handoff_v1 h\n"
            "INNER JOIN static_analysis_runs r ON r.id = h.static_run_id\n"
            f"WHERE r.session_stamp = {lit};"
        )
        print(
            f"SELECT COUNT(*) FROM runs WHERE session_stamp = {lit};  -- legacy mirror\n"
            "SELECT COUNT(*) FROM metrics m INNER JOIN runs r ON r.run_id = m.run_id "
            f"WHERE r.session_stamp = {lit};"
        )

    if warnings:
        print()
        print("Warnings:")
        for w in warnings:
            print(f"  - {w}")

    st_m_lower = str(st_m).lower()
    masvs_views_missing = (
        mc_m is None
        and (
            "1146" in str(st_m)
            or "doesn't exist" in st_m_lower
            or "does not exist" in st_m_lower
            or "unknown table" in st_m_lower
        )
    )
    if masvs_session_exc is not None and vdr.sql_object_missing_error(masvs_session_exc):
        masvs_views_missing = True

    if masvs_views_missing:
        print()
        print(vdr.remediation_text())

    if args.strict_masvs_views and masvs_views_missing:
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
