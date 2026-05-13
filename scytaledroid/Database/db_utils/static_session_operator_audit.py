"""Operator-facing static session audit (canonical tables, views, legacy mirror).

Single implementation shared by ``scripts/db/audit_static_session.py`` and any
in-process callers. Read-only queries only.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence


def sql_literal_for_session(session: str) -> str:
    """Return a single-quoted SQL literal for ``session_stamp`` (escape ``'``)."""

    return "'" + session.replace("'", "''") + "'"


def _safe_scalar(
    run_sql: Callable[..., object],
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


def audit_static_session_operator(
    session: str,
    *,
    print_sql_appendix: bool = True,
    strict_masvs_views: bool = False,
) -> int:
    """Run the full static session audit to stdout; return CLI exit code semantics.

    Returns:
        0 — audit completed; at least one ``static_analysis_runs`` row for session
        1 — DB error or import failure
        2 — no ``static_analysis_runs`` rows for session
        3 — ``strict_masvs_views`` and MASVS views missing on catalog
    """

    session = str(session or "").strip()
    if not session:
        return 1

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import view_deploy_remediation as vdr
        from scytaledroid.Database.db_utils.legacy_static_mirror_diagnostics import (
            legacy_findings_count_via_static_run_id,
            legacy_mirror_table_presence_audit,
            legacy_runs_count_by_session_stamp,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    run_sql = core_q.run_sql
    legacy_mirror_presence = legacy_mirror_table_presence_audit()
    lit = sql_literal_for_session(session)
    bridge_on = False  # legacy Persistence/db_writer mirror removed

    print("Static session audit (research cohort)")
    print(f"  session_stamp     : {session}")
    print(
        "  legacy DB mirror  : removed (canonical static_analysis_* only; "
        "runs/metrics/buckets no longer written)"
    )

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

    canonical_rows: list[tuple[str, int | None, str]] = []

    c, st = _safe_scalar(run_sql, "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s", (session,))
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

    _print_table("CANONICAL — core static tables (session-scoped)", canonical_rows)

    mc_m, st_m = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM v_static_masvs_matrix_v1 m
        WHERE m.session_stamp=%s
        """,
        (session,),
    )
    print()
    print("CANONICAL — MASVS matrix rows (view-backed)")
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
        print("CANONICAL — MASVS session summary (view-backed)")
        print("-" * 56)
        if masvs_summary and isinstance(masvs_summary, dict):
            key_w = 40
            for key in sorted(masvs_summary.keys()):
                raw = masvs_summary.get(key)
                disp = "—" if raw is None else str(raw)
                print(f"  {str(key):<{key_w}} {disp}")
        else:
            print("  (no rollup row — views missing or session absent from matrix)")

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

    _print_table("CANONICAL / OPTIONAL — permission audit & parity", perm_rows)

    view_rows: list[tuple[str, int | None, str]] = []

    c, st = _safe_scalar(
        run_sql,
        "SELECT COUNT(*) FROM v_web_app_sessions WHERE session_stamp=%s",
        (session,),
    )
    view_rows.append(("v_web_app_sessions", c, st))

    c, st = _safe_scalar(
        run_sql,
        """
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

    _print_table("CANONICAL / DERIVED — Web read-model views", view_rows)

    handoff_rows: list[tuple[str, int | None, str]] = []
    c, st = _safe_scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM v_static_handoff_v1 h
        INNER JOIN static_analysis_runs r ON r.id = h.static_run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    handoff_rows.append(("v_static_handoff_v1 **", c, st))
    _print_table("CANONICAL — static-to-dynamic handoff", handoff_rows)

    legacy_rows: list[tuple[str, int | None, str]] = []
    runs_mirror_present = (not legacy_mirror_presence) or legacy_mirror_presence.get("runs", True)

    if not runs_mirror_present:
        legacy_rows.append(("runs (legacy mirror)", None, "SKIP (table absent)"))
        legacy_rows.append(("metrics (legacy mirror)", None, "SKIP (requires runs mirror)"))
        legacy_rows.append(("buckets (legacy mirror)", None, "SKIP (requires runs mirror)"))
    else:
        lr, st = legacy_runs_count_by_session_stamp(run_sql, session)
        legacy_rows.append(("runs (legacy mirror)", lr, st))

        metrics_mirror_present = (not legacy_mirror_presence) or legacy_mirror_presence.get("metrics", True)
        if not metrics_mirror_present:
            legacy_rows.append(("metrics (legacy mirror)", None, "SKIP (table absent)"))
        else:
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

        buckets_mirror_present = (not legacy_mirror_presence) or legacy_mirror_presence.get("buckets", True)
        if not buckets_mirror_present:
            legacy_rows.append(("buckets (legacy mirror)", None, "SKIP (table absent)"))
        else:
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

    findings_mirror_present = (not legacy_mirror_presence) or legacy_mirror_presence.get("findings", True)
    if not findings_mirror_present:
        legacy_rows.append(("findings (legacy mirror)", None, "SKIP (table absent)"))
    else:
        lf, st = legacy_findings_count_via_static_run_id(run_sql, session)
        legacy_rows.append(("findings (legacy mirror)", lf, st))

    legacy_note = "historical rows only (mirror writers removed); not canonical static truth"
    _print_table(f"LEGACY MIRROR — compatibility ({legacy_note})", legacy_rows)

    print()
    print("Notes:")
    print(
        "  * v_web_app_findings is built from “latest” surfaces per package; "
        "row count can be lower than raw static_analysis_findings."
    )
    print(
        "  ** v_static_handoff_v1 includes only COMPLETED runs with run_class CANONICAL, "
        "identity_valid = 1, and handoff hashes populated — compare counts to static_analysis_runs for the session."
    )
    if not bridge_on:
        print(
            "  Legacy mirror counts are informational only — static analysis no longer writes these tables "
            "(empty or stale rows from older toolchains are OK)."
        )

    warnings: list[str] = []
    fc = canonical_rows[1][1]
    if fc == 0:
        warnings.append("static_analysis_findings count is 0 — verify detectors/persistence for this session.")

    if print_sql_appendix:
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

    if strict_masvs_views and masvs_views_missing:
        return 3

    return 0


__all__ = [
    "audit_static_session_operator",
    "sql_literal_for_session",
]
