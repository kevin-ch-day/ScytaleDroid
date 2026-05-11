#!/usr/bin/env python3
"""Read-only session health probe for static analysis (MariaDB).

Joins ``static_analysis_runs`` to ``app_versions`` / ``apps`` for package names.
Does **not** mutate the database.

Environment: same analyst DSN as CLI (``SCYTALEDROID_DB_*``). From repo root::

  PYTHONPATH=. python scripts/db/session_static_health.py --session 20260510-all-full

Exit codes:
  0 - probe completed (session may still have zero rows; see stdout)
  1 - DB error, import failure, or empty --session
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Mapping
from typing import Any


def _table_exists(run_sql, table_name: str) -> bool:
    try:
        row = run_sql(
            """
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = %s
            """,
            (table_name,),
            fetch="one",
        )
        return bool(row and int(row[0] or 0) > 0)
    except Exception:
        return False


def _scalar(run_sql, sql: str, params: tuple[object, ...]) -> tuple[int | None, str]:
    try:
        row = run_sql(sql, params, fetch="one")
        if row is None:
            return 0, "OK"
        val = row[0] if not isinstance(row, dict) else next(iter(row.values()))
        return int(val or 0), "OK"
    except Exception as exc:
        return None, f"ERROR: {exc}"


def _rows(run_sql, sql: str, params: tuple[object, ...]) -> tuple[list[Any], str]:
    try:
        out = run_sql(sql, params, fetch="all") or []
        return list(out), "OK"
    except Exception as exc:
        return [], f"ERROR: {exc}"


def _print_section(title: str) -> None:
    print()
    print(title)
    print("-" * min(72, max(40, len(title) + 4)))


def _audit_persistence_summary(session: str, output_dir: str | None) -> None:
    try:
        from scytaledroid.StaticAnalysis.cli.audit.post_run_session_summary import (
            load_persistence_audit_payload,
            resolve_persistence_audit_path,
        )
    except ImportError:
        print("  (persistence audit helpers not importable)")
        return

    path = resolve_persistence_audit_path(session, output_dir=output_dir)
    if path:
        print(f"  audit_file          : {path}")
    payload = load_persistence_audit_payload(session, output_dir=output_dir)
    if not payload:
        print("  persistence_audit   : not found (expected path under output/audit/persistence/)")
        return

    rows_raw = payload.get("rows")
    rows = [dict(r) for r in rows_raw] if isinstance(rows_raw, list) else []
    with_exc = [r for r in rows if r.get("exception_class") or r.get("exception_message")]
    with_warn = [r for r in rows if r.get("persistence_warnings")]
    outcome = payload.get("outcome") if isinstance(payload.get("outcome"), Mapping) else {}
    stages = Counter(str(r.get("stage") or "unknown") for r in rows)

    print(f"  audit_rows          : {len(rows)}")
    print(f"  rows_w_exception    : {len(with_exc)}")
    print(f"  rows_w_warnings     : {len(with_warn)}")
    if isinstance(outcome, Mapping):
        print(f"  outcome.persistence_failed : {outcome.get('persistence_failed')}")
        print(f"  outcome.canonical_failed   : {outcome.get('canonical_failed')}")
    if stages:
        top = ", ".join(f"{k}={v}" for k, v in stages.most_common(12))
        print(f"  stages (row counts) : {top}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only static session health (DB + optional persistence audit JSON).",
    )
    parser.add_argument(
        "--session",
        required=True,
        help="session_stamp on static_analysis_runs (e.g. 20260510-all-full)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override output root when resolving persistence audit JSON (default: app OUTPUT_DIR).",
    )
    parser.add_argument(
        "--mismatch-limit",
        type=int,
        default=15,
        help="Max matrix/vnext skew rows to print (default: 15).",
    )
    args = parser.parse_args()
    session = str(args.session).strip()
    if not session:
        sys.stderr.write("Empty --session.\n")
        return 1

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    run_sql = core_q.run_sql

    _print_section(f"Session static health: {session}")

    n_runs, st = _scalar(
        run_sql,
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s",
        (session,),
    )
    if st != "OK":
        print(f"static_analysis_runs: {st}")
        return 1
    print(f"static_analysis_runs rows : {n_runs}")
    if n_runs == 0:
        print("  (no rows for this session_stamp - check stamp spelling or persistence target DB)")
        return 0

    min_id, _ = _scalar(
        run_sql,
        "SELECT MIN(id) FROM static_analysis_runs WHERE session_stamp=%s",
        (session,),
    )
    max_id, _ = _scalar(
        run_sql,
        "SELECT MAX(id) FROM static_analysis_runs WHERE session_stamp=%s",
        (session,),
    )
    print("example static_run_id (SQL drill-down only; not 'the' cohort id):")
    print(f"  min_id : {min_id}")
    print(f"  max_id : {max_id}  (high-water example for ad hoc queries)")

    _print_section("Run status counts (static_analysis_runs)")
    for label, sql in (
        ("COMPLETED", "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='COMPLETED'"),
        ("FAILED", "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='FAILED'"),
        ("STARTED", "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='STARTED'"),
        ("RUNNING", "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='RUNNING'"),
    ):
        c, stc = _scalar(run_sql, sql, (session,))
        print(f"  {label:<12} : {c if stc == 'OK' else stc}")

    _print_section("FAILED abort_reason histogram")
    hist_rows, sth = _rows(
        run_sql,
        """
        SELECT COALESCE(NULLIF(TRIM(abort_reason), ''), '<blank>') AS reason_token, COUNT(*) AS n
        FROM static_analysis_runs
        WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='FAILED'
        GROUP BY reason_token
        ORDER BY n DESC, reason_token ASC
        """,
        (session,),
    )
    if sth != "OK":
        print(f"  {sth}")
    elif not hist_rows:
        print("  (no FAILED rows)")
    else:
        for row in hist_rows:
            token = row[0]
            n = row[1]
            print(f"  {str(token)[:80]!s:<82} {int(n)}")

    blank_failed, _ = _scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM static_analysis_runs
        WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='FAILED'
          AND (abort_reason IS NULL OR TRIM(abort_reason) = '')
        """,
        (session,),
    )
    print(f"\nFAILED with blank abort_reason : {blank_failed}")

    _print_section("Canonical + legacy findings (session-scoped)")
    cf, stf = _scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM static_analysis_findings f
        INNER JOIN static_analysis_runs r ON r.id = f.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    print(f"static_analysis_findings (via run join) : {cf if stf == 'OK' else stf}")

    lf = None
    lf_st = "skipped"
    try:
        lf, lf_st = _scalar(
            run_sql,
            """
            SELECT COUNT(*) FROM findings f
            INNER JOIN runs lr ON lr.run_id = f.run_id
            WHERE lr.session_stamp=%s
            """,
            (session,),
        )
    except Exception as exc:
        lf_st = f"ERROR: {exc}"
    print(f"legacy findings (runs.session_stamp)   : {lf if lf_st == 'OK' else lf_st}")

    _print_section("Permission matrix / vnext / audit apps")
    pm, stpm = _scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM static_permission_matrix m
        WHERE m.run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )
    print(f"static_permission_matrix rows          : {pm if stpm == 'OK' else stpm}")

    vnext_exists = _table_exists(run_sql, "static_permission_risk_vnext")
    if not vnext_exists:
        print("static_permission_risk_vnext           : (table not present in this catalog)")
        pr = None
        stpr = "N/A"
    else:
        pr, stpr = _scalar(
            run_sql,
            """
            SELECT COUNT(*) FROM static_permission_risk_vnext p
            WHERE p.run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
            """,
            (session,),
        )
        print(f"static_permission_risk_vnext rows        : {pr if stpr == 'OK' else stpr}")

    pa, stpa = _scalar(
        run_sql,
        """
        SELECT COUNT(*) FROM permission_audit_apps p
        WHERE p.static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session,),
    )
    print(f"permission_audit_apps rows             : {pa if stpa == 'OK' else stpa}")

    _print_section("Matrix / vnext mismatch summary (per static_run_id)")
    if not vnext_exists:
        print("  (skip: static_permission_risk_vnext missing)")
    else:
        try:
            from scytaledroid.StaticAnalysis.cli.audit.permission_session_insights import (
                _classify_matrix_risk_skew,
            )
        except ImportError:
            _classify_matrix_risk_skew = None  # type: ignore[assignment]

        skew_rows, sts = _rows(
            run_sql,
            """
            SELECT sar.id,
                   COALESCE(a.package_name, '?'),
                   COALESCE(sar.status, ''),
                   (SELECT COUNT(*) FROM static_permission_matrix m WHERE m.run_id = sar.id) AS mc,
                   (SELECT COUNT(*) FROM static_permission_risk_vnext r WHERE r.run_id = sar.id) AS rc
            FROM static_analysis_runs sar
            LEFT JOIN app_versions av ON av.id = sar.app_version_id
            LEFT JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp=%s
            ORDER BY sar.id ASC
            """,
            (session,),
        )
        if sts != "OK":
            print(f"  {sts}")
        elif not skew_rows:
            print("  (no rows)")
        else:
            klass_counts: Counter[str] = Counter()
            suspicious: list[str] = []
            for row in skew_rows:
                if len(row) < 5:
                    continue
                sid, pkg, status, mc, rc = row[0], str(row[1]), str(row[2]), int(row[3] or 0), int(row[4] or 0)
                if _classify_matrix_risk_skew is None:
                    skew = None
                    if (mc > 0) != (rc > 0):
                        skew = ("SKEW", "matrix and vnext counts differ")
                else:
                    skew = _classify_matrix_risk_skew(status, mc, rc)
                if skew:
                    klass, reason = skew
                    klass_counts[klass] += 1
                    if klass.startswith("SUSPICIOUS") and len(suspicious) < max(1, int(args.mismatch_limit)):
                        suspicious.append(
                            f"  static_run_id={sid} pkg={pkg} status={status} matrix={mc} vnext={rc} :: {klass} - {reason}"
                        )
            if klass_counts:
                print("  skew_class counts:")
                for k, v in klass_counts.most_common():
                    print(f"    {k}: {v}")
            else:
                print("  (no matrix/vnext skew by current rules)")
            if suspicious:
                print(f"  sample SUSPICIOUS rows (up to {args.mismatch_limit}):")
                for line in suspicious[: args.mismatch_limit]:
                    print(line)

    _print_section("Persistence audit JSON (filesystem)")
    _audit_persistence_summary(session, args.output_dir)

    _print_section("Package listing hint")
    print("  Package names are not on static_analysis_runs; use a join or view, e.g.:")
    print(
        "    SELECT sar.id, a.package_name, sar.status "
        "FROM static_analysis_runs sar "
        "LEFT JOIN app_versions av ON av.id = sar.app_version_id "
        "LEFT JOIN apps a ON a.id = av.app_id "
        f"WHERE sar.session_stamp = '{session.replace(chr(39), chr(39)+chr(39))}' "
        "ORDER BY sar.id LIMIT 25;"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
