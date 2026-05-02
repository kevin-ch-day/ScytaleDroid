#!/usr/bin/env python3
"""Validate canonical MASVS views against a static session stamp (ops / research).

For ``session_stamp`` (e.g. RDA ``20260502-rda-full``):

- Lists each ``static_run_id`` / package for that session from ``static_analysis_runs``.
- Reads matrix columns from ``v_static_masvs_matrix_v1``.
- Counts findings missing MASVS tags (same predicate as the view).
- Optionally compares each row to ``fetch_masvs_matrix()`` **only when** the Python matrix
  reports the same ``run_id`` as this session's static run (global "latest per package"
  otherwise differs — the script prints ``[SKIP]`` for those).

Requires ``SCYTALEDROID_DB_*``. Run from repo root::

  PYTHONPATH=. python scripts/db/validate_canonical_masvs_session.py --session 20260502-rda-full

Exit codes: 0 OK, 1 DB/compare error (including missing VIEWs — remediation printed to stderr), 2 usage.
Missing ``v_static_masvs_matrix_v1``: ``PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate --confirm``
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping


def _normalise_sql_status(raw: object) -> str:
    text = str(raw or "").strip().upper().replace("_", " ")
    if text == "NO DATA":
        return "NO DATA"
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session",
        required=True,
        help="static_analysis_runs.session_stamp",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print one summary line only.",
    )
    ns = parser.parse_args(argv)
    session_stamp = str(ns.session).strip()
    if not session_stamp:
        return 2

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import view_deploy_remediation as vdr
        from scytaledroid.StaticAnalysis.cli.persistence.reports import masvs_summary_report
    except Exception as exc:
        print(f"Import failed: {exc.__class__.__name__}:{exc}", file=sys.stderr)
        return 1

    try:
        core_q.run_sql(
            "SELECT COUNT(*) FROM v_static_masvs_matrix_v1",
            (),
            fetch="one",
        )
    except Exception as exc:
        if vdr.sql_object_missing_error(exc):
            print(vdr.remediation_text(), file=sys.stderr)
            return 1
        print(f"{exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1

    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    sql_cols = ("masvs_network_status", "masvs_platform_status", "masvs_privacy_status", "masvs_storage_status")

    try:
        session_runs = core_q.run_sql(
            """
            SELECT sar.id, a.package_name
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
            ORDER BY a.package_name, sar.id
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
        ) or []
        if not session_runs:
            print(f"No static_analysis_runs for session_stamp={session_stamp!r}.")
            return 1

        unmapped_row = core_q.run_sql(
            """
            SELECT COUNT(*) FROM static_analysis_findings saf
            JOIN static_analysis_runs sar ON sar.id = saf.run_id
            WHERE sar.session_stamp = %s
              AND (
                   NULLIF(TRIM(COALESCE(saf.masvs_area, '')), '') IS NULL
               AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NULL
               AND NULLIF(TRIM(COALESCE(saf.masvs_control_id, '')), '') IS NULL
              )
            """,
            (session_stamp,),
            fetch="one",
        )
        unmapped_count = int(unmapped_row[0] if unmapped_row and unmapped_row[0] is not None else 0)

        py_matrix = masvs_summary_report.fetch_masvs_matrix()

        mismatches = 0
        skipped = 0
        compared = 0

        if not ns.quiet:
            print(f"Session {session_stamp}: {len(session_runs)} static run row(s).")
            print(f"Findings lacking any MASVS tag: {unmapped_count}")
            print()

        for run in session_runs:
            sid = int(run["id"])
            pkg = str(run.get("package_name") or "")
            row = core_q.run_sql(
                f"""
                SELECT package_name, {", ".join(sql_cols)},
                       findings_total, findings_masvs_mapped, findings_masvs_unmapped
                FROM v_static_masvs_matrix_v1
                WHERE static_run_id = %s
                """,
                (sid,),
                fetch="one",
                dictionary=True,
            )
            if not row:
                print(f"[MISS] static_run_id={sid} package={pkg!r}: no SQL matrix row.")
                mismatches += 1
                continue

            py = py_matrix.get(pkg) if isinstance(py_matrix, Mapping) else None
            if not isinstance(py, Mapping):
                print(f"[SKIP] {pkg}: not in Python matrix.")
                skipped += 1
                continue
            py_rid = int(py.get("run_id") or 0)
            if py_rid != sid:
                if not ns.quiet:
                    print(
                        f"[SKIP] {pkg}: Python latest run_id={py_rid} "
                        f"!= session static_run_id={sid} (compare SQL only for this cohort)."
                    )
                skipped += 1
                continue

            compared += 1
            st_py = py.get("status") if isinstance(py.get("status"), Mapping) else {}
            for area, col in zip(areas, sql_cols, strict=True):
                sql_s = _normalise_sql_status(row.get(col))
                py_s = _normalise_sql_status(st_py.get(area) if isinstance(st_py, Mapping) else None)
                if sql_s != py_s:
                    print(f"[MISS] {pkg} sid={sid} {area}: SQL={sql_s!r} Python={py_s!r}")
                    mismatches += 1

        if ns.quiet:
            print(
                f"{session_stamp}\tmismatches={mismatches}\tskip_latest_mismatch={skipped}\t"
                f"compared={compared}\tunmapped_findings={unmapped_count}"
            )
        else:
            print()
            print(f"Compared Python vs SQL (same static_run_id): {compared} package(s).")
            print(f"Mismatched area statuses: {mismatches}")

        return 1 if mismatches else 0
    except Exception as exc:
        print(f"{exc.__class__.__name__}: {exc}", file=sys.stderr)
        if os.environ.get("SCYTALEDROID_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
