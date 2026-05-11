#!/usr/bin/env python3
"""Run permission_risk persistence for a saved static report JSON (narrow validation).

Loads ``detector_metrics.permissions_profile.permission_profiles`` and calls
``persist_permission_risk`` with the given ``static_run_id`` (vnext rows use ``run_id = static_run_id``).

**Production safety:** by default this script is **dry-run only** (no DB writes). It never runs the
full persistence transaction (no ``static_permission_matrix`` rows). Writing only vnext rows against
a real ``static_run_id`` will skew matrix↔vnext diagnostics for that run — use ``--write-live`` only
with intent, and prefer leaving rows only when ``--keep-validation-rows`` is set; otherwise vnext
rows are removed again in a ``finally`` block after the check.

Repair a historical orphan (risk rows, no matrix)::

  PYTHONPATH=. python scripts/static_analysis/validate_report_permission_risk.py \\
    --prune-vnext-rows --static-run-id 2362

Dry-run (report current matrix/vnext counts, no writes)::

  PYTHONPATH=. python scripts/static_analysis/validate_report_permission_risk.py \\
    --report data/static_analysis/reports/latest/<sha>.json \\
    --package com.mobileapp.android.relia \\
    --static-run-id 2362

Live validation (pre-delete vnext for run, persist, verify, then delete vnext again unless ``--keep-validation-rows``)::

  PYTHONPATH=. python scripts/static_analysis/validate_report_permission_risk.py \\
    --write-live \\
    --report data/static_analysis/reports/latest/<sha>.json \\
    --package com.mobileapp.android.relia \\
    --static-run-id <disposable_or_test_run_id> \\
    --keep-validation-rows   # only if you intentionally want rows left in DB

Requires a configured analyst DB (same as static persistence).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_profiles(report_path: Path) -> dict[str, dict[str, object]]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    dm = data.get("detector_metrics") or {}
    if not isinstance(dm, dict):
        return {}
    pp = dm.get("permissions_profile") or {}
    if not isinstance(pp, dict):
        return {}
    profiles = pp.get("permission_profiles") or {}
    return dict(profiles) if isinstance(profiles, dict) else {}


def _print_run_surface(static_run_id: int) -> None:
    from scytaledroid.Database.db_core import db_queries as core_q

    try:
        m = core_q.run_sql(
            "SELECT COUNT(*) FROM static_permission_matrix WHERE run_id=%s",
            (static_run_id,),
            fetch="one",
        )
        v = core_q.run_sql(
            "SELECT COUNT(*) FROM static_permission_risk_vnext WHERE run_id=%s",
            (static_run_id,),
            fetch="one",
        )
        st = core_q.run_sql(
            "SELECT COALESCE(status,''), session_stamp FROM static_analysis_runs WHERE id=%s",
            (static_run_id,),
            fetch="one",
        )
        mc = int(m[0] or 0) if m else 0
        vc = int(v[0] or 0) if v else 0
        if st:
            print(
                f"DB surface for static_run_id={static_run_id}: "
                f"status={st[0]!r} session_stamp={st[1]!r} "
                f"matrix_rows={mc} vnext_rows={vc}"
            )
        else:
            print(
                f"DB surface for static_run_id={static_run_id}: "
                f"no static_analysis_runs row (matrix_rows={mc} vnext_rows={vc})"
            )
    except Exception as exc:
        print(f"Could not query DB surface: {exc.__class__.__name__}: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--package", default=None)
    parser.add_argument("--static-run-id", type=int, required=True)
    parser.add_argument("--session-stamp", default="validate-permission-risk")
    parser.add_argument("--scope-label", default="validate")
    parser.add_argument(
        "--write-live",
        action="store_true",
        help="Allow DB writes (pre-delete vnext for run, persist, verify; see --keep-validation-rows).",
    )
    parser.add_argument(
        "--keep-validation-rows",
        action="store_true",
        help="With --write-live, skip the final DELETE of vnext rows for this run_id (leaves DB mutated).",
    )
    parser.add_argument(
        "--prune-vnext-rows",
        action="store_true",
        help="DELETE all static_permission_risk_vnext rows for --static-run-id and exit (repair orphan vnext).",
    )
    parser.add_argument(
        "--delete-vnext-for-run",
        action="store_true",
        help="[Deprecated] Pre-delete is automatic when using --write-live; ignored otherwise.",
    )
    args = parser.parse_args()

    from scytaledroid.Database.db_core import db_queries as core_q

    if args.prune_vnext_rows:
        core_q.run_sql(
            "DELETE FROM static_permission_risk_vnext WHERE run_id=%s",
            (args.static_run_id,),
        )
        print(f"Pruned static_permission_risk_vnext rows for run_id={args.static_run_id}.")
        _print_run_surface(args.static_run_id)
        return 0

    if not args.report or not args.package:
        parser.error("--report and --package are required unless --prune-vnext-rows is set.")

    report_path: Path = args.report
    if not report_path.is_file():
        print(f"Report not found: {report_path}", file=sys.stderr)
        return 2

    profiles = _load_profiles(report_path)
    if not profiles:
        print("No permission_profiles under detector_metrics.permissions_profile; nothing to persist.", file=sys.stderr)
        return 2

    if args.delete_vnext_for_run and args.write_live:
        print(
            "Note: --delete-vnext-for-run is redundant with --write-live (pre-delete is always applied).",
            file=sys.stderr,
        )

    _print_run_surface(args.static_run_id)

    if not args.write_live:
        print(
            "Dry-run: no vnext rows written or deleted. "
            "Pass --write-live to persist (temporary: pre-delete + post-delete unless --keep-validation-rows)."
        )
        print(f"permission_profiles loaded: {len(profiles)} keys")
        return 0

    from scytaledroid.StaticAnalysis.cli.persistence.metrics_writer import MetricsBundle
    from scytaledroid.StaticAnalysis.cli.persistence.permission_risk import persist_permission_risk

    class _Report:
        metadata: dict[str, object]

        def __init__(self, meta: dict[str, object]) -> None:
            self.metadata = meta

    core_q.run_sql(
        "DELETE FROM static_permission_risk_vnext WHERE run_id=%s",
        (args.static_run_id,),
    )
    try:
        detail = {
            "dangerous_count": 1,
            "signature_count": 0,
            "vendor_count": 0,
            "score_3dp": 2.0,
            "grade": "B",
        }
        bundle = MetricsBundle(
            buckets={},
            contributors=[],
            code_http_hosts=0,
            asset_http_hosts=0,
            uses_cleartext=False,
            dangerous_permissions=1,
            signature_permissions=0,
            oem_permissions=0,
            permission_score=2.0,
            permission_grade="B",
            permission_detail=detail,
        )

        meta = {"app_label": args.package, "sha256": "00" * 32, "apk_id": args.static_run_id}
        warns = persist_permission_risk(
            run_id=args.static_run_id,
            static_run_id=args.static_run_id,
            report=_Report(meta),
            package_name=args.package,
            session_stamp=args.session_stamp,
            scope_label=args.scope_label,
            metrics_bundle=bundle,
            baseline_payload={},
            permission_profiles=profiles,
        )
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM static_permission_risk_vnext WHERE run_id=%s AND permission_name=%s",
            (args.static_run_id, "android.permission.use_biometric"),
            fetch="one",
        )
        cnt = int(row[0] or 0) if row else 0
        print(f"persistence_warnings: {len(warns)}")
        for w in warns:
            print(f"  {w}")
        print(f"static_permission_risk_vnext rows for use_biometric & run_id={args.static_run_id}: {cnt}")
    finally:
        if not args.keep_validation_rows:
            core_q.run_sql(
                "DELETE FROM static_permission_risk_vnext WHERE run_id=%s",
                (args.static_run_id,),
            )
            print(
                "Removed static_permission_risk_vnext rows for this run_id after validation "
                "(omit this by passing --keep-validation-rows)."
            )
        _print_run_surface(args.static_run_id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
