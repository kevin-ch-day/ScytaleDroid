#!/usr/bin/env python3
"""Read-only static session grain / integrity report (no DML, no deletes).

Summarizes canonical DB row counts for a ``session_stamp``, optional archive JSON
file counts under ``data/static_analysis/reports/archive/<session>/``, optional
pipeline_summary rollups from those JSON files (artifact-stage sums; not deduped),
and optional ``--with-display-labels`` for a curated/DB display column on the
top-packages table.

Run from repo root::

  PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py --session-stamp 20260510-all-full
  PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py --session-stamp 20260510-all-full --json
  PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py --session-stamp X --aggregate-json-summaries

Exit codes:
  0 — report produced (including zero-row sessions when ``--allow-empty``)
  1 — import/argument/runtime error
  2 — no ``static_analysis_runs`` rows for session (unless ``--allow-empty``)
  3 — DB unavailable / query failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only static pipeline grain / integrity report for one session_stamp.",
    )
    p.add_argument(
        "--session-stamp",
        required=True,
        help="session_stamp on static_analysis_runs (same token as static CLI session stamp).",
    )
    p.add_argument(
        "--scope-label",
        default=None,
        help="Optional filter: only static_analysis_runs rows with this scope_label.",
    )
    p.add_argument(
        "--top-packages",
        type=int,
        default=25,
        help="Number of packages to list in the DB footprint table (default: 25).",
    )
    p.add_argument(
        "--data-dir",
        default="data",
        help="Repo data directory for archive JSON path resolution (default: data).",
    )
    p.add_argument(
        "--count-archive-json",
        action="store_true",
        help="Count *.json files under reports/archive/<session>/ (non-recursive).",
    )
    p.add_argument(
        "--aggregate-json-summaries",
        action="store_true",
        help="Parse each archive JSON and sum pipeline_summary WARN/policy/error rows (I/O heavy).",
    )
    p.add_argument(
        "--max-json-files",
        type=int,
        default=5000,
        help="Cap for --aggregate-json-summaries (default: 5000).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of plain text.",
    )
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="Exit 0 when no static_analysis_runs rows exist (default: exit 2).",
    )
    p.add_argument(
        "--with-display-labels",
        action="store_true",
        help=(
            "Add a display column on the top-packages table: curated CSV display_name (if "
            "--display-overrides-csv) else apps.display_name else package. Does not load static JSON."
        ),
    )
    p.add_argument(
        "--display-overrides-csv",
        default=None,
        help=(
            "Optional hygiene-style CSV (package_name, display_name). When --with-display-labels is set "
            "and this is omitted, defaults to <repo>/data/reference/app_display_name_overrides.csv if present."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    session = str(args.session_stamp or "").strip()
    if not session:
        sys.stderr.write("--session-stamp must be non-empty.\n")
        return 1

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.static_session_grain_integrity import (
            aggregate_archive_json_pipeline_totals,
            collect_session_grain,
            count_json_files_in_dir,
            load_grain_operator_display_overrides,
            render_text_report,
            reports_archive_dir,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    archive_dir = reports_archive_dir(session_stamp=session, data_dir=args.data_dir)
    json_count: int | None = None
    if args.count_archive_json or args.aggregate_json_summaries:
        json_count = count_json_files_in_dir(archive_dir)

    json_aggregate: dict | None = None
    if args.aggregate_json_summaries:
        json_aggregate = aggregate_archive_json_pipeline_totals(
            archive_dir,
            max_files=int(args.max_json_files),
        )

    try:
        data = collect_session_grain(
            core_q.run_sql,
            session_stamp=session,
            scope_label=args.scope_label,
            top_packages=int(args.top_packages),
        )
    except Exception as exc:
        sys.stderr.write(f"DB query failed: {exc}\n")
        return 3

    if int(data.get("static_run_rows") or 0) == 0:
        if args.allow_empty:
            pass
        else:
            sys.stderr.write(
                "No static_analysis_runs rows for this session_stamp "
                "(use --allow-empty to exit 0, or fix the stamp).\n"
            )
            return 2

    if args.json:
        out: dict = dict(data)
        out["reports_archive_dir"] = str(archive_dir)
        if json_count is not None:
            out["archive_json_file_count"] = json_count
        if json_aggregate is not None:
            out["archive_json_pipeline_aggregate"] = json_aggregate
        if args.with_display_labels:
            csv_path = Path(args.display_overrides_csv) if args.display_overrides_csv else _REPO_ROOT / "data/reference/app_display_name_overrides.csv"
            out["grain_display_overrides_csv"] = str(csv_path)
            out["grain_display_override_rows"] = len(load_grain_operator_display_overrides(csv_path))
        sys.stdout.write(json.dumps(out, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    override_map: dict[str, str] | None = None
    if args.with_display_labels:
        csv_path = Path(args.display_overrides_csv) if args.display_overrides_csv else _REPO_ROOT / "data/reference/app_display_name_overrides.csv"
        override_map = load_grain_operator_display_overrides(csv_path)

    text = render_text_report(
        data,
        json_archive_count=json_count if args.count_archive_json or args.aggregate_json_summaries else None,
        json_aggregate=json_aggregate,
        with_display_labels=bool(args.with_display_labels),
        display_override_by_lower=override_map,
    )
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
