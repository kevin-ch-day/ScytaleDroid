#!/usr/bin/env python3
"""Recompute ``static_analysis_sessions`` counters and disposition from run/child facts.

Leaves operator-controlled columns untouched: ``web_visibility_default``,
``cleanup_status``, ``superseded_by_session_id``.

Runs from repo root with the usual ``SCYTALEDROID_DB_*`` / ``SCYTALEDROID_DB_URL`` env.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Refresh every (session_stamp, scope_label) present in static_analysis_runs.",
    )
    parser.add_argument("--session-stamp", type=str, default=None, help="Target session_stamp.")
    parser.add_argument(
        "--scope-label",
        type=str,
        default="",
        help="Target scope_label (omit or empty string for '').",
    )
    parser.add_argument(
        "--materialize-rollups",
        action="store_true",
        help="Also upsert missing static_session_rollups rows from static_analysis_runs aggregates.",
    )
    args = parser.parse_args()

    from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
        refresh_all_static_analysis_sessions_from_runs,
        refresh_static_analysis_session_summary,
    )

    if args.all:
        n = refresh_all_static_analysis_sessions_from_runs(
            materialize_rollups=args.materialize_rollups,
        )
        print(f"sessions_refreshed={n}")
        return 0

    stamp = (args.session_stamp or "").strip()
    if not stamp:
        parser.error("--session-stamp is required unless --all is set")

    scope = args.scope_label if args.scope_label is not None else ""
    ok = refresh_static_analysis_session_summary(
        session_stamp=stamp,
        scope_label=scope,
        materialize_rollup=args.materialize_rollups,
    )
    print(f"refreshed={1 if ok else 0}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
