#!/usr/bin/env python3
"""Report static-analysis database cleanup candidates without modifying data."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Database.db_core import db_queries as core_q

DEV_SESSION_RE = re.compile(r"gatefix|seedtest|smoke|postfix|static-batch|test", re.IGNORECASE)


def is_dev_or_legacy_session(session_stamp: object) -> bool:
    if not isinstance(session_stamp, str):
        return False
    token = session_stamp.strip()
    if not token:
        return False
    return bool(DEV_SESSION_RE.search(token))


def _fetch_rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    rows = core_q.run_sql(query, params, fetch="all", dictionary=True)
    return list(rows or [])


def _fetch_one(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    row = core_q.run_sql(query, params, fetch="one", dictionary=True)
    return dict(row or {})


def build_report(*, sample_limit: int = 20) -> dict[str, Any]:
    legacy_profiles = _fetch_rows(
        """
        SELECT profile_key, display_name, scope_group, is_active
        FROM android_app_profiles
        WHERE display_name REGEXP 'Paper|Profile v3'
        ORDER BY sort_order, profile_key
        """
    )

    stale_rollups = _fetch_rows(
        """
        SELECT
          s.session_stamp,
          s.scope_label,
          s.apps_total,
          s.completed,
          s.failed,
          s.running,
          s.created_at,
          s.updated_at
        FROM static_session_rollups s
        LEFT JOIN static_analysis_runs r
          ON r.session_stamp=s.session_stamp
        LEFT JOIN static_session_run_links l
          ON l.session_stamp=s.session_stamp
        WHERE r.id IS NULL
          AND l.link_id IS NULL
        ORDER BY s.updated_at DESC
        """
    )

    missing_rollups = _fetch_rows(
        """
        SELECT
          l.session_stamp,
          COUNT(*) AS links,
          SUM(CASE WHEN UPPER(COALESCE(r.status, ''))='FAILED' THEN 1 ELSE 0 END) AS failed_runs,
          SUM(CASE WHEN UPPER(COALESCE(r.status, ''))='COMPLETED' THEN 1 ELSE 0 END) AS completed_runs
        FROM static_session_run_links l
        JOIN static_analysis_runs r
          ON r.id=l.static_run_id
        LEFT JOIN static_session_rollups s
          ON s.session_stamp=l.session_stamp
        WHERE s.session_stamp IS NULL
        GROUP BY l.session_stamp
        ORDER BY links DESC, l.session_stamp DESC
        """
    )

    failed_sessions = _fetch_rows(
        """
        SELECT
          session_stamp,
          scope_label,
          status,
          canonical_reason,
          non_canonical_reasons,
          created_at
        FROM static_analysis_runs
        WHERE status='FAILED'
        ORDER BY created_at DESC
        """
    )

    persistence_failure_rows = _fetch_rows(
        """
        SELECT
          spf.static_run_id,
          spf.stage,
          spf.exception_class,
          spf.exception_message,
          spf.occurred_at_utc,
          sar.session_stamp,
          sar.scope_label
        FROM static_persistence_failures spf
        LEFT JOIN static_analysis_runs sar
          ON sar.id=spf.static_run_id
        ORDER BY spf.occurred_at_utc DESC
        """
    )

    dev_or_legacy_runs = _fetch_rows(
        """
        SELECT session_stamp, scope_label, status, created_at
        FROM static_analysis_runs
        ORDER BY created_at DESC
        """
    )
    dev_or_legacy_runs = [
        row for row in dev_or_legacy_runs if is_dev_or_legacy_session(row.get("session_stamp"))
    ]

    failed_session_counts = Counter(str(row.get("session_stamp") or "") for row in failed_sessions)
    persistence_stage_counts = Counter(str(row.get("stage") or "") for row in persistence_failure_rows)
    legacy_status_counts = Counter(str(row.get("status") or "") for row in dev_or_legacy_runs)

    total_static_runs = int(
        _fetch_one("SELECT COUNT(*) AS rows_count FROM static_analysis_runs").get("rows_count") or 0
    )

    return {
        "summary": {
            "total_static_runs": total_static_runs,
            "legacy_profile_labels": len(legacy_profiles),
            "stale_rollup_rows": len(stale_rollups),
            "missing_rollup_sessions": len(missing_rollups),
            "failed_static_runs": len(failed_sessions),
            "dev_or_legacy_runs": len(dev_or_legacy_runs),
            "persistence_failure_rows": len(persistence_failure_rows),
        },
        "counts": {
            "failed_sessions_by_stamp": dict(failed_session_counts.most_common(sample_limit)),
            "persistence_failures_by_stage": dict(persistence_stage_counts.most_common(sample_limit)),
            "dev_or_legacy_status_counts": dict(legacy_status_counts.most_common()),
        },
        "samples": {
            "legacy_profile_labels": legacy_profiles[:sample_limit],
            "stale_rollups": stale_rollups[:sample_limit],
            "missing_rollups": missing_rollups[:sample_limit],
            "failed_static_runs": failed_sessions[:sample_limit],
            "dev_or_legacy_runs": dev_or_legacy_runs[:sample_limit],
            "persistence_failures": persistence_failure_rows[:sample_limit],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit static-analysis DB cleanup candidates.")
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=20,
        help="Maximum rows to include per sample section (default: 20).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON only.",
    )
    args = parser.parse_args(argv)

    report = build_report(sample_limit=max(1, args.sample_limit))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 0

    print(json.dumps(report["summary"], indent=2, sort_keys=True, default=str))
    print()
    print(json.dumps(report["counts"], indent=2, sort_keys=True, default=str))
    print()
    print(json.dumps(report["samples"], indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
