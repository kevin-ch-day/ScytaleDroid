#!/usr/bin/env python3
"""Read-only report over canonical DB-backed research cohorts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--members", action="store_true", help="Include active member rows for each cohort.")
    parser.add_argument(
        "--all-members",
        action="store_true",
        help="Include active and inactive member rows for each cohort.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_func.research_cohorts import (
            fetch_active_research_cohort_members,
            list_active_research_cohorts,
        )
        from scytaledroid.Database.db_core import run_sql
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    cohorts = list_active_research_cohorts()
    payload: dict[str, object] = {
        "cohort_count": len(cohorts),
        "cohorts": cohorts,
    }
    include_members = args.members or args.all_members
    if include_members:
        if args.all_members:
            members_by_key = {}
            for row in cohorts:
                cohort_key = str(row.get("cohort_key") or "")
                members_by_key[cohort_key] = run_sql(
                    """
                    SELECT
                      rc.cohort_key,
                      rc.display_name,
                      rcm.package_name,
                      rcm.member_source,
                      rcm.source_cohort_key,
                      rcm.sort_order,
                      rcm.is_active,
                      rcm.notes
                    FROM research_cohorts rc
                    JOIN research_cohort_members rcm
                      ON rcm.cohort_id = rc.cohort_id
                    WHERE rc.cohort_key = %s
                    ORDER BY rcm.is_active DESC, rcm.sort_order ASC, rcm.package_name ASC
                    """,
                    (cohort_key,),
                    fetch="all",
                    dictionary=True,
                ) or []
        else:
            members_by_key = {
                str(row.get("cohort_key") or ""): fetch_active_research_cohort_members(str(row.get("cohort_key") or ""))
                for row in cohorts
            }
        payload["members"] = members_by_key
        payload["member_mode"] = "all" if args.all_members else "active"

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# research cohorts")
    print(f"active_cohort_count: {len(cohorts)}")
    for row in cohorts:
        key = str(row.get("cohort_key") or "")
        print(
            f"- {row.get('display_name') or key}: key={key} "
            f"members={row.get('active_member_count') or 0} "
            f"selection_rule={row.get('selection_rule') or 'unknown'}"
        )
        if include_members:
            if args.all_members:
                member_rows = payload.get("members", {}).get(key, []) if isinstance(payload.get("members"), dict) else []
            else:
                member_rows = fetch_active_research_cohort_members(key)
            for member in member_rows:
                state = "active" if int(member.get("is_active") or 0) == 1 else "inactive"
                print(
                    "    "
                    f"{member.get('sort_order') or 0:>2} "
                    f"{member.get('package_name') or ''} "
                    f"[{member.get('member_source') or 'unknown'} | {state}]"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
