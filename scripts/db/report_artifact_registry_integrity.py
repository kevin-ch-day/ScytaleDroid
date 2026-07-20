#!/usr/bin/env python3
"""Read-only artifact registry integrity report (no DML/DDL/filesystem deletes).

Summarizes ``v_artifact_registry_integrity`` row counts, dangling breakdowns by
``artifact_type`` and age bucket, top orphan ``run_id`` values, and optional
cheap host_path existence sampling for operator triage.

Run from repo root::

  PYTHONPATH=. python scripts/db/report_artifact_registry_integrity.py
  PYTHONPATH=. python scripts/db/report_artifact_registry_integrity.py --json
  PYTHONPATH=. python scripts/db/report_artifact_registry_integrity.py --path-sample 50

Exit codes: 0 success, 1 unexpected error, 2 DB unavailable/disabled.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _rows(core_q: Any, sql: str, params: Sequence[Any] | None = None) -> list[tuple[Any, ...]]:
    out = core_q.run_sql(sql, params, fetch="all", query_name="report.artifact_registry_integrity")
    if not out:
        return []
    return [tuple(r) for r in out]


def collect_report(
    core_q: Any,
    *,
    top_n: int,
    path_sample_limit: int,
) -> dict[str, Any]:
    """Run read-only SQL and optional host_path probes; return structured report."""

    totals = _rows(
        core_q,
        """
        SELECT run_type, link_state, COUNT(*) AS c
        FROM v_artifact_registry_integrity
        GROUP BY run_type, link_state
        ORDER BY run_type, link_state
        """,
    )
    dangling_by_type = _rows(
        core_q,
        """
        SELECT run_type, artifact_type, link_state, COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE link_state LIKE 'dangling%%' OR link_state = 'unknown_run_type'
        GROUP BY run_type, artifact_type, link_state
        ORDER BY c DESC, run_type, artifact_type
        """,
    )
    dangling_age = _rows(
        core_q,
        """
        SELECT
          run_type,
          link_state,
          CASE
            WHEN created_at_utc IS NULL THEN 'null_created_at'
            WHEN created_at_utc >= (NOW() - INTERVAL 7 DAY) THEN '0-7d'
            WHEN created_at_utc >= (NOW() - INTERVAL 90 DAY) THEN '7-90d'
            ELSE '90d+'
          END AS age_bucket,
          COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE link_state LIKE 'dangling%%' OR link_state = 'unknown_run_type'
        GROUP BY run_type, link_state, age_bucket
        ORDER BY run_type, link_state, age_bucket
        """,
    )
    top_static = _rows(
        core_q,
        """
        SELECT run_id, COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE run_type = 'static' AND link_state = 'dangling_static_run'
        GROUP BY run_id
        ORDER BY c DESC
        LIMIT %s
        """,
        (int(top_n),),
    )
    top_dynamic = _rows(
        core_q,
        """
        SELECT run_id, COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE run_type = 'dynamic' AND link_state = 'dangling_dynamic_run'
        GROUP BY run_id
        ORDER BY c DESC
        LIMIT %s
        """,
        (int(top_n),),
    )
    static_non_numeric = _rows(
        core_q,
        """
        SELECT COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE run_type = 'static'
          AND run_id NOT REGEXP '^[0-9]+$'
        """,
    )
    static_numeric_missing_sar = _rows(
        core_q,
        """
        SELECT COUNT(*) AS c
        FROM v_artifact_registry_integrity ar
        WHERE ar.run_type = 'static'
          AND ar.run_id REGEXP '^[0-9]+$'
          AND NOT EXISTS (
            SELECT 1 FROM static_analysis_runs sar
            WHERE sar.id = CAST(ar.run_id AS UNSIGNED)
          )
        """,
    )

    path_probe: dict[str, Any] | None = None
    if path_sample_limit > 0:
        sample = _rows(
            core_q,
            """
            SELECT artifact_id, run_type, link_state, host_path
            FROM v_artifact_registry_integrity
            WHERE link_state LIKE 'dangling%%'
              AND host_path IS NOT NULL
              AND TRIM(host_path) <> ''
            ORDER BY created_at_utc DESC
            LIMIT %s
            """,
            (int(path_sample_limit),),
        )
        present = 0
        missing = 0
        unknown = 0
        examples: list[dict[str, Any]] = []
        for row in sample:
            aid, rt, ls, hp = row[0], str(row[1] or ""), str(row[2] or ""), str(row[3] or "").strip()
            if not hp:
                unknown += 1
                continue
            try:
                exists = Path(hp).is_file()
            except OSError:
                exists = False
                unknown += 1
                continue
            if exists:
                present += 1
            else:
                missing += 1
            if len(examples) < 8:
                examples.append(
                    {
                        "artifact_id": int(aid) if aid is not None else None,
                        "run_type": rt,
                        "link_state": ls,
                        "host_path": hp[:200],
                        "host_path_exists": exists,
                    }
                )
        path_probe = {
            "sampled_rows": len(sample),
            "host_path_exists_true": present,
            "host_path_exists_false": missing,
            "host_path_probe_errors": unknown,
            "examples": examples,
        }

    totals_rows = [
        {"run_type": str(a), "link_state": str(b), "count": int(c or 0)} for a, b, c in totals
    ]
    summary_counts = {
        "total_rows": sum(int(row["count"]) for row in totals_rows),
        "linked_rows": sum(int(row["count"]) for row in totals_rows if row["link_state"] == "linked"),
        "dangling_static_run_rows": sum(
            int(row["count"]) for row in totals_rows if row["link_state"] == "dangling_static_run"
        ),
        "dangling_dynamic_run_rows": sum(
            int(row["count"]) for row in totals_rows if row["link_state"] == "dangling_dynamic_run"
        ),
        "unknown_run_type_rows": sum(
            int(row["count"]) for row in totals_rows if row["link_state"] == "unknown_run_type"
        ),
    }

    return {
        "summary_counts": summary_counts,
        "totals_by_run_type_link_state": totals_rows,
        "dangling_by_artifact_type": [
            {"run_type": str(a), "artifact_type": str(b), "link_state": str(c), "count": int(d or 0)}
            for a, b, c, d in dangling_by_type
        ],
        "dangling_by_age_bucket": [
            {"run_type": str(a), "link_state": str(b), "age_bucket": str(c), "count": int(d or 0)}
            for a, b, c, d in dangling_age
        ],
        "top_dangling_static_run_ids": [
            {"run_id": str(a), "count": int(b or 0)} for a, b in top_static
        ],
        "top_dangling_dynamic_run_ids": [
            {"run_id": str(a), "count": int(b or 0)} for a, b in top_dynamic
        ],
        "static_rows_nonnumeric_run_id": int((static_non_numeric[0][0] if static_non_numeric else 0) or 0),
        "static_numeric_run_id_rows_missing_sar": int(
            (static_numeric_missing_sar[0][0] if static_numeric_missing_sar else 0) or 0
        ),
        "host_path_probe": path_probe,
    }


def format_text_report(data: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# artifact_registry integrity (read-only)")
    lines.append("")
    summary = data.get("summary_counts") or {}
    if summary:
        lines.append("## summary")
        lines.append(f"  total_rows={summary.get('total_rows')}")
        lines.append(f"  linked_rows={summary.get('linked_rows')}")
        lines.append(f"  dangling_static_run_rows={summary.get('dangling_static_run_rows')}")
        lines.append(f"  dangling_dynamic_run_rows={summary.get('dangling_dynamic_run_rows')}")
        lines.append(f"  unknown_run_type_rows={summary.get('unknown_run_type_rows')}")
        lines.append("")
    lines.append("## totals by run_type × link_state")
    for row in data.get("totals_by_run_type_link_state") or []:
        lines.append(f"  {row.get('run_type')}\t{row.get('link_state')}\t{row.get('count')}")
    lines.append("")
    lines.append("## dangling rows by artifact_type (dangling_* + unknown_run_type)")
    for row in data.get("dangling_by_artifact_type") or []:
        lines.append(
            f"  {row.get('run_type')}\t{row.get('link_state')}\t{row.get('artifact_type')}\t{row.get('count')}"
        )
    lines.append("")
    lines.append("## dangling rows by age bucket (created_at_utc vs NOW())")
    for row in data.get("dangling_by_age_bucket") or []:
        lines.append(
            f"  {row.get('run_type')}\t{row.get('link_state')}\t{row.get('age_bucket')}\t{row.get('count')}"
        )
    lines.append("")
    lines.append("## top dangling static run_id values")
    for row in data.get("top_dangling_static_run_ids") or []:
        lines.append(f"  {row.get('run_id')}\t{row.get('count')}")
    lines.append("")
    lines.append("## top dangling dynamic run_id values")
    for row in data.get("top_dangling_dynamic_run_ids") or []:
        lines.append(f"  {row.get('run_id')}\t{row.get('count')}")
    lines.append("")
    lines.append("## static run_id shape (integrity view semantics)")
    lines.append(f"  static rows with non-numeric run_id: {data.get('static_rows_nonnumeric_run_id')}")
    lines.append(
        f"  static numeric run_id rows with no SAR row (subset of dangling): "
        f"{data.get('static_numeric_run_id_rows_missing_sar')}"
    )
    probe = data.get("host_path_probe")
    lines.append("")
    lines.append("## host_path sample (dangling rows only; cheap exists check)")
    if not probe:
        lines.append("  (skipped; use --path-sample N to probe up to N rows)")
    else:
        lines.append(f"  sampled_rows={probe.get('sampled_rows')}")
        lines.append(f"  exists_true={probe.get('host_path_exists_true')}")
        lines.append(f"  exists_false={probe.get('host_path_exists_false')}")
        lines.append(f"  probe_errors={probe.get('host_path_probe_errors')}")
        for ex in probe.get("examples") or []:
            lines.append(f"    {ex}")
    lines.append("")
    lines.append(
        "Notes: link_state comes from v_artifact_registry_integrity. "
        "static linked prefers typed static_run_id joins and falls back to numeric legacy run_id parsing only for unmigrated rows. "
        "Dynamic linked prefers typed dynamic_run_id joins and falls back to legacy run_id only when dynamic_run_id is still blank."
    )
    lines.append(
        "Interpretation: large static dangling_static_run counts usually mean numeric run_id rows whose "
        "SAR row is gone (DB reset, selective delete, or test churn) — a derived-ledger gap, not necessarily "
        "bad harvest/APK data. Age buckets show backlog age; use prune_artifact_registry_dangling.py for "
        "age-gated registry cleanup (receipt + --apply). Dynamic dangling_* is separate (same prune script, "
        "--run-type dynamic)."
    )
    lines.append(
        "See docs/maintenance/artifact_registry_cleanup_track.md. "
        "Read-only buckets: scripts/db/report_artifact_registry_cleanup_candidates.py; "
        "scoped prune: scripts/db/prune_artifact_registry_dangling.py."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON on stdout (still read-only).",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=15,
        metavar="N",
        help="Max distinct dangling run_ids to list per static/dynamic section (default: 15).",
    )
    parser.add_argument(
        "--path-sample",
        type=int,
        default=0,
        metavar="N",
        help="Probe up to N dangling rows with non-empty host_path via Path.is_file() (default: 0 skip).",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        data = collect_report(
            core_q,
            top_n=max(1, min(int(args.top_n), 500)),
            path_sample_limit=max(0, min(int(args.path_sample), 5_000)),
        )
    except Exception as exc:
        sys.stderr.write(f"Report query failed: {exc}\n")
        return 2

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(format_text_report(data), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
