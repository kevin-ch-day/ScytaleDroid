#!/usr/bin/env python3
"""Read-only report: dynamic session vs canonical static alignment (analyst core DB).

Summarizes how ``dynamic_sessions`` relate to ``static_analysis_runs`` (hash-level),
``android_apk_repository``, and harvest path tables. Produces a compact worklist of
``(package_name, base_apk_sha256)`` pairs that need a **completed canonical** static run
for the **exact** dynamic base APK hash — not package-level guessing.

**Do not** backfill ``dynamic_sessions.static_run_id`` by package name when hashes differ.

Run from repo root::

  PYTHONPATH=. python scripts/db/report_dynamic_static_alignment.py
  PYTHONPATH=. python scripts/db/report_dynamic_static_alignment.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _table_exists(core_q, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (name,),
        fetch="one",
        dictionary=True,
        query_name="report_dynamic_static_alignment.table_exists",
    )
    return bool(row and int(row.get("c") or 0))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit one JSON object (buckets, worklist, notes) on stdout.",
    )
    parser.add_argument(
        "--worklist-limit",
        type=int,
        default=25,
        help="Max worklist rows (default 25, cap 5000).",
    )
    parser.add_argument(
        "--skip-collation-note",
        action="store_true",
        help="Omit information_schema collation sample section.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts.dynamic_static_alignment_report import (
            run_all_bucket_counts,
            run_scalar,
            sql_link_preview_count,
            sql_schema_collation_sample,
            sql_worklist,
            sql_worklist_distinct_hash_count,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    if not _table_exists(core_q, "dynamic_sessions"):
        sys.stderr.write("dynamic_sessions missing; nothing to report.\n")
        return 2

    notes: list[str] = [
        "Do not UPDATE dynamic_sessions.static_run_id by package_name when base_apk_sha256 "
        "does not match a completed canonical static run for that exact hash.",
        "Optional repair preview (manual only): after exact static runs exist, rows where "
        "dynamic_sessions.base_apk_sha256 = static_analysis_runs.base_apk_sha256 AND status "
        "is COMPLETED AND run_class CANONICAL AND identity_valid = 1 may be linkable by hash.",
    ]

    total = run_scalar(
        core_q,
        "SELECT COUNT(*) AS c FROM dynamic_sessions",
        query_name="report_dynamic_static_alignment.total_ds",
    )

    buckets = run_all_bucket_counts(core_q)
    bucket_sum = sum(buckets.values())
    if bucket_sum != total:
        notes.append(
            f"warning: bucket_sum ({bucket_sum}) != dynamic_sessions_total ({total}); "
            "review classification logic or unexpected NULL/duplicate edge cases."
        )
    worklist_n = run_scalar(
        core_q,
        sql_worklist_distinct_hash_count(),
        query_name="report_dynamic_static_alignment.worklist_distinct",
    )
    link_preview = run_scalar(
        core_q, sql_link_preview_count(), query_name="report_dynamic_static_alignment.link_preview"
    )

    rows = core_q.run_sql(
        sql_worklist(args.worklist_limit),
        (),
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_alignment.worklist",
    ) or []

    coll_rows: list[dict[str, object]] = []
    if not args.skip_collation_note:
        try:
            coll_rows = list(
                core_q.run_sql(
                    sql_schema_collation_sample(),
                    (),
                    fetch="all",
                    dictionary=True,
                    query_name="report_dynamic_static_alignment.collations",
                )
                or []
            )
        except Exception as exc:  # noqa: BLE001 — diagnostic script
            notes.append(f"collation sample skipped: {exc}")

    payload = {
        "dynamic_sessions_total": total,
        "buckets": buckets,
        "worklist_hashes_needing_static_analysis": worklist_n,
        "link_preview_count_unlinked_but_exact_static_exists": link_preview,
        "worklist_top": rows,
        "schema_collation_sample": coll_rows,
        "notes": notes,
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    print("=== Dynamic / static alignment ===")
    print(f"  dynamic_sessions_total: {total}")
    for k in sorted(buckets.keys()):
        print(f"  {k}: {buckets[k]}")
    print(f"  worklist_hashes_needing_static_analysis: {worklist_n}")
    print(f"  unlinked_sessions_with_exact_static_candidate: {link_preview}")
    print("\n=== Top worklist (exact APK hash needs static analysis) ===")
    if not rows:
        print("  (empty)")
    else:
        for r in rows:
            pkg = r.get("package_name") or ""
            h = (r.get("base_apk_sha256") or "")[:16]
            apk_id = r.get("apk_id")
            dr = r.get("dynamic_runs")
            lp = (r.get("local_rel_path") or "")[:64]
            sp = (r.get("source_path") or "")[:64]
            print(
                f"  {pkg} | hash {h}… | apk_id {apk_id} | dynamic_runs {dr} | "
                f"local_rel={lp!r} | source={sp!r}"
            )

    print("\n=== Operator notes ===")
    for ln in notes:
        print(f"  - {ln}")

    if coll_rows:
        print("\n=== Schema hygiene: hash / package column collations (sample) ===")
        for cr in coll_rows:
            print(
                f"  {cr.get('table_name')}.{cr.get('column_name')}: {cr.get('collation_name')}"
            )
        print(
            "  hint: joins across mixed collations should use explicit CONVERT(... COLLATE "
            "utf8mb4_unicode_ci); long-term consider CHAR(64) ascii_bin for hash columns."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
