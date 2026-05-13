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


def _index_columns(core_q, table_name: str) -> dict[str, tuple[str, ...]]:
    rows = core_q.run_sql(
        """
        SELECT index_name, column_name
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
        ORDER BY index_name, seq_in_index
        """,
        (table_name,),
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_alignment.index_columns",
    )
    indexes: dict[str, list[str]] = {}
    for row in rows or []:
        indexes.setdefault(str(row.get("index_name") or ""), []).append(
            str(row.get("column_name") or "")
        )
    return {name: tuple(cols) for name, cols in indexes.items() if name}


def _has_index_prefix(indexes: dict[str, tuple[str, ...]], columns: tuple[str, ...]) -> bool:
    return any(index_columns[: len(columns)] == columns for index_columns in indexes.values())


def _index_posture(core_q) -> dict[str, int]:
    dyn_indexes = _index_columns(core_q, "dynamic_sessions")
    sar_indexes = _index_columns(core_q, "static_analysis_runs")
    static_contract_cols = ("base_apk_sha256", "status", "run_class", "identity_valid")
    return {
        "dynamic_sessions_base_apk_sha256_index_present": int(
            dyn_indexes.get("ix_dynamic_sessions_base_apk_sha256") == ("base_apk_sha256",)
        ),
        "static_runs_base_hash_contract_index_present": int(
            sar_indexes.get("ix_static_runs_base_hash_contract") == static_contract_cols
        ),
        "static_runs_base_apk_sha256_index_covered": int(
            _has_index_prefix(sar_indexes, ("base_apk_sha256",))
        ),
    }


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
        default=15,
        help="Max worklist rows (default 15, cap 5000).",
    )
    parser.add_argument(
        "--skip-collation-note",
        action="store_true",
        help="Omit information_schema collation sample section.",
    )
    parser.add_argument(
        "--exact-target-readiness",
        action="store_true",
        help=(
            "Annotate worklist rows with local-byte readiness for exact-hash static analysis. "
            "Read-only; does not create receipts, static runs, or dynamic links."
        ),
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
    index_posture = _index_posture(core_q)

    rows = core_q.run_sql(
        sql_worklist(args.worklist_limit),
        (),
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_alignment.worklist",
    ) or []

    readiness_rows: list[dict[str, object]] = []
    if args.exact_target_readiness:
        try:
            from scytaledroid.StaticAnalysis.cli.flows.exact_target import (
                assess_exact_target_readiness,
            )
            from scytaledroid.StaticAnalysis.core.repository import group_artifacts

            groups = tuple(group_artifacts())
            for row in rows:
                readiness = assess_exact_target_readiness(
                    apk_id=row.get("apk_id"),
                    base_apk_sha256=row.get("base_apk_sha256"),
                    package_name=row.get("package_name"),
                    dynamic_runs=_safe_int(row.get("dynamic_runs")),
                    groups=groups,
                )
                readiness_rows.append(readiness.as_dict())
        except Exception as exc:  # noqa: BLE001 — diagnostic script
            notes.append(f"exact target readiness skipped: {exc}")

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
        "exact_target_readiness": readiness_rows,
        "index_posture": index_posture,
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
    print("  dynamic_sessions_base_apk_sha256_index_present: "
          f"{index_posture['dynamic_sessions_base_apk_sha256_index_present']}")
    print("  static_runs_base_hash_contract_index_present: "
          f"{index_posture['static_runs_base_hash_contract_index_present']}")
    print("  static_runs_base_apk_sha256_index_covered: "
          f"{index_posture['static_runs_base_apk_sha256_index_covered']}")
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
        print(
            f"  hint: showing top {len(rows)} row(s). "
            "Use --worklist-limit N for more, or --json for structured output."
        )

    if args.exact_target_readiness:
        print("\n=== Exact target readiness (local bytes) ===")
        if not readiness_rows:
            print("  (empty or unavailable)")
        else:
            _print_readiness_summary(readiness_rows)
            for r in readiness_rows:
                print(
                    "  "
                    f"{r.get('package_name')} | apk_id {r.get('apk_id')} | "
                    f"hash {str(r.get('base_apk_sha256') or '')[:16]}… | "
                    f"dyn {r.get('dynamic_runs')} | "
                    f"repo={_yn(r.get('repository_row_exists'))} | "
                    f"receipt={_yn(r.get('receipt_backed_group_available'))} | "
                    f"base={_yn(r.get('base_file_available'))}/"
                    f"verified={_yn(r.get('base_file_hash_verified'))} | "
                    f"splits={r.get('split_files_available')}/{r.get('split_files_expected')} | "
                    f"recorded={_yn(r.get('recorded_local_file_available'))} | "
                    f"store={_yn(r.get('canonical_store_file_available'))} | "
                    f"root={r.get('storage_root_id') or 'unknown'} | "
                    f"action={r.get('recommended_action')}"
                )
                reason = str(r.get("reason") or "").strip()
                if reason:
                    print(f"    reason: {reason}")
                recorded_root = str(r.get("recorded_storage_root") or "").strip()
                recorded_path = str(r.get("recorded_abs_path") or "").strip()
                canonical_path = str(r.get("canonical_store_path") or "").strip()
                if recorded_root and not bool(r.get("recorded_storage_root_exists")):
                    print(f"    missing root: {recorded_root}")
                if recorded_path:
                    print(f"    recorded path: {recorded_path}")
                if canonical_path:
                    print(f"    canonical path: {canonical_path}")

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


def _safe_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _yn(value: object) -> str:
    return "yes" if bool(value) else "no"


def _print_readiness_summary(rows: list[dict[str, object]]) -> None:
    by_action: dict[str, dict[str, int]] = {}
    by_root: dict[str, dict[str, object]] = {}
    exact_available = 0
    for row in rows:
        action = str(row.get("recommended_action") or "unknown")
        dynamic_runs = _safe_int(row.get("dynamic_runs")) or 0
        bucket = by_action.setdefault(action, {"rows": 0, "dynamic_runs": 0})
        bucket["rows"] += 1
        bucket["dynamic_runs"] += dynamic_runs
        if action == "exact_static_available":
            exact_available += 1

        root_id = str(row.get("storage_root_id") or "unknown")
        root = str(row.get("recorded_storage_root") or "unknown")
        key = f"{root_id}|{root}"
        root_bucket = by_root.setdefault(
            key,
            {
                "root_id": root_id,
                "root": root,
                "exists": bool(row.get("recorded_storage_root_exists")),
                "rows": 0,
                "dynamic_runs": 0,
            },
        )
        root_bucket["rows"] = int(root_bucket["rows"]) + 1
        root_bucket["dynamic_runs"] = int(root_bucket["dynamic_runs"]) + dynamic_runs

    print("  summary:")
    print(f"    exact_static_available rows: {exact_available}/{len(rows)}")
    for action in sorted(by_action):
        bucket = by_action[action]
        print(
            f"    action {action}: rows={bucket['rows']} dynamic_runs={bucket['dynamic_runs']}"
        )
    print("  storage roots:")
    for bucket in sorted(by_root.values(), key=lambda item: str(item["root_id"])):
        print(
            f"    root_id={bucket['root_id']} exists={_yn(bucket['exists'])} "
            f"rows={bucket['rows']} dynamic_runs={bucket['dynamic_runs']} "
            f"path={bucket['root']}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
