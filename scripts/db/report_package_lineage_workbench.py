#!/usr/bin/env python3
"""Read-only package lineage workbench.

Shows one package as package -> version/hash/install-set -> byte/static/dynamic
coverage -> recommended action.  Harvest folders are treated as provenance, not
identity.

No DDL, DML, filesystem writes, static runs, or dynamic links are made.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument("--package", dest="package_name", help="Package name to inspect.")
    parser.add_argument(
        "--only-actionable",
        action="store_true",
        help="Hide rows that are fully covered and have no lifecycle/review/link signal.",
    )
    parser.add_argument(
        "--hash-limit",
        type=int,
        default=0,
        help="Maximum version/hash rows to print in text mode (default 0 = all).",
    )
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="Show recorded and canonical paths for every row, not only missing roots.",
    )
    parser.add_argument(
        "--top-actions",
        type=int,
        default=12,
        help="When --package is omitted, show this many high-priority package choices.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    if not args.package_name:
        payload = _package_choices(core_q, limit=max(args.top_actions, 1))
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        else:
            _print_package_choices(payload)
        return 0

    payload = build_workbench_payload(
        core_q,
        package_name=args.package_name,
        only_actionable=args.only_actionable,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    _print_workbench(payload, hash_limit=max(args.hash_limit, 0), show_paths=args.show_paths)
    return 0


def build_workbench_payload(
    core_q: Any,
    *,
    package_name: str,
    only_actionable: bool = False,
) -> dict[str, Any]:
    from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
    from scytaledroid.DeviceAnalysis.services import artifact_store

    pkg_lc = str(package_name or "").strip().lower()
    rows = lineage.fetch_base_rows(core_q, package_name=pkg_lc)
    static_by_hash = lineage.fetch_static_coverage(core_q)
    dynamic_by_hash = lineage.fetch_dynamic_coverage(core_q)
    apk_sets_by_hash = lineage.fetch_apk_sets_by_hash(core_q)
    drift_keys = lineage.fetch_same_version_hash_drift_keys(core_q)

    hash_rows: list[dict[str, Any]] = []
    for row in rows:
        sha = str(row.get("base_apk_sha256") or "").strip().lower()
        pkg = str(row.get("package_name") or "").strip().lower()
        if not sha or not pkg:
            continue
        recorded_path = lineage.recorded_abs_path(row)
        canonical_path = artifact_store.canonical_apk_path(sha)
        recorded_exists = bool(recorded_path and recorded_path.exists())
        canonical_exists = canonical_path.exists()
        byte_status = lineage.byte_status(
            recorded_exists=recorded_exists,
            canonical_exists=canonical_exists,
            recorded_root_exists=lineage.path_exists(row.get("data_root")),
            recorded_location_known=bool(row.get("local_rel_path")),
        )
        static_cov = static_by_hash.get(sha, {})
        dynamic_cov = dynamic_by_hash.get(sha, {})
        set_info = apk_sets_by_hash.get(sha, {})
        exact_static = int(static_cov.get("canonical_completed_identity_valid") or 0)
        dynamic_sessions = int(dynamic_cov.get("dynamic_sessions") or 0)
        dynamic_linked = int(dynamic_cov.get("dynamic_linked_sessions") or 0)
        dynamic_unlinked = int(dynamic_cov.get("dynamic_unlinked_sessions") or 0)
        split_status = lineage.split_status(set_info=set_info, byte_status=byte_status)
        drift = (
            pkg,
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        ) in drift_keys
        reason = lineage.target_reason(
            exact_static=exact_static,
            byte_status=byte_status,
            dynamic_sessions=dynamic_sessions,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=drift,
        )
        target_status = lineage.target_status(
            exact_static=exact_static,
            byte_status=byte_status,
            split_status=split_status,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=drift,
        )
        action = _workbench_action(target_status)
        hash_rows.append(
            {
                "version_code": row.get("version_code"),
                "version_name": row.get("version_name"),
                "base_apk_sha256": sha,
                "apk_id": row.get("apk_id"),
                "apk_set_id": set_info.get("apk_set_id"),
                "artifact_set_hash": set_info.get("artifact_set_hash"),
                "split_members": int(set_info.get("member_count") or 0),
                "split_count": int(set_info.get("split_count") or 0),
                "bytes_available": byte_status.startswith("available"),
                "availability_state": byte_status,
                "static_run_count": int(static_cov.get("static_runs") or 0),
                "static_coverage_state": "covered" if exact_static > 0 else "missing",
                "latest_static_session": static_cov.get("latest_static_session"),
                "dynamic_sessions": dynamic_sessions,
                "paired_dynamic_sessions": dynamic_linked,
                "unpaired_dynamic_sessions": dynamic_unlinked,
                "exact_static_dynamic_gap": dynamic_sessions > 0 and exact_static == 0,
                "review_flags": ["same_version_hash_drift_review"] if drift else [],
                "target_status": target_status,
                "reason": reason,
                "recommended_action": action,
                "recorded_path": recorded_path.as_posix() if recorded_path else None,
                "canonical_store_path": canonical_path.as_posix(),
                "recorded_root": row.get("data_root"),
                "recorded_root_exists": lineage.path_exists(row.get("data_root")),
            }
        )

    all_hash_count = len(hash_rows)
    summary_all = _summary(hash_rows, package_name=pkg_lc)
    if only_actionable:
        hash_rows = [row for row in hash_rows if _is_actionable(row)]

    hash_rows.sort(
        key=lambda item: (
            _action_rank(str(item["recommended_action"])),
            -int(item["dynamic_sessions"]),
            str(item.get("version_code") or ""),
            str(item["base_apk_sha256"]),
        )
    )
    view_summary = _summary(hash_rows, package_name=pkg_lc)
    display_name = str(rows[0].get("display_name") or pkg_lc) if rows else pkg_lc
    summary_all["display_name"] = display_name
    view_summary["display_name"] = display_name
    payload = {
        "package": summary_all,
        "view": view_summary,
        "hashes": hash_rows,
        "filters": {
            "only_actionable": only_actionable,
            "hash_rows_total_before_filter": all_hash_count,
            "hash_rows_returned": len(hash_rows),
        },
        "notes": [
            "Known APK identity, byte availability, static coverage, dynamic coverage, and pairing are separate states.",
            "apk_set_id is preferred when present; base_apk_sha256 remains the fallback for historical rows.",
            "This workbench is read-only and does not run static analysis or repair links.",
            "Rows with static=covered but bytes=no are artifact lifecycle gaps, not static-analysis gaps.",
        ],
    }
    return payload


def _summary(rows: list[dict[str, Any]], *, package_name: str) -> dict[str, Any]:
    versions = {
        (str(row.get("version_code") or ""), str(row.get("version_name") or ""))
        for row in rows
    }
    actions = [str(row.get("recommended_action") or "") for row in rows]
    action_counts = _count_by(rows, "recommended_action")
    status_counts = _count_by(rows, "target_status")
    availability_counts = _count_by(rows, "availability_state")
    return {
        "package_name": package_name,
        "versions_seen": len(versions),
        "base_hashes_seen": len(rows),
        "install_sets_seen": sum(1 for row in rows if row.get("apk_set_id")),
        "bytes_available": sum(1 for row in rows if row.get("bytes_available")),
        "static_covered": sum(1 for row in rows if row.get("static_coverage_state") == "covered"),
        "dynamic_covered": sum(1 for row in rows if int(row.get("dynamic_sessions") or 0) > 0),
        "dynamic_sessions": sum(int(row.get("dynamic_sessions") or 0) for row in rows),
        "dynamic_exact_static_links": sum(int(row.get("paired_dynamic_sessions") or 0) for row in rows),
        "exact_static_dynamic_gaps": sum(1 for row in rows if row.get("exact_static_dynamic_gap")),
        "static_missing": sum(1 for row in rows if row.get("static_coverage_state") == "missing"),
        "static_covered_missing_bytes": sum(
            1
            for row in rows
            if row.get("static_coverage_state") == "covered"
            and not bool(row.get("bytes_available"))
        ),
        "action_counts": action_counts,
        "status_counts": status_counts,
        "availability_counts": availability_counts,
        "recommended_next_action": _priority_action(actions),
    }


def _package_choices(core_q: Any, *, limit: int) -> dict[str, Any]:
    from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage

    rows = lineage.fetch_base_rows(core_q, package_name=None)
    static_by_hash = lineage.fetch_static_coverage(core_q)
    dynamic_by_hash = lineage.fetch_dynamic_coverage(core_q)
    apk_sets_by_hash = lineage.fetch_apk_sets_by_hash(core_q)
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        pkg = str(row.get("package_name") or "").strip().lower()
        sha = str(row.get("base_apk_sha256") or "").strip().lower()
        if not pkg or not sha:
            continue
        static_count = int(static_by_hash.get(sha, {}).get("canonical_completed_identity_valid") or 0)
        dynamic_count = int(dynamic_by_hash.get(sha, {}).get("dynamic_sessions") or 0)
        bucket = buckets.setdefault(
            pkg,
            {
                "package_name": pkg,
                "display_name": row.get("display_name") or pkg,
                "base_hashes_seen": 0,
                "install_sets_seen": 0,
                "static_covered": 0,
                "dynamic_sessions": 0,
                "exact_static_dynamic_gaps": 0,
            },
        )
        bucket["base_hashes_seen"] += 1
        bucket["install_sets_seen"] += int(sha in apk_sets_by_hash)
        bucket["static_covered"] += int(static_count > 0)
        bucket["dynamic_sessions"] += dynamic_count
        bucket["exact_static_dynamic_gaps"] += int(dynamic_count > 0 and static_count == 0)
    packages = sorted(
        buckets.values(),
        key=lambda item: (
            -int(item["exact_static_dynamic_gaps"]),
            -int(item["dynamic_sessions"]),
            str(item["package_name"]),
        ),
    )[:limit]
    return {
        "packages": packages,
        "notes": ["Run again with --package <package_name> to open a package workbench."],
    }


def _workbench_action(target_status: str) -> str:
    return {
        "covered": "already_covered",
        "ready": "analyze_exact_static",
        "blocked_missing_bytes": "restore_artifacts",
        "needs_reharvest": "reharvest_required",
        "artifact_lifecycle_gap": "restore_artifacts",
        "link_repair_preview_available": "dynamic_link_preview_available",
        "review": "dynamic_identity_mismatch_review",
        "blocked_split_context": "restore_artifacts",
        "rebuild_canonical_store": "restore_artifacts",
    }.get(target_status, "review_required")


def _is_actionable(row: dict[str, Any]) -> bool:
    if row.get("recommended_action") != "already_covered":
        return True
    if row.get("review_flags"):
        return True
    if row.get("exact_static_dynamic_gap"):
        return True
    if not bool(row.get("bytes_available")):
        return True
    if int(row.get("unpaired_dynamic_sessions") or 0) > 0:
        return True
    return False


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _priority_action(actions: list[str]) -> str:
    priority = [
        "analyze_exact_static",
        "dynamic_link_preview_available",
        "restore_artifacts",
        "reharvest_required",
        "dynamic_identity_mismatch_review",
        "review_required",
        "already_covered",
    ]
    for action in priority:
        if action in actions:
            return action
    return "already_covered" if not actions else actions[0]


def _action_rank(action: str) -> int:
    order = {
        "analyze_exact_static": 10,
        "dynamic_link_preview_available": 20,
        "restore_artifacts": 30,
        "reharvest_required": 40,
        "dynamic_identity_mismatch_review": 50,
        "review_required": 60,
        "already_covered": 90,
    }
    return order.get(action, 80)


def _print_package_choices(payload: dict[str, Any]) -> None:
    print("=== Package Lineage Workbench ===")
    print("Choose a package with --package <package_name>.")
    print()
    print("=== High-priority packages ===")
    for row in payload["packages"]:
        print(
            f"  {row['package_name']} ({row['display_name']}) | "
            f"hashes={row['base_hashes_seen']} sets={row['install_sets_seen']} "
            f"static={row['static_covered']}/{row['base_hashes_seen']} "
            f"dynamic_sessions={row['dynamic_sessions']} "
            f"exact_gaps={row['exact_static_dynamic_gaps']}"
        )
    print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")


def _print_workbench(
    payload: dict[str, Any],
    *,
    hash_limit: int = 0,
    show_paths: bool = False,
) -> None:
    pkg = payload["package"]
    print("=== Package Lineage Workbench ===")
    print(f"Package : {pkg['package_name']} ({pkg['display_name']})")
    print(f"Action  : {pkg['recommended_next_action']}")
    print()
    print("=== Coverage Summary ===")
    print(f"  versions_seen              : {pkg['versions_seen']}")
    print(f"  base_hashes_seen           : {pkg['base_hashes_seen']}")
    print(f"  install_sets_seen          : {pkg['install_sets_seen']}")
    print(f"  bytes_available            : {pkg['bytes_available']}/{pkg['base_hashes_seen']}")
    print(f"  static_covered             : {pkg['static_covered']}/{pkg['base_hashes_seen']}")
    print(f"  static_missing             : {pkg['static_missing']}")
    print(f"  static_covered_missing_bytes: {pkg['static_covered_missing_bytes']}")
    print(f"  dynamic_hashes             : {pkg['dynamic_covered']}")
    print(f"  dynamic_sessions           : {pkg['dynamic_sessions']}")
    print(f"  dynamic_exact_static_links : {pkg['dynamic_exact_static_links']}")
    print(f"  exact_static_dynamic_gaps  : {pkg['exact_static_dynamic_gaps']}")
    filters = payload.get("filters") or {}
    if filters.get("only_actionable"):
        print(
            f"  row_filter                 : actionable "
            f"({filters.get('hash_rows_returned')}/{filters.get('hash_rows_total_before_filter')})"
        )
    print()
    view = payload.get("view") or pkg
    action_title = "Visible Action Summary" if filters.get("only_actionable") else "Action Summary"
    availability_title = (
        "Visible Availability Summary" if filters.get("only_actionable") else "Availability Summary"
    )
    _print_counts(action_title, view.get("action_counts") or {})
    _print_counts(availability_title, view.get("availability_counts") or {})
    print()
    print("=== Version / Hash / Install Set Rows ===")
    rows = payload["hashes"][:hash_limit] if hash_limit else payload["hashes"]
    if not rows:
        print("  (no package rows)")
    for row in rows:
        print(
            f"  [{row['recommended_action']}] "
            f"status={row['target_status']} reason={row['reason']} | "
            f"vCode={row.get('version_code') or 'unknown'} "
            f"vName={row.get('version_name') or 'unknown'} "
            f"sha={str(row['base_apk_sha256'])[:16]}... "
            f"apk_set={row.get('apk_set_id') or 'none'} "
            f"members={row.get('split_members') or 0} "
            f"bytes={'yes' if row['bytes_available'] else 'no'}:{row['availability_state']} "
            f"static={row['static_coverage_state']}({row['static_run_count']}) "
            f"dynamic={row['dynamic_sessions']} "
            f"paired={row['paired_dynamic_sessions']} "
            f"unpaired={row['unpaired_dynamic_sessions']}"
        )
        if row.get("review_flags"):
            print(f"    review_flags: {', '.join(row['review_flags'])}")
        if row.get("recorded_root") and not row.get("recorded_root_exists"):
            print(f"    missing root: {row['recorded_root']}")
        if show_paths:
            if row.get("recorded_path"):
                print(f"    recorded path: {row['recorded_path']}")
            if row.get("canonical_store_path"):
                print(f"    canonical path: {row['canonical_store_path']}")
    if hash_limit and len(payload["hashes"]) > hash_limit:
        print(
            f"  hint: showing {hash_limit}/{len(payload['hashes'])} row(s). "
            "Use --hash-limit 0 or --json for all."
        )
    print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")


def _print_counts(title: str, counts: dict[str, int]) -> None:
    print(f"=== {title} ===")
    if not counts:
        print("  (none)")
        return
    for key, value in counts.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
