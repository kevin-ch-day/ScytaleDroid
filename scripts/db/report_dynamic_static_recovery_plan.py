#!/usr/bin/env python3
"""Read-only recovery/reharvest planner for exact dynamic/static gaps.

The dynamic/static worklist answers "which exact dynamic APK hashes lack
canonical static coverage?"  This report adds byte availability and recovery
classification.  Missing APK bytes are reported as an availability state, not
as database corruption.

No DDL, DML, filesystem writes, static runs, or dynamic links are made.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument(
        "--limit",
        type=int,
        default=5000,
        help="Maximum exact dynamic/static gap rows to evaluate (default 5000).",
    )
    parser.add_argument(
        "--package",
        dest="package_name",
        help="Limit to one package name.",
    )
    parser.add_argument(
        "--write-receipt",
        action="store_true",
        help=(
            "Write a non-destructive JSON recovery plan receipt under "
            "data/receipts/artifact_recovery_plans. Default is no filesystem writes."
        ),
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help=(
            "Write a read-only audit bundle under output/audit/dynamic_static_recovery_plan. "
            "No DB rows or APK files are changed."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Report output directory when --write-report is used.",
    )
    parser.add_argument(
        "--receipt-dir",
        default="data/receipts/artifact_recovery_plans",
        help="Receipt output directory when --write-receipt is used.",
    )
    parser.add_argument(
        "--old-root-policy",
        choices=("restore", "unrecoverable"),
        default="unrecoverable",
        help=(
            "How to classify gaps whose recorded storage root is missing. "
            "'restore' keeps restore_old_root; 'unrecoverable' marks them "
            "historical_identity_only. Default: unrecoverable."
        ),
    )
    parser.add_argument(
        "--note",
        action="append",
        default=[],
        help="Optional operator note to include in JSON output and receipts; repeatable.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts.dynamic_static_alignment_report import sql_worklist
        from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
        from scytaledroid.StaticAnalysis.cli.flows.exact_target import (
            assess_exact_target_readiness,
        )
        from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    rows = list(
        core_q.run_sql(
            sql_worklist(max(1, min(int(args.limit), 5000))),
            (),
            fetch="all",
            dictionary=True,
            query_name="report_dynamic_static_recovery_plan.worklist",
        )
        or []
    )
    if args.package_name:
        pkg_lc = str(args.package_name).strip().lower()
        rows = [row for row in rows if str(row.get("package_name") or "").lower() == pkg_lc]

    display_names = _fetch_display_names(core_q)
    versions = _fetch_repo_versions(core_q)
    static_coverage = lineage.fetch_static_coverage(core_q)
    apk_sets = lineage.fetch_apk_sets_by_hash(core_q)
    groups = tuple(group_artifacts())

    gap_rows: list[dict[str, Any]] = []
    for row in rows:
        sha = lineage.norm_sha(row.get("base_apk_sha256"))
        pkg = str(row.get("package_name") or "").strip().lower()
        readiness = assess_exact_target_readiness(
            apk_id=row.get("apk_id"),
            base_apk_sha256=sha,
            package_name=pkg,
            dynamic_runs=_safe_int(row.get("dynamic_runs")),
            groups=groups,
        ).as_dict()
        version = versions.get((pkg, sha), {})
        static_count = int(
            (static_coverage.get(sha) or {}).get("canonical_completed_identity_valid") or 0
        )
        action = _recovery_action(
            readiness,
            static_exact_coverage=static_count,
            old_root_policy=args.old_root_policy,
        )
        set_info = apk_sets.get(sha, {})
        gap_rows.append(
            {
                "package_name": pkg,
                "display_name": display_names.get(pkg) or pkg,
                "version_code": version.get("version_code"),
                "version_name": version.get("version_name"),
                "base_apk_sha256": sha,
                "apk_id": row.get("apk_id"),
                "apk_set_id": set_info.get("apk_set_id"),
                "artifact_set_hash": set_info.get("artifact_set_hash"),
                "dynamic_sessions": _safe_int(row.get("dynamic_runs")) or 0,
                "first_dynamic_started": _stringify(row.get("first_dynamic_started")),
                "last_dynamic_started": _stringify(row.get("last_dynamic_started")),
                "recorded_root": readiness.get("recorded_storage_root"),
                "recorded_root_exists": bool(readiness.get("recorded_storage_root_exists")),
                "recorded_path": readiness.get("recorded_abs_path"),
                "canonical_store_path": readiness.get("canonical_store_path"),
                "recorded_path_exists": bool(readiness.get("recorded_local_file_available")),
                "canonical_store_exists": bool(readiness.get("canonical_store_file_available")),
                "receipt_backed": bool(readiness.get("receipt_backed_group_available")),
                "split_members_expected": int(readiness.get("split_files_expected") or 0),
                "split_members_available": int(readiness.get("split_files_available") or 0),
                "static_exact_coverage": static_count,
                "readiness_action": readiness.get("recommended_action"),
                "recommended_action": action,
                "operator_next_step": _operator_next_step(action),
                "reason": readiness.get("reason"),
            }
        )

    packages = _package_summary(gap_rows)
    root_groups = _root_summary(gap_rows)
    payload = {
        "receipt_type": "artifact_recovery_plan",
        "schema_version": "1",
        "created_at": _utc_now_iso(),
        "decision": "plan_only_no_apply",
        "filters": {
            "package_name": args.package_name,
            "limit": max(1, min(int(args.limit), 5000)),
            "old_root_policy": args.old_root_policy,
        },
        "operator_notes": [str(note) for note in args.note],
        "operator_state": _operator_state(args.old_root_policy, gap_rows),
        "summary": _summary(gap_rows, packages),
        "packages": packages,
        "storage_roots": root_groups,
        "gaps": gap_rows,
        "operator_conclusion": _operator_conclusion(gap_rows),
        "notes": [
            "Missing bytes mean identity known but analysis not currently runnable.",
            "This report is read-only; it does not create static runs or update dynamic links.",
            "Use exact static analysis only for analyze_exact_static_available rows.",
            "Legacy missing roots are historical identity only unless an external archive is explicitly provided.",
        ],
    }
    if args.write_receipt:
        receipt_path = _write_receipt(payload, receipt_dir=Path(args.receipt_dir))
        payload["receipt_path"] = str(receipt_path)
    if args.write_report or args.output_dir:
        output_dir = (
            Path(args.output_dir)
            if args.output_dir
            else Path("output/audit/dynamic_static_recovery_plan") / _receipt_stamp(payload["created_at"])
        )
        payload["output_files"] = _write_report_bundle(payload, output_dir=output_dir)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    _print_text(payload)
    return 0


def _fetch_display_names(core_q: Any) -> dict[str, str]:
    rows = core_q.run_sql(
        "SELECT LOWER(TRIM(package_name)) AS package_name, NULLIF(display_name, '') AS display_name FROM apps",
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_recovery_plan.display_names",
    ) or []
    return {
        str(row.get("package_name") or "").lower(): str(row.get("display_name") or "").strip()
        for row in rows
        if row.get("display_name")
    }


def _fetch_repo_versions(core_q: Any) -> dict[tuple[str, str], dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(package_name)) AS package_name,
          LOWER(TRIM(sha256)) AS base_apk_sha256,
          MAX(CAST(version_code AS CHAR)) AS version_code,
          MAX(version_name) AS version_name
        FROM android_apk_repository
        WHERE sha256 IS NOT NULL
          AND COALESCE(is_split_member, 0) = 0
        GROUP BY LOWER(TRIM(package_name)), LOWER(TRIM(sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_recovery_plan.repo_versions",
    ) or []
    return {
        (str(row.get("package_name") or "").lower(), str(row.get("base_apk_sha256") or "").lower()): dict(row)
        for row in rows
    }


def _recovery_action(
    readiness: dict[str, Any],
    *,
    static_exact_coverage: int,
    old_root_policy: str = "restore",
) -> str:
    if static_exact_coverage > 0:
        return "no_action_already_covered"
    action = str(readiness.get("recommended_action") or "")
    if action == "hash_mismatch":
        return "hash_mismatch_investigate"
    if action in {"exact_static_available", "base_only_available_explicit"}:
        return "analyze_exact_static_available"
    if bool(readiness.get("recorded_local_file_available")) and not bool(readiness.get("canonical_store_file_available")):
        return "rehydrate_canonical_store"
    if bool(readiness.get("canonical_store_file_available")):
        return "restore_from_current_store"
    if not bool(readiness.get("recorded_storage_root_exists")) and readiness.get("recorded_storage_root"):
        if old_root_policy == "unrecoverable":
            return "historical_identity_only"
        return "restore_old_root"
    if action == "partial_split_restore_needed":
        return "restore_from_archive"
    return "explicit_reharvest"


def _operator_next_step(action: str) -> str:
    return {
        "analyze_exact_static_available": "Run exact static preflight and static analysis.",
        "restore_old_root": "Mount or copy the recorded old storage root, then rerun readiness.",
        "restore_from_current_store": "Copy canonical SHA-store bytes back into the expected artifact path if needed.",
        "rehydrate_canonical_store": "Verify recorded bytes and copy them into the canonical SHA store.",
        "restore_from_archive": "Restore missing split/base members from archive, then rerun readiness.",
        "explicit_reharvest": "Reharvest this exact package/build if still available on device or external source.",
        "historical_identity_only": "Keep as historical dynamic-only evidence; exclude from strict paired analysis unless an external archive supplies exact bytes.",
        "unrecoverable_without_archive": "Treat as historical identity only unless an external archive can supply exact bytes.",
        "no_action_already_covered": "No static recovery action; refresh reports or preview link repair if needed.",
        "hash_mismatch_investigate": "Investigate local bytes before any analysis or linking.",
    }.get(action, "Review recovery state manually.")


def _package_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    for row in rows:
        pkg = row["package_name"]
        bucket = packages.setdefault(
            pkg,
            {
                "package_name": pkg,
                "display_name": row["display_name"],
                "versions_affected": set(),
                "hashes_affected": 0,
                "dynamic_sessions_affected": 0,
                "available_now": 0,
                "restore_needed": 0,
                "reharvest_needed": 0,
                "historical_identity_only": 0,
                "recommended_actions": set(),
            },
        )
        bucket["versions_affected"].add(str(row.get("version_code") or ""))
        bucket["hashes_affected"] += 1
        bucket["dynamic_sessions_affected"] += int(row.get("dynamic_sessions") or 0)
        action = str(row.get("recommended_action") or "")
        bucket["recommended_actions"].add(action)
        if action == "analyze_exact_static_available":
            bucket["available_now"] += 1
        if action in {"restore_old_root", "restore_from_archive", "restore_from_current_store", "rehydrate_canonical_store"}:
            bucket["restore_needed"] += 1
        if action in {"explicit_reharvest", "current_build_reharvest_needed"}:
            bucket["reharvest_needed"] += 1
        if action in {"historical_identity_only", "unrecoverable_without_archive"}:
            bucket["historical_identity_only"] += 1
    finalized = []
    for bucket in packages.values():
        actions = sorted(bucket.pop("recommended_actions"))
        versions = bucket.pop("versions_affected")
        bucket["versions_affected"] = len({v for v in versions if v})
        bucket["recommended_actions"] = actions
        bucket["recommended_action"] = _priority_action(actions)
        finalized.append(bucket)
    finalized.sort(
        key=lambda item: (
            -int(item["dynamic_sessions_affected"]),
            -int(item["hashes_affected"]),
            str(item["package_name"]),
        )
    )
    return finalized


def _priority_action(actions: list[str]) -> str:
    priority = [
        "hash_mismatch_investigate",
        "analyze_exact_static_available",
        "restore_from_current_store",
        "rehydrate_canonical_store",
        "restore_old_root",
        "restore_from_archive",
        "explicit_reharvest",
        "current_build_reharvest_needed",
        "historical_identity_only",
        "unrecoverable_without_archive",
        "no_action_already_covered",
    ]
    for action in priority:
        if action in actions:
            return action
    return actions[0] if actions else "none"


def _summary(rows: list[dict[str, Any]], packages: list[dict[str, Any]]) -> dict[str, int]:
    actions: dict[str, int] = {}
    dynamic_by_action: dict[str, int] = {}
    for row in rows:
        action = str(row.get("recommended_action") or "unknown")
        actions[action] = actions.get(action, 0) + 1
        dynamic_by_action[action] = dynamic_by_action.get(action, 0) + int(
            row.get("dynamic_sessions") or 0
        )
    return {
        "packages": len(packages),
        "exact_gap_hashes": len(rows),
        "dynamic_sessions_affected": sum(int(row.get("dynamic_sessions") or 0) for row in rows),
        "ready_for_exact_static_analysis": actions.get("analyze_exact_static_available", 0),
        "actions": actions,
        "dynamic_sessions_by_action": dynamic_by_action,
    }


def _operator_conclusion(rows: list[dict[str, Any]]) -> list[str]:
    actions: dict[str, int] = {}
    dynamic_by_action: dict[str, int] = {}
    for row in rows:
        action = str(row.get("recommended_action") or "unknown")
        actions[action] = actions.get(action, 0) + 1
        dynamic_by_action[action] = dynamic_by_action.get(action, 0) + int(
            row.get("dynamic_sessions") or 0
        )

    lines: list[str] = []
    ready = actions.get("analyze_exact_static_available", 0)
    total = len(rows)
    if total and ready == 0:
        lines.append(
            f"No exact static analysis can be run for the {total} dynamic/static gap(s) from current local bytes."
        )
    elif ready:
        lines.append(f"{ready}/{total} dynamic/static gap hash(es) are ready for exact static analysis.")
    else:
        lines.append("No dynamic/static exact gaps are currently present.")

    historical = actions.get("historical_identity_only", 0) + actions.get(
        "unrecoverable_without_archive", 0
    )
    if historical:
        lines.append(
            f"{historical} are historical identity only unless an external archive is explicitly provided."
        )

    restore = actions.get("restore_old_root", 0)
    if restore:
        lines.append(f"{restore} require old APK root/artifact restore before analysis.")

    reharvest = actions.get("explicit_reharvest", 0)
    if reharvest:
        dyn = dynamic_by_action.get("explicit_reharvest", 0)
        lines.append(f"{reharvest} require explicit reharvest ({dyn} dynamic session(s) affected).")

    if total and ready < total:
        lines.append("Dynamic link repair remains blocked for rows without exact completed static coverage.")
    return lines


def _root_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    roots: dict[str, dict[str, Any]] = {}
    for row in rows:
        root = str(row.get("recorded_root") or "<unknown>")
        bucket = roots.setdefault(
            root,
            {
                "recorded_root": None if root == "<unknown>" else root,
                "root_exists": bool(row.get("recorded_root_exists")),
                "hashes": 0,
                "dynamic_sessions": 0,
                "actions": {},
            },
        )
        bucket["root_exists"] = bool(bucket["root_exists"] or row.get("recorded_root_exists"))
        bucket["hashes"] += 1
        bucket["dynamic_sessions"] += int(row.get("dynamic_sessions") or 0)
        action = str(row.get("recommended_action") or "unknown")
        bucket["actions"][action] = int(bucket["actions"].get(action, 0)) + 1
    result = list(roots.values())
    result.sort(
        key=lambda item: (
            bool(item["root_exists"]),
            -int(item["dynamic_sessions"]),
            str(item.get("recorded_root") or ""),
        )
    )
    return result


def _operator_state(old_root_policy: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    historical_hashes = sum(
        1
        for row in rows
        if str(row.get("recommended_action") or "")
        in {"historical_identity_only", "unrecoverable_without_archive"}
    )
    historical_dynamic = sum(
        int(row.get("dynamic_sessions") or 0)
        for row in rows
        if str(row.get("recommended_action") or "")
        in {"historical_identity_only", "unrecoverable_without_archive"}
    )
    return {
        "legacy_apk_root_retired": old_root_policy == "unrecoverable" and historical_hashes > 0,
        "historical_identity_only_hashes": historical_hashes,
        "historical_identity_only_dynamic_sessions": historical_dynamic,
        "strict_paired_analysis_excludes_historical_identity_only": historical_hashes > 0,
        "future_collection_root": "current configured device_apks root",
        "future_collection_store": "canonical SHA store",
    }


def _print_text(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    print("=== Dynamic/static recovery plan ===")
    print(f"  packages: {summary['packages']}")
    print(f"  exact_gap_hashes: {summary['exact_gap_hashes']}")
    print(f"  dynamic_sessions_affected: {summary['dynamic_sessions_affected']}")
    print("  actions:")
    for action, count in sorted(summary["actions"].items()):
        dyn = summary["dynamic_sessions_by_action"].get(action, 0)
        print(f"    {action}: hashes={count} dynamic_sessions={dyn}")
    print(f"  ready_for_exact_static_analysis: {summary['ready_for_exact_static_analysis']}")
    print()
    print("=== Operator conclusion ===")
    for line in payload.get("operator_conclusion") or []:
        print(f"  - {line}")
    print()
    state = payload.get("operator_state") or {}
    print("=== Operator state ===")
    print(f"  legacy_apk_root_retired: {_yn(state.get('legacy_apk_root_retired'))}")
    print(f"  historical_identity_only_hashes: {state.get('historical_identity_only_hashes', 0)}")
    print(
        "  historical_identity_only_dynamic_sessions: "
        f"{state.get('historical_identity_only_dynamic_sessions', 0)}"
    )
    print(
        "  strict_paired_analysis_excludes_historical_identity_only: "
        f"{_yn(state.get('strict_paired_analysis_excludes_historical_identity_only'))}"
    )
    print(f"  future_collection_root: {state.get('future_collection_root') or 'unknown'}")
    print(f"  future_collection_store: {state.get('future_collection_store') or 'unknown'}")
    print()
    print("=== Storage roots ===")
    if not payload["storage_roots"]:
        print("  (empty)")
    for root in payload["storage_roots"]:
        action_text = ", ".join(
            f"{action}={count}" for action, count in sorted(root.get("actions", {}).items())
        )
        print(
            f"  exists={_yn(root['root_exists'])} hashes={root['hashes']} "
            f"dynamic_sessions={root['dynamic_sessions']} root={root.get('recorded_root') or '<unknown>'}"
        )
        if action_text:
            print(f"    actions: {action_text}")
    print()
    print("=== Packages ===")
    for pkg in payload["packages"]:
        print(
            f"{pkg['package_name']} ({pkg['display_name']}) | "
            f"versions={pkg['versions_affected']} hashes={pkg['hashes_affected']} "
            f"dynamic_sessions={pkg['dynamic_sessions_affected']} "
            f"available_now={pkg['available_now']} restore={pkg['restore_needed']} "
            f"reharvest={pkg['reharvest_needed']} "
            f"historical={pkg.get('historical_identity_only', 0)} "
            f"action={pkg['recommended_action']}"
        )
    print()
    print("=== Exact gap rows ===")
    if not payload["gaps"]:
        print("  (empty)")
    for row in payload["gaps"]:
        print(
            f"  {row['package_name']} | vCode={row.get('version_code') or 'unknown'} "
            f"sha={str(row['base_apk_sha256'])[:16]}... apk_id={row.get('apk_id') or 'unknown'} "
            f"apk_set={row.get('apk_set_id') or 'none'} dyn={row['dynamic_sessions']} "
            f"recorded={_yn(row['recorded_path_exists'])} "
            f"store={_yn(row['canonical_store_exists'])} "
            f"receipt={_yn(row['receipt_backed'])} "
            f"splits={row['split_members_available']}/{row['split_members_expected']} "
            f"static={row['static_exact_coverage']} action={row['recommended_action']}"
        )
        print(f"    next: {row['operator_next_step']}")
        if row.get("recorded_root") and not row.get("recorded_root_exists"):
            print(f"    missing root: {row['recorded_root']}")
        if row.get("recorded_path"):
            print(f"    recorded path: {row['recorded_path']}")
        if row.get("canonical_store_path"):
            print(f"    canonical path: {row['canonical_store_path']}")
    print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")
    if payload.get("operator_notes"):
        print()
        print("=== Operator notes ===")
        for note in payload["operator_notes"]:
            print(f"  - {note}")
    if payload.get("receipt_path"):
        print()
        print("=== Receipt ===")
        print(f"  path: {payload['receipt_path']}")
    if payload.get("output_files"):
        print()
        print("=== Report bundle ===")
        for label, path in sorted(payload["output_files"].items()):
            print(f"  {label}: {path}")


def _write_receipt(payload: dict[str, Any], *, receipt_dir: Path) -> Path:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    receipt_dir.mkdir(parents=True, exist_ok=True)
    stamp = _receipt_stamp(str(payload.get("created_at") or _utc_now_iso()))
    package_filter = payload.get("filters", {}).get("package_name")
    suffix = _safe_segment(str(package_filter)) if package_filter else "all"
    path = receipt_dir / f"{stamp}_{suffix}.json"
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    return path


def _write_report_bundle(payload: dict[str, Any], *, output_dir: Path) -> dict[str, str]:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "summary_json": output_dir / "summary.json",
        "packages_csv": output_dir / "packages.csv",
        "storage_roots_csv": output_dir / "storage_roots.csv",
        "gaps_csv": output_dir / "gaps.csv",
        "historical_identity_only_csv": output_dir / "historical_identity_only.csv",
        "reharvest_candidates_csv": output_dir / "reharvest_candidates.csv",
    }
    serializable_payload = dict(payload)
    serializable_payload["output_files"] = {key: str(path) for key, path in files.items()}
    atomic_write_text(
        files["summary_json"],
        json.dumps(serializable_payload, indent=2, sort_keys=True, default=str) + "\n",
    )
    _write_csv(files["packages_csv"], payload.get("packages") or [])
    _write_csv(files["storage_roots_csv"], _flatten_storage_roots(payload.get("storage_roots") or []))
    gaps = list(payload.get("gaps") or [])
    _write_csv(files["gaps_csv"], gaps)
    _write_csv(
        files["historical_identity_only_csv"],
        [
            row
            for row in gaps
            if str(row.get("recommended_action") or "")
            in {"historical_identity_only", "unrecoverable_without_archive"}
        ],
    )
    _write_csv(
        files["reharvest_candidates_csv"],
        [
            row
            for row in gaps
            if str(row.get("recommended_action") or "")
            in {"explicit_reharvest", "current_build_reharvest_needed"}
        ],
    )
    return {key: str(path) for key, path in files.items()}


def _flatten_storage_roots(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        actions = item.get("actions")
        if isinstance(actions, dict):
            item["actions_json"] = json.dumps(actions, sort_keys=True)
        item.pop("actions", None)
        flattened.append(item)
    return flattened


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    if not rows:
        atomic_write_text(path, "")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})
    atomic_write_text(path, buffer.getvalue())


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, sort_keys=True, default=str)
    return value


def _receipt_stamp(value: str) -> str:
    return (
        value.replace("-", "")
        .replace(":", "")
        .replace(".", "")
        .replace("+", "")
        .replace("Z", "")
    )


def _safe_segment(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value.strip())
    return cleaned.strip("._") or "package"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _yn(value: Any) -> str:
    return "yes" if bool(value) else "no"


if __name__ == "__main__":
    raise SystemExit(main())
