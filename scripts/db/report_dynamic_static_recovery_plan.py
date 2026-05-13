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
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts.dynamic_static_alignment_report import sql_worklist
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
    static_coverage = _fetch_static_exact_coverage(core_q)
    apk_sets = _fetch_apk_sets_by_hash(core_q)
    groups = tuple(group_artifacts())

    gap_rows: list[dict[str, Any]] = []
    for row in rows:
        sha = _norm_sha(row.get("base_apk_sha256"))
        pkg = str(row.get("package_name") or "").strip().lower()
        readiness = assess_exact_target_readiness(
            apk_id=row.get("apk_id"),
            base_apk_sha256=sha,
            package_name=pkg,
            dynamic_runs=_safe_int(row.get("dynamic_runs")),
            groups=groups,
        ).as_dict()
        version = versions.get((pkg, sha), {})
        static_count = int(static_coverage.get(sha, 0))
        action = _recovery_action(readiness, static_exact_coverage=static_count)
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
                "reason": readiness.get("reason"),
            }
        )

    packages = _package_summary(gap_rows)
    payload = {
        "summary": _summary(gap_rows, packages),
        "packages": packages,
        "gaps": gap_rows,
        "notes": [
            "Missing bytes mean identity known but analysis not currently runnable.",
            "This report is read-only; it does not create static runs or update dynamic links.",
            "Use exact static analysis only for analyze_exact_static_available rows.",
        ],
    }

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


def _fetch_static_exact_coverage(core_q: Any) -> dict[str, int]:
    rows = core_q.run_sql(
        """
        SELECT LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
               SUM(CASE
                     WHEN status='COMPLETED'
                      AND run_class='CANONICAL'
                      AND COALESCE(identity_valid,0)=1
                     THEN 1 ELSE 0
                   END) AS exact_static_runs
        FROM static_analysis_runs
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_recovery_plan.static_coverage",
    ) or []
    return {
        str(row.get("base_apk_sha256") or "").lower(): int(row.get("exact_static_runs") or 0)
        for row in rows
    }


def _fetch_apk_sets_by_hash(core_q: Any) -> dict[str, dict[str, Any]]:
    if not _table_exists(core_q, "apk_sets"):
        return {}
    rows = core_q.run_sql(
        """
        SELECT LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
               MIN(apk_set_id) AS apk_set_id,
               MIN(artifact_set_hash) AS artifact_set_hash
        FROM apk_sets
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_dynamic_static_recovery_plan.apk_sets",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _table_exists(core_q: Any, table_name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (table_name,),
        fetch="one_dict",
        query_name="report_dynamic_static_recovery_plan.table_exists",
    )
    return int((row or {}).get("n") or 0) > 0


def _recovery_action(readiness: dict[str, Any], *, static_exact_coverage: int) -> str:
    if static_exact_coverage > 0:
        return "already_covered_refresh_report"
    action = str(readiness.get("recommended_action") or "")
    if action == "hash_mismatch":
        return "hash_mismatch_investigate"
    if action in {"exact_static_available", "base_only_available_explicit"}:
        return "analyze_exact_static_available"
    if bool(readiness.get("canonical_store_file_available")):
        return "restore_from_current_store"
    if not bool(readiness.get("recorded_storage_root_exists")) and readiness.get("recorded_storage_root"):
        return "restore_old_root"
    if action == "partial_split_restore_needed":
        return "restore_from_archive"
    return "explicit_reharvest_needed"


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
        if action in {"restore_old_root", "restore_from_archive", "restore_from_current_store"}:
            bucket["restore_needed"] += 1
        if action in {"explicit_reharvest_needed", "current_build_reharvest_needed"}:
            bucket["reharvest_needed"] += 1
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
        "restore_old_root",
        "restore_from_archive",
        "explicit_reharvest_needed",
        "current_build_reharvest_needed",
        "already_covered_refresh_report",
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
        "actions": actions,
        "dynamic_sessions_by_action": dynamic_by_action,
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
    print()
    print("=== Packages ===")
    for pkg in payload["packages"]:
        print(
            f"{pkg['package_name']} ({pkg['display_name']}) | "
            f"versions={pkg['versions_affected']} hashes={pkg['hashes_affected']} "
            f"dynamic_sessions={pkg['dynamic_sessions_affected']} "
            f"available_now={pkg['available_now']} restore={pkg['restore_needed']} "
            f"reharvest={pkg['reharvest_needed']} action={pkg['recommended_action']}"
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


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _norm_sha(value: Any) -> str:
    return str(value or "").strip().lower()


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _yn(value: Any) -> str:
    return "yes" if bool(value) else "no"


if __name__ == "__main__":
    raise SystemExit(main())
