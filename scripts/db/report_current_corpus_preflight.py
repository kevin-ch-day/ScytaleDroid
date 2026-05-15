#!/usr/bin/env python3
"""Read-only preflight for building a clean current APK corpus.

Checks whether repository rows, canonical SHA-store bytes, install-set rows,
split metadata, and static target states are present after a fresh inventory /
harvest.  This report does not write DB rows, copy APKs, run static analysis,
or repair dynamic links.
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
    parser.add_argument("--package", dest="package_name", help="Limit to one package name.")
    parser.add_argument(
        "--only-current-bytes",
        action="store_true",
        help="Show only rows with recorded or canonical bytes currently available.",
    )
    parser.add_argument(
        "--status",
        choices=("covered", "ready", "review"),
        help="Limit rows to one current target status.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum row details to print in text output (default 100).",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
        from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    rows = _build_rows(
        lineage,
        core_q,
        package_name=args.package_name,
        groups=tuple(group_artifacts()),
    )
    if args.only_current_bytes:
        rows = [row for row in rows if row["bytes_available"]]
    if args.status:
        rows = [row for row in rows if row["status"] == args.status]

    payload = {
        "report_type": "current_corpus_preflight",
        "schema_version": "1",
        "filters": {
            "package_name": args.package_name,
            "only_current_bytes": bool(args.only_current_bytes),
            "status": args.status,
        },
        "summary": _summary(rows),
        "packages": _package_summary(rows),
        "rows": rows,
        "review_drift_comparisons": _build_review_drift_comparisons(core_q, rows)
        if args.status == "review"
        else [],
        "current_collection_workflow": [
            "fresh device inventory",
            "fresh APK harvest into the current configured root",
            "populate canonical SHA store",
            "create and verify apk_sets plus split members",
            "run exact static analysis on current install sets",
            "run dynamic analysis after exact static identity exists, or label it dynamic-only",
        ],
        "notes": [
            "This report is read-only and does not run harvest, static analysis, or link repair.",
            "Historical missing old-root rows are outside the current-corpus preflight.",
            "base_only_or_split_context_missing should not be used to rescue missing split install sets.",
        ],
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0
    _print_text(payload, limit=max(1, int(args.limit)))
    return 0


def _build_rows(
    lineage: Any,
    core_q: Any,
    *,
    package_name: str | None,
    groups: tuple[Any, ...],
) -> list[dict[str, Any]]:
    base_rows = lineage.fetch_base_rows(core_q, package_name=package_name)
    static = lineage.fetch_static_coverage(core_q)
    dynamic = lineage.fetch_dynamic_coverage(core_q)
    apk_sets = lineage.fetch_apk_sets_by_hash(core_q)
    same_version_drift = lineage.fetch_same_version_hash_drift_keys(core_q)
    canonical_paths = _canonical_store_paths(groups)

    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in base_rows:
        sha = lineage.norm_sha(row.get("base_apk_sha256"))
        package = str(row.get("package_name") or "").strip().lower()
        if not sha or not package:
            continue
        key = (package, str(row.get("version_code") or ""), sha)
        if key in seen:
            continue
        seen.add(key)

        recorded_path = lineage.recorded_abs_path(row)
        recorded_exists = bool(recorded_path and recorded_path.exists())
        recorded_root_exists = lineage.path_exists(row.get("data_root"))
        canonical_path = canonical_paths.get(sha)
        canonical_exists = bool(canonical_path and canonical_path.exists())
        byte_state = lineage.byte_status(
            recorded_exists=recorded_exists,
            canonical_exists=canonical_exists,
            recorded_root_exists=recorded_root_exists,
            recorded_location_known=bool(recorded_path),
        )
        set_info = apk_sets.get(sha, {})
        split_state = lineage.split_status(set_info=set_info, byte_status=byte_state)
        static_count = int(
            (static.get(sha) or {}).get("canonical_completed_identity_valid") or 0
        )
        dynamic_info = dynamic.get(sha) or {}
        dynamic_sessions = int(dynamic_info.get("dynamic_sessions") or 0)
        dynamic_unlinked = int(dynamic_info.get("dynamic_unlinked_sessions") or 0)
        drift = (
            package,
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        ) in same_version_drift
        status = lineage.target_status(
            exact_static=static_count,
            byte_status=byte_state,
            split_status=split_state,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=drift,
        )
        reason = lineage.target_reason(
            exact_static=static_count,
            byte_status=byte_state,
            dynamic_sessions=dynamic_sessions,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=drift,
        )
        result.append(
            {
                "package_name": package,
                "display_name": row.get("display_name") or package,
                "version_code": row.get("version_code"),
                "version_name": row.get("version_name"),
                "base_apk_sha256": sha,
                "apk_id": row.get("apk_id"),
                "bytes_available": byte_state.startswith("available"),
                "byte_status": byte_state,
                "canonical_store_file_available": canonical_exists,
                "recorded_file_available": recorded_exists,
                "recorded_root_exists": recorded_root_exists,
                "apk_set_id": set_info.get("apk_set_id"),
                "artifact_set_hash": set_info.get("artifact_set_hash"),
                "apk_set_present": bool(set_info),
                "apk_set_member_count": int(set_info.get("member_count") or 0),
                "apk_set_split_count": int(set_info.get("split_count") or 0),
                "members": int(set_info.get("member_count") or 0),
                "splits": int(set_info.get("split_count") or 0),
                "split_status": split_state,
                "static_exact_coverage": static_count,
                "static_run_count": static_count,
                "dynamic_sessions": dynamic_sessions,
                "dynamic_unlinked_sessions": dynamic_unlinked,
                "target_status": status,
                "target_reason": reason,
                "status": status,
                "review_reason": reason if status == "review" else None,
                "operator_action": lineage.operator_action(status),
                "recommended_action": lineage.operator_action(status),
            }
        )

    result.sort(
        key=lambda item: (
            not bool(item["bytes_available"]),
            not bool(item["apk_set_present"]),
            str(item["package_name"]),
            str(item.get("version_code") or ""),
        )
    )
    return result


def _build_review_drift_comparisons(
    core_q: Any,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    comparisons: list[dict[str, Any]] = []
    review_rows = [row for row in rows if row.get("status") == "review"]
    for row in review_rows:
        drift_rows = _fetch_same_version_hash_rows(core_q, row)
        by_hash: dict[str, dict[str, Any]] = {}
        for item in drift_rows:
            sha = str(item.get("base_apk_sha256") or "").lower()
            if not sha:
                continue
            bucket = by_hash.setdefault(
                sha,
                {
                    "base_apk_sha256": sha,
                    "apk_ids": [],
                    "apk_set_ids": [],
                    "artifact_set_hashes": [],
                    "first_seen_at": None,
                    "last_seen_at": None,
                    "harvest_runs": [],
                    "storage_roots": [],
                    "recorded_paths": [],
                    "source_kind": None,
                    "static_run_count": 0,
                },
            )
            _append_unique(bucket["apk_ids"], item.get("apk_id"))
            _append_unique(bucket["apk_set_ids"], item.get("apk_set_id"))
            _append_unique(bucket["artifact_set_hashes"], item.get("artifact_set_hash"))
            _append_unique(bucket["harvest_runs"], item.get("harvest_run"))
            _append_unique(bucket["storage_roots"], item.get("storage_root"))
            _append_unique(bucket["recorded_paths"], item.get("recorded_path"))
            if item.get("source_kind") and not bucket["source_kind"]:
                bucket["source_kind"] = item.get("source_kind")
            bucket["static_run_count"] = max(
                int(bucket.get("static_run_count") or 0),
                int(item.get("static_run_count") or 0),
            )
            bucket["first_seen_at"] = _min_datetime_text(
                bucket.get("first_seen_at"),
                item.get("first_seen_at") or item.get("harvested_at"),
            )
            bucket["last_seen_at"] = _max_datetime_text(
                bucket.get("last_seen_at"),
                item.get("last_seen_at") or item.get("harvested_at"),
            )

        current_sha = str(row.get("base_apk_sha256") or "").lower()
        current_hash = by_hash.get(current_sha, {})
        other_hashes = [
            value for sha, value in sorted(by_hash.items()) if sha != current_sha
        ]
        suggestion, severity = _review_classification(str(row.get("package_name") or ""))
        comparisons.append(
            {
                "package_name": row.get("package_name"),
                "display_name": row.get("display_name"),
                "version_code": row.get("version_code"),
                "version_name": row.get("version_name"),
                "current_base_apk_sha256": current_sha,
                "current_apk_id": row.get("apk_id"),
                "current_apk_set_id": row.get("apk_set_id"),
                "current_artifact_set_hash": row.get("artifact_set_hash"),
                "current_seen_at": current_hash.get("last_seen_at"),
                "current_harvest_run": _latest_text(current_hash.get("harvest_runs")),
                "current_storage_roots": current_hash.get("storage_roots") or [],
                "current_recorded_paths": current_hash.get("recorded_paths") or [],
                "other_hash_count_for_same_package_version": len(other_hashes),
                "other_hashes": other_hashes,
                "classification_suggestion": suggestion,
                "review_severity": severity,
            }
        )
    return comparisons


def _fetch_same_version_hash_rows(core_q: Any, row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(
        core_q.run_sql(
            """
            SELECT
              r.apk_id,
              LOWER(TRIM(r.sha256)) AS base_apk_sha256,
              r.harvested_at,
              sr.data_root AS storage_root,
              h.local_rel_path AS recorded_path,
              s.apk_set_id,
              s.artifact_set_hash,
              s.source_kind,
              s.first_seen_at,
              s.last_seen_at,
              hs.session_label AS harvest_run,
              COALESCE(st.static_run_count, 0) AS static_run_count
            FROM android_apk_repository r
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            LEFT JOIN apk_sets s
              ON CONVERT(LOWER(TRIM(s.base_apk_sha256)) USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(LOWER(TRIM(r.sha256)) USING utf8mb4) COLLATE utf8mb4_unicode_ci
            LEFT JOIN harvest_apk_observations hao
              ON hao.apk_id = r.apk_id
             AND CONVERT(LOWER(TRIM(hao.sha256)) USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(LOWER(TRIM(r.sha256)) USING utf8mb4) COLLATE utf8mb4_unicode_ci
             AND hao.role = 'base'
            LEFT JOIN harvest_sessions hs
              ON hs.harvest_session_id = hao.harvest_session_id
            LEFT JOIN (
              SELECT
                LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
                COUNT(*) AS static_run_count
              FROM static_analysis_runs
              WHERE base_apk_sha256 IS NOT NULL
                AND status = 'COMPLETED'
                AND run_class = 'CANONICAL'
                AND COALESCE(identity_valid, 0) = 1
              GROUP BY LOWER(TRIM(base_apk_sha256))
            ) st ON CONVERT(st.base_apk_sha256 USING utf8mb4) COLLATE utf8mb4_unicode_ci
                = CONVERT(LOWER(TRIM(r.sha256)) USING utf8mb4) COLLATE utf8mb4_unicode_ci
            WHERE LOWER(TRIM(r.package_name)) = %s
              AND COALESCE(CAST(r.version_code AS CHAR), '') = %s
              AND COALESCE(r.version_name, '') = %s
              AND r.sha256 IS NOT NULL
              AND COALESCE(r.is_split_member, 0) = 0
            ORDER BY r.harvested_at, r.apk_id
            """,
            (
                str(row.get("package_name") or "").lower(),
                str(row.get("version_code") or ""),
                str(row.get("version_name") or ""),
            ),
            fetch="all",
            dictionary=True,
            query_name="current_corpus_preflight.same_version_hash_rows",
        )
        or []
    )


def _review_classification(package_name: str) -> tuple[str, str]:
    package = package_name.strip().lower()
    trusted_prefixes = (
        "android.",
        "com.android.",
        "com.google.",
        "com.motorola.",
        "com.marvin.",
    )
    if package.startswith(trusted_prefixes):
        return "normal_google_oem_drift", "informational_review"
    if package:
        return "third_party_same_version_hash_drift", "manual_review"
    return "needs_manual_review", "manual_review"


def _append_unique(values: list[Any], value: Any) -> None:
    if value is None or value == "":
        return
    if value not in values:
        values.append(value)


def _latest_text(values: Any) -> Any:
    if isinstance(values, list) and values:
        return max(str(value) for value in values)
    return None


def _min_datetime_text(left: Any, right: Any) -> str | None:
    left_text = str(left) if left else None
    right_text = str(right) if right else None
    if not left_text:
        return right_text
    if not right_text:
        return left_text
    return min(left_text, right_text)


def _max_datetime_text(left: Any, right: Any) -> str | None:
    left_text = str(left) if left else None
    right_text = str(right) if right else None
    if not left_text:
        return right_text
    if not right_text:
        return left_text
    return max(left_text, right_text)


def _canonical_store_paths(groups: tuple[Any, ...]) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for group in groups:
        for artifact in getattr(group, "artifacts", ()) or ():
            metadata = getattr(artifact, "metadata", {}) or {}
            if bool(metadata.get("is_split_member")):
                continue
            sha = str(metadata.get("sha256") or "").strip().lower()
            path = getattr(artifact, "path", None)
            if sha and path:
                paths[sha] = Path(path)
    return paths


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    byte_states: dict[str, int] = {}
    statuses: dict[str, int] = {}
    reasons: dict[str, int] = {}
    for row in rows:
        byte_state = str(row.get("byte_status") or "unknown")
        status = str(row.get("target_status") or "unknown")
        reason = str(row.get("target_reason") or "unknown")
        byte_states[byte_state] = byte_states.get(byte_state, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1
        reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "repository_base_rows": len(rows),
        "base_hashes": len({row["base_apk_sha256"] for row in rows}),
        "packages": len({row["package_name"] for row in rows}),
        "bytes_available": sum(1 for row in rows if row["bytes_available"]),
        "canonical_store_files_present": sum(
            1 for row in rows if row["canonical_store_file_available"]
        ),
        "apk_sets_present": sum(1 for row in rows if row["apk_set_present"]),
        "split_sets_present": sum(1 for row in rows if int(row["apk_set_split_count"]) > 0),
        "static_ready_targets": statuses.get("ready", 0),
        "static_covered_targets": statuses.get("covered", 0),
        "byte_statuses": byte_states,
        "target_statuses": statuses,
        "target_reasons": reasons,
        "review_reason_counts": {
            reason: count
            for reason, count in sorted(reasons.items())
            if any(
                row.get("target_status") == "review" and row.get("target_reason") == reason
                for row in rows
            )
        },
    }


def _package_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    for row in rows:
        package = row["package_name"]
        bucket = packages.setdefault(
            package,
            {
                "package_name": package,
                "display_name": row["display_name"],
                "repository_base_rows": 0,
                "bytes_available": 0,
                "canonical_store_files_present": 0,
                "apk_sets_present": 0,
                "static_ready_targets": 0,
                "static_covered_targets": 0,
            },
        )
        bucket["repository_base_rows"] += 1
        bucket["bytes_available"] += int(bool(row["bytes_available"]))
        bucket["canonical_store_files_present"] += int(
            bool(row["canonical_store_file_available"])
        )
        bucket["apk_sets_present"] += int(bool(row["apk_set_present"]))
        bucket["static_ready_targets"] += int(row["target_status"] == "ready")
        bucket["static_covered_targets"] += int(row["target_status"] == "covered")
    return sorted(
        packages.values(),
        key=lambda item: (
            -int(item["bytes_available"]),
            -int(item["repository_base_rows"]),
            str(item["package_name"]),
        ),
    )


def _print_text(payload: dict[str, Any], *, limit: int) -> None:
    summary = payload["summary"]
    print("=== Current corpus preflight ===")
    for key in (
        "packages",
        "repository_base_rows",
        "base_hashes",
        "bytes_available",
        "canonical_store_files_present",
        "apk_sets_present",
        "split_sets_present",
        "static_ready_targets",
        "static_covered_targets",
    ):
        print(f"  {key}: {summary[key]}")
    print("  byte_statuses:")
    for key, value in sorted(summary["byte_statuses"].items()):
        print(f"    {key}: {value}")
    print("  target_statuses:")
    for key, value in sorted(summary["target_statuses"].items()):
        print(f"    {key}: {value}")
    if summary["review_reason_counts"]:
        print("  review_reason_counts:")
        for key, value in sorted(summary["review_reason_counts"].items()):
            print(f"    {key}: {value}")
    print()
    print("=== Packages ===")
    if not payload["packages"]:
        print("  (empty)")
    for row in payload["packages"]:
        print(
            f"  {row['package_name']} | rows={row['repository_base_rows']} "
            f"bytes={row['bytes_available']} store={row['canonical_store_files_present']} "
            f"apk_sets={row['apk_sets_present']} ready={row['static_ready_targets']} "
            f"covered={row['static_covered_targets']}"
        )
    print()
    print("=== Row details ===")
    if not payload["rows"]:
        print("  (empty)")
    for row in payload["rows"][:limit]:
        print(
            f"  {row['package_name']} ({row['display_name']}) | "
            f"vCode={row.get('version_code') or 'unknown'} "
            f"vName={row.get('version_name') or 'unknown'} "
            f"sha={row['base_apk_sha256'][:16]}... "
            f"apk_id={row.get('apk_id') or 'none'} "
            f"apk_set={row.get('apk_set_id') or 'none'} "
            f"artifact_set_hash={_short_hash(row.get('artifact_set_hash'))} "
            f"members={row['members']} splits={row['splits']} "
            f"static={row['static_run_count']} status={row['status']} "
            f"review_reason={row.get('review_reason') or 'none'} "
            f"action={row['recommended_action']}"
        )
    if len(payload["rows"]) > limit:
        print(f"  hint: showing {limit}/{len(payload['rows'])} row(s). Use --limit N or --json.")
    if payload.get("review_drift_comparisons"):
        print()
        print("=== Review drift comparison ===")
        for item in payload["review_drift_comparisons"][:limit]:
            current_root = ", ".join(item.get("current_storage_roots") or []) or "unknown"
            print(
                f"  {item['package_name']} ({item['display_name']}) | "
                f"vCode={item.get('version_code') or 'unknown'} "
                f"vName={item.get('version_name') or 'unknown'} "
                f"current_sha={_short_hash(item.get('current_base_apk_sha256'))} "
                f"current_apk_id={item.get('current_apk_id') or 'none'} "
                f"current_apk_set={item.get('current_apk_set_id') or 'none'} "
                f"current_artifact_set_hash={_short_hash(item.get('current_artifact_set_hash'))} "
                f"current_seen_at={item.get('current_seen_at') or 'unknown'} "
                f"current_harvest_run={item.get('current_harvest_run') or 'unknown'} "
                f"other_hashes={item['other_hash_count_for_same_package_version']} "
                f"classification={item['classification_suggestion']} "
                f"severity={item['review_severity']}"
            )
            print(f"    current_storage_root: {current_root}")
            if not item.get("other_hashes"):
                print("    other hashes: none")
            for other in item.get("other_hashes") or []:
                roots = ", ".join(other.get("storage_roots") or []) or "unknown"
                print(
                    f"    other sha={_short_hash(other.get('base_apk_sha256'))} "
                    f"apk_ids={_join_values(other.get('apk_ids'))} "
                    f"apk_sets={_join_values(other.get('apk_set_ids'))} "
                    f"artifact_set_hashes={_join_hashes(other.get('artifact_set_hashes'))} "
                    f"first_seen_at={other.get('first_seen_at') or 'unknown'} "
                    f"last_seen_at={other.get('last_seen_at') or 'unknown'} "
                    f"static={other.get('static_run_count') or 0}"
                )
                print(f"      storage_root: {roots}")
        if len(payload["review_drift_comparisons"]) > limit:
            print(
                f"  hint: showing {limit}/{len(payload['review_drift_comparisons'])} "
                "drift comparison row(s). Use --limit N or --json."
            )
    print()
    print("=== Current collection workflow ===")
    for step in payload["current_collection_workflow"]:
        print(f"  - {step}")
    print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")


def _short_hash(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "none"
    if len(text) <= 16:
        return text
    return f"{text[:16]}..."


def _join_values(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "none"
    return ",".join(str(value) for value in values)


def _join_hashes(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "none"
    return ",".join(_short_hash(value) for value in values)


if __name__ == "__main__":
    raise SystemExit(main())
