#!/usr/bin/env python3
"""Read-only static target queue derived from package/version/hash lineage.

This is a queue-like read model, not a writable queue table.  It converts known
APK identities into actionable static-analysis targets with explicit block
reasons.  Missing bytes are an artifact lifecycle state, not corruption.

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
    parser.add_argument("--package", dest="package_name", help="Limit to one package.")
    parser.add_argument(
        "--only-actionable",
        action="store_true",
        help="Hide fully covered rows with no review/action signal.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum target rows to print in text mode (default 100).",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.DeviceAnalysis.services import artifact_store
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    rows = _fetch_base_rows(core_q, package_name=args.package_name)
    static_by_hash = _fetch_static_coverage(core_q)
    dynamic_by_hash = _fetch_dynamic_coverage(core_q)
    apk_sets_by_hash = _fetch_apk_sets_by_hash(core_q)
    drift_keys = _fetch_same_version_hash_drift_keys(core_q)

    targets: list[dict[str, Any]] = []
    for row in rows:
        sha = _norm_sha(row.get("base_apk_sha256"))
        pkg = str(row.get("package_name") or "").strip().lower()
        if not sha or not pkg:
            continue
        recorded_path = _recorded_abs_path(row)
        canonical_path = artifact_store.canonical_apk_path(sha)
        recorded_exists = bool(recorded_path and recorded_path.exists())
        canonical_exists = canonical_path.exists()
        byte_status = _byte_status(
            recorded_exists=recorded_exists,
            canonical_exists=canonical_exists,
            recorded_root_exists=_path_exists(row.get("data_root")),
            recorded_location_known=bool(row.get("local_rel_path")),
        )
        static_cov = static_by_hash.get(sha, {})
        dynamic_cov = dynamic_by_hash.get(sha, {})
        set_info = apk_sets_by_hash.get(sha, {})
        exact_static = int(static_cov.get("canonical_completed_identity_valid") or 0)
        dynamic_sessions = int(dynamic_cov.get("dynamic_sessions") or 0)
        dynamic_linked = int(dynamic_cov.get("dynamic_linked_sessions") or 0)
        dynamic_unlinked = int(dynamic_cov.get("dynamic_unlinked_sessions") or 0)
        split_status = _split_status(set_info=set_info, byte_status=byte_status)
        review = (
            pkg,
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        ) in drift_keys
        reason = _target_reason(
            exact_static=exact_static,
            byte_status=byte_status,
            dynamic_sessions=dynamic_sessions,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=review,
        )
        target_status = _target_status(
            exact_static=exact_static,
            byte_status=byte_status,
            split_status=split_status,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=review,
        )
        priority = _priority(reason=reason, target_status=target_status, dynamic_sessions=dynamic_sessions)
        action = _operator_action(target_status)
        target = {
            "package_name": pkg,
            "display_name": row.get("display_name") or pkg,
            "version_code": row.get("version_code"),
            "version_name": row.get("version_name"),
            "base_apk_sha256": sha,
            "apk_id": row.get("apk_id"),
            "apk_set_id": set_info.get("apk_set_id"),
            "artifact_set_hash": set_info.get("artifact_set_hash"),
            "member_count": int(set_info.get("member_count") or 0),
            "split_count": int(set_info.get("split_count") or 0),
            "reason": reason,
            "review_flags": ["same_version_hash_drift_review"] if review else [],
            "byte_status": byte_status,
            "split_status": split_status,
            "priority": priority,
            "target_status": target_status,
            "operator_action": action,
            "static_exact_coverage": exact_static,
            "static_run_count": int(static_cov.get("static_runs") or 0),
            "latest_static_session": static_cov.get("latest_static_session"),
            "dynamic_session_count": dynamic_sessions,
            "dynamic_linked_count": dynamic_linked,
            "dynamic_unlinked_count": dynamic_unlinked,
            "recorded_path": recorded_path.as_posix() if recorded_path else None,
            "canonical_store_path": canonical_path.as_posix(),
            "recorded_root": row.get("data_root"),
            "recorded_root_exists": _path_exists(row.get("data_root")),
        }
        if not args.only_actionable or _is_actionable(target):
            targets.append(target)

    targets.sort(
        key=lambda item: (
            int(item["priority"]),
            -int(item["dynamic_session_count"]),
            str(item["package_name"]),
            str(item.get("version_code") or ""),
            str(item["base_apk_sha256"]),
        )
    )
    payload = {
        "summary": _summary(targets),
        "targets": targets,
        "notes": [
            "apk_set_id is preferred when present; base_apk_sha256 remains the historical fallback.",
            "ready targets may still need exact-target preflight before execution.",
            "This is a read-only target queue model; it does not enqueue or run static analysis.",
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    _print_text(payload, limit=max(args.limit, 0))
    return 0


def _fetch_base_rows(core_q: Any, *, package_name: str | None) -> list[dict[str, Any]]:
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(r.package_name)) = %s"
        params.append(str(package_name).strip().lower())
    return list(
        core_q.run_sql(
            f"""
            SELECT
              r.apk_id,
              LOWER(TRIM(r.package_name)) AS package_name,
              COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))) AS display_name,
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)) AS base_apk_sha256,
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            FROM android_apk_repository r
            LEFT JOIN apps a ON LOWER(TRIM(a.package_name)) = LOWER(TRIM(r.package_name))
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            WHERE r.sha256 IS NOT NULL
              AND COALESCE(r.is_split_member, 0) = 0
              {package_filter}
            GROUP BY
              r.apk_id,
              LOWER(TRIM(r.package_name)),
              COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))),
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)),
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            """,
            tuple(params),
            fetch="all",
            dictionary=True,
            query_name="report_static_analysis_targets.base_rows",
        )
        or []
    )


def _fetch_static_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS static_runs,
          SUM(CASE
                WHEN status='COMPLETED'
                 AND run_class='CANONICAL'
                 AND COALESCE(identity_valid,0)=1
                THEN 1 ELSE 0
              END) AS canonical_completed_identity_valid,
          MAX(static_session_id) AS latest_static_session
        FROM static_analysis_runs
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_static_analysis_targets.static_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _fetch_dynamic_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(ds.base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS dynamic_sessions,
          SUM(CASE WHEN ds.static_run_id IS NULL THEN 1 ELSE 0 END) AS dynamic_unlinked_sessions,
          SUM(CASE
                WHEN sar.id IS NOT NULL
                 AND LOWER(TRIM(sar.base_apk_sha256)) = LOWER(TRIM(ds.base_apk_sha256))
                 AND sar.status = 'COMPLETED'
                 AND sar.run_class = 'CANONICAL'
                 AND COALESCE(sar.identity_valid, 0) = 1
                THEN 1 ELSE 0
              END) AS dynamic_linked_sessions
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar ON sar.id = ds.static_run_id
        WHERE ds.base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(ds.base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_static_analysis_targets.dynamic_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _fetch_apk_sets_by_hash(core_q: Any) -> dict[str, dict[str, Any]]:
    if not _table_exists(core_q, "apk_sets"):
        return {}
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS install_sets_seen,
          MIN(apk_set_id) AS apk_set_id,
          MIN(artifact_set_hash) AS artifact_set_hash,
          MAX(member_count) AS member_count,
          MAX(split_count) AS split_count
        FROM apk_sets
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_static_analysis_targets.apk_sets",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _fetch_same_version_hash_drift_keys(core_q: Any) -> set[tuple[str, str, str]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(package_name)) AS package_name,
          COALESCE(CAST(version_code AS CHAR), '') AS version_code,
          COALESCE(version_name, '') AS version_name,
          COUNT(DISTINCT LOWER(TRIM(sha256))) AS hashes
        FROM android_apk_repository
        WHERE sha256 IS NOT NULL
          AND COALESCE(is_split_member, 0) = 0
        GROUP BY
          LOWER(TRIM(package_name)),
          COALESCE(CAST(version_code AS CHAR), ''),
          COALESCE(version_name, '')
        HAVING hashes > 1
        """,
        fetch="all",
        dictionary=True,
        query_name="report_static_analysis_targets.same_version_drift",
    ) or []
    return {
        (
            str(row.get("package_name") or "").lower(),
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        )
        for row in rows
    }


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
        query_name="report_static_analysis_targets.table_exists",
    )
    return int((row or {}).get("n") or 0) > 0


def _byte_status(
    *,
    recorded_exists: bool,
    canonical_exists: bool,
    recorded_root_exists: bool,
    recorded_location_known: bool,
) -> str:
    if recorded_exists and canonical_exists:
        return "available_recorded_and_canonical"
    if canonical_exists:
        return "available_canonical"
    if recorded_exists:
        return "available_recorded"
    if not recorded_location_known:
        return "missing_no_recorded_location"
    if recorded_root_exists:
        return "missing_current_root_file"
    return "missing_old_root"


def _split_status(*, set_info: dict[str, Any], byte_status: str) -> str:
    if set_info:
        return "install_set_known"
    if byte_status.startswith("available"):
        return "base_only_or_split_context_missing"
    return "unknown_until_bytes_restored"


def _target_reason(
    *,
    exact_static: int,
    byte_status: str,
    dynamic_sessions: int,
    dynamic_unlinked: int,
    same_version_hash_drift: bool,
) -> str:
    if exact_static > 0 and dynamic_unlinked > 0:
        return "dynamic_static_gap"
    if exact_static > 0 and not byte_status.startswith("available"):
        return "artifact_lifecycle_gap"
    if exact_static > 0 and byte_status == "available_recorded":
        return "artifact_lifecycle_gap"
    if exact_static == 0 and dynamic_sessions > 0:
        return "dynamic_static_gap"
    if same_version_hash_drift:
        return "same_version_hash_drift_review"
    if exact_static == 0:
        return "new_hash_seen"
    return "covered"


def _target_status(
    *,
    exact_static: int,
    byte_status: str,
    split_status: str,
    dynamic_unlinked: int,
    same_version_hash_drift: bool,
) -> str:
    if exact_static > 0 and dynamic_unlinked > 0:
        return "link_repair_preview_available"
    if exact_static > 0 and byte_status == "available_recorded":
        return "rebuild_canonical_store"
    if exact_static > 0 and byte_status == "missing_old_root":
        return "blocked_missing_bytes"
    if exact_static > 0 and byte_status in {"missing_current_root_file", "missing_no_recorded_location"}:
        return "needs_reharvest"
    if exact_static > 0 and not same_version_hash_drift:
        return "covered"
    if same_version_hash_drift and exact_static > 0:
        return "review"
    if byte_status == "missing_old_root":
        return "blocked_missing_bytes"
    if byte_status in {"missing_current_root_file", "missing_no_recorded_location"}:
        return "needs_reharvest"
    if split_status == "base_only_or_split_context_missing":
        return "blocked_split_context"
    if byte_status.startswith("available"):
        return "ready"
    return "blocked_missing_bytes"


def _priority(*, reason: str, target_status: str, dynamic_sessions: int) -> int:
    if target_status == "ready" and reason == "dynamic_static_gap":
        return 10
    if target_status == "link_repair_preview_available":
        return 20
    if target_status == "blocked_missing_bytes" and reason == "dynamic_static_gap":
        return 30
    if target_status == "needs_reharvest" and reason == "dynamic_static_gap":
        return 35
    if target_status == "ready":
        return 40
    if target_status == "review":
        return 50
    if target_status == "rebuild_canonical_store":
        return 55
    if target_status.startswith("blocked"):
        return 60 if dynamic_sessions else 70
    return 90


def _operator_action(target_status: str) -> str:
    return {
        "ready": "Run exact static analysis",
        "blocked_missing_bytes": "Restore old root",
        "needs_reharvest": "Reharvest current app",
        "blocked_split_context": "Restore split context or use explicit base-only mode",
        "link_repair_preview_available": "Preview dynamic link repair",
        "rebuild_canonical_store": "Rebuild canonical SHA store",
        "covered": "No action needed",
        "review": "Review same-version hash drift",
    }.get(target_status, "Review target state")


def _is_actionable(target: dict[str, Any]) -> bool:
    return str(target.get("target_status")) not in {"covered"}


def _summary(targets: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    for target in targets:
        by_status[str(target["target_status"])] = by_status.get(str(target["target_status"]), 0) + 1
        by_reason[str(target["reason"])] = by_reason.get(str(target["reason"]), 0) + 1
    return {
        "targets": len(targets),
        "by_status": by_status,
        "by_reason": by_reason,
        "dynamic_sessions_on_targets": sum(int(t["dynamic_session_count"]) for t in targets),
    }


def _print_text(payload: dict[str, Any], *, limit: int) -> None:
    summary = payload["summary"]
    print("=== Static analysis target queue (read-only) ===")
    print(f"  targets: {summary['targets']}")
    print(f"  dynamic_sessions_on_targets: {summary['dynamic_sessions_on_targets']}")
    print("  by_status:")
    for key, value in sorted(summary["by_status"].items()):
        print(f"    {key}: {value}")
    print("  by_reason:")
    for key, value in sorted(summary["by_reason"].items()):
        print(f"    {key}: {value}")
    print()
    print("=== Targets ===")
    rows = payload["targets"][:limit] if limit else payload["targets"]
    if not rows:
        print("  (empty)")
    for row in rows:
        print(
            f"  P{row['priority']:02d} {row['package_name']} | "
            f"vCode={row.get('version_code') or 'unknown'} "
            f"sha={str(row['base_apk_sha256'])[:16]}... "
            f"apk_set={row.get('apk_set_id') or 'none'} "
            f"bytes={row['byte_status']} split={row['split_status']} "
            f"static={row['static_exact_coverage']} dynamic={row['dynamic_session_count']} "
            f"status={row['target_status']} reason={row['reason']} "
            f"action={row['operator_action']}"
        )
    if limit and len(payload["targets"]) > limit:
        print(f"  hint: showing {limit}/{len(payload['targets'])} target(s). Use --limit N or --json.")
    print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")


def _recorded_abs_path(row: dict[str, Any]) -> Path | None:
    raw = str(row.get("local_rel_path") or "").strip()
    if not raw:
        return None
    local = Path(raw).expanduser()
    if local.is_absolute():
        return local
    root = str(row.get("data_root") or "").strip()
    if root:
        return Path(root).expanduser() / local
    return Path.cwd() / local


def _path_exists(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and Path(text).expanduser().exists())


def _norm_sha(value: Any) -> str:
    return str(value or "").strip().lower()


if __name__ == "__main__":
    raise SystemExit(main())
