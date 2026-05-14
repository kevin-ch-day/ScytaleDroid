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

from scytaledroid.Database.db_scripts import package_lineage_read_model as _lineage_read_model


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
        from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
        from scytaledroid.DeviceAnalysis.services import artifact_store
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    rows = lineage.fetch_base_rows(core_q, package_name=args.package_name)
    static_by_hash = lineage.fetch_static_coverage(core_q)
    dynamic_by_hash = lineage.fetch_dynamic_coverage(core_q)
    apk_sets_by_hash = lineage.fetch_apk_sets_by_hash(core_q)
    drift_keys = lineage.fetch_same_version_hash_drift_keys(core_q)

    targets: list[dict[str, Any]] = []
    for row in rows:
        sha = lineage.norm_sha(row.get("base_apk_sha256"))
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
        review = (
            pkg,
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        ) in drift_keys
        reason = lineage.target_reason(
            exact_static=exact_static,
            byte_status=byte_status,
            dynamic_sessions=dynamic_sessions,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=review,
        )
        target_status = lineage.target_status(
            exact_static=exact_static,
            byte_status=byte_status,
            split_status=split_status,
            dynamic_unlinked=dynamic_unlinked,
            same_version_hash_drift=review,
        )
        priority = lineage.target_priority(
            reason=reason,
            target_status=target_status,
            dynamic_sessions=dynamic_sessions,
        )
        action = lineage.operator_action(target_status)
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
            "recorded_root_exists": lineage.path_exists(row.get("data_root")),
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



# Compatibility aliases for tests and any external callers that imported these
# script-private helpers before the shared read model existed.
_fetch_base_rows = _lineage_read_model.fetch_base_rows
_fetch_static_coverage = _lineage_read_model.fetch_static_coverage
_fetch_dynamic_coverage = _lineage_read_model.fetch_dynamic_coverage
_fetch_apk_sets_by_hash = _lineage_read_model.fetch_apk_sets_by_hash
_fetch_same_version_hash_drift_keys = _lineage_read_model.fetch_same_version_hash_drift_keys
_table_exists = _lineage_read_model.table_exists
_recorded_abs_path = _lineage_read_model.recorded_abs_path
_path_exists = _lineage_read_model.path_exists
_norm_sha = _lineage_read_model.norm_sha
_byte_status = _lineage_read_model.byte_status
_split_status = _lineage_read_model.split_status
_target_reason = _lineage_read_model.target_reason
_target_status = _lineage_read_model.target_status
_priority = _lineage_read_model.target_priority
_operator_action = _lineage_read_model.operator_action


if __name__ == "__main__":
    raise SystemExit(main())
