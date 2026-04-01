"""Authoritative per-package harvest manifests and status evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from . import common
from .common import normalise_local_path
from .models import PackagePlan, PullResult


def package_manifest_path(package_dir: Path) -> Path:
    return package_dir / "harvest_package_manifest.json"


def planned_artifact_entries(plan: PackagePlan) -> list[dict[str, object]]:
    total = len(plan.artifacts)
    captured_paths = [str(path) for path in plan.inventory.apk_paths if str(path).strip()]
    entries: list[dict[str, object]] = []
    for index, artifact in enumerate(plan.artifacts, start=1):
        entries.append(
            {
                "artifact_index": index,
                "artifact_total": total,
                "split_label": artifact.artifact,
                "file_name": artifact.file_name,
                "is_base": not artifact.is_split_member,
                "planned_source_path": artifact.source_path,
                "inventory_captured_path_set": captured_paths,
            }
        )
    return entries


def observed_artifact_entries(result: PullResult) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for artifact in result.ok:
        entries.append(
            {
                "split_label": artifact.artifact_label or artifact.file_name,
                "file_name": artifact.file_name,
                "is_base": bool(artifact.is_base) if artifact.is_base is not None else None,
                "local_artifact_path": normalise_local_path(artifact.dest_path),
                "observed_source_path": artifact.observed_source_path or artifact.source_path,
                "sha256": artifact.sha256,
                "file_size": artifact.file_size,
                "pulled_at": artifact.pulled_at,
                "pull_outcome": artifact.status,
                "mirror_failure_reasons": list(artifact.mirror_failure_reasons),
            }
        )
    return entries


def build_package_comparison(plan: PackagePlan, result: PullResult) -> dict[str, object]:
    planned = planned_artifact_entries(plan)
    observed = observed_artifact_entries(result)
    observed_keys = {_comparison_key(entry) for entry in observed}
    planned_keys = {_comparison_key(entry) for entry in planned}
    missing = [entry for entry in planned if _comparison_key(entry) not in observed_keys]
    unexpected = [entry for entry in observed if _comparison_key(entry) not in planned_keys]
    return {
        "planned_artifact_count": len(planned),
        "observed_artifact_count": len(observed),
        "missing_artifacts": missing,
        "unexpected_artifacts": unexpected,
        "matches_planned_artifacts": not missing and not unexpected and len(observed) == len(planned),
        "observed_hashes_complete": all(bool(entry.get("sha256")) for entry in observed),
    }


def finalize_package_result(result: PullResult, *, write_db_requested: bool) -> None:
    comparison = build_package_comparison(result.plan, result)
    result.comparison = comparison
    if result.capture_status != "drifted":
        if comparison["matches_planned_artifacts"] and not result.errors:
            result.capture_status = "clean"
        elif result.ok:
            result.capture_status = "partial"
        else:
            result.capture_status = "failed"
    if write_db_requested:
        result.persistence_status = "mirror_failed" if result.mirror_failure_reasons else "mirrored"
    else:
        result.persistence_status = "not_requested"
    if result.capture_status in {"partial", "failed", "drifted"}:
        result.research_status = "ineligible"
    elif not comparison["matches_planned_artifacts"] or not comparison["observed_hashes_complete"]:
        result.research_status = "ineligible"
    else:
        result.research_status = "pending_audit"


def write_package_manifest(
    *,
    result: PullResult,
    package_dir: Path,
    serial: str,
    session_stamp: str,
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
    execution_state: str,
) -> None:
    manifest_path = result.package_manifest_path or package_manifest_path(package_dir)
    result.package_manifest_path = manifest_path
    inventory = result.plan.inventory
    payload = {
        "schema": "harvest_package_manifest_v1",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "execution_state": execution_state,
        "package": {
            "package_name": inventory.package_name,
            "app_label": inventory.app_label,
            "version_name": inventory.version_name,
            "version_code": inventory.version_code,
            "device_serial": serial,
            "snapshot_id": snapshot_id,
            "snapshot_captured_at": snapshot_captured_at,
            "session_label": session_stamp,
            "package_dir": normalise_local_path(package_dir),
        },
        "inventory": {
            "installer": inventory.installer,
            "category": inventory.category,
            "profile_key": inventory.profile_key,
            "profile_name": inventory.profile,
            "primary_path": inventory.primary_path,
            "apk_paths": list(inventory.apk_paths),
            "split_count": inventory.split_count,
        },
        "planning": {
            "preflight_reason": result.preflight_reason,
            "total_paths": result.plan.total_paths,
            "policy_filtered_count": result.plan.policy_filtered_count,
            "policy_filtered_reason": result.plan.policy_filtered_reason,
            "expected_artifacts": planned_artifact_entries(result.plan),
        },
        "execution": {
            "observed_artifacts": observed_artifact_entries(result),
            "errors": [
                {"source_path": error.source_path, "reason": error.reason}
                for error in result.errors
            ],
            "runtime_skips": list(result.skipped),
            "mirror_failure_reasons": list(result.mirror_failure_reasons),
            "drift_reasons": list(result.drift_reasons),
        },
        "status": {
            "capture_status": result.capture_status,
            "persistence_status": result.persistence_status,
            "research_status": result.research_status,
        },
        "comparison": dict(result.comparison),
    }
    common.write_json_manifest(manifest_path, payload)


def _comparison_key(entry: Mapping[str, object]) -> tuple[str, str]:
    return (
        str(entry.get("split_label") or "").strip(),
        str(entry.get("file_name") or "").strip(),
    )


__all__ = [
    "build_package_comparison",
    "finalize_package_result",
    "observed_artifact_entries",
    "package_manifest_path",
    "planned_artifact_entries",
    "write_package_manifest",
]
