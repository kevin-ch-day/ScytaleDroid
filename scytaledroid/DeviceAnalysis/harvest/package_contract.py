"""Authoritative per-package harvest manifests and status evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DeviceAnalysis.identity import (
    compute_split_membership_hash,
    is_base_artifact,
    resolve_hex_digest,
)
from scytaledroid.DeviceAnalysis.services import artifact_store

from . import common
from .common import normalise_local_path, package_evidence_leaf_name
from .models import (
    CANONICAL_MATERIALIZATION_FAILED,
    ArtifactError,
    InventoryRow,
    PackagePlan,
    PullResult,
)


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
                "is_base": is_base_artifact(
                    is_base=artifact.is_base,
                    file_name=artifact.file_name,
                    split_label=artifact.artifact_label,
                ),
                "local_artifact_path": normalise_local_path(artifact.dest_path),
                "canonical_store_path": artifact.canonical_store_path,
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
    declared_split_count = _declared_split_count(plan.inventory)
    inventory_path_count = len(plan.inventory.apk_paths)
    inventory_paths_match_declared_splits = (
        inventory_path_count == declared_split_count if declared_split_count is not None else None
    )
    return {
        "planned_artifact_count": len(planned),
        "observed_artifact_count": len(observed),
        "missing_artifacts": missing,
        "unexpected_artifacts": unexpected,
        "matches_planned_artifacts": not missing
        and not unexpected
        and len(observed) == len(planned),
        "observed_hashes_complete": all(bool(entry.get("sha256")) for entry in observed),
        "canonical_store_complete": bool(observed)
        and all(bool(str(entry.get("canonical_store_path") or "").strip()) for entry in observed),
        "canonical_durability_status": _canonical_durability_status(result, observed),
        "acquisition_complete": bool(observed)
        and not missing
        and not unexpected
        and len(observed) == len(planned)
        and all(bool(entry.get("sha256")) for entry in observed),
        "package_manager_split_count": declared_split_count,
        "inventory_path_count": inventory_path_count,
        "inventory_paths_match_declared_splits": inventory_paths_match_declared_splits,
    }


def finalize_package_result(result: PullResult, *, write_db_requested: bool) -> None:
    comparison = build_package_comparison(result.plan, result)
    result.comparison = comparison
    durable_canonical = _package_has_durable_canonical(result, comparison)
    if (
        _canonical_durability_failed(result)
        and CANONICAL_MATERIALIZATION_FAILED not in result.mirror_failure_reasons
    ):
        result.mirror_failure_reasons.append(CANONICAL_MATERIALIZATION_FAILED)
    if result.capture_status != "drifted":
        if (
            comparison["matches_planned_artifacts"]
            and comparison["inventory_paths_match_declared_splits"] is not False
            and not result.errors
            and durable_canonical
        ):
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
    elif (
        not comparison["matches_planned_artifacts"]
        or not comparison["observed_hashes_complete"]
        or comparison["inventory_paths_match_declared_splits"] is False
        or not durable_canonical
    ):
        result.research_status = "ineligible"
    else:
        result.research_status = "pending_audit"


def _artifact_has_canonical_store(artifact: object) -> bool:
    return bool(str(getattr(artifact, "canonical_store_path", None) or "").strip())


def _canonical_durability_failed(result: PullResult) -> bool:
    if any(error.reason == CANONICAL_MATERIALIZATION_FAILED for error in result.errors):
        return True
    return any(
        getattr(artifact, "status", None) == CANONICAL_MATERIALIZATION_FAILED
        or not _artifact_has_canonical_store(artifact)
        for artifact in result.ok
    )


def _package_has_durable_canonical(result: PullResult, comparison: Mapping[str, object]) -> bool:
    if result.errors and any(
        error.reason == CANONICAL_MATERIALIZATION_FAILED for error in result.errors
    ):
        return False
    if not comparison.get("matches_planned_artifacts"):
        return False
    if not result.ok:
        return False
    return all(_artifact_has_canonical_store(artifact) for artifact in result.ok)


def _canonical_durability_status(result: PullResult, observed: list[dict[str, object]]) -> str:
    if _canonical_durability_failed(result) or (
        observed
        and not all(
            bool(str(entry.get("canonical_store_path") or "").strip()) for entry in observed
        )
    ):
        return "failed"
    if observed and all(
        bool(str(entry.get("canonical_store_path") or "").strip()) for entry in observed
    ):
        return "ok"
    return "not_attempted"


def inventory_signer_fingerprint(inventory: InventoryRow) -> str | None:
    raw = dict(inventory.raw or {})
    return resolve_hex_digest(
        raw,
        "signer_cert_digest",
        "signer_fingerprint",
        "signer_primary_digest",
    )


def inventory_signer_set_hash(inventory: InventoryRow) -> str | None:
    raw = dict(inventory.raw or {})
    direct = resolve_hex_digest(raw, "signer_set_hash")
    if direct:
        return direct
    primary = inventory_signer_fingerprint(inventory)
    return primary if primary and len(primary) == 64 else None


def inventory_split_membership_hash(inventory: InventoryRow) -> str | None:
    raw = dict(inventory.raw or {})
    direct = resolve_hex_digest(raw, "split_membership_hash")
    if direct:
        return direct
    return compute_split_membership_hash(inventory.apk_paths)


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
            "signer_cert_digest": inventory_signer_fingerprint(inventory),
            "signer_set_hash": inventory_signer_set_hash(inventory),
            "evidence_leaf": package_evidence_leaf_name(inventory),
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
            "split_membership_hash": inventory_split_membership_hash(inventory),
            "package_manager_split_names": _declared_split_names(inventory),
            "package_manager_split_count": _declared_split_count(inventory),
            "split_path_count_consistent": _inventory_split_path_count_consistent(inventory),
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
            "errors": [_error_payload(error) for error in result.errors],
            "runtime_skips": list(result.skipped),
            "mirror_failure_reasons": list(result.mirror_failure_reasons),
            "drift_reasons": list(result.drift_reasons),
            "stale_replan": _stale_replan_payload(result),
        },
        "status": {
            "capture_status": result.capture_status,
            "persistence_status": result.persistence_status,
            "research_status": result.research_status,
            "canonical_durability_status": result.comparison.get("canonical_durability_status"),
            "acquisition_complete": result.comparison.get("acquisition_complete"),
        },
        "comparison": dict(result.comparison),
    }
    receipt_path = artifact_store.harvest_receipt_path(
        session_label=session_stamp,
        package_name=inventory.package_name,
    )
    payload["paths"] = {
        "legacy_manifest_path": normalise_local_path(manifest_path),
        "receipt_path": artifact_store.repo_relative_path(receipt_path),
    }
    common.write_json_manifest(manifest_path, payload)
    artifact_store.write_harvest_receipt(
        session_label=session_stamp,
        package_name=inventory.package_name,
        payload=payload,
    )


def _error_payload(error: ArtifactError) -> dict[str, object]:
    payload: dict[str, object] = {
        "source_path": error.source_path,
        "reason": error.reason,
    }
    if error.sha256:
        payload["sha256"] = error.sha256
    if error.session_copy:
        payload["session_copy"] = error.session_copy
    if error.file_name:
        payload["file_name"] = error.file_name
    if error.detail:
        payload["detail"] = error.detail
    return payload


def _comparison_key(entry: Mapping[str, object]) -> tuple[str, str]:
    return (
        str(entry.get("split_label") or "").strip(),
        str(entry.get("file_name") or "").strip(),
    )


def _declared_split_names(inventory: InventoryRow) -> list[str]:
    raw = dict(inventory.raw or {})
    value = raw.get("package_manager_split_names")
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _declared_split_count(inventory: InventoryRow) -> int | None:
    raw = dict(inventory.raw or {})
    value = raw.get("package_manager_split_count")
    if isinstance(value, bool):
        return None
    try:
        count = int(str(value).strip())
    except (TypeError, ValueError):
        names = _declared_split_names(inventory)
        return len(names) if names else None
    return count if count >= 1 else None


def _inventory_split_path_count_consistent(inventory: InventoryRow) -> bool | None:
    declared_count = _declared_split_count(inventory)
    if declared_count is None:
        return None
    return len(inventory.apk_paths) == declared_count


def _stale_replan_payload(result: PullResult) -> dict[str, object]:
    return {
        "required": bool(result.stale_replan_required),
        "outcome": result.stale_replan_outcome,
        "details": dict(result.stale_replan_details or {}),
    }


__all__ = [
    "build_package_comparison",
    "finalize_package_result",
    "inventory_signer_fingerprint",
    "inventory_signer_set_hash",
    "inventory_split_membership_hash",
    "observed_artifact_entries",
    "package_manifest_path",
    "planned_artifact_entries",
    "write_package_manifest",
]
