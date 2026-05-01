"""One-time migration from legacy harvest tree to canonical store/receipts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest import common
from scytaledroid.DeviceAnalysis.services import artifact_store


@dataclass
class LegacyHarvestMigrationSummary:
    manifests_scanned: int = 0
    artifacts_scanned: int = 0
    artifacts_materialized: int = 0
    sidecars_written: int = 0
    receipts_written: int = 0
    errors: list[str] = field(default_factory=list)


def migrate_legacy_harvest_tree(source_root: Path | None = None) -> LegacyHarvestMigrationSummary:
    root = (source_root or artifact_store.device_apks_root()).expanduser().resolve()
    summary = LegacyHarvestMigrationSummary()
    if not root.exists():
        return summary

    options = common.HarvestOptions(
        write_meta=True,
        meta_fields=tuple(getattr(app_config, "HARVEST_META_FIELDS", common.DEFAULT_META_FIELDS)),
        pull_mode="migrated",
    )

    for manifest_path in sorted(root.rglob("harvest_package_manifest.json")):
        summary.manifests_scanned += 1
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            summary.errors.append(f"{manifest_path}: manifest_read_failed:{type(exc).__name__}")
            continue
        if not isinstance(payload, dict):
            summary.errors.append(f"{manifest_path}: manifest_not_object")
            continue

        package = payload.get("package")
        inventory = payload.get("inventory")
        execution = payload.get("execution")
        if not isinstance(package, dict) or not isinstance(execution, dict):
            summary.errors.append(f"{manifest_path}: manifest_missing_sections")
            continue
        if not isinstance(inventory, dict):
            inventory = {}

        session_label = str(package.get("session_label") or "").strip()
        package_name = str(package.get("package_name") or "").strip().lower()
        observed = execution.get("observed_artifacts")
        if not session_label or not package_name or not isinstance(observed, list):
            summary.errors.append(f"{manifest_path}: manifest_missing_identity")
            continue

        updated_observed: list[dict[str, Any]] = []
        for artifact_entry in observed:
            if not isinstance(artifact_entry, dict):
                continue
            summary.artifacts_scanned += 1
            try:
                migrated = _migrate_artifact(
                    manifest_path=manifest_path,
                    package=package,
                    inventory=inventory,
                    artifact_entry=artifact_entry,
                    session_label=session_label,
                    options=options,
                )
            except Exception as exc:
                summary.errors.append(
                    f"{manifest_path}:{artifact_entry.get('file_name') or 'artifact'}: {type(exc).__name__}:{exc}"
                )
                migrated = dict(artifact_entry)
            else:
                summary.artifacts_materialized += 1
                summary.sidecars_written += 1
            updated_observed.append(migrated)

        migrated_payload = json.loads(json.dumps(payload))
        migrated_payload.setdefault("paths", {})
        migrated_payload["paths"]["legacy_manifest_path"] = common.normalise_local_path(manifest_path)
        receipt_path = artifact_store.harvest_receipt_path(
            session_label=session_label,
            package_name=package_name,
        )
        migrated_payload["paths"]["receipt_path"] = artifact_store.repo_relative_path(receipt_path)
        migrated_payload.setdefault("migration", {})
        migrated_payload["migration"].update(
            {
                "migrated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "source": "legacy_harvest_tree",
            }
        )
        migrated_payload.setdefault("execution", {})
        migrated_payload["execution"]["observed_artifacts"] = updated_observed
        artifact_store.write_harvest_receipt(
            session_label=session_label,
            package_name=package_name,
            payload=migrated_payload,
        )
        summary.receipts_written += 1
    return summary


def _migrate_artifact(
    *,
    manifest_path: Path,
    package: dict[str, Any],
    inventory: dict[str, Any],
    artifact_entry: dict[str, Any],
    session_label: str,
    options: common.HarvestOptions,
) -> dict[str, Any]:
    file_name = str(artifact_entry.get("file_name") or "").strip()
    if not file_name:
        raise ValueError("artifact file_name missing")

    legacy_path = _resolve_legacy_artifact_path(manifest_path=manifest_path, artifact_entry=artifact_entry)
    if not legacy_path.exists():
        raise FileNotFoundError(legacy_path)

    sidecar_payload = _load_json(legacy_path.with_suffix(legacy_path.suffix + ".meta.json"))
    hashes = _resolve_hashes(legacy_path, sidecar_payload, artifact_entry)
    sha256_digest = str(hashes.get("sha256") or "").strip().lower()
    if not sha256_digest:
        raise ValueError("artifact sha256 missing")

    canonical_path = artifact_store.materialize_apk(legacy_path, sha256_digest=sha256_digest)
    artifact_payload = {
        "source_path": artifact_entry.get("observed_source_path") or sidecar_payload.get("source_path"),
        "is_split_member": not bool(artifact_entry.get("is_base")),
        "split_group_id": sidecar_payload.get("split_group_id"),
    }
    inventory_payload = {
        "package_name": package.get("package_name"),
        "app_label": package.get("app_label"),
        "installer": inventory.get("installer"),
        "version_name": package.get("version_name"),
        "version_code": package.get("version_code"),
    }
    canonical_relpath = artifact_store.repo_relative_path(canonical_path)
    common.write_metadata_sidecar(
        canonical_path,
        inventory=inventory_payload,
        artifact=artifact_payload,
        hashes=hashes,
        serial=str(package.get("device_serial") or sidecar_payload.get("device_serial") or ""),
        session_stamp=session_label,
        options=options,
        extra={
            "artifact": artifact_entry.get("split_label") or sidecar_payload.get("artifact") or canonical_path.stem,
            "artifact_kind": sidecar_payload.get("artifact_kind") or "apk",
            "canonical_store_path": canonical_relpath,
            "local_path": canonical_relpath,
            "local_artifact_path": artifact_entry.get("local_artifact_path"),
            "captured_at": sidecar_payload.get("captured_at") or artifact_entry.get("pulled_at"),
            "apk_id": sidecar_payload.get("apk_id"),
            "occurrence_index": sidecar_payload.get("occurrence_index"),
            "category": sidecar_payload.get("category") or inventory.get("category"),
        },
    )

    migrated = dict(artifact_entry)
    migrated["canonical_store_path"] = canonical_relpath
    migrated.setdefault("local_artifact_path", common.normalise_local_path(legacy_path))
    migrated.setdefault("sha256", sha256_digest)
    migrated.setdefault("file_size", canonical_path.stat().st_size if canonical_path.exists() else None)
    return migrated


def _resolve_legacy_artifact_path(*, manifest_path: Path, artifact_entry: dict[str, Any]) -> Path:
    local_path = str(artifact_entry.get("local_artifact_path") or "").strip()
    if local_path:
        candidate = Path(local_path)
        if not candidate.is_absolute():
            candidate = Path.cwd() / local_path
        if candidate.exists():
            return candidate.resolve()
    file_name = str(artifact_entry.get("file_name") or "").strip()
    if file_name:
        candidate = manifest_path.parent / file_name
        if candidate.exists():
            return candidate.resolve()
    return (manifest_path.parent / file_name).resolve()


def _resolve_hashes(artifact_path: Path, sidecar_payload: dict[str, Any], artifact_entry: dict[str, Any]) -> dict[str, str]:
    hashes = {
        "sha256": str(
            sidecar_payload.get("sha256")
            or artifact_entry.get("sha256")
            or ""
        ).strip(),
        "sha1": str(sidecar_payload.get("sha1") or "").strip(),
        "md5": str(sidecar_payload.get("md5") or "").strip(),
    }
    if hashes["sha256"] and hashes["sha1"] and hashes["md5"]:
        return hashes
    computed = common.compute_hashes(artifact_path)
    for key in ("sha256", "sha1", "md5"):
        hashes[key] = hashes[key] or computed.get(key, "")
    return hashes


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


__all__ = ["LegacyHarvestMigrationSummary", "migrate_legacy_harvest_tree"]
