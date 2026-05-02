"""Repair/replay DB mirror rows from authoritative harvest manifests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from ..services import artifact_store
from . import common


@dataclass(slots=True)
class ReplayArtifactOutcome:
    file_name: str
    status: str
    reason: str | None = None
    apk_id: int | None = None


@dataclass(slots=True)
class ReplayPackageOutcome:
    manifest_path: Path
    package_name: str
    session_label: str | None
    previous_persistence_status: str | None
    status: str
    replayed_artifacts: int = 0
    skipped_artifacts: int = 0
    failed_artifacts: int = 0
    artifact_results: list[ReplayArtifactOutcome] = field(default_factory=list)
    failure_reasons: list[str] = field(default_factory=list)
    updated_manifest: bool = False

    @property
    def succeeded(self) -> bool:
        return self.status == "replayed"


def find_package_manifests(root: Path) -> list[Path]:
    """Return every ``harvest_package_manifest.json`` under *root* (recursive).

    Only on-disk **package manifests** are supported; shallow receipt JSON trees
    without that filename are not inferred (use ``device_apks`` or pass a directory
    tree that actually contains package manifests).
    """

    return common.iter_harvest_package_manifest_paths(root.resolve())


def load_package_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "harvest_package_manifest_v1":
        raise ValueError(f"Unsupported harvest manifest schema for {path}")
    if not isinstance(payload.get("package"), dict):
        raise ValueError(f"Invalid package payload in {path}")
    return payload


def replay_package_manifest(
    manifest_path: Path,
    *,
    repo_module: ModuleType | object | None = None,
    storage_root_id: int | None = None,
    force: bool = False,
) -> ReplayPackageOutcome:
    payload = load_package_manifest(manifest_path)
    package = dict(payload.get("package") or {})
    inventory = dict(payload.get("inventory") or {})
    execution = dict(payload.get("execution") or {})
    status = dict(payload.get("status") or {})

    package_name = str(package.get("package_name") or "").strip()
    session_label = str(package.get("session_label") or "").strip() or None
    previous_persistence_status = str(status.get("persistence_status") or "").strip() or None
    outcome = ReplayPackageOutcome(
        manifest_path=manifest_path,
        package_name=package_name,
        session_label=session_label,
        previous_persistence_status=previous_persistence_status,
        status="skipped",
    )

    if not package_name:
        outcome.status = "failed"
        outcome.failure_reasons.append("package_name_missing")
        return outcome

    if str(payload.get("execution_state") or "").strip().lower() != "completed" and not force:
        outcome.failure_reasons.append("execution_not_completed")
        return outcome

    if previous_persistence_status != "mirror_failed" and not force:
        outcome.failure_reasons.append("persistence_status_not_mirror_failed")
        return outcome

    observed = [
        dict(entry)
        for entry in (execution.get("observed_artifacts") or [])
        if isinstance(entry, dict)
        and str(entry.get("pull_outcome") or "").strip().lower() == "written"
    ]
    if not observed:
        outcome.status = "failed"
        outcome.failure_reasons.append("no_written_observed_artifacts")
        return outcome

    repo = repo_module if repo_module is not None else _load_repo_module()
    if repo is None:
        outcome.status = "failed"
        outcome.failure_reasons.append("db_repo_unavailable")
        return outcome

    try:
        storage_root_id = int(storage_root_id) if storage_root_id is not None else _ensure_storage_root_id(repo)
    except Exception as exc:
        outcome.status = "failed"
        outcome.failure_reasons.append(f"storage_root_failed:{exc}")
        return outcome

    try:
        app_id = repo.ensure_app_definition(
            package_name,
            package.get("app_label"),
            category_name=inventory.get("category"),
            profile_key=inventory.get("profile_key"),
            profile_name=inventory.get("profile_name"),
            context={
                "event": "harvest.replay.ensure_app_definition",
                "package_name": package_name,
                "session_stamp": session_label,
            },
        )
    except Exception as exc:
        outcome.status = "failed"
        outcome.failure_reasons.append(f"app_definition_failed:{exc}")
        return outcome

    group_id: int | None = None
    if len(observed) > 1:
        try:
            group_id = repo.ensure_split_group(
                package_name,
                context={
                    "event": "harvest.replay.ensure_split_group",
                    "package_name": package_name,
                    "session_stamp": session_label,
                },
            )
        except Exception as exc:
            outcome.status = "failed"
            outcome.failure_reasons.append(f"split_group_failed:{exc}")
            return outcome

    for artifact in observed:
        artifact_result = _replay_artifact(
            repo,
            package_name=package_name,
            package=package,
            inventory=inventory,
            artifact=artifact,
            app_id=app_id,
            group_id=group_id,
            storage_root_id=storage_root_id,
        )
        outcome.artifact_results.append(artifact_result)
        if artifact_result.status == "replayed":
            outcome.replayed_artifacts += 1
        elif artifact_result.status == "skipped":
            outcome.skipped_artifacts += 1
            if artifact_result.reason:
                outcome.failure_reasons.append(artifact_result.reason)
        else:
            outcome.failed_artifacts += 1
            if artifact_result.reason:
                outcome.failure_reasons.append(artifact_result.reason)

    if outcome.failed_artifacts:
        outcome.status = "partial" if outcome.replayed_artifacts else "failed"
    else:
        outcome.status = "replayed" if outcome.replayed_artifacts else "skipped"

    updated = _record_repair_result(payload, outcome)
    if updated:
        common.write_json_manifest(manifest_path, payload)
        outcome.updated_manifest = True
    return outcome


def replay_manifests(
    root: Path,
    *,
    session_label: str | None = None,
    package_names: set[str] | None = None,
    force: bool = False,
    repo_module: ModuleType | object | None = None,
    limit: int | None = None,
) -> list[ReplayPackageOutcome]:
    results: list[ReplayPackageOutcome] = []
    seen = 0
    for manifest_path in find_package_manifests(root):
        payload = load_package_manifest(manifest_path)
        package = dict(payload.get("package") or {})
        if session_label and str(package.get("session_label") or "").strip() != session_label:
            continue
        if package_names and str(package.get("package_name") or "").strip() not in package_names:
            continue
        seen += 1
        if limit is not None and seen > limit:
            break
        results.append(
            replay_package_manifest(
                manifest_path,
                repo_module=repo_module,
                force=force,
            )
        )
    return results


def _replay_artifact(
    repo: ModuleType | object,
    *,
    package_name: str,
    package: dict[str, Any],
    inventory: dict[str, Any],
    artifact: dict[str, Any],
    app_id: int,
    group_id: int | None,
    storage_root_id: int,
) -> ReplayArtifactOutcome:
    file_name = str(artifact.get("file_name") or "").strip()
    local_artifact_path = str(artifact.get("local_artifact_path") or "").strip()
    canonical_store_path = str(artifact.get("canonical_store_path") or "").strip()
    observed_source_path = str(artifact.get("observed_source_path") or "").strip() or None
    if not file_name:
        return ReplayArtifactOutcome(file_name="", status="failed", reason="file_name_missing")
    if not local_artifact_path and not canonical_store_path:
        return ReplayArtifactOutcome(file_name=file_name, status="failed", reason="artifact_path_missing")

    absolute_path = _resolve_absolute_artifact_path(
        local_artifact_path=local_artifact_path,
        canonical_store_path=canonical_store_path,
    )
    if not absolute_path.exists():
        return ReplayArtifactOutcome(file_name=file_name, status="failed", reason="artifact_file_missing")

    local_rel_path = _manifest_local_rel_path(
        local_artifact_path=local_artifact_path,
        canonical_store_path=canonical_store_path,
        absolute_path=absolute_path,
    )
    sha256 = str(artifact.get("sha256") or "").strip()
    if not sha256:
        sha256 = common.compute_hashes(absolute_path)["sha256"]

    file_size = artifact.get("file_size")
    if not isinstance(file_size, int):
        try:
            file_size = int(file_size)
        except Exception:
            file_size = absolute_path.stat().st_size

    try:
        record = repo.ApkRecord(
            package_name=package_name,
            app_id=app_id,
            file_name=file_name,
            file_size=file_size,
            is_system=str(inventory.get("category") or "").strip().lower() != "user",
            installer=str(inventory.get("installer") or "").strip() or None,
            version_name=str(package.get("version_name") or "").strip() or None,
            version_code=str(package.get("version_code") or "").strip() or None,
            sha256=sha256,
            device_serial=str(package.get("device_serial") or "").strip() or None,
            harvested_at=str(artifact.get("pulled_at") or "").strip() or None,
            is_split_member=not bool(artifact.get("is_base")),
            split_group_id=group_id,
        )
        apk_id = repo.upsert_apk_record(
            record,
            context={
                "event": "harvest.replay.upsert_apk_record",
                "package_name": package_name,
                "artifact_path": observed_source_path,
                "sha256": sha256,
            },
        )
        repo.upsert_artifact_path(
            apk_id,
            storage_root_id=storage_root_id,
            local_rel_path=local_rel_path,
            context={
                "event": "harvest.replay.upsert_artifact_path",
                "package_name": package_name,
                "apk_id": apk_id,
            },
        )
        if observed_source_path:
            repo.upsert_source_path(
                apk_id,
                observed_source_path,
                context={
                    "event": "harvest.replay.upsert_source_path",
                    "package_name": package_name,
                    "apk_id": apk_id,
                },
            )
        return ReplayArtifactOutcome(file_name=file_name, status="replayed", apk_id=int(apk_id))
    except Exception as exc:
        return ReplayArtifactOutcome(file_name=file_name, status="failed", reason=str(exc))


def _ensure_storage_root_id(repo: ModuleType | object) -> int:
    host_name, data_root = common.resolve_storage_root()
    return int(
        repo.ensure_storage_root(
            host_name,
            data_root,
            context={
                "event": "harvest.replay.ensure_storage_root",
                "host_name": host_name,
                "data_root": data_root,
            },
        )
    )


def _resolve_absolute_artifact_path(*, local_artifact_path: str, canonical_store_path: str) -> Path:
    if canonical_store_path:
        path = Path(canonical_store_path)
        if not path.is_absolute():
            path = Path.cwd() / canonical_store_path
        if path.exists():
            return path.resolve()
    path = Path(local_artifact_path)
    if path.is_absolute():
        return path
    _, data_root = common.resolve_storage_root()
    return (Path(data_root) / path).resolve()


def _manifest_local_rel_path(*, local_artifact_path: str, canonical_store_path: str, absolute_path: Path) -> str:
    if canonical_store_path:
        path = Path(canonical_store_path)
        return path.as_posix() if not path.is_absolute() else artifact_store.repo_relative_path(absolute_path)
    path = Path(local_artifact_path)
    if not path.is_absolute():
        return path.as_posix()
    return common.normalise_local_path(absolute_path)


def _record_repair_result(payload: dict[str, Any], outcome: ReplayPackageOutcome) -> bool:
    repairs = payload.setdefault("repairs", [])
    if not isinstance(repairs, list):
        payload["repairs"] = repairs = []
    repairs.append(
        {
            "action": "db_mirror_replay",
            "repaired_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "status": outcome.status,
            "replayed_artifacts": outcome.replayed_artifacts,
            "skipped_artifacts": outcome.skipped_artifacts,
            "failed_artifacts": outcome.failed_artifacts,
            "failure_reasons": list(dict.fromkeys(outcome.failure_reasons)),
        }
    )
    if outcome.succeeded:
        status = payload.setdefault("status", {})
        if isinstance(status, dict):
            status["persistence_status"] = "mirrored"
        return True
    return True


def _load_repo_module() -> ModuleType | None:
    try:
        from scytaledroid.Database.db_func.harvest import apk_repository as repo
    except Exception:
        return None
    return repo


__all__ = [
    "ReplayArtifactOutcome",
    "ReplayPackageOutcome",
    "find_package_manifests",
    "load_package_manifest",
    "replay_manifests",
    "replay_package_manifest",
]
