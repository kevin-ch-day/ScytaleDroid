"""Quick APK harvest implementation using live device state."""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from scytaledroid.Database.db_func import apk_repository as repo
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import rules
from .common import (
    DedupeTracker,
    adb_pull,
    cleanup_duplicate,
    compute_hashes,
    inventory_payload as build_inventory_payload,
    is_system_package,
    load_options,
    normalise_local_path,
    resolve_storage_root,
    write_metadata_sidecar,
)
from .models import ArtifactError, ArtifactPlan, ArtifactResult, InventoryRow, PackagePlan, PullResult


def quick_harvest(
    packages: Sequence[PackagePlan],
    *,
    adb_path: str,
    dest_root: Path,
    session_stamp: str,
    config: object,
    serial: Optional[str] = None,
    verbose: bool = False,
) -> List[PullResult]:
    """Execute a lightweight harvest by resolving paths via ``pm path``."""

    resolved_serial = serial or dest_root.name
    dest_root.mkdir(parents=True, exist_ok=True)

    options = load_options(config, pull_mode="quick")
    tracker = DedupeTracker(options)
    if options.write_db:
        host_name, data_root = resolve_storage_root()
        storage_root_id: Optional[int] = repo.ensure_storage_root(host_name, data_root)
    else:
        storage_root_id = None

    results: List[PullResult] = []
    for plan in packages:
        result = PullResult(plan=plan)
        skip_reason = plan.skip_reason
        if skip_reason and skip_reason != "no_paths":
            result.skipped.append(skip_reason)
            results.append(result)
            continue

        inventory = plan.inventory
        package_dir = dest_root / inventory.package_name / session_stamp
        package_dir.mkdir(parents=True, exist_ok=True)

        paths, error = _resolve_package_paths(
            adb_path,
            resolved_serial,
            inventory.package_name,
            verbose=verbose,
        )
        if error:
            log.warning(
                f"pm path failed for {inventory.package_name}: {error}",
                category="device",
            )
            result.errors.append(ArtifactError(source_path="pm path", reason=error))
            results.append(result)
            continue
        if not paths:
            result.skipped.append("no_paths")
            results.append(result)
            continue

        artifact_plans = [
            _build_artifact_plan(inventory, source_path)
            for source_path in paths
        ]
        plan.artifacts = artifact_plans
        plan.total_paths = len(paths)
        plan.skip_reason = None

        app_id: Optional[int] = None
        if options.write_db:
            try:
                app_id = repo.ensure_app_definition(
                    inventory.package_name,
                    inventory.app_label,
                )
            except Exception as exc:  # pragma: no cover - database failures
                log.error(
                    f"Failed to ensure app definition for {inventory.package_name}: {exc}",
                    category="database",
                )
                result.skipped.append("app_definition_failed")
                results.append(result)
                continue

        group_id: Optional[int] = None
        if options.write_db and len(artifact_plans) > 1:
            try:
                group_id = repo.ensure_split_group(inventory.package_name)
            except Exception as exc:  # pragma: no cover - database failures
                log.error(
                    f"Failed to ensure split group for {inventory.package_name}: {exc}",
                    category="database",
                )
                result.errors.append(ArtifactError(source_path="split-group", reason=str(exc)))
                results.append(result)
                continue

        for artifact in artifact_plans:
            artifact_payload = {
                "source_path": artifact.source_path,
                "is_split_member": artifact.is_split_member,
                "split_group_id": group_id,
            }
            dest_path = package_dir / artifact.file_name
            pull_outcome = adb_pull(
                adb_path=adb_path,
                serial=resolved_serial,
                source_path=artifact.source_path,
                dest_path=dest_path,
                package_name=inventory.package_name,
                verbose=verbose,
            )
            if isinstance(pull_outcome, ArtifactError):
                result.errors.append(pull_outcome)
                continue

            try:
                hashes = compute_hashes(dest_path)
            except FileNotFoundError as exc:  # pragma: no cover - IO race
                result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                continue

            keep, occurrence = tracker.register(hashes["sha256"])
            if not keep:
                cleanup_duplicate(dest_path)
                result.skipped.append("dedupe_sha256")
                continue

            apk_id: Optional[int] = None
            if options.write_db:
                local_rel_path = normalise_local_path(dest_path)
                record = repo.ApkRecord(
                    package_name=inventory.package_name,
                    app_id=app_id,
                    file_name=dest_path.name,
                    file_size=dest_path.stat().st_size,
                    is_system=is_system_package(inventory),
                    installer=inventory.installer,
                    version_name=inventory.version_name,
                    version_code=inventory.version_code,
                    md5=hashes["md5"],
                    sha1=hashes["sha1"],
                    sha256=hashes["sha256"],
                    device_serial=resolved_serial,
                    source_path=artifact.source_path,
                    harvested_at=datetime.utcnow(),
                    is_split_member=artifact.is_split_member,
                    split_group_id=group_id,
                )
                try:
                    apk_id = repo.upsert_apk_record(record)
                except Exception as exc:  # pragma: no cover - database failures
                    log.error(
                        f"Failed to upsert APK metadata for {inventory.package_name} ({artifact.source_path}): {exc}",
                        category="database",
                    )
                    result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                    continue

                if storage_root_id is not None:
                    try:
                        repo.upsert_artifact_path(
                            apk_id,
                            storage_root_id=storage_root_id,
                            source_path=artifact.source_path,
                            local_rel_path=local_rel_path,
                        )
                    except Exception as exc:  # pragma: no cover - database failures
                        log.warning(
                            f"Failed to persist artifact path for apk_id={apk_id}: {exc}",
                            category="database",
                        )
                        result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                        continue

            inventory_meta = build_inventory_payload(inventory)
            extra_meta = {
                "apk_id": apk_id,
                "occurrence_index": occurrence,
                "artifact": artifact.artifact,
            }
            try:
                write_metadata_sidecar(
                    dest_path,
                    inventory=inventory_meta,
                    artifact=artifact_payload,
                    hashes=hashes,
                    serial=resolved_serial,
                    session_stamp=session_stamp,
                    options=options,
                    extra=extra_meta,
                )
            except Exception as exc:  # pragma: no cover - filesystem issues
                log.warning(
                    f"Failed to write metadata sidecar for {dest_path}: {exc}",
                    category="filesystem",
                )

            result.ok.append(
                ArtifactResult(
                    file_name=dest_path.name,
                    apk_id=apk_id,
                    dest_path=dest_path,
                    source_path=artifact.source_path,
                    sha256=hashes.get("sha256"),
                )
            )

        results.append(result)

    return results


def _resolve_package_paths(
    adb_path: str,
    serial: str,
    package_name: str,
    *,
    verbose: bool = False,
) -> Tuple[List[str], Optional[str]]:
    command = [adb_path, "-s", serial, "shell", "pm", "path", package_name]
    if verbose:
        print(status_messages.status(f"Executing: {' '.join(command)}", level="info"))
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return [], str(exc)

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        error = stderr or stdout or f"pm path exited with {completed.returncode}"
        return [], error

    paths: List[str] = []
    for raw in completed.stdout.splitlines():
        cleaned = raw.strip()
        if not cleaned:
            continue
        if cleaned.startswith("package:"):
            cleaned = cleaned.split("package:", 1)[1]
        if cleaned:
            paths.append(cleaned)
    return paths, None


def _build_artifact_plan(inventory: InventoryRow, source_path: str) -> ArtifactPlan:
    name = Path(source_path).name
    artifact, is_split_member = _artifact_identifier(name)
    file_name = rules.canonical_filename(
        inventory.package_name,
        inventory.version_code or "unknown",
        artifact,
    )
    return ArtifactPlan(
        source_path=source_path,
        artifact=artifact,
        file_name=file_name,
        is_split_member=is_split_member,
    )


def _artifact_identifier(source_name: str) -> Tuple[str, bool]:
    cleaned = source_name.strip()
    if cleaned.lower() == "base.apk":
        return "base", False
    if cleaned.lower().endswith(".apk"):
        cleaned = cleaned[:-4]
    safe = cleaned.replace(" ", "_") or "artifact"
    return safe, True


__all__ = ["quick_harvest"]
