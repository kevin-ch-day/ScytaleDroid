"""Execute planned APK harvest operations."""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Sequence

from scytaledroid.Database.db_func import apk_repository as repo
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .models import ArtifactError, ArtifactPlan, ArtifactResult, PackagePlan, PullResult


def execute_harvest(
    serial: str,
    adb_path: str,
    dest_root: Path,
    session_stamp: str,
    plans: Sequence[PackagePlan],
    *,
    verbose: bool = False,
) -> List[PullResult]:
    """Execute the provided harvest plan and return per-package results."""

    results: List[PullResult] = []
    total = len(plans)
    for index, plan in enumerate(plans, start=1):
        if not verbose:
            _print_progress(index, total, plan)
        results.append(
            _execute_package_plan(
                serial=serial,
                adb_path=adb_path,
                dest_root=dest_root,
                session_stamp=session_stamp,
                plan=plan,
                verbose=verbose,
            )
        )
    return results


def _execute_package_plan(
    *,
    serial: str,
    adb_path: str,
    dest_root: Path,
    session_stamp: str,
    plan: PackagePlan,
    verbose: bool,
) -> PullResult:
    result = PullResult(plan=plan)

    if plan.skip_reason:
        result.skipped.append(plan.skip_reason)
        return result

    inventory = plan.inventory
    package_name = inventory.package_name
    package_dir = dest_root / package_name / session_stamp
    package_dir.mkdir(parents=True, exist_ok=True)

    try:
        app_id = repo.ensure_app_definition(package_name, inventory.app_label)
    except Exception as exc:
        message = f"Failed to ensure app definition for {package_name}: {exc}"
        log.error(message, category="database")
        result.skipped.append("app_definition_failed")
        return result

    group_id = None
    if len(plan.artifacts) > 1:
        try:
            group_id = repo.ensure_split_group(package_name)
        except Exception as exc:
            message = f"Failed to ensure split group for {package_name}: {exc}"
            log.error(message, category="database")
            result.errors.append(ArtifactError(source_path="split-group", reason=str(exc)))
            return result

    for artifact in plan.artifacts:
        artifact_result = _pull_and_record(
            serial=serial,
            adb_path=adb_path,
            package_dir=package_dir,
            plan=plan,
            artifact=artifact,
            app_id=app_id,
            group_id=group_id,
            verbose=verbose,
        )
        if isinstance(artifact_result, ArtifactResult):
            result.ok.append(artifact_result)
        else:
            result.errors.append(artifact_result)

    return result


def _pull_and_record(
    *,
    serial: str,
    adb_path: str,
    package_dir: Path,
    plan: PackagePlan,
    artifact: ArtifactPlan,
    app_id: int,
    group_id: int | None,
    verbose: bool,
):
    dest_path = package_dir / artifact.file_name
    pull_result = _ensure_local_copy(
        adb_path=adb_path,
        serial=serial,
        source_path=artifact.source_path,
        dest_path=dest_path,
        verbose=verbose,
        package_name=plan.inventory.package_name,
    )
    if isinstance(pull_result, ArtifactError):
        return pull_result

    hashes = _compute_hashes(dest_path)
    record = repo.ApkRecord(
        package_name=plan.inventory.package_name,
        app_id=app_id,
        file_name=dest_path.name,
        file_size=dest_path.stat().st_size,
        is_system=(plan.inventory.category or "").lower() != "user",
        installer=plan.inventory.installer,
        version_name=plan.inventory.version_name,
        version_code=plan.inventory.version_code,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        device_serial=serial,
        source_path=artifact.source_path,
        local_path=str(dest_path.resolve()),
        harvested_at=datetime.utcnow(),
        is_split_member=artifact.is_split_member,
        split_group_id=group_id,
    )

    try:
        apk_id = repo.upsert_apk_record(record)
    except Exception as exc:
        message = (
            f"Failed to upsert APK metadata for {plan.inventory.package_name} "
            f"({artifact.source_path}): {exc}"
        )
        log.error(message, category="database")
        return ArtifactError(source_path=artifact.source_path, reason=str(exc))

    return ArtifactResult(
        file_name=dest_path.name,
        apk_id=apk_id,
        dest_path=dest_path,
        source_path=artifact.source_path,
    )


def _ensure_local_copy(
    *,
    adb_path: str,
    serial: str,
    source_path: str,
    dest_path: Path,
    package_name: str,
    verbose: bool,
):
    if dest_path.exists():
        return True

    command = [adb_path, "-s", serial, "pull", source_path, str(dest_path)]
    if verbose:
        print(status_messages.status(f"Executing: {' '.join(command)}", level="info"))
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except Exception as exc:
        log.error(f"adb pull execution failed for {package_name}: {exc}", category="device")
        return ArtifactError(source_path=source_path, reason=str(exc))

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "adb pull failed"
        log.warning(
            f"adb pull returned {completed.returncode} for {package_name}: {stderr}",
            category="device",
        )
        level = "warn" if "permission denied" in stderr.lower() else "error"
        print(status_messages.status(f"adb pull failed: {stderr}", level=level))
        reason = "permission denied" if "permission denied" in stderr.lower() else stderr
        return ArtifactError(source_path=source_path, reason=reason)

    return True


def _compute_hashes(dest_path: Path) -> Dict[str, str]:
    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    with dest_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def _print_progress(index: int, total: int, plan: PackagePlan) -> None:
    artifact_count = len(plan.artifacts)
    suffix = "artifact" if artifact_count == 1 else "artifacts"
    message = (
        f"[{index:>3}/{total}] {plan.inventory.package_name} "
        f"({artifact_count} {suffix})"
    )
    print(status_messages.status(message))


__all__ = ["execute_harvest"]
