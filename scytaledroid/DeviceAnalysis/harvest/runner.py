"""Execute planned APK harvest operations."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Mapping, Optional, Sequence, Tuple

from scytaledroid.Database.db_func.harvest import apk_repository as repo
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import common
from .common import (
    DedupeTracker,
    HarvestOptions,
    adb_pull,
    cleanup_duplicate,
    compute_hashes,
    format_file_size,
    inventory_payload,
    is_system_package,
    load_options,
    normalise_local_path,
    resolve_storage_root,
    write_metadata_sidecar,
)
from .models import ArtifactError, ArtifactPlan, ArtifactResult, PackagePlan, PullResult


def execute_harvest(
    serial: str,
    adb_path: str,
    dest_root: Path,
    session_stamp: str,
    plans: Sequence[PackagePlan],
    config: object,
    *,
    verbose: bool = False,
    pull_mode: str = "legacy",
) -> List[PullResult]:
    """Execute the provided harvest plan and return per-package results."""

    options = load_options(config, pull_mode=pull_mode)
    tracker = DedupeTracker(options)
    storage_root_id: Optional[int]
    if options.write_db:
        host_name, data_root = resolve_storage_root()
        storage_root_id = repo.ensure_storage_root(host_name, data_root)
    else:
        storage_root_id = None
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
                options=options,
                tracker=tracker,
                storage_root_id=storage_root_id if storage_root_id is not None else 0,
                package_index=index,
                package_total=total,
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
    options: HarvestOptions,
    tracker: DedupeTracker,
    storage_root_id: Optional[int],
    package_index: int,
    package_total: int,
) -> PullResult:
    result = PullResult(plan=plan)

    if plan.skip_reason:
        result.skipped.append(plan.skip_reason)
        return result

    inventory = plan.inventory
    package_name = inventory.package_name
    package_dir = dest_root / package_name / session_stamp
    package_dir.mkdir(parents=True, exist_ok=True)

    app_id: Optional[int] = None
    if options.write_db:
        try:
            app_id = repo.ensure_app_definition(package_name, inventory.app_label)
        except Exception as exc:
            message = f"Failed to ensure app definition for {package_name}: {exc}"
            log.error(message, category="database")
            result.skipped.append("app_definition_failed")
            return result

    group_id: Optional[int] = None
    if options.write_db and len(plan.artifacts) > 1:
        try:
            group_id = repo.ensure_split_group(package_name)
        except Exception as exc:
            message = f"Failed to ensure split group for {package_name}: {exc}"
            log.error(message, category="database")
            result.errors.append(ArtifactError(source_path="split-group", reason=str(exc)))
            return result

    _print_package_header(plan, package_index, package_total)

    artifact_total = len(plan.artifacts)
    package_stats = {"saved": 0, "skipped": 0, "errors": 0, "bytes": 0}
    for artifact_index, artifact in enumerate(plan.artifacts, start=1):
        artifact_result, skip_reason = _pull_and_record(
            serial=serial,
            adb_path=adb_path,
            package_dir=package_dir,
            plan=plan,
            artifact=artifact,
            app_id=app_id,
            group_id=group_id,
            verbose=verbose,
            options=options,
            tracker=tracker,
            session_stamp=session_stamp,
            storage_root_id=storage_root_id,
            artifact_index=artifact_index,
            artifact_total=artifact_total,
            verbose_output=verbose,
        )
        if skip_reason:
            result.skipped.append(skip_reason)
            package_stats["skipped"] += 1
        elif isinstance(artifact_result, ArtifactResult):
            result.ok.append(artifact_result)
            package_stats["saved"] += 1
            try:
                package_stats["bytes"] += artifact_result.dest_path.stat().st_size
            except FileNotFoundError:
                pass
        elif isinstance(artifact_result, ArtifactError):
            result.errors.append(artifact_result)
            package_stats["errors"] += 1

    _print_package_footer(plan, package_stats)
    return result


def _pull_and_record(
    *,
    serial: str,
    adb_path: str,
    package_dir: Path,
    plan: PackagePlan,
    artifact: ArtifactPlan,
    app_id: Optional[int],
    group_id: Optional[int],
    verbose: bool,
    options: HarvestOptions,
    tracker: DedupeTracker,
    session_stamp: str,
    storage_root_id: Optional[int],
    artifact_index: int,
    artifact_total: int,
    verbose_output: bool,
) -> Tuple[ArtifactResult | ArtifactError | None, Optional[str]]:
    dest_path = package_dir / artifact.file_name
    pull_result = adb_pull(
        adb_path=adb_path,
        serial=serial,
        source_path=artifact.source_path,
        dest_path=dest_path,
        package_name=plan.inventory.package_name,
        verbose=verbose_output,
    )
    if isinstance(pull_result, ArtifactError):
        common.print_artifact_status(
            plan.inventory.display_name(),
            artifact.file_name,
            index=artifact_index,
            total=artifact_total,
            suffix=pull_result.reason,
            level="error",
        )
        return pull_result, None

    try:
        hashes = compute_hashes(dest_path)
    except FileNotFoundError as exc:  # pragma: no cover - IO race
        return ArtifactError(source_path=artifact.source_path, reason=str(exc)), None

    keep, occurrence = tracker.register(hashes["sha256"])
    if not keep:
        cleanup_duplicate(dest_path)
        common.print_artifact_status(
            plan.inventory.display_name(),
            artifact.file_name,
            index=artifact_index,
            total=artifact_total,
            suffix="skipped duplicate (sha256 match)",
            level="warn",
        )
        return None, "dedupe_sha256"

    local_rel_path = normalise_local_path(dest_path)

    apk_id: Optional[int] = None
    if options.write_db:
        record = repo.ApkRecord(
            package_name=plan.inventory.package_name,
            app_id=app_id,
            file_name=dest_path.name,
            file_size=dest_path.stat().st_size,
            is_system=is_system_package(plan.inventory),
            installer=plan.inventory.installer,
            version_name=plan.inventory.version_name,
            version_code=plan.inventory.version_code,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            device_serial=serial,
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
            return ArtifactError(source_path=artifact.source_path, reason=str(exc)), None

        if storage_root_id is not None:
            try:
                repo.upsert_artifact_path(
                    apk_id,
                    storage_root_id=storage_root_id,
                    local_rel_path=local_rel_path,
                )
            except Exception as exc:
                log.warning(
                    f"Failed to persist artifact path for apk_id={apk_id}: {exc}",
                    category="database",
                )

        if apk_id and artifact.source_path:
            try:
                repo.upsert_source_path(apk_id, artifact.source_path)
            except Exception as exc:
                log.warning(
                    f"Failed to persist source path for apk_id={apk_id}: {exc}",
                    category="database",
                )

    artifact_payload = {
        "source_path": artifact.source_path,
        "is_split_member": artifact.is_split_member,
        "split_group_id": group_id,
    }
    inventory_meta = inventory_payload(plan.inventory)
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
            serial=serial,
            session_stamp=session_stamp,
            options=options,
            extra=extra_meta,
        )
    except Exception as exc:  # pragma: no cover - filesystem issues
        log.warning(
            f"Failed to write metadata sidecar for {dest_path}: {exc}",
            category="filesystem",
        )

    file_size_text = common.format_file_size(dest_path.stat().st_size)
    common.print_artifact_status(
        plan.inventory.display_name(),
        artifact.file_name,
        index=artifact_index,
        total=artifact_total,
        suffix=f"saved ({file_size_text})",
        level="success",
    )

    return (
        ArtifactResult(
            file_name=dest_path.name,
            apk_id=apk_id,
            dest_path=dest_path,
            source_path=artifact.source_path,
            sha256=hashes.get("sha256"),
        ),
        None,
    )


def _print_progress(index: int, total: int, plan: PackagePlan) -> None:
    artifact_count = len(plan.artifacts)
    suffix = "artifact" if artifact_count == 1 else "artifacts"
    message = (
        f"[{index:>3}/{total}] {plan.inventory.package_name} "
        f"({artifact_count} {suffix})"
    )
    print(status_messages.status(message))


def _print_package_header(plan: PackagePlan, package_index: int, package_total: int) -> None:
    label = plan.inventory.display_name()
    artifact_total = len(plan.artifacts)
    detail = f"{artifact_total} artifact(s)"
    if package_index > 1:
        print()
    print(
        status_messages.status(
            f"→ Package {package_index}/{package_total}: {label} ({detail})",
            level="info",
        )
    )


def _print_package_footer(plan: PackagePlan, stats: Mapping[str, int]) -> None:
    saved = int(stats.get("saved", 0) or 0)
    skipped = int(stats.get("skipped", 0) or 0)
    errors = int(stats.get("errors", 0) or 0)
    total_bytes = int(stats.get("bytes", 0) or 0)

    parts: list[str] = []
    parts.append(
        f"saved {saved} artifact{'s' if saved != 1 else ''}"
    )
    parts.append(f"skipped {skipped}")
    parts.append(f"errors {errors}")
    if total_bytes > 0:
        parts.append(format_file_size(total_bytes))

    summary = " • ".join(parts)
    package_label = plan.inventory.display_name()

    if errors:
        level = "error"
    elif skipped and not saved:
        level = "warn"
    else:
        level = "success"

    print(
        status_messages.status(
            f"    ↳ Summary: {package_label} — {summary}",
            level=level,
        )
    )

    log.info(
        (
            f"Harvest summary for {plan.inventory.package_name}: "
            f"saved={saved}, skipped={skipped}, errors={errors}, bytes={total_bytes}"
        ),
        category="device",
    )


__all__ = ["execute_harvest"]
