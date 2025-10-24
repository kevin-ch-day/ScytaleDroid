"""Quick APK harvest implementation using live device state."""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from scytaledroid.Database.db_func.harvest import apk_repository as repo
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils import logging_engine

from . import rules
from . import common
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


def _print_package_header(plan: PackagePlan, package_index: int, package_total: int, artifact_total: int) -> None:
    label = plan.inventory.display_name()
    detail = f"{artifact_total} artifact(s)"
    if package_index > 1:
        print()
    print(
        status_messages.status(
            f"→ Package {package_index}/{package_total}: {label} ({detail})",
            level="info",
        )
    )




def quick_harvest(
    packages: Sequence[PackagePlan],
    *,
    adb_path: str,
    dest_root: Path,
    session_stamp: str,
    config: object,
    serial: Optional[str] = None,
    verbose: bool = False,
    run_id: Optional[str] = None,
    harvest_logger: Optional[logging_engine.ContextAdapter] = None,
) -> List[PullResult]:
    """Execute a lightweight harvest by resolving paths via ``pm path``."""

    resolved_serial = serial or dest_root.name
    dest_root.mkdir(parents=True, exist_ok=True)

    options = load_options(config, pull_mode="quick")
    tracker = DedupeTracker(options)

    run_identifier = run_id or f"{resolved_serial}-{session_stamp}"
    base_context: Dict[str, object] = {
        "run_id": run_identifier,
        "device_serial": resolved_serial,
        "session_stamp": session_stamp,
        "pull_mode": "quick",
    }

    log_adapter = harvest_logger
    close_logger = False
    if log_adapter is None:
        log_adapter = log.harvest_adapter(
            run_identifier,
            started_at=datetime.utcnow(),
            context=base_context,
        )
        close_logger = True
    else:
        base_context.update({k: v for k, v in getattr(log_adapter, "extra", {}).items() if k not in base_context})

    def _emit(
        level: str,
        event: str,
        extra: Optional[Mapping[str, object]] = None,
        message: Optional[str] = None,
    ) -> None:
        if log_adapter is None:
            return
        payload = dict(base_context)
        if extra:
            payload.update({k: v for k, v in extra.items() if v is not None})
        payload["event"] = event
        record_message = message or event
        log_method = getattr(log_adapter, level)
        log_method(record_message, extra=logging_engine.ensure_trace(payload))

    stats: Dict[str, int] = {
        "packages_total": len(packages),
        "packages_skipped": 0,
        "artifacts_planned": 0,
        "artifacts_written": 0,
        "artifacts_failed": 0,
        "artifacts_skipped": 0,
        "bytes_written": 0,
        "db_storage_root": 0,
        "db_app_definitions": 0,
        "db_apk_rows": 0,
        "db_split_groups": 0,
        "db_artifact_paths": 0,
        "db_source_paths": 0,
        "db_errors": 0,
    }

    _emit(
        "info",
        "harvest.start",
        extra={"package_total": stats["packages_total"], "write_db": options.write_db},
    )

    if options.write_db:
        host_name, data_root = resolve_storage_root()
        try:
            storage_root_id = repo.ensure_storage_root(
                host_name,
                data_root,
                context={**base_context, "event": "storage_root.ensure"},
            )
            stats["db_storage_root"] += 1
        except Exception as exc:
            stats["db_errors"] += 1
            _emit(
                "error",
                "harvest.db.error",
                extra={"stage": "ensure_storage_root", "error": str(exc)},
            )
            raise
    else:
        storage_root_id = None

    results: List[PullResult] = []
    total_packages = len(packages)

    try:
        for package_index, plan in enumerate(packages, start=1):
            result = PullResult(plan=plan)
            package_name = plan.inventory.package_name
            skip_reason = plan.skip_reason
            if skip_reason and skip_reason != "no_paths":
                result.skipped.append(skip_reason)
                stats["packages_skipped"] += 1
                _emit(
                    "info",
                    "harvest.package.skipped",
                    extra={
                        "package_name": package_name,
                        "skip_reason": skip_reason,
                        "package_index": package_index,
                        "package_total": total_packages,
                    },
                )
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
                stats["artifacts_failed"] += 1
                _emit(
                    "error",
                    "harvest.package.error",
                    extra={
                        "package_name": package_name,
                        "stage": "pm_path",
                        "error": error,
                    },
                )
                results.append(result)
                continue
            if not paths:
                result.skipped.append("no_paths")
                stats["packages_skipped"] += 1
                stats["artifacts_skipped"] += 1
                _emit(
                    "info",
                    "harvest.package.skipped",
                    extra={
                        "package_name": package_name,
                        "skip_reason": "no_paths",
                        "package_index": package_index,
                        "package_total": total_packages,
                    },
                )
                results.append(result)
                continue

            artifact_plans = [
                _build_artifact_plan(inventory, source_path)
                for source_path in paths
            ]
            plan.artifacts = artifact_plans
            plan.total_paths = len(paths)
            plan.skip_reason = None
            stats["artifacts_planned"] += len(artifact_plans)

            app_id: Optional[int] = None
            if options.write_db:
                try:
                    app_id = repo.ensure_app_definition(
                        inventory.package_name,
                        inventory.app_label,
                        context={**base_context, "package_name": package_name},
                    )
                    stats["db_app_definitions"] += 1
                except Exception as exc:
                    log.error(
                        f"Failed to ensure app definition for {inventory.package_name}: {exc}",
                        category="database",
                    )
                    stats["db_errors"] += 1
                    _emit(
                        "error",
                        "harvest.db.error",
                        extra={
                            "package_name": package_name,
                            "stage": "ensure_app_definition",
                            "error": str(exc),
                        },
                    )
                    result.skipped.append("app_definition_failed")
                    stats["packages_skipped"] += 1
                    results.append(result)
                    continue

            group_id: Optional[int] = None
            if options.write_db and len(artifact_plans) > 1:
                try:
                    group_id = repo.ensure_split_group(
                        inventory.package_name,
                        context={**base_context, "package_name": package_name},
                    )
                    stats["db_split_groups"] += 1
                except Exception as exc:
                    log.error(
                        f"Failed to ensure split group for {inventory.package_name}: {exc}",
                        category="database",
                    )
                    stats["db_errors"] += 1
                    _emit(
                        "error",
                        "harvest.db.error",
                        extra={
                            "package_name": package_name,
                            "stage": "ensure_split_group",
                            "error": str(exc),
                        },
                    )
                    result.errors.append(ArtifactError(source_path="split-group", reason=str(exc)))
                    results.append(result)
                    continue

            artifact_total = len(artifact_plans)
            _print_package_header(plan, package_index, total_packages, artifact_total)
            _emit(
                "info",
                "harvest.package.start",
                extra={
                    "package_name": package_name,
                    "package_index": package_index,
                    "package_total": total_packages,
                    "artifact_total": artifact_total,
                },
            )

            package_stats = {"saved": 0, "skipped": 0, "errors": 0, "bytes": 0}

            for artifact_index, artifact in enumerate(artifact_plans, start=1):
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
                    common.print_artifact_status(
                        inventory.display_name(),
                        artifact.file_name,
                        index=artifact_index,
                        total=artifact_total,
                        suffix=pull_outcome.reason,
                        level="error",
                    )
                    result.errors.append(pull_outcome)
                    package_stats["errors"] += 1
                    stats["artifacts_failed"] += 1
                    _emit(
                        "error",
                        "harvest.artifact.error",
                        extra={
                            "package_name": package_name,
                            "artifact_path": artifact.source_path,
                            "file_name": artifact.file_name,
                            "error": pull_outcome.reason,
                        },
                    )
                    continue

                try:
                    hashes = compute_hashes(dest_path)
                except FileNotFoundError as exc:
                    result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                    package_stats["errors"] += 1
                    stats["artifacts_failed"] += 1
                    _emit(
                        "error",
                        "harvest.artifact.error",
                        extra={
                            "package_name": package_name,
                            "artifact_path": artifact.source_path,
                            "file_name": artifact.file_name,
                            "error": str(exc),
                        },
                    )
                    continue

                keep, occurrence = tracker.register(hashes["sha256"])
                if not keep:
                    cleanup_duplicate(dest_path)
                    common.print_artifact_status(
                        inventory.display_name(),
                        artifact.file_name,
                        index=artifact_index,
                        total=artifact_total,
                        suffix="skipped duplicate (sha256 match)",
                        level="warn",
                    )
                    result.skipped.append("dedupe_sha256")
                    package_stats["skipped"] += 1
                    stats["artifacts_skipped"] += 1
                    _emit(
                        "info",
                        "harvest.artifact.skipped",
                        extra={
                            "package_name": package_name,
                            "artifact_path": artifact.source_path,
                            "file_name": artifact.file_name,
                            "skip_reason": "dedupe_sha256",
                        },
                    )
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
                        harvested_at=datetime.utcnow(),
                        is_split_member=artifact.is_split_member,
                        split_group_id=group_id,
                    )
                    try:
                        apk_id = repo.upsert_apk_record(
                            record,
                            context={
                                **base_context,
                                "package_name": package_name,
                                "artifact_path": artifact.source_path,
                                "sha256": hashes["sha256"],
                            },
                        )
                        stats["db_apk_rows"] += 1
                    except Exception as exc:
                        log.error(
                            f"Failed to upsert APK metadata for {inventory.package_name} ({artifact.source_path}): {exc}",
                            category="database",
                        )
                        stats["db_errors"] += 1
                        _emit(
                            "error",
                            "harvest.db.error",
                            extra={
                                "package_name": package_name,
                                "artifact_path": artifact.source_path,
                                "stage": "upsert_apk_record",
                                "error": str(exc),
                            },
                        )
                        result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                        package_stats["errors"] += 1
                        stats["artifacts_failed"] += 1
                        continue

                    if storage_root_id is not None:
                        try:
                            repo.upsert_artifact_path(
                                apk_id,
                                storage_root_id=storage_root_id,
                                local_rel_path=local_rel_path,
                                context={
                                    **base_context,
                                    "package_name": package_name,
                                    "artifact_path": artifact.source_path,
                                    "apk_id": apk_id,
                                },
                            )
                            stats["db_artifact_paths"] += 1
                        except Exception as exc:
                            log.warning(
                                f"Failed to persist artifact path for {inventory.package_name}: {exc}",
                                category="database",
                            )
                            stats["db_errors"] += 1
                            _emit(
                                "warning",
                                "harvest.db.error",
                                extra={
                                    "package_name": package_name,
                                    "artifact_path": artifact.source_path,
                                    "stage": "upsert_artifact_path",
                                    "error": str(exc),
                                },
                            )
                            result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                            package_stats["errors"] += 1
                            stats["artifacts_failed"] += 1
                            continue

                    if apk_id and artifact.source_path:
                        try:
                            repo.upsert_source_path(
                                apk_id,
                                artifact.source_path,
                                context={
                                    **base_context,
                                    "package_name": package_name,
                                    "artifact_path": artifact.source_path,
                                    "apk_id": apk_id,
                                },
                            )
                            stats["db_source_paths"] += 1
                        except Exception as exc:
                            log.warning(
                                f"Failed to persist source path for {inventory.package_name}: {exc}",
                                category="database",
                            )
                            stats["db_errors"] += 1
                            _emit(
                                "warning",
                                "harvest.db.error",
                                extra={
                                    "package_name": package_name,
                                    "artifact_path": artifact.source_path,
                                    "stage": "upsert_source_path",
                                    "error": str(exc),
                                },
                            )
                            result.errors.append(ArtifactError(source_path=artifact.source_path, reason=str(exc)))
                            package_stats["errors"] += 1
                            stats["artifacts_failed"] += 1
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
                except Exception as exc:
                    log.warning(
                        f"Failed to write metadata sidecar for {dest_path}: {exc}",
                        category="filesystem",
                    )

                file_size = dest_path.stat().st_size if dest_path.exists() else 0
                common.print_artifact_status(
                    inventory.display_name(),
                    artifact.file_name,
                    index=artifact_index,
                    total=artifact_total,
                    suffix=f"saved ({common.format_file_size(file_size)})",
                    level="success",
                )

                package_stats["saved"] += 1
                package_stats["bytes"] += file_size
                stats["artifacts_written"] += 1
                stats["bytes_written"] += file_size

                result.ok.append(
                    ArtifactResult(
                        file_name=dest_path.name,
                        apk_id=apk_id,
                        dest_path=dest_path,
                        source_path=artifact.source_path,
                        sha256=hashes.get("sha256"),
                    )
                )

                _emit(
                    "info",
                    "harvest.artifact.saved",
                    extra={
                        "package_name": package_name,
                        "artifact_path": artifact.source_path,
                        "file_name": artifact.file_name,
                        "bytes": file_size,
                        "apk_id": apk_id,
                    },
                )

            _emit(
                "info",
                "harvest.package.summary",
                extra={
                    "package_name": package_name,
                    "saved": package_stats["saved"],
                    "skipped": package_stats["skipped"],
                    "errors": package_stats["errors"],
                    "bytes": package_stats["bytes"],
                },
            )

            results.append(result)
    finally:
        summary = {
            "package_total": stats["packages_total"],
            "packages_skipped": stats["packages_skipped"],
            "packages_processed": stats["packages_total"] - stats["packages_skipped"],
            "artifacts_planned": stats["artifacts_planned"],
            "artifacts_written": stats["artifacts_written"],
            "artifacts_failed": stats["artifacts_failed"],
            "artifacts_skipped": stats["artifacts_skipped"],
            "bytes_written": stats["bytes_written"],
            "db_storage_root": stats["db_storage_root"],
            "db_app_definitions": stats["db_app_definitions"],
            "db_apk_rows": stats["db_apk_rows"],
            "db_split_groups": stats["db_split_groups"],
            "db_artifact_paths": stats["db_artifact_paths"],
            "db_source_paths": stats["db_source_paths"],
            "db_errors": stats["db_errors"],
        }
        _emit("info", "harvest.summary", extra=summary)
        log.info(
            "Quick harvest completed",
            category="device",
            extra={**summary, **base_context},
        )
        if close_logger:
            log.close_harvest_adapter(run_identifier)

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
