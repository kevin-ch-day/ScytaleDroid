"""Execute planned APK harvest operations."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Database.db_func.harvest import apk_repository as repo
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger

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
    pull_mode: str = "inventory",
    run_id: str | None = None,
    harvest_logger: logging_engine.ContextAdapter | None = None,
    scope_label: str | None = None,
    snapshot_id: int | None = None,
    snapshot_captured_at: str | None = None,
) -> list[PullResult]:
    """Execute the provided harvest plan and return per-package results."""

    options = load_options(config, pull_mode=pull_mode)
    compact_mode = _compact_mode()
    tracker = DedupeTracker(options)
    resolved_serial = serial or dest_root.name
    run_identifier = run_id or f"{resolved_serial}-{session_stamp}"
    base_context: dict[str, object] = {
        "run_id": run_identifier,
        "device_serial": resolved_serial,
        "session_stamp": session_stamp,
        "pull_mode": pull_mode,
    }
    if snapshot_id is not None:
        base_context["snapshot_id"] = snapshot_id
    if snapshot_captured_at:
        base_context["snapshot_captured_at"] = snapshot_captured_at
    run_ctx = RunContext(
        subsystem="harvest",
        device_serial=resolved_serial,
        device_model=None,
        run_id=run_identifier,
        scope=scope_label,
        profile=pull_mode,
    )
    run_logger = get_run_logger("harvest", run_ctx)
    try:
        run_logger.info(
            "Harvest RUN_START",
            extra={
                "event": log_events.RUN_START,
                "packages_total": len(plans),
                "scope": scope_label,
                "pull_mode": pull_mode,
            },
        )
    except Exception:
        pass

    log_adapter = harvest_logger
    close_logger = False
    if log_adapter is None:
        log_adapter = log.harvest_adapter(
            run_identifier,
            started_at=datetime.now(UTC),
            context={**base_context, "scope_label": scope_label},
        )
        close_logger = True
    else:
        base_context.update({k: v for k, v in getattr(log_adapter, "extra", {}).items() if k not in base_context})

    def _emit(
        level: str,
        event: str,
        extra: Mapping[str, object | None] = None,
        message: str | None = None,
    ) -> None:
        if log_adapter is None:
            return
        payload = dict(base_context)
        if scope_label:
            payload.setdefault("scope_label", scope_label)
        if extra:
            payload.update({k: v for k, v in extra.items() if v is not None})
        payload["event"] = event
        record_message = message or event
        log_method = getattr(log_adapter, level)
        log_method(record_message, extra=logging_engine.ensure_trace(payload))

    stats: dict[str, int] = {
        "packages_total": len(plans),
        "packages_skipped": 0,
        "packages_clean": 0,
        "packages_partial": 0,
        "packages_failed": 0,
        "artifacts_planned": sum(len(plan.artifacts) for plan in plans),
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
        extra={
            "package_total": stats["packages_total"],
            "artifact_total": stats["artifacts_planned"],
            "write_db": options.write_db,
        },
    )

    storage_root_id: int | None
    if options.write_db:
        host_name, data_root = resolve_storage_root()
        try:
            storage_root_id = repo.ensure_storage_root(
                host_name,
                data_root,
                context={**base_context, "event": "storage_root.ensure"},
            )
            stats["db_storage_root"] += 1
            try:
                run_logger = get_run_logger(
                    "harvest",
                    RunContext(
                        subsystem="harvest",
                        device_serial=resolved_serial,
                        device_model=None,
                        run_id=run_identifier,
                        scope=scope_label,
                        profile=pull_mode,
                    ),
                )
                run_logger.info(
                    "Harvest db.persist",
                    extra={
                        "event": log_events.DB_PERSIST,
                        "entity": "harvest.storage_root",
                        "rows": 1,
                        "host": host_name,
                    },
                )
            except Exception:
                pass
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

    results: list[PullResult] = []
    total = len(plans)
    display_total = sum(1 for plan in plans if not plan.skip_reason)
    display_index = 0
    run_failed = False
    run_error: str | None = None

    try:
        for index, plan in enumerate(plans, start=1):
            current_display_index = None
            if not plan.skip_reason:
                display_index += 1
                current_display_index = display_index
            result = _execute_package_plan(
                serial=resolved_serial,
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
                compact_mode=compact_mode,
                display_index=current_display_index,
                display_total=display_total,
                base_context=base_context,
                emit=_emit,
                stats=stats,
                snapshot_id=snapshot_id,
                snapshot_captured_at=snapshot_captured_at,
            )
            results.append(result)
            _update_package_outcome(stats, result)
            _maybe_print_progress(
                result=result,
                stats=stats,
                package_index=index,
                package_total=total,
                display_index=current_display_index,
                display_total=display_total,
            )
    except Exception as exc:
        run_failed = True
        run_error = str(exc)
        _emit(
            "error",
            "harvest.run.failed",
            extra={"error": run_error},
        )
        log.error(
            "Harvest run failed",
            category="device",
            extra={**base_context, "error": run_error},
        )
        raise
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
            "run_failed": run_failed,
            "run_error": run_error,
        }
        _emit("info", "harvest.summary", extra=summary)
        log.info(
            "Harvest run completed",
            category="device",
            extra={**summary, **base_context},
        )
        if _quiet_mode() and stats.get("packages_skipped", 0):
            skip_reasons: Counter[str] = Counter()
            for result in results:
                skip_reasons.update(result.skipped)
            if skip_reasons:
                top = skip_reasons.most_common(2)
                reason_text = ", ".join(f"{reason}={count}" for reason, count in top)
                print(status_messages.status(f"Skip summary: {reason_text}", level="info"))
        if close_logger:
            log.close_harvest_adapter(run_identifier)

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
    storage_root_id: int | None,
    package_index: int,
    package_total: int,
    compact_mode: bool,
    display_index: int | None,
    display_total: int,
    base_context: Mapping[str, object],
    emit: Callable[[str, str, Mapping[str, object | None], str | None], None],
    stats: dict[str, int],
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
) -> PullResult:
    result = PullResult(plan=plan)

    if plan.skip_reason:
        result.skipped.append(plan.skip_reason)
        stats["packages_skipped"] += 1
        emit(
            "info",
            "harvest.package.skipped",
            extra={
                "package_name": plan.inventory.package_name,
                "skip_reason": plan.skip_reason,
                "package_index": package_index,
                "package_total": package_total,
            },
        )
        return result

    inventory = plan.inventory
    package_name = inventory.package_name
    package_dir = dest_root / package_name
    package_dir.mkdir(parents=True, exist_ok=True)

    app_id: int | None = None
    if options.write_db:
        try:
            app_id = repo.ensure_app_definition(
                package_name,
                inventory.app_label,
                profile_key=inventory.profile_key,
                context={**base_context, "package_name": package_name},
            )
            stats["db_app_definitions"] += 1
        except Exception as exc:
            message = f"Failed to ensure app definition for {package_name}: {exc}"
            log.error(message, category="database")
            stats["db_errors"] += 1
            emit(
                "error",
                "harvest.db.error",
                extra={
                    "package_name": package_name,
                    "stage": "ensure_app_definition",
                    "error": str(exc),
                },
            )
            result.skipped.append("app_definition_failed")
            return result

    group_id: int | None = None
    if options.write_db and len(plan.artifacts) > 1:
        try:
            group_id = repo.ensure_split_group(
                package_name,
                context={**base_context, "package_name": package_name},
            )
            stats["db_split_groups"] += 1
        except Exception as exc:
            message = f"Failed to ensure split group for {package_name}: {exc}"
            log.error(message, category="database")
            stats["db_errors"] += 1
            emit(
                "error",
                "harvest.db.error",
                extra={
                    "package_name": package_name,
                    "stage": "ensure_split_group",
                    "error": str(exc),
                },
            )
            result.errors.append(ArtifactError(source_path="split-group", reason=str(exc)))
            return result

    ui_index = display_index or package_index
    ui_total = display_total or package_total
    _print_package_header(plan, ui_index, ui_total, compact_mode=compact_mode)
    emit(
        "info",
        "harvest.package.start",
        extra={
            "package_name": package_name,
            "package_index": package_index,
            "package_total": package_total,
            "artifact_total": len(plan.artifacts),
        },
    )

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
            base_context=base_context,
            emit=emit,
            stats=stats,
            snapshot_id=snapshot_id,
            snapshot_captured_at=snapshot_captured_at,
        )
        if skip_reason:
            result.skipped.append(skip_reason)
            package_stats["skipped"] += 1
            stats["artifacts_skipped"] += 1
        elif isinstance(artifact_result, ArtifactResult):
            result.ok.append(artifact_result)
            package_stats["saved"] += 1
            try:
                package_stats["bytes"] += artifact_result.dest_path.stat().st_size
            except FileNotFoundError:
                pass
            stats["artifacts_written"] += 1
            try:
                stats["bytes_written"] += artifact_result.dest_path.stat().st_size
            except FileNotFoundError:
                pass
        elif isinstance(artifact_result, ArtifactError):
            result.errors.append(artifact_result)
            package_stats["errors"] += 1
            stats["artifacts_failed"] += 1

    _print_package_footer(plan, package_stats, ui_index, ui_total, compact_mode=compact_mode)
    emit(
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
    return result


def _pull_and_record(
    *,
    serial: str,
    adb_path: str,
    package_dir: Path,
    plan: PackagePlan,
    artifact: ArtifactPlan,
    app_id: int | None,
    group_id: int | None,
    verbose: bool,
    options: HarvestOptions,
    tracker: DedupeTracker,
    session_stamp: str,
    storage_root_id: int | None,
    artifact_index: int,
    artifact_total: int,
    verbose_output: bool,
    base_context: Mapping[str, object],
    emit: Callable[[str, str, Mapping[str, object | None], str | None], None],
    stats: dict[str, int],
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
) -> tuple[ArtifactResult | ArtifactError | None, str | None]:
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
        emit(
            "error",
            "harvest.artifact.error",
            extra={
                "package_name": plan.inventory.package_name,
                "artifact_path": artifact.source_path,
                "file_name": artifact.file_name,
                "error": pull_result.reason,
            },
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
        emit(
            "info",
            "harvest.artifact.skipped",
            extra={
                "package_name": plan.inventory.package_name,
                "artifact_path": artifact.source_path,
                "file_name": artifact.file_name,
                "skip_reason": "dedupe_sha256",
            },
        )
        return None, "dedupe_sha256"

    local_rel_path = normalise_local_path(dest_path)

    apk_id: int | None = None
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
            harvested_at=datetime.now(UTC),
            is_split_member=artifact.is_split_member,
            split_group_id=group_id,
        )

        try:
            apk_id = repo.upsert_apk_record(
                record,
                context={
                    **base_context,
                    "package_name": plan.inventory.package_name,
                    "artifact_path": artifact.source_path,
                    "sha256": hashes["sha256"],
                },
            )
            stats["db_apk_rows"] += 1
        except Exception as exc:
            message = (
                f"Failed to upsert APK metadata for {plan.inventory.package_name} "
                f"({artifact.source_path}): {exc}"
            )
            log.error(message, category="database")
            stats["db_errors"] += 1
            emit(
                "error",
                "harvest.db.error",
                extra={
                    "package_name": plan.inventory.package_name,
                    "artifact_path": artifact.source_path,
                    "stage": "upsert_apk_record",
                    "error": str(exc),
                },
            )
            return ArtifactError(source_path=artifact.source_path, reason=str(exc)), None

        if storage_root_id is not None:
            try:
                repo.upsert_artifact_path(
                    apk_id,
                    storage_root_id=storage_root_id,
                    local_rel_path=local_rel_path,
                    context={
                        **base_context,
                        "package_name": plan.inventory.package_name,
                        "artifact_path": artifact.source_path,
                        "apk_id": apk_id,
                    },
                )
                stats["db_artifact_paths"] += 1
            except Exception as exc:
                log.warning(
                    f"Failed to persist artifact path for apk_id={apk_id}: {exc}",
                    category="database",
                )
                stats["db_errors"] += 1
                emit(
                    "warning",
                    "harvest.db.error",
                    extra={
                        "package_name": plan.inventory.package_name,
                        "artifact_path": artifact.source_path,
                        "stage": "upsert_artifact_path",
                        "error": str(exc),
                    },
                )

        if apk_id and artifact.source_path:
            try:
                repo.upsert_source_path(
                    apk_id,
                    artifact.source_path,
                    context={
                        **base_context,
                        "package_name": plan.inventory.package_name,
                        "artifact_path": artifact.source_path,
                        "apk_id": apk_id,
                    },
                )
                stats["db_source_paths"] += 1
            except Exception as exc:
                log.warning(
                    f"Failed to persist source path for apk_id={apk_id}: {exc}",
                    category="database",
                )
                stats["db_errors"] += 1
                emit(
                    "warning",
                    "harvest.db.error",
                    extra={
                        "package_name": plan.inventory.package_name,
                        "artifact_path": artifact.source_path,
                        "stage": "upsert_source_path",
                        "error": str(exc),
                    },
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
    if snapshot_id is not None:
        extra_meta["snapshot_id"] = snapshot_id
    if snapshot_captured_at:
        extra_meta["snapshot_captured_at"] = snapshot_captured_at
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

    emit(
        "info",
        "harvest.artifact.saved",
        extra={
            "package_name": plan.inventory.package_name,
            "artifact_path": artifact.source_path,
            "file_name": dest_path.name,
            "bytes": dest_path.stat().st_size if dest_path.exists() else None,
            "apk_id": apk_id,
        },
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


def _compact_mode() -> bool:
    return os.getenv("SCYTALEDROID_HARVEST_COMPACT", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _quiet_mode() -> bool:
    if _simple_mode():
        return True
    return os.getenv("SCYTALEDROID_HARVEST_QUIET", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _simple_mode() -> bool:
    return os.getenv("SCYTALEDROID_HARVEST_SIMPLE", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _progress_every() -> int:
    value = os.getenv("SCYTALEDROID_HARVEST_PROGRESS_EVERY", "5").strip()
    try:
        return max(int(value), 1)
    except ValueError:
        return 5


def _update_package_outcome(stats: dict[str, int], result: PullResult) -> None:
    if result.skipped and not result.ok and not result.errors:
        return
    if result.errors and result.ok:
        stats["packages_partial"] += 1
    elif result.errors and not result.ok:
        stats["packages_failed"] += 1
    else:
        stats["packages_clean"] += 1


def _maybe_print_progress(
    result: PullResult,
    stats: Mapping[str, int],
    package_index: int,
    package_total: int,
    *,
    display_index: int | None = None,
    display_total: int | None = None,
) -> None:
    if not _quiet_mode():
        return
    use_display = isinstance(display_total, int) and display_total > 0
    if use_display and not isinstance(display_index, int):
        return
    total = display_total if use_display else package_total
    index = display_index if use_display else package_index
    if total <= 0:
        return
    if result.errors:
        _print_progress_line(result, stats, index, total, force=True)
        return
    every = _progress_every()
    if index % every == 0 or index == total:
        _print_progress_line(result, stats, index, total, force=False)


def _print_progress_line(
    result: PullResult,
    stats: Mapping[str, int],
    package_index: int,
    package_total: int,
    *,
    force: bool,
) -> None:
    if not _quiet_mode() and not force:
        return
    ok_count = int(stats.get("packages_clean", 0)) + int(stats.get("packages_partial", 0))
    err_count = int(stats.get("packages_failed", 0))
    skipped = int(stats.get("packages_skipped", 0))
    package_index = min(package_index, package_total)
    skip_hint = ""
    if result.skipped:
        recent_reason = str(result.skipped[0])
        skip_hint = f" (latest_skip={recent_reason})"
    line = (
        f"Progress: {package_index}/{package_total} "
        f"ok={ok_count} fail={err_count} skipped={skipped}{skip_hint}"
    )
    level = "error" if err_count else "info"
    print(status_messages.status(line, level=level))


def _print_package_header(plan: PackagePlan, package_index: int, package_total: int, *, compact_mode: bool) -> None:
    if compact_mode or _quiet_mode():
        return
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


def _print_package_footer(
    plan: PackagePlan,
    stats: Mapping[str, int],
    package_index: int,
    package_total: int,
    *,
    compact_mode: bool,
) -> None:
    saved = int(stats.get("saved", 0) or 0)
    skipped = int(stats.get("skipped", 0) or 0)
    errors = int(stats.get("errors", 0) or 0)
    total_bytes = int(stats.get("bytes", 0) or 0)

    if _quiet_mode() and errors == 0 and skipped == 0:
        return

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

    if compact_mode:
        if _quiet_mode() and errors == 0 and skipped == 0:
            return
        total_planned = saved + skipped + errors
        prefix = f"[{package_index}/{package_total}] "
        compact_line = (
            f"{prefix}{plan.inventory.package_name} • saved {saved}/{total_planned} • "
            f"skipped {skipped} • errors {errors}"
        )
        if total_bytes > 0:
            compact_line += f" • {format_file_size(total_bytes)}"
        print(status_messages.status(compact_line, level=level))
        return

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
