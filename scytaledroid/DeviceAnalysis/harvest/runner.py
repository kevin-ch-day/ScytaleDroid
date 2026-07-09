"""Execute planned APK harvest operations."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger

from . import artifact_execution, common, package_contract, package_execution, package_refresh, stale_replan
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
from .status import build_harvest_run_status_from_runtime_stats


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
    overwrite_existing: bool = False,
    run_id: str | None = None,
    harvest_logger: logging_engine.ContextAdapter | None = None,
    scope_label: str | None = None,
    snapshot_id: int | None = None,
    snapshot_captured_at: str | None = None,
) -> list[PullResult]:
    """Execute the provided harvest plan and return per-package results."""

    options = load_options(config, pull_mode=pull_mode)
    requested_db_mirror = bool(options.write_db)
    if overwrite_existing:
        options = HarvestOptions(
            dedupe_sha256=options.dedupe_sha256,
            keep_last=options.keep_last,
            write_db=options.write_db,
            write_meta=options.write_meta,
            meta_fields=options.meta_fields,
            pull_mode=options.pull_mode,
            overwrite_existing=True,
            thin_session=options.thin_session,
        )
    # DB is optional for OSS vNext. If the backend is configured but not reachable,
    # do not skip filesystem harvests due to DB mirror failures.
    if options.write_db:
        try:
            from scytaledroid.Database.db_utils import diagnostics  # local import (optional DB)

            if not diagnostics.check_connection():
                print(
                    status_messages.status(
                        "DB configured but unreachable; continuing harvest without DB writes.",
                        level="warn",
                    )
                )
                options = HarvestOptions(
                    dedupe_sha256=options.dedupe_sha256,
                    keep_last=options.keep_last,
                    write_db=False,
                    write_meta=options.write_meta,
                    meta_fields=options.meta_fields,
                    pull_mode=options.pull_mode,
                    overwrite_existing=options.overwrite_existing,
                    thin_session=options.thin_session,
                )
        except Exception:
            # If diagnostics isn't available, keep the existing posture; DB failures will
            # still be logged by the DB session helpers.
            pass
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
        "packages_reviewed": 0,
        "packages_eligible": sum(1 for plan in plans if not plan.skip_reason),
        "packages_attempted": 0,
        "packages_harvested": 0,
        "packages_skipped": 0,
        "packages_clean": 0,
        "packages_partial": 0,
        "packages_failed": 0,
        "packages_drifted": 0,
        "packages_mirror_failed": 0,
        "packages_runtime_skipped": 0,
        "packages_path_stale": 0,
        "packages_replanned": 0,
        "packages_replan_success": 0,
        "packages_replan_failed": 0,
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
        "db_harvest_sessions": 0,
        "db_apk_sets": 0,
        "db_apk_set_members": 0,
        "db_harvest_observations": 0,
        "db_errors": 0,
    }

    _emit(
        "info",
        "harvest.start",
        extra={
            "package_total": stats["packages_total"],
            "artifact_total": stats["artifacts_planned"],
            "write_db": options.write_db,
            "write_db_requested": requested_db_mirror,
        },
    )

    storage_root_id: int | None = None
    db_repo: ModuleType | None = None
    db_install_sets: ModuleType | None = None
    if options.write_db:
        # Import DB repositories only when DB writes are enabled. This keeps harvest usable
        # on clean machines where DB deps/connectors/migrations may be absent.
        try:
            from scytaledroid.Database.db_func.harvest import (
                apk_repository as repo,  # local import (optional DB)
                install_sets as install_set_repo,
            )

            db_repo = repo
            db_install_sets = install_set_repo
        except Exception as exc:
            stats["db_errors"] += 1
            _emit(
                "error",
                "harvest.db.error",
                extra={"stage": "import_db_repo", "error": str(exc)},
            )
            print(
                status_messages.status(
                    "DB mirror unavailable (DB repository import failed); continuing harvest without DB writes.",
                    level="warn",
                )
            )
            options = HarvestOptions(
                dedupe_sha256=options.dedupe_sha256,
                keep_last=options.keep_last,
                write_db=False,
                write_meta=options.write_meta,
                meta_fields=options.meta_fields,
                pull_mode=options.pull_mode,
                overwrite_existing=options.overwrite_existing,
            )
        if options.write_db:
            host_name, data_root = resolve_storage_root()
            try:
                storage_root_id = db_repo.ensure_storage_root(
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
                # DB is a mirror/index layer for harvest; filesystem artifacts are canonical.
                # Do not block a paper-grade APK pull due to DB mirror failure.
                print(
                    status_messages.status(
                        "DB mirror unavailable (storage root write failed); continuing harvest without DB writes.",
                        level="warn",
                    )
                )
                options = HarvestOptions(
                    dedupe_sha256=options.dedupe_sha256,
                    keep_last=options.keep_last,
                    write_db=False,
                    write_meta=options.write_meta,
                    meta_fields=options.meta_fields,
                    pull_mode=options.pull_mode,
                    overwrite_existing=options.overwrite_existing,
                    thin_session=options.thin_session,
                )
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
                db_repo=db_repo,
                db_install_sets=db_install_sets,
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
            terminal_abort_reason = _terminal_abort_reason(result)
            if terminal_abort_reason:
                run_error = terminal_abort_reason
                packages_remaining = max(total - len(results), 0)
                print(
                    status_messages.status(
                        "ADB device unavailable; stopping harvest early.",
                        level="warn",
                    )
                )
                _emit(
                    "warning",
                    "harvest.run.aborted",
                    extra={
                        "reason": terminal_abort_reason,
                        "package_name": result.plan.inventory.package_name,
                        "packages_processed": len(results),
                        "packages_remaining": packages_remaining,
                    },
                )
                break
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
        status_summary = build_harvest_run_status_from_runtime_stats(
            stats,
            run_error=run_error,
            write_db_requested=requested_db_mirror,
            write_db_effective=options.write_db,
        )
        summary = {
            "package_total": stats["packages_total"],
            "packages_reviewed": stats["packages_reviewed"],
            "packages_eligible": stats["packages_eligible"],
            "packages_attempted": stats["packages_attempted"],
            "packages_harvested": stats["packages_harvested"],
            "packages_skipped": stats["packages_skipped"],
            "packages_runtime_skipped": stats["packages_runtime_skipped"],
            "packages_path_stale": stats["packages_path_stale"],
            "packages_replanned": stats["packages_replanned"],
            "packages_replan_success": stats["packages_replan_success"],
            "packages_replan_failed": stats["packages_replan_failed"],
            "packages_processed": len(results),
            "packages_remaining": max(stats["packages_total"] - len(results), 0),
            "packages_clean": stats["packages_clean"],
            "packages_partial": stats["packages_partial"],
            "packages_failed": stats["packages_failed"],
            "packages_drifted": stats["packages_drifted"],
            "packages_mirror_failed": stats["packages_mirror_failed"],
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
            "db_harvest_sessions": stats["db_harvest_sessions"],
            "db_apk_sets": stats["db_apk_sets"],
            "db_apk_set_members": stats["db_apk_set_members"],
            "db_harvest_observations": stats["db_harvest_observations"],
            "db_errors": stats["db_errors"],
            "write_db_requested": requested_db_mirror,
            "write_db_effective": options.write_db,
            "run_state": "FAILED" if run_failed else status_summary.status.upper(),
            "harvest_status": status_summary.status,
            "harvest_status_reason": status_summary.status_reason,
            "harvest_operator_summary": status_summary.operator_summary,
            "run_failed": run_failed,
            "run_error": run_error,
        }
        _emit("info", "harvest.summary", extra=summary)
        log.info(
            "Harvest run completed",
            category="device",
            extra={**summary, **base_context},
        )
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
    db_repo: ModuleType | None,
    db_install_sets: ModuleType | None,
    emit: Callable[[str, str, Mapping[str, object | None], str | None], None],
    stats: dict[str, int],
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
) -> PullResult:
    request = package_execution.PackageExecutionRequest(
        serial=serial,
        adb_path=adb_path,
        dest_root=dest_root,
        session_stamp=session_stamp,
        plan=plan,
        verbose=verbose,
        options=options,
        tracker=tracker,
        storage_root_id=storage_root_id,
        package_index=package_index,
        package_total=package_total,
        compact_mode=compact_mode,
        display_index=display_index,
        display_total=display_total,
        base_context=base_context,
        db_repo=db_repo,
        db_install_sets=db_install_sets,
        emit=emit,
        stats=stats,
        snapshot_id=snapshot_id,
        snapshot_captured_at=snapshot_captured_at,
    )
    deps = package_execution.PackageExecutionDeps(
        pull_and_record=_pull_and_record,
        persist_install_set_spine=_persist_install_set_spine,
        print_package_header=lambda package_plan, ui_index, ui_total: _print_package_header(
            package_plan, ui_index, ui_total, compact_mode=compact_mode
        ),
        print_package_footer=lambda package_plan, package_stats, ui_index, ui_total: _print_package_footer(
            package_plan, package_stats, ui_index, ui_total, compact_mode=compact_mode
        ),
        print_stale_replan_outcome=lambda package_plan, artifact, artifact_index, artifact_total, outcome: (
            _print_stale_replan_outcome(
                plan=package_plan,
                artifact=artifact,
                artifact_index=artifact_index,
                artifact_total=artifact_total,
                outcome=outcome,
            )
        ),
        log_warning=lambda message, category: log.warning(message, category=category),
    )
    return package_execution.execute_package_plan(request, deps)


def _persist_install_set_spine(
    *,
    result: PullResult,
    serial: str,
    session_stamp: str,
    app_id: int | None,
    snapshot_id: int | None,
    db_install_sets: ModuleType,
    stats: dict[str, int],
    emit: Callable[[str, str, Mapping[str, object | None], str | None], None],
    base_context: Mapping[str, object],
) -> None:
    inventory = result.plan.inventory
    members = []
    for ordinal, artifact in enumerate(result.ok):
        digest = str(artifact.sha256 or "").strip().lower()
        if len(digest) != 64:
            return
        is_base = bool(artifact.is_base)
        split_name = artifact.artifact_label or ("base" if is_base else artifact.file_name)
        role = "base" if is_base else "split"
        members.append(
            db_install_sets.InstallSetMember(
                apk_id=artifact.apk_id,
                role=role,
                split_name=str(split_name or role).strip().lower(),
                sha256=digest,
                source_path=artifact.observed_source_path or artifact.source_path,
                local_relpath=normalise_local_path(artifact.dest_path),
                canonical_relpath=artifact.canonical_store_path,
                member_status=artifact.status,
                ordinal=ordinal,
            )
        )
    if len([member for member in members if member.role == "base"]) != 1:
        return

    try:
        record = db_install_sets.InstallSetRecord(
            session_label=session_stamp,
            package_name=inventory.package_name,
            device_serial=serial,
            snapshot_id=snapshot_id,
            app_id=app_id,
            version_code=inventory.version_code,
            version_name=inventory.version_name,
            status=result.capture_status or "unknown",
            generated_at_utc=datetime.now(UTC),
            receipt_root="data/receipts/harvest",
            members=tuple(members),
            source_kind="harvest_runner",
        )
        apk_set_id = db_install_sets.upsert_install_set(record)
        if apk_set_id is None:
            return
        stats["db_harvest_sessions"] += 1
        stats["db_apk_sets"] += 1
        stats["db_apk_set_members"] += len(members)
        stats["db_harvest_observations"] += len(members)
        emit(
            "info",
            "harvest.install_set.persisted",
            extra={
                "package_name": inventory.package_name,
                "apk_set_id": apk_set_id,
                "member_count": len(members),
                "base_apk_sha256": next((member.sha256 for member in members if member.role == "base"), None),
            },
        )
    except Exception as exc:
        if hasattr(db_install_sets, "log_mirror_failure"):
            db_install_sets.log_mirror_failure(inventory.package_name, exc)
        stats["db_errors"] += 1
        emit(
            "warning",
            "harvest.db.error",
            extra={
                "package_name": inventory.package_name,
                "stage": "upsert_install_set_spine",
                "error": str(exc),
                **dict(base_context),
            },
        )


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
    db_repo: ModuleType | None,
    emit: Callable[[str, str, Mapping[str, object | None], str | None], None],
    stats: dict[str, int],
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
) -> tuple[ArtifactResult | ArtifactError | None, str | None]:
    request = artifact_execution.ArtifactExecutionRequest(
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
        verbose_output=verbose_output,
        base_context=base_context,
        db_repo=db_repo,
        emit=emit,
        stats=stats,
        snapshot_id=snapshot_id,
        snapshot_captured_at=snapshot_captured_at,
    )
    deps = artifact_execution.ArtifactExecutionDeps(
        adb_pull=adb_pull,
        compute_hashes=compute_hashes,
        tracker_register=tracker.register,
        cleanup_duplicate=cleanup_duplicate,
        materialize_apk=lambda path, sha256_digest, suffix: artifact_store.materialize_apk(
            path,
            sha256_digest=sha256_digest,
            suffix=suffix,
        ),
        repo_relative_path=artifact_store.repo_relative_path,
        inventory_signer_fingerprint=package_contract.inventory_signer_fingerprint,
        inventory_payload=inventory_payload,
        write_metadata_sidecar=write_metadata_sidecar,
        print_artifact_status=lambda label, file_name, index, total, suffix, level: common.print_artifact_status(
            label,
            file_name,
            index=index,
            total=total,
            suffix=suffix,
            level=level,
        ),
        replace_session_apk_with_symlink_to_canonical=lambda session_artifact_path, canonical_absolute, enabled: (
            common.replace_session_apk_with_symlink_to_canonical(
                session_artifact_path=session_artifact_path,
                canonical_absolute=canonical_absolute,
                enabled=enabled,
            )
        ),
        format_file_size=common.format_file_size,
        artifact_status_suffix=_artifact_status_suffix,
        is_system_package=is_system_package,
        normalise_local_path=normalise_local_path,
        log_warning=lambda message, category: log.warning(message, category=category),
        log_error=lambda message, category: log.error(message, category=category),
    )
    return artifact_execution.pull_and_record(request, deps)


def _artifact_status_suffix(reason: str) -> str:
    if reason == "path_stale":
        return "path stale; replan required"
    return reason


def _print_stale_replan_outcome(
    *,
    plan: PackagePlan,
    artifact: ArtifactPlan,
    artifact_index: int,
    artifact_total: int,
    outcome: str,
) -> None:
    suffix, level = stale_replan.stale_replan_outcome_text(outcome)
    common.print_artifact_status(
        plan.inventory.display_name(),
        artifact.file_name,
        index=artifact_index,
        total=artifact_total,
        suffix=suffix,
        level=level,
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
    value = os.getenv("SCYTALEDROID_HARVEST_PROGRESS_EVERY", "10").strip()
    try:
        return max(int(value), 1)
    except ValueError:
        return 10


def _progress_step_for_total(display_total: int) -> int:
    """Larger runs get wider spacing so the CLI is not flooded (~10 updates per harvest)."""
    base = _progress_every()
    if display_total <= 0:
        return base
    # Simple/quiet mode: fewer milestone lines for long runs.
    target_lines = 5 if _simple_mode() else 10
    adaptive = max(1, (display_total + target_lines - 1) // target_lines)
    return max(base, adaptive)


def _update_package_outcome(stats: dict[str, int], result: PullResult) -> None:
    stats["packages_reviewed"] += 1
    if result.preflight_reason:
        return
    stats["packages_attempted"] += 1
    if result.ok:
        stats["packages_harvested"] += 1
    if result.skipped and not result.ok and not result.errors:
        stats["packages_runtime_skipped"] += 1
    stale_replan_required = bool(getattr(result, "stale_replan_required", False))
    stale_replan_outcome = getattr(result, "stale_replan_outcome", None)
    if stale_replan_required:
        stats["packages_path_stale"] += 1
    if stale_replan_outcome:
        stats["packages_replanned"] += 1
        if stale_replan.is_successful_stale_replan_outcome(stale_replan_outcome):
            stats["packages_replan_success"] += 1
        elif stale_replan.is_failed_stale_replan_outcome(stale_replan_outcome):
            stats["packages_replan_failed"] += 1
    if result.capture_status == "drifted":
        stats["packages_drifted"] += 1
    elif result.capture_status == "partial":
        stats["packages_partial"] += 1
    elif result.capture_status == "failed":
        stats["packages_failed"] += 1
    else:
        stats["packages_clean"] += 1
    if result.persistence_status == "mirror_failed":
        stats["packages_mirror_failed"] += 1


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
        if package_index == package_total:
            _print_progress_line(result, stats, display_total, display_total, force=True)
        return
    total = display_total if use_display else package_total
    index = display_index if use_display else package_index
    if total <= 0:
        return
    if result.errors:
        _print_progress_line(result, stats, index, total, force=True)
        return
    step = _progress_step_for_total(total)
    if index % step == 0 or index == total:
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
    status_summary = build_harvest_run_status_from_runtime_stats(
        stats,
        run_error=None,
        write_db_requested=False,
        write_db_effective=True,
    )
    line = f"Harvest: {status_summary.operator_summary}"
    skip_hint = ""
    if force and (result.preflight_reason or status_summary.failed_count or status_summary.drifted_count):
        if result.preflight_reason:
            skip_hint = f" · preflight={result.preflight_reason}"
        elif result.skipped:
            non_fatal = {
                "app_definition_failed",
                "split_group_failed",
                "apk_record_failed",
                "artifact_path_failed",
                "source_path_failed",
            }
            recent_reason = ""
            for r in result.skipped:
                if r in non_fatal and result.ok:
                    continue
                recent_reason = str(r)
                break
            if recent_reason:
                skip_hint = f" · skip={recent_reason}"
    line += skip_hint
    level = "error" if status_summary.failed_count or status_summary.drifted_count else "info"
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
    library_hits = int(stats.get("library_hits", 0) or 0)
    pure_library_hit = library_hits > 0 and library_hits == skipped and saved == 0 and errors == 0

    if _quiet_mode() and (pure_library_hit or (errors == 0 and skipped == 0)):
        return

    parts: list[str] = []
    if pure_library_hit:
        parts.append(f"reused {library_hits} from APK library")
        parts.append("pulled 0")
    else:
        parts.append(f"saved {saved} artifact{'s' if saved != 1 else ''}")
        if library_hits:
            parts.append(f"reused {library_hits} from APK library")
            remaining_skips = max(skipped - library_hits, 0)
            parts.append(f"other skipped {remaining_skips}")
        else:
            parts.append(f"skipped {skipped}")
    parts.append(f"errors {errors}")
    if total_bytes > 0:
        parts.append(format_file_size(total_bytes))

    summary = " • ".join(parts)
    package_label = plan.inventory.display_name()

    if errors:
        level = "error"
    elif pure_library_hit:
        level = "info"
    elif skipped and not saved:
        level = "warn"
    else:
        level = "success"

    if compact_mode:
        if _quiet_mode() and (pure_library_hit or (errors == 0 and skipped == 0)):
            return
        total_planned = saved + skipped + errors
        prefix = f"[{package_index}/{package_total}] "
        if pure_library_hit:
            compact_line = (
                f"{prefix}{plan.inventory.package_name} • "
                f"reused {library_hits}/{total_planned} from APK library • errors {errors}"
            )
        else:
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
def _terminal_abort_reason(result: PullResult) -> str | None:
    for error in result.errors:
        if error.reason == "device_unavailable":
            return "device_unavailable"
    return None


__all__ = ["execute_harvest"]
