"""Package-level harvest execution orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from scytaledroid.DeviceAnalysis.services import apk_library_service

from . import package_contract, package_refresh, stale_replan
from .common import DedupeTracker, HarvestOptions, package_evidence_dir
from .models import ArtifactError, ArtifactPlan, ArtifactResult, PackagePlan, PullResult

EmitFn = Callable[[str, str, Mapping[str, object | None], str | None], None]


@dataclass(frozen=True)
class PackageExecutionRequest:
    serial: str
    adb_path: str
    dest_root: Path
    session_stamp: str
    plan: PackagePlan
    verbose: bool
    options: HarvestOptions
    tracker: DedupeTracker
    storage_root_id: int | None
    package_index: int
    package_total: int
    compact_mode: bool
    display_index: int | None
    display_total: int
    base_context: Mapping[str, object]
    db_repo: ModuleType | None
    db_install_sets: ModuleType | None
    emit: EmitFn
    stats: dict[str, int]
    snapshot_id: int | None
    snapshot_captured_at: str | None


@dataclass(frozen=True)
class PackageExecutionDeps:
    pull_and_record: Callable[..., tuple[ArtifactResult | ArtifactError | None, str | None]]
    persist_install_set_spine: Callable[..., None]
    print_package_header: Callable[[PackagePlan, int, int], None]
    print_package_footer: Callable[[PackagePlan, dict[str, int], int, int], None]
    print_stale_replan_outcome: Callable[[PackagePlan, ArtifactPlan, int, int, str], None]
    log_warning: Callable[[str, str], None]


def execute_package_plan(
    request: PackageExecutionRequest,
    deps: PackageExecutionDeps,
) -> PullResult:
    result = PullResult(
        plan=request.plan,
        persistence_status="mirrored" if request.options.write_db else "not_requested",
    )
    if request.plan.skip_reason:
        return _handle_preflight_skip(request, result)

    inventory = request.plan.inventory
    package_name = inventory.package_name
    package_dir = package_evidence_dir(request.dest_root, inventory)
    package_dir.mkdir(parents=True, exist_ok=True)
    result.package_manifest_path = package_contract.package_manifest_path(package_dir)
    package_contract.write_package_manifest(
        result=result,
        package_dir=package_dir,
        serial=request.serial,
        session_stamp=request.session_stamp,
        snapshot_id=request.snapshot_id,
        snapshot_captured_at=request.snapshot_captured_at,
        execution_state="started",
    )

    effective_options, app_id, group_id = _prepare_db_mirror(
        request=request,
        deps=deps,
        result=result,
        package_name=package_name,
    )

    ui_index = request.display_index or request.package_index
    ui_total = request.display_total or request.package_total
    deps.print_package_header(request.plan, ui_index, ui_total)
    request.emit(
        "info",
        "harvest.package.start",
        extra={
            "package_name": package_name,
            "package_index": request.package_index,
            "package_total": request.package_total,
            "artifact_total": len(request.plan.artifacts),
        },
    )

    library_hit = _try_resolve_from_apk_library(
        request=request,
        result=result,
        write_db_requested=effective_options.write_db,
    )
    if library_hit is not None:
        package_stats = library_hit
    else:
        package_stats = _run_artifact_loop(
            request=request,
            deps=deps,
            result=result,
            package_dir=package_dir,
            effective_options=effective_options,
            app_id=app_id,
            group_id=group_id,
            package_name=package_name,
        )
        package_contract.finalize_package_result(result, write_db_requested=request.options.write_db)
        apk_library_service.register_result(
            result,
            serial=request.serial,
            session_stamp=request.session_stamp,
        )

    if effective_options.write_db and request.db_install_sets is not None and result.ok:
        deps.persist_install_set_spine(
            result=result,
            serial=request.serial,
            session_stamp=request.session_stamp,
            app_id=app_id,
            snapshot_id=request.snapshot_id,
            db_install_sets=request.db_install_sets,
            stats=request.stats,
            emit=request.emit,
            base_context=request.base_context,
        )
        package_contract.finalize_package_result(result, write_db_requested=request.options.write_db)
    package_contract.write_package_manifest(
        result=result,
        package_dir=package_dir,
        serial=request.serial,
        session_stamp=request.session_stamp,
        snapshot_id=request.snapshot_id,
        snapshot_captured_at=request.snapshot_captured_at,
        execution_state="completed",
    )

    deps.print_package_footer(request.plan, package_stats, ui_index, ui_total)
    request.emit(
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


def _try_resolve_from_apk_library(
    *,
    request: PackageExecutionRequest,
    result: PullResult,
    write_db_requested: bool,
) -> dict[str, int] | None:
    if request.options.overwrite_existing:
        return None
    variant_entry = apk_library_service.content_variant_entry_for_plan(request.plan)
    if variant_entry is not None:
        request.emit(
            "info",
            "harvest.package.apk_library_content_variant_pull_required",
            extra={
                "package_name": request.plan.inventory.package_name,
                "version_code": request.plan.inventory.version_code,
                "artifact_total": len(request.plan.artifacts),
                "apk_library_manifest_path": str(variant_entry.manifest_path),
                "planned_split_set_hash": variant_entry.planned_split_set_hash,
                "split_set_hash": variant_entry.split_set_hash,
                "reason": "content_variant_requires_fresh_pull",
            },
        )
        return None
    entry = apk_library_service.find_entry_for_plan(request.plan)
    if entry is None:
        return None
    artifacts = apk_library_service.artifact_results_for_entry(entry, request.plan)
    if len(artifacts) != len(request.plan.artifacts):
        return None
    result.ok.extend(artifacts)
    result.skipped.append("apk_library_hit")
    apk_library_service.record_observation(
        entry,
        plan=request.plan,
        serial=request.serial,
        session_stamp=request.session_stamp,
        pull_action="skipped_existing_library_entry",
    )
    package_contract.finalize_package_result(result, write_db_requested=write_db_requested)
    result.comparison.setdefault("apk_library_hit", True)
    result.comparison["apk_library_manifest_path"] = str(entry.manifest_path)
    request.stats["artifacts_skipped"] += len(artifacts)
    request.emit(
        "info",
        "harvest.package.apk_library_hit",
        extra={
            "package_name": request.plan.inventory.package_name,
            "version_code": request.plan.inventory.version_code,
            "artifact_total": len(artifacts),
            "apk_library_manifest_path": str(entry.manifest_path),
            "planned_split_set_hash": entry.planned_split_set_hash,
        },
    )
    return {
        "saved": 0,
        "skipped": len(artifacts),
        "errors": 0,
        "bytes": 0,
        "library_hits": len(artifacts),
    }


def _handle_preflight_skip(
    request: PackageExecutionRequest,
    result: PullResult,
) -> PullResult:
    inventory = request.plan.inventory
    package_name = inventory.package_name
    package_dir = package_evidence_dir(request.dest_root, inventory)
    package_dir.mkdir(parents=True, exist_ok=True)
    result.package_manifest_path = package_contract.package_manifest_path(package_dir)
    result.preflight_reason = request.plan.skip_reason
    result.capture_status = "failed"
    result.persistence_status = "not_requested"
    result.research_status = "ineligible"
    result.comparison = package_contract.build_package_comparison(request.plan, result)
    result.skipped.append(request.plan.skip_reason or "unknown_skip")
    package_contract.write_package_manifest(
        result=result,
        package_dir=package_dir,
        serial=request.serial,
        session_stamp=request.session_stamp,
        snapshot_id=request.snapshot_id,
        snapshot_captured_at=request.snapshot_captured_at,
        execution_state="completed",
    )
    request.stats["packages_skipped"] += 1
    request.emit(
        "info",
        "harvest.package.skipped",
        extra={
            "package_name": package_name,
            "skip_reason": request.plan.skip_reason,
            "package_index": request.package_index,
            "package_total": request.package_total,
        },
    )
    return result


def _prepare_db_mirror(
    *,
    request: PackageExecutionRequest,
    deps: PackageExecutionDeps,
    result: PullResult,
    package_name: str,
) -> tuple[HarvestOptions, int | None, int | None]:
    inventory = request.plan.inventory
    effective_options = request.options
    app_id: int | None = None
    if effective_options.write_db and request.db_repo is not None:
        try:
            app_id = request.db_repo.ensure_app_definition(
                package_name,
                inventory.app_label,
                profile_key=inventory.profile_key,
                context={**request.base_context, "package_name": package_name},
            )
            request.stats["db_app_definitions"] += 1
        except Exception as exc:
            deps.log_warning(f"Failed to ensure app definition for {package_name}: {exc}", "database")
            request.stats["db_errors"] += 1
            request.emit(
                "warning",
                "harvest.db.error",
                extra={
                    "package_name": package_name,
                    "stage": "ensure_app_definition",
                    "error": str(exc),
                },
            )
            result.mirror_failure_reasons.append("app_definition_failed")
            result.skipped.append("app_definition_failed")
            effective_options = _without_db(request.options)

    group_id: int | None = None
    if effective_options.write_db and request.db_repo is not None and len(request.plan.artifacts) > 1:
        try:
            group_id = request.db_repo.ensure_split_group(
                package_name,
                context={**request.base_context, "package_name": package_name},
            )
            request.stats["db_split_groups"] += 1
        except Exception as exc:
            deps.log_warning(f"Failed to ensure split group for {package_name}: {exc}", "database")
            request.stats["db_errors"] += 1
            request.emit(
                "warning",
                "harvest.db.error",
                extra={
                    "package_name": package_name,
                    "stage": "ensure_split_group",
                    "error": str(exc),
                },
            )
            result.mirror_failure_reasons.append("split_group_failed")
            result.skipped.append("split_group_failed")
            effective_options = _without_db(request.options)
            group_id = None
    return effective_options, app_id, group_id


def _run_artifact_loop(
    *,
    request: PackageExecutionRequest,
    deps: PackageExecutionDeps,
    result: PullResult,
    package_dir: Path,
    effective_options: HarvestOptions,
    app_id: int | None,
    group_id: int | None,
    package_name: str,
) -> dict[str, int]:
    active_plan = request.plan
    stale_replan_attempted = False
    artifact_total = len(active_plan.artifacts)
    package_stats = {"saved": 0, "skipped": 0, "errors": 0, "bytes": 0}
    artifact_index = 1
    while artifact_index <= len(active_plan.artifacts):
        artifact = active_plan.artifacts[artifact_index - 1]
        artifact_result, skip_reason = deps.pull_and_record(
            serial=request.serial,
            adb_path=request.adb_path,
            package_dir=package_dir,
            plan=active_plan,
            artifact=artifact,
            app_id=app_id,
            group_id=group_id,
            verbose=request.verbose,
            options=effective_options,
            tracker=request.tracker,
            session_stamp=request.session_stamp,
            storage_root_id=request.storage_root_id,
            artifact_index=artifact_index,
            artifact_total=artifact_total,
            verbose_output=request.verbose,
            base_context=request.base_context,
            db_repo=request.db_repo,
            emit=request.emit,
            stats=request.stats,
            snapshot_id=request.snapshot_id,
            snapshot_captured_at=request.snapshot_captured_at,
        )
        if (
            isinstance(artifact_result, ArtifactError)
            and artifact_result.reason == "path_stale"
            and not stale_replan_attempted
        ):
            stale_replan_attempted = True
            handled, next_index, next_total, next_plan = _handle_stale_replan(
                request=request,
                deps=deps,
                result=result,
                package_name=package_name,
                artifact=artifact,
                artifact_index=artifact_index,
                artifact_total=artifact_total,
                active_plan=active_plan,
                package_stats=package_stats,
            )
            if handled == "continue":
                active_plan = next_plan or active_plan
                artifact_total = next_total
                artifact_index = next_index
                continue
            if handled == "break":
                break
        if skip_reason:
            result.skipped.append(skip_reason)
            package_stats["skipped"] += 1
            request.stats["artifacts_skipped"] += 1
        elif isinstance(artifact_result, ArtifactResult):
            result.ok.append(artifact_result)
            if artifact_result.mirror_failure_reasons:
                result.mirror_failure_reasons.extend(artifact_result.mirror_failure_reasons)
                result.skipped.extend(artifact_result.mirror_failure_reasons)
            package_stats["saved"] += 1
            try:
                size = artifact_result.dest_path.stat().st_size
                package_stats["bytes"] += size
                request.stats["bytes_written"] += size
            except FileNotFoundError:
                pass
            request.stats["artifacts_written"] += 1
        elif isinstance(artifact_result, ArtifactError):
            result.errors.append(artifact_result)
            package_stats["errors"] += 1
            request.stats["artifacts_failed"] += 1
        artifact_index += 1
    return package_stats


def _handle_stale_replan(
    *,
    request: PackageExecutionRequest,
    deps: PackageExecutionDeps,
    result: PullResult,
    package_name: str,
    artifact: ArtifactPlan,
    artifact_index: int,
    artifact_total: int,
    active_plan: PackagePlan,
    package_stats: dict[str, int],
) -> tuple[str, int, int, PackagePlan | None]:
    result.stale_replan_required = True
    result.stale_replan_details = {
        "attempted_source_path": artifact.source_path,
        "attempted_artifact_label": artifact.artifact,
        "attempted_artifact_index": artifact_index,
        "attempted_artifact_total": artifact_total,
    }
    refreshed_plan, drift_reasons = package_refresh.replan_package_after_stale_path(
        serial=request.serial,
        plan=active_plan,
    )
    if refreshed_plan is not None:
        request.emit(
            "warning",
            "harvest.package.replanned",
            extra={
                "package_name": package_name,
                "artifact_path": artifact.source_path,
                "artifact_index": artifact_index,
                "artifact_total": artifact_total,
                "drift_detected": bool(drift_reasons),
                "drift_reasons": ",".join(drift_reasons) if drift_reasons else None,
            },
        )
        deps.log_warning(
            f"Package stale path detected; replanning from live package state for {package_name}"
            + (f" ({','.join(drift_reasons)})" if drift_reasons else ""),
            "device",
        )
        result.stale_replan_outcome = stale_replan.classify_stale_replan_outcome(
            refreshed_plan=refreshed_plan,
            drift_reasons=drift_reasons,
        )
        result.stale_replan_details.update(
            stale_replan.build_stale_replan_details(
                refreshed_plan=refreshed_plan,
                drift_reasons=drift_reasons,
            )
        )
        deps.print_stale_replan_outcome(
            active_plan,
            artifact,
            artifact_index,
            artifact_total,
            result.stale_replan_outcome,
        )
        recoverable_inventory_drift = (
            not refreshed_plan.skip_reason
            and "version_code_changed" not in drift_reasons
            and package_refresh.written_artifacts_fit_plan(refreshed_plan, result.ok)
        )
        if recoverable_inventory_drift:
            result.stale_replan_details["recovered_inventory_drift"] = True
        if drift_reasons:
            result.stale_replan_details["blocking_inventory_drift"] = not recoverable_inventory_drift
            if not recoverable_inventory_drift:
                result.drift_reasons = list(drift_reasons)
                result.capture_status = "drifted"
            if refreshed_plan.skip_reason and not result.ok:
                result.preflight_reason = refreshed_plan.skip_reason
                if refreshed_plan.skip_reason not in result.skipped:
                    result.skipped.append(refreshed_plan.skip_reason)
            if result.ok and not recoverable_inventory_drift:
                result.errors.append(
                    ArtifactError(
                        source_path=artifact.source_path,
                        reason="package_drift_detected_after_partial_pull",
                    )
                )
                package_stats["errors"] += 1
                request.stats["artifacts_failed"] += 1
                return "break", artifact_index, artifact_total, None
        result.plan = refreshed_plan
        next_total = len(refreshed_plan.artifacts)
        next_index = package_refresh.next_unwritten_artifact_index(refreshed_plan, result.ok)
        if next_index <= len(refreshed_plan.artifacts):
            return "continue", next_index, next_total, refreshed_plan
        return "break", next_index, next_total, refreshed_plan

    result.stale_replan_outcome = "path_stale_replan_failed"
    result.stale_replan_details.update(
        {
            "refresh_failed": True,
            "drift_reasons": ["package_refresh_failed"],
        }
    )
    deps.print_stale_replan_outcome(
        active_plan,
        artifact,
        artifact_index,
        artifact_total,
        result.stale_replan_outcome,
    )
    result.capture_status = "drifted"
    result.drift_reasons = ["package_refresh_failed"]
    result.errors.append(
        ArtifactError(
            source_path=artifact.source_path,
            reason="package_replan_failed_after_stale_path",
        )
    )
    package_stats["errors"] += 1
    request.stats["artifacts_failed"] += 1
    return "break", artifact_index, artifact_total, None


def _without_db(options: HarvestOptions) -> HarvestOptions:
    return HarvestOptions(
        dedupe_sha256=options.dedupe_sha256,
        keep_last=options.keep_last,
        write_db=False,
        write_meta=options.write_meta,
        meta_fields=options.meta_fields,
        pull_mode=options.pull_mode,
        overwrite_existing=options.overwrite_existing,
        thin_session=options.thin_session,
    )


__all__ = [
    "PackageExecutionDeps",
    "PackageExecutionRequest",
    "execute_package_plan",
]
