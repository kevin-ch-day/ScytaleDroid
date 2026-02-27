"""Workflow orchestration for APK pulls."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import harvest, inventory
from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DeviceAnalysis.apk import delta, planner, ui
from scytaledroid.DeviceAnalysis.apk.models import PlanResolution, SnapshotContext
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard import (
    get_last_guard_decision,
    get_latest_inventory_metadata,
)
from scytaledroid.Utils.DisplayUtils import text_blocks
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.ops.operation_result import OperationResult


def run_apk_pull(
    serial: str | None,
    *,
    auto_scope: bool = False,
    noninteractive: bool = False,
) -> OperationResult:
    """Pull APK files for the active device and upsert metadata into the repository."""

    if not serial:
        ui.report_no_device()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: no active device.",
            error_code="apk_pull_no_device",
        )

    if not adb_client.is_available():
        ui.report_no_adb()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: adb not available.",
            error_code="apk_pull_no_adb",
        )

    snapshot_ctx = ensure_inventory_snapshot(serial)
    if snapshot_ctx is None:
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: inventory snapshot unavailable.",
            error_code="apk_pull_inventory_missing",
        )

    is_rooted = device_is_rooted(serial)
    resolution = resolve_harvest_plan(
        serial=serial,
        rows=snapshot_ctx.rows,
        is_rooted=is_rooted,
        snapshot_id=snapshot_ctx.snapshot_id,
        snapshot_captured_at=snapshot_ctx.snapshot_captured_at,
        auto_scope=auto_scope,
        noninteractive=noninteractive,
    )
    if resolution is None:
        return OperationResult.failure(
            status="CANCELLED",
            user_message="APK pull cancelled by user.",
            error_code="apk_pull_cancelled",
        )

    adb_path = adb_client.get_adb_binary()
    if not adb_path:
        ui.report_no_adb()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: adb not available.",
            error_code="apk_pull_no_adb",
        )

    now_utc = datetime.now(UTC)
    session_stamp = now_utc.strftime("%Y%m%d")
    dest_root = Path(app_config.DATA_DIR) / "device_apks" / serial / session_stamp
    dest_root.mkdir(parents=True, exist_ok=True)

    run_id = f"{serial or 'device'}-{now_utc.strftime('%Y%m%d-%H%M%S')}"
    harvest_logger = log.harvest_adapter(
        run_id,
        started_at=datetime.now(UTC),
        context={
            "device_serial": serial,
            "session_stamp": session_stamp,
            "scope_label": resolution.selection.label,
            "pull_mode": resolution.pull_mode,
            "snapshot_id": snapshot_ctx.snapshot_id,
            "snapshot_captured_at": snapshot_ctx.snapshot_captured_at,
        },
    )

    try:
        if resolution.pull_mode == "quick":
            results = harvest.quick_harvest(
                resolution.plan.packages,
                adb_path=adb_path,
                dest_root=dest_root,
                session_stamp=session_stamp,
                config=app_config,
                serial=serial,
                verbose=resolution.verbose,
                run_id=run_id,
                harvest_logger=harvest_logger,
                snapshot_id=snapshot_ctx.snapshot_id,
                snapshot_captured_at=snapshot_ctx.snapshot_captured_at,
            )
        else:
            results = harvest.execute_harvest(
                serial=serial,
                adb_path=adb_path,
                dest_root=dest_root,
                session_stamp=session_stamp,
                plans=resolution.plan.packages,
                config=app_config,
                verbose=resolution.verbose,
                pull_mode=resolution.pull_mode,
                run_id=run_id,
                harvest_logger=harvest_logger,
                scope_label=resolution.selection.label,
                snapshot_id=snapshot_ctx.snapshot_id,
                snapshot_captured_at=snapshot_ctx.snapshot_captured_at,
            )
    except Exception as exc:
        logging_engine.get_error_logger().exception(
            "APK harvest failed (exception)",
            extra=logging_engine.ensure_trace(
                {
                    "event": "apk_harvest_exception",
                    "run_id": run_id,
                    "device_serial": serial,
                    "pull_mode": resolution.pull_mode,
                    "scope_label": resolution.selection.label,
                }
            ),
        )
        log.close_harvest_adapter(run_id)
        return OperationResult.failure(
            user_message=f"APK harvest failed to start ({exc.__class__.__name__}). See logs/error.log.",
            error_code="apk_harvest_exception",
            context={"run_id": run_id, "device_serial": serial},
        )

    if resolution.verbose:
        for result in results:
            harvest.print_package_result(result, verbose=True)
    else:
        if not harvest.is_harvest_simple_mode():
            for result in results:
                harvest.print_package_result(result, verbose=False)

    try:
        harvest.render_harvest_summary(
            resolution.plan,
            results,
            selection=resolution.selection,
            pull_mode=resolution.pull_mode,
            serial=serial,
            run_timestamp=session_stamp,
            guard_brief=resolution.selection.metadata.get("inventory_guard_brief"),
            run_id=run_id,
            harvest_logger=harvest_logger,
        )
    except Exception as exc:
        logging_engine.get_error_logger().exception(
            "Harvest summary rendering failed",
            extra=logging_engine.ensure_trace(
                {
                    "event": "apk_harvest.summary_failed",
                    "run_id": run_id,
                    "device_serial": serial,
                    "scope_label": resolution.selection.label,
                }
            ),
        )
        ui.report_summary_failure(exc)
    ui.maybe_save_watchlist(resolution.selection)
    log.close_harvest_adapter(run_id)
    return OperationResult.success(
        context={"run_id": run_id, "device_serial": serial, "packages": len(resolution.plan.packages)}
    )


def device_is_rooted(serial: str) -> bool:
    try:
        completed = adb_shell.run_shell_command(serial, ["id", "-u"])
    except RuntimeError as exc:
        log.warning(f"Failed to determine root state for {serial}: {exc}", category="device")
        return False
    if completed.returncode != 0:
        return False
    return completed.stdout.strip() == "0"


def apply_guard_metadata(
    selection: harvest.ScopeSelection,
    guard_decision: Mapping[str, object] | None,
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
) -> None:
    if guard_decision:
        policy_value = guard_decision.get("policy")
        if policy_value:
            selection.metadata["inventory_policy"] = policy_value
        stale_level_value = guard_decision.get("stale_level")
        if stale_level_value:
            selection.metadata["inventory_stale_level"] = stale_level_value
        reason_value = guard_decision.get("reason")
        if reason_value:
            selection.metadata["inventory_guard_reason"] = reason_value
        guard_brief_value = guard_decision.get("guard_brief")
        if guard_brief_value:
            selection.metadata["inventory_guard_brief"] = guard_brief_value
        scope_hash_delta = guard_decision.get("scope_hash_changed")
        if scope_hash_delta is not None:
            selection.metadata["inventory_scope_hash_changed"] = bool(scope_hash_delta)
        scope_delta = guard_decision.get("scope_changed")
        if scope_delta is not None:
            selection.metadata["inventory_scope_changed"] = bool(scope_delta)
        delta_summary_value = guard_decision.get("package_delta")
        if delta_summary_value:
            selection.metadata["package_delta_summary"] = delta_summary_value
        delta_brief_value = guard_decision.get("package_delta_brief")
        if delta_brief_value:
            selection.metadata["package_delta_brief"] = delta_brief_value
    if snapshot_id is not None:
        selection.metadata["inventory_snapshot_id"] = snapshot_id
    if snapshot_captured_at:
        selection.metadata["inventory_snapshot_captured_at"] = snapshot_captured_at


def ensure_inventory_snapshot(serial: str) -> SnapshotContext | None:
    snapshot = inventory.load_latest_inventory(serial)
    if not snapshot:
        ui.report_missing_inventory_snapshot()
        if ui.prompt_inventory_sync():
            from scytaledroid.DeviceAnalysis.services import inventory_service

            try:
                inventory_service.run_full_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                snapshot = inventory.load_latest_inventory(serial)
            except Exception as exc:
                ui.report_inventory_sync_failure(exc)
                return None
        else:
            return None

    if not snapshot or not snapshot.get("packages"):
        ui.report_invalid_snapshot_after_sync()
        return None

    snapshot_id = snapshot.get("snapshot_id")
    snapshot_captured_at = snapshot.get("generated_at")
    packages = snapshot.get("packages", [])
    rows = harvest.build_inventory_rows(packages)
    if not rows:
        ui.report_empty_snapshot()
        return None

    return SnapshotContext(
        snapshot=snapshot,
        rows=rows,
        snapshot_id=snapshot_id if isinstance(snapshot_id, int) else None,
        snapshot_captured_at=str(snapshot_captured_at) if snapshot_captured_at else None,
    )


def resolve_harvest_plan(
    *,
    serial: str,
    rows: list[harvest.InventoryRow],
    is_rooted: bool,
    snapshot_id: int | None,
    snapshot_captured_at: str | None,
    auto_scope: bool = False,
    noninteractive: bool = False,
) -> PlanResolution | None:
    active_plan = None
    active_selection = None
    verbose = False
    google_allowlist = harvest.rules.load_google_allowlist()
    guard_metadata: dict[str, object] | None = get_latest_inventory_metadata(
        serial, with_current_state=True
    )
    guard_decision = get_last_guard_decision()
    pull_mode: str | None = None
    auto_selection = None
    # Applies only within this pull session. Once a user opts into/out of delta filtering,
    # keep it stable across re-scopes to avoid confusing behavior changes mid-run.
    apply_delta_filter_choice: bool | None = None
    # Harvest mode: delta (changed-only) vs full_refresh. Defaults to delta when a delta
    # summary exists unless the scope explicitly disables delta filtering.
    harvest_mode: str | None = None
    if auto_scope or noninteractive:
        auto_selection = harvest.select_package_scope_auto(
            rows,
            device_serial=serial,
            is_rooted=is_rooted,
            google_allowlist=google_allowlist,
        )
        if auto_selection is None:
            ui.report_apk_pull_cancelled()
            return None

    while True:
        active_plan = None
        active_selection = None
        pull_mode = None
        verbose = False
        if auto_selection is not None:
            selection = auto_selection
            auto_selection = None
            reason = selection.metadata.get("auto_scope_reason")
            if reason:
                # Auto-scope reason is kept in metadata for summaries; no CLI noise here.
                pass
        else:
            selection = harvest.select_package_scope(
                rows,
                device_serial=serial,
                is_rooted=is_rooted,
                google_allowlist=google_allowlist,
            )
        if selection is None:
            ui.report_apk_pull_cancelled()
            return None
        if not selection.packages:
            ui.report_no_packages_selected()
            continue

        scoped_metadata = get_latest_inventory_metadata(
            serial,
            with_current_state=True,
            scope_packages=selection.packages,
        )
        if scoped_metadata:
            guard_metadata = scoped_metadata
        guard_decision = get_last_guard_decision()
        apply_guard_metadata(
            selection,
            guard_decision,
            snapshot_id,
            snapshot_captured_at,
        )

        summary = delta.extract_delta_summary(selection.metadata) or delta.extract_delta_summary(
            guard_metadata or {}
        )
        delta_applied = False
        delta_count = len(selection.packages)
        if summary and not bool(selection.metadata.get("disable_delta_filter")):
            if apply_delta_filter_choice is None and not noninteractive:
                apply_delta_filter_choice = ui.prompt_delta_filter_mode(summary)
            if apply_delta_filter_choice is False:
                selection.metadata["disable_delta_filter"] = True
                harvest_mode = "full_refresh"
            else:
                harvest_mode = "delta"

        if summary and not bool(selection.metadata.get("disable_delta_filter")):
            include = delta.collect_delta_package_names(summary)
            filtered_rows = delta.apply_delta_filter(selection.packages, include=include)
            delta_count = len(filtered_rows)
            if not include:
                delta_applied = False
            else:
                delta_applied = True
                new_metadata = dict(selection.metadata)
                new_metadata["delta_filter_applied"] = True
                new_metadata["delta_filter_total"] = len(include)
                new_metadata["delta_filter_matched"] = len(filtered_rows)
                new_metadata["delta_filter_packages"] = sorted(include)
                selection = harvest.ScopeSelection(
                    label=selection.label,
                    packages=filtered_rows,
                    kind=selection.kind,
                    metadata=new_metadata,
                )

        if delta_applied:
            if delta_count == 0:
                ui.report_delta_scope_empty()
                continue
            ui.report_delta_scope_applied(delta_count)
        elif summary and bool(selection.metadata.get("disable_delta_filter")):
            # Operator clarity: full refresh was selected/forced; do not frame as "delta".
            ui.report_full_refresh_scope_applied(len(selection.packages))

        plan = harvest.build_harvest_plan(
            selection.packages,
            include_system_partitions=planner.include_system_partitions(selection, is_rooted),
        )
        stats = planner.compute_plan_stats(plan, policy=selection.metadata.get("policy"))
        if int(stats["scheduled_files"]) == 0:
            ui.report_plan_no_artifacts()
            skip_reasons: dict[str, tuple[int, list[str]]] = {}
            for pkg in plan.packages:
                reason = pkg.skip_reason or "unknown"
                count, samples = skip_reasons.get(reason, (0, []))
                count += 1
                if len(samples) < 3:
                    samples.append(pkg.inventory.display_name())
                skip_reasons[reason] = (count, samples)
            if skip_reasons:
                ui.report_skip_reasons(skip_reasons)
            choice = ui.print_no_artifacts_menu()
            if choice == "0":
                return None
            if choice == "2":
                from scytaledroid.DeviceAnalysis.services import inventory_service

                try:
                    inventory_service.run_full_sync(
                        serial=serial,
                        ui_prefs=text_blocks.UI_PREFS,
                        progress_sink="cli",
                    )
                except Exception as exc:
                    ui.report_inventory_sync_issue(exc)
            continue

        preview_resolution = PlanResolution(
            plan=plan,
            selection=selection,
            stats=stats,
            pull_mode="inventory",
            verbose=False,
            guard_metadata=guard_metadata,
        )
        ui.render_plan_overview(preview_resolution)

        if noninteractive:
            pull_mode = "inventory"
            verbose = False
            return planner.build_plan(
                selection,
                is_rooted=is_rooted,
                pull_mode=pull_mode,
                verbose=verbose,
                guard_metadata=guard_metadata,
            )

        refresh_requested = False
        while True:
            action = ui.prompt_plan_action(preview_resolution)
            if action == "dry-run":
                harvest.preview_plan(plan)
                ui.pause_after_preview()
                continue
            if action == "rescope":
                break
            if action == "cancel":
                ui.report_apk_pull_cancelled()
                return None
            if action == "use_snapshot":
                ui.report_using_existing_snapshot()
                return None
            if action == "refresh_subset":
                if ui.run_scope_refresh(serial, selection.packages):
                    snapshot = inventory.load_latest_inventory(serial)
                    if not snapshot or not snapshot.get("packages"):
                        ui.report_scoped_snapshot_invalid()
                        return None
                    packages = snapshot.get("packages", [])
                    rows = harvest.build_inventory_rows(packages)
                    if not rows:
                        ui.report_scoped_snapshot_empty()
                        return None
                    latest_metadata = get_latest_inventory_metadata(
                        serial,
                        with_current_state=True,
                        scope_packages=selection.packages,
                    )
                    if latest_metadata:
                        guard_metadata = latest_metadata
                    refresh_requested = True
                    break
                break
            if action == "refresh_full":
                from scytaledroid.DeviceAnalysis.services import inventory_service

                try:
                    inventory_service.run_full_sync(
                        serial=serial,
                        ui_prefs=text_blocks.UI_PREFS,
                        progress_sink="cli",
                    )
                except Exception as exc:
                    ui.report_inventory_sync_issue(exc)
                    continue

                snapshot = inventory.load_latest_inventory(serial)
                if not snapshot or not snapshot.get("packages"):
                    ui.report_refresh_snapshot_invalid()
                    return None
                packages = snapshot.get("packages", [])
                rows = harvest.build_inventory_rows(packages)
                if not rows:
                    ui.report_refresh_snapshot_empty()
                    return None
                latest_metadata = get_latest_inventory_metadata(
                    serial,
                    with_current_state=True,
                    scope_packages=selection.packages,
                )
                if latest_metadata:
                    guard_metadata = latest_metadata
                refresh_requested = True
                break
            if action in {"pull_quick", "pull_quick_verbose", "pull_snapshot", "pull_snapshot_verbose"}:
                if action in {"pull_quick", "pull_quick_verbose"}:
                    pull_mode = "quick"
                    verbose = action == "pull_quick_verbose"
                else:
                    pull_mode = "inventory"
                    verbose = action == "pull_snapshot_verbose"
                active_plan = plan
                active_selection = selection
                break
        if refresh_requested:
            continue
        if active_plan and active_selection and pull_mode:
            if ui.is_harvest_simple_mode():
                candidate_count = active_selection.metadata.get("candidate_count") or len(
                    active_selection.packages
                )
                selected_count = active_selection.metadata.get("selected_count") or len(
                    active_selection.packages
                )
                eligible = max(int(stats["scheduled_packages"]) + int(stats["policy_blocked"]), 0)
                blocked_total = int(stats["blocked_packages"])
                blocked_policy = int(stats["policy_blocked"])
                blocked_scope = max(blocked_total - blocked_policy, 0)
                artifacts = sum(
                    len(pkg.artifacts)
                    for pkg in active_plan.packages
                    if not pkg.skip_reason
                )
                ui.report_harvest_started(
                    candidate_count=candidate_count,
                    selected_count=selected_count,
                    policy_eligible=eligible,
                    scheduled=int(stats["scheduled_packages"]),
                    blocked_policy=blocked_policy,
                    blocked_scope=blocked_scope,
                    artifacts=artifacts,
                    policy=str(stats["policy"]),
                    harvest_mode=(str(active_selection.metadata.get("harvest_mode") or "").strip() or harvest_mode),
                    delta_filter_applied=bool(active_selection.metadata.get("delta_filter_applied")) if summary else None,
                )
            return planner.build_plan(
                active_selection,
                is_rooted=is_rooted,
                pull_mode=pull_mode,
                verbose=verbose,
                guard_metadata=guard_metadata,
            )
