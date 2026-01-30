"""apk_pull.py - Pull APK artifacts from a connected device and persist metadata."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence, Set, Tuple

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import adb_client, adb_shell, harvest, inventory
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard import (
    get_last_guard_decision,
    get_latest_inventory_metadata,
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import (
    coerce_float,
    humanize_seconds,
)
from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    prompt_utils,
    status_messages,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.ops.operation_result import OperationResult


def _extract_delta_summary(
    selection_metadata: Mapping[str, object],
    guard_metadata: Optional[Mapping[str, object]],
) -> Optional[Mapping[str, object]]:
    """Return the most relevant delta summary available for the current scope."""

    for container in (selection_metadata, guard_metadata or {}):
        summary = container.get("package_delta_summary") if isinstance(container, Mapping) else None
        if isinstance(summary, Mapping) and summary.get("total_changed"):
            return summary
        alternate = container.get("package_delta") if isinstance(container, Mapping) else None
        if isinstance(alternate, Mapping) and alternate.get("total_changed"):
            return alternate
    return None


def _collect_delta_package_names(summary: Mapping[str, object]) -> Set[str]:
    """Extract the set of package names that should be harvested based on a delta summary."""

    names: Set[str] = set()
    added = summary.get("added_full") or summary.get("added")
    if isinstance(added, Sequence):
        for entry in added:
            if isinstance(entry, str) and entry:
                names.add(entry)

    updated = summary.get("updated_full") or summary.get("updated")
    if isinstance(updated, Sequence):
        for entry in updated:
            if isinstance(entry, Mapping):
                candidate = entry.get("package")
                if isinstance(candidate, str) and candidate:
                    names.add(candidate)

    # Explicitly ignore removed packages (nothing to harvest)
    return names


def _apply_delta_filter(
    selection: harvest.ScopeSelection,
    guard_metadata: Optional[Mapping[str, object]],
) -> Tuple[bool, int]:
    """Filter the selection packages down to delta-only scope when appropriate.

    Returns a tuple indicating whether a delta filter was applied, and how many packages remain.
    """

    summary = _extract_delta_summary(selection.metadata, guard_metadata)
    if not summary:
        return (False, len(selection.packages))

    delta_packages = _collect_delta_package_names(summary)
    if not delta_packages:
        return (False, len(selection.packages))

    filtered = [row for row in selection.packages if row.package_name in delta_packages]
    selection.metadata["delta_filter_applied"] = True
    selection.metadata["delta_filter_total"] = len(delta_packages)
    selection.metadata["delta_filter_matched"] = len(filtered)
    selection.metadata["delta_filter_packages"] = sorted(delta_packages)

    if not filtered:
        selection.packages.clear()
        return (True, 0)

    selection.packages = filtered
    return (True, len(filtered))


def pull_apks(serial: Optional[str]) -> OperationResult:
    """Pull APK files for the active device and upsert metadata into the repository."""

    if not serial:
        error_panels.print_error_panel(
            "APK Pull",
            "No active device. Connect first to pull APKs.",
        )
        prompt_utils.press_enter_to_continue()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: no active device.",
            error_code="apk_pull_no_device",
        )

    if not adb_client.is_available():
        error_panels.print_error_panel(
            "APK Pull",
            "adb binary not found on PATH.",
            hint="Ensure the Android platform tools are installed and exported in PATH.",
        )
        prompt_utils.press_enter_to_continue()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: adb not available.",
            error_code="apk_pull_no_adb",
        )

    snapshot = inventory.load_latest_inventory(serial)
    if not snapshot:
        error_panels.print_error_panel(
            "APK Pull",
            "No inventory snapshot found for this device.",
            hint="Run an inventory sync before attempting to harvest APKs.",
        )
        if prompt_utils.prompt_yes_no("Run an inventory sync now?", default=True):
            from scytaledroid.DeviceAnalysis.services import inventory_service
            try:
                inventory_service.run_full_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                snapshot = inventory.load_latest_inventory(serial)
            except Exception as exc:
                error_panels.print_error_panel("APK Pull", f"Inventory sync failed: {exc}")
                prompt_utils.press_enter_to_continue()
                return OperationResult.failure(
                    status="FAILED",
                    user_message="APK pull failed: inventory sync error.",
                    error_code="apk_pull_inventory_sync_failed",
                )
        else:
            prompt_utils.press_enter_to_continue()
            return OperationResult.failure(
                status="CANCELLED",
                user_message="APK pull cancelled before inventory sync.",
                error_code="apk_pull_cancelled",
            )

    if not snapshot or not snapshot.get("packages"):
        error_panels.print_error_panel(
            "APK Pull",
            "Unable to retrieve inventory data after sync.",
        )
        prompt_utils.press_enter_to_continue()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: inventory data unavailable.",
            error_code="apk_pull_inventory_missing",
        )

    snapshot_id = snapshot.get("snapshot_id")
    snapshot_captured_at = snapshot.get("generated_at")
    packages = snapshot.get("packages", [])
    rows = harvest.build_inventory_rows(packages)
    if not rows:
        error_panels.print_error_panel(
            "APK Pull",
            "Inventory snapshot contains no packages.",
        )
        prompt_utils.press_enter_to_continue()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: inventory snapshot empty.",
            error_code="apk_pull_inventory_empty",
        )

    is_rooted = _device_is_rooted(serial)

    active_plan = None
    active_selection = None
    include_system_partitions = False
    verbose = False
    google_allowlist = harvest.rules.load_google_allowlist()
    guard_metadata: Optional[Dict[str, object]] = get_latest_inventory_metadata(
        serial, with_current_state=True
    )
    guard_decision = get_last_guard_decision()
    pull_mode: Optional[str] = None

    while True:
        active_plan = None
        active_selection = None
        pull_mode = None
        verbose = False
        selection = harvest.select_package_scope(
            rows,
            device_serial=serial,
            is_rooted=is_rooted,
            google_allowlist=google_allowlist,
        )
        if selection is None:
            print(status_messages.status("APK pull cancelled by user.", level="warn"))
            prompt_utils.press_enter_to_continue()
            return OperationResult.failure(
                status="CANCELLED",
                user_message="APK pull cancelled by user.",
                error_code="apk_pull_cancelled",
            )
        if not selection.packages:
            print(status_messages.status("Selection contains no packages. Nothing to pull.", level="warn"))
            continue

        scoped_metadata = get_latest_inventory_metadata(
            serial,
            with_current_state=True,
            scope_packages=selection.packages,
        )
        if scoped_metadata:
            guard_metadata = scoped_metadata
        guard_decision = get_last_guard_decision()
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

        delta_applied, delta_count = _apply_delta_filter(selection, guard_metadata)
        if delta_applied:
            if delta_count == 0:
                print(
                    status_messages.status(
                        "Inventory delta shows no packages requiring harvest.",
                        level="info",
                    )
                )
                prompt_utils.press_enter_to_continue()
                continue
            print(
                status_messages.status(
                    f"Δ harvest scope: {delta_count} package(s) scheduled.",
                    level="info",
                )
            )

        include_system_partitions = (
            selection.kind in {"families", "everything"} and is_rooted
        )
        plan = harvest.build_harvest_plan(
            selection.packages,
            include_system_partitions=include_system_partitions,
        )

        scheduled_packages = sum(1 for pkg in plan.packages if not pkg.skip_reason)
        blocked_packages = sum(1 for pkg in plan.packages if pkg.skip_reason)
        scheduled_files = sum(len(pkg.artifacts) for pkg in plan.packages if not pkg.skip_reason)
        if scheduled_files == 0:
            print(
                status_messages.status(
                    "Plan contains no readable artifacts. Adjust the scope and try again.",
                    level="warn",
                )
            )
            continue

        _render_plan_overview(selection, plan, scheduled_packages, scheduled_files, blocked_packages)

        refresh_requested = False
        while True:
            action = _prompt_plan_action(selection, plan)
            if action == "dry-run":
                harvest.preview_plan(plan)
                prompt_utils.press_enter_to_continue()
                continue
            if action == "rescope":
                break
            if action == "cancel":
                print(status_messages.status("APK pull cancelled by user.", level="warn"))
                prompt_utils.press_enter_to_continue()
                return OperationResult.failure(
                    status="CANCELLED",
                    user_message="APK pull cancelled by user.",
                    error_code="apk_pull_cancelled",
                )
            if action == "use_snapshot":
                print(
                    status_messages.status(
                        "Proceeding with existing inventory snapshot only.",
                        level="warn",
                    )
                )
                prompt_utils.press_enter_to_continue()
                return OperationResult.failure(
                    status="CANCELLED",
                    user_message="APK pull cancelled: using snapshot only.",
                    error_code="apk_pull_snapshot_only",
                )
            if action == "refresh_subset":
                if _run_scope_refresh(serial, selection.packages):
                    snapshot = inventory.load_latest_inventory(serial)
                    if not snapshot or not snapshot.get("packages"):
                        error_panels.print_error_panel(
                            "APK Pull",
                            "Scoped refresh did not yield a valid snapshot.",
                            hint="Run a full inventory sync to recover.",
                        )
                        prompt_utils.press_enter_to_continue()
                        return OperationResult.failure(
                            status="FAILED",
                            user_message="APK pull failed: scoped refresh produced no snapshot.",
                            error_code="apk_pull_scoped_refresh_empty",
                        )
                    packages = snapshot.get("packages", [])
                    rows = harvest.build_inventory_rows(packages)
                    if not rows:
                        error_panels.print_error_panel(
                            "APK Pull",
                            "Scoped snapshot contains no packages.",
                            hint="Adjust your selection or run a full sync.",
                        )
                        prompt_utils.press_enter_to_continue()
                        return OperationResult.failure(
                            status="FAILED",
                            user_message="APK pull failed: scoped snapshot empty.",
                            error_code="apk_pull_scoped_snapshot_empty",
                        )
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
                progress = _make_progress_callback("Refreshing full inventory")
                from scytaledroid.DeviceAnalysis.services import inventory_service
                try:
                    inventory_service.run_full_sync(
                        serial=serial,
                        ui_prefs=text_blocks.UI_PREFS,
                        progress_sink="cli",
                    )
                except Exception as exc:
                    print(
                        status_messages.status(
                            f"Inventory sync cancelled or failed: {exc}",
                            level="warn",
                        )
                    )
                    continue

                snapshot = inventory.load_latest_inventory(serial)
                if not snapshot or not snapshot.get("packages"):
                    error_panels.print_error_panel(
                        "APK Pull",
                        "Inventory refresh did not yield a valid snapshot.",
                        hint="Run inventory sync from the main menu.",
                    )
                    prompt_utils.press_enter_to_continue()
                    return OperationResult.failure(
                        status="FAILED",
                        user_message="APK pull failed: inventory refresh produced no snapshot.",
                        error_code="apk_pull_refresh_empty",
                    )
                packages = snapshot.get("packages", [])
                rows = harvest.build_inventory_rows(packages)
                if not rows:
                    error_panels.print_error_panel(
                        "APK Pull",
                        "Inventory snapshot contains no packages after refresh.",
                    )
                    prompt_utils.press_enter_to_continue()
                    return OperationResult.failure(
                        status="FAILED",
                        user_message="APK pull failed: inventory snapshot empty after refresh.",
                        error_code="apk_pull_refresh_snapshot_empty",
                    )
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
        if active_plan and active_selection:
            break

    if not active_plan or not active_selection or not pull_mode:
        error_panels.print_error_panel(
            "APK Pull",
            "No harvest plan available.",
        )
        prompt_utils.press_enter_to_continue()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: no harvest plan.",
            error_code="apk_pull_no_plan",
        )

    adb_path = adb_client.get_adb_binary()
    if not adb_path:
        error_panels.print_error_panel(
            "APK Pull",
            "adb binary not found on PATH.",
            hint="Install platform-tools and ensure adb is accessible.",
        )
        prompt_utils.press_enter_to_continue()
        return OperationResult.failure(
            status="FAILED",
            user_message="APK pull failed: adb not available.",
            error_code="apk_pull_no_adb",
        )

    session_stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dest_root = Path(app_config.DATA_DIR) / "apks" / "device_apks" / serial
    dest_root.mkdir(parents=True, exist_ok=True)

    run_id = f"{serial or 'device'}-{session_stamp}"
    harvest_logger = log.harvest_adapter(
        run_id,
        started_at=datetime.utcnow(),
        context={
            "device_serial": serial,
            "session_stamp": session_stamp,
            "scope_label": active_selection.label,
            "pull_mode": pull_mode,
            "snapshot_id": snapshot_id if isinstance(snapshot_id, int) else None,
            "snapshot_captured_at": str(snapshot_captured_at) if snapshot_captured_at else None,
        },
    )

    try:
        if pull_mode == "quick":
            results = harvest.quick_harvest(
                active_plan.packages,
                adb_path=adb_path,
                dest_root=dest_root,
                session_stamp=session_stamp,
                config=app_config,
                serial=serial,
                verbose=verbose,
                run_id=run_id,
                harvest_logger=harvest_logger,
                snapshot_id=snapshot_id if isinstance(snapshot_id, int) else None,
                snapshot_captured_at=str(snapshot_captured_at) if snapshot_captured_at else None,
            )
        else:
            results = harvest.execute_harvest(
                serial=serial,
                adb_path=adb_path,
                dest_root=dest_root,
                session_stamp=session_stamp,
                plans=active_plan.packages,
                config=app_config,
                verbose=verbose,
                pull_mode=pull_mode,
                run_id=run_id,
                harvest_logger=harvest_logger,
                scope_label=active_selection.label,
                snapshot_id=snapshot_id if isinstance(snapshot_id, int) else None,
                snapshot_captured_at=str(snapshot_captured_at) if snapshot_captured_at else None,
            )
    except NameError as exc:
        if "compact_mode" in str(exc):
            log.close_harvest_adapter(run_id)
            logging_engine.get_error_logger().exception(
                "APK harvest failed (compact_mode)",
                extra=logging_engine.ensure_trace(
                    {"event": "apk_harvest.compact_mode_error", "run_id": run_id}
                ),
            )
            return OperationResult.failure(
                user_message="compact_mode is not defined",
                error_code="apk_harvest_compact_mode",
                context={"run_id": run_id, "device_serial": serial},
            )
        logging_engine.get_error_logger().exception(
            "APK harvest failed (NameError)",
            extra=logging_engine.ensure_trace(
                {
                    "event": "apk_harvest_name_error",
                    "run_id": run_id,
                    "device_serial": serial,
                    "pull_mode": pull_mode,
                    "scope_label": active_selection.label,
                }
            ),
        )
        log.close_harvest_adapter(run_id)
        return OperationResult.failure(
            user_message="APK harvest failed to start (NameError). See logs/error.log.",
            error_code="apk_harvest_name_error",
            context={"run_id": run_id, "device_serial": serial},
        )
    except Exception as exc:
        logging_engine.get_error_logger().exception(
            "APK harvest failed (exception)",
            extra=logging_engine.ensure_trace(
                {
                    "event": "apk_harvest_exception",
                    "run_id": run_id,
                    "device_serial": serial,
                    "pull_mode": pull_mode,
                    "scope_label": active_selection.label,
                }
            ),
        )
        log.close_harvest_adapter(run_id)
        return OperationResult.failure(
            user_message=f"APK harvest failed to start ({exc.__class__.__name__}). See logs/error.log.",
            error_code="apk_harvest_exception",
            context={"run_id": run_id, "device_serial": serial},
        )

    if verbose:
        for result in results:
            harvest.print_package_result(result, verbose=True)
    else:
        for result in results:
            harvest.print_package_result(result, verbose=False)

    try:
        harvest.render_harvest_summary(
            active_plan,
            results,
            selection=active_selection,
            pull_mode=pull_mode,
            serial=serial,
            run_timestamp=session_stamp,
            guard_brief=active_selection.metadata.get("inventory_guard_brief"),
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
                    "scope_label": active_selection.label,
                }
            ),
        )
        error_panels.print_error_panel(
            "APK Harvest",
            f"Harvest completed, but summary rendering failed: {exc}",
            hint="Artifacts and logs were written; inspect harvest logs for details.",
        )
    _maybe_save_watchlist(active_selection)
    log.close_harvest_adapter(run_id)
    prompt_utils.press_enter_to_continue()
    return OperationResult.success(
        context={"run_id": run_id, "device_serial": serial, "packages": len(active_plan.packages)}
    )


def _make_progress_callback(action_label: str) -> Callable[[Dict[str, object]], bool]:
    last_reported = 0.0

    def _callback(event: Dict[str, object]) -> bool:
        nonlocal last_reported

        phase = event.get("phase")
        if phase == "start":
            total = event.get("total")
            if isinstance(total, int) and total > 0:
                message = f"{action_label}: {total} packages"
            else:
                message = f"{action_label}..."
            print(status_messages.status(message, level="info"))
            return True

        if phase == "progress":
            percentage = event.get("percentage")
            eta_seconds = coerce_float(event.get("eta_seconds"))
            percent_value = None
            if isinstance(percentage, (int, float)):
                percent_value = float(percentage)
            else:
                processed = event.get("processed")
                total = event.get("total")
                if isinstance(processed, int) and isinstance(total, int) and total:
                    percent_value = (processed / total) * 100

            if percent_value is not None:
                if percent_value >= 100 or percent_value - last_reported >= 5:
                    last_reported = percent_value
                    if eta_seconds is not None and eta_seconds > 0:
                        eta_text = humanize_seconds(eta_seconds)
                        message = f"{action_label} progress: {percent_value:.1f}% (ETA {eta_text})"
                    else:
                        message = f"{action_label} progress: {percent_value:.1f}%"
                    print(status_messages.status(message, level="info"))
            elif eta_seconds is not None and eta_seconds > 0:
                eta_text = humanize_seconds(eta_seconds)
                print(
                    status_messages.status(
                        f"{action_label} progress (ETA {eta_text})",
                        level="info",
                    )
                )

            return True

        if phase == "complete":
            elapsed = coerce_float(event.get("elapsed_seconds"))
            if elapsed is not None and elapsed >= 0:
                message = f"{action_label} completed in {humanize_seconds(elapsed)}."
            else:
                message = f"{action_label} completed."
            print(status_messages.status(message, level="success"))
            return True

        return True

    return _callback


def _run_scope_refresh(serial: str, packages: Sequence[object]) -> bool:
    if not packages:
        print(status_messages.status("No packages provided for scoped refresh.", level="warn"))
        return False

    progress = _make_progress_callback("Refreshing scoped inventory")
    try:
        snapshot_path = inventory.sync_subset(
            packages,
            serial=serial,
            progress_callback=progress,
        )
    except inventory.InventorySyncAborted:
        print(status_messages.status("Scoped refresh cancelled.", level="warn"))
        return False
    except Exception as exc:  # pragma: no cover - defensive logging
        log.warning(f"Scoped inventory refresh failed: {exc}", category="device")
        print(status_messages.status("Scoped refresh failed.", level="error"))
        return False

    if not snapshot_path:
        print(status_messages.status("Scoped refresh produced no snapshot.", level="warn"))
        return False

    print(status_messages.status(f"Scoped inventory saved to {str(snapshot_path)}", level="success"))
    return True


def _render_plan_overview(
    selection: harvest.ScopeSelection,
    plan: harvest.HarvestPlan,
    packages: int,
    files: int,
    blocked_packages: int,
) -> None:
    print()
    print("APK Harvest Plan")
    print("-" * 86)
    candidate_count = selection.metadata.get("candidate_count")
    selected_count = selection.metadata.get("selected_count")
    if selection.metadata.get("delta_filter_applied"):
        candidate_count = selection.metadata.get("delta_filter_matched")
        selected_count = len(selection.packages)
    if not candidate_count:
        candidate_count = len(selection.packages)
    if selected_count is None:
        selected_count = len(selection.packages)

    policy_blocked = sum(
        1 for pkg in plan.packages if pkg.skip_reason == "policy_non_root"
    )
    eligible_policy = max(int(candidate_count) - int(policy_blocked), 0)
    eligible_artifacts = packages
    policy = selection.metadata.get("policy")
    if not policy:
        policy = ",".join(sorted(plan.policy_filtered.keys())) if plan.policy_filtered else "none"
    print(
        f"Scope={selection.label} | candidates={candidate_count} | "
        f"eligible_policy={eligible_policy} | eligible_artifacts={eligible_artifacts} | "
        f"blocked_policy={policy_blocked} | blocked={blocked_packages} | "
        f"files≈{files} | policy={policy}"
    )
    focus = selection.metadata.get("sample_names") or []
    total = selection.metadata.get("selected_count") or len(selection.packages)
    if focus:
        extra = f" (+{int(total) - len(focus)} more)" if total and int(total) > len(focus) else ""
        print(f"Focus: {', '.join(focus)}{extra}")
    print("-" * 86)


def _prompt_plan_action(
    selection: harvest.ScopeSelection, plan: harvest.HarvestPlan
) -> str:
    print("1) Full Pull (default)   - download APK splits + metadata")
    print("2) Test Pull             - dry run (list only)")
    print("0) Cancel")
    choice = prompt_utils.get_choice(["1", "2", "0"], default="1", prompt="Select: ")
    if choice == "1":
        return "pull_snapshot"
    if choice == "2":
        return "dry-run"
    return "cancel"


def _device_is_rooted(serial: str) -> bool:
    try:
        completed = adb_shell.run_shell_command(serial, ["id", "-u"])
    except RuntimeError as exc:
        log.warning(f"Failed to determine root state for {serial}: {exc}", category="device")
        return False
    if completed.returncode != 0:
        return False
    return completed.stdout.strip() == "0"


def _maybe_save_watchlist(selection: harvest.ScopeSelection) -> None:
    if selection.kind not in {"profile_subset", "profiles"}:
        return

    packages = [row.package_name for row in selection.packages]
    if len(packages) < 2:
        return
    if not prompt_utils.prompt_yes_no("Save this scope as a watchlist?", default=False):
        return

    default_name = selection.metadata.get("watchlist", selection.label)
    default_name = str(default_name).replace("Watchlist:", "").strip() or "New Watchlist"

    while True:
        name = prompt_utils.prompt_text("Watchlist name", default=default_name)
        try:
            path = harvest.save_watchlist(name, packages, overwrite=False)
        except FileExistsError:
            overwrite = prompt_utils.prompt_yes_no(
                "Watchlist exists. Overwrite?", default=False
            )
            if overwrite:
                path = harvest.save_watchlist(name, packages, overwrite=True)
            else:
                default_name = f"{name}-copy"
                continue
        print(status_messages.status(f"Watchlist saved to {path}", level="success"))
        break


__all__ = ["pull_apks"]
