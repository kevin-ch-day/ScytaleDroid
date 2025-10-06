"""apk_pull.py - Pull APK artifacts from a connected device and persist metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Sequence, Tuple

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import adb_utils, harvest, inventory
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard import (
    INVENTORY_STALE_SECONDS,
    get_last_guard_decision,
    get_latest_inventory_metadata,
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import (
    coerce_float,
    humanize_seconds,
)
from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def pull_apks(serial: Optional[str]) -> None:
    """Pull APK files for the active device and upsert metadata into the repository."""

    if not serial:
        error_panels.print_error_panel(
            "APK Pull",
            "No active device. Connect first to pull APKs.",
        )
        prompt_utils.press_enter_to_continue()
        return

    if not adb_utils.is_available():
        error_panels.print_error_panel(
            "APK Pull",
            "adb binary not found on PATH.",
            hint="Ensure the Android platform tools are installed and exported in PATH.",
        )
        prompt_utils.press_enter_to_continue()
        return

    snapshot = inventory.load_latest_inventory(serial)
    if not snapshot:
        error_panels.print_error_panel(
            "APK Pull",
            "No inventory snapshot found for this device.",
            hint="Run an inventory sync before attempting to harvest APKs.",
        )
        if prompt_utils.prompt_yes_no("Run an inventory sync now?", default=True):
            inventory.run_inventory_sync(serial)
            snapshot = inventory.load_latest_inventory(serial)
        else:
            prompt_utils.press_enter_to_continue()
            return

    if not snapshot or not snapshot.get("packages"):
        error_panels.print_error_panel(
            "APK Pull",
            "Unable to retrieve inventory data after sync.",
        )
        prompt_utils.press_enter_to_continue()
        return

    packages = snapshot.get("packages", [])
    rows = harvest.build_inventory_rows(packages)
    if not rows:
        error_panels.print_error_panel(
            "APK Pull",
            "Inventory snapshot contains no packages.",
        )
        prompt_utils.press_enter_to_continue()
        return

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
            return
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

        include_system_partitions = (
            selection.kind in {"families", "everything"} and is_rooted
        )
        plan = harvest.build_harvest_plan(
            selection.packages,
            include_system_partitions=include_system_partitions,
        )

        harvest.render_plan_summary(
            selection,
            plan,
            is_rooted=is_rooted,
            include_system_partitions=include_system_partitions,
        )

        scheduled_files = sum(len(pkg.artifacts) for pkg in plan.packages if not pkg.skip_reason)
        if scheduled_files == 0:
            print(
                status_messages.status(
                    "Plan contains no readable artifacts. Adjust the scope and try again.",
                    level="warn",
                )
            )
            continue

        refresh_requested = False
        while True:
            action = _prompt_plan_action()
            if action == "dry-run":
                harvest.preview_plan(plan)
                prompt_utils.press_enter_to_continue()
                continue
            if action == "rescope":
                break
            if action == "cancel":
                print(status_messages.status("APK pull cancelled by user.", level="warn"))
                prompt_utils.press_enter_to_continue()
                return
            if action == "use_snapshot":
                print(
                    status_messages.status(
                        "Proceeding with existing inventory snapshot only.",
                        level="warn",
                    )
                )
                prompt_utils.press_enter_to_continue()
                return
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
                        return
                    packages = snapshot.get("packages", [])
                    rows = harvest.build_inventory_rows(packages)
                    if not rows:
                        error_panels.print_error_panel(
                            "APK Pull",
                            "Scoped snapshot contains no packages.",
                            hint="Adjust your selection or run a full sync.",
                        )
                        prompt_utils.press_enter_to_continue()
                        return
                    latest_metadata = get_latest_inventory_metadata(
                        serial,
                        with_current_state=True,
                        scope_packages=selection.packages,
                    )
                    if latest_metadata:
                        guard_metadata = latest_metadata
                    refresh_requested = True
                break
            if action == "refresh_full":
                progress = _make_progress_callback("Refreshing full inventory")
                try:
                    inventory.run_inventory_sync(
                        serial,
                        interactive=False,
                        progress_callback=progress,
                    )
                except inventory.InventorySyncAborted:
                    print(
                        status_messages.status(
                            "Inventory sync cancelled before completion.",
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
                    return
                packages = snapshot.get("packages", [])
                rows = harvest.build_inventory_rows(packages)
                if not rows:
                    error_panels.print_error_panel(
                        "APK Pull",
                        "Inventory snapshot contains no packages after refresh.",
                    )
                    prompt_utils.press_enter_to_continue()
                    return
                latest_metadata = get_latest_inventory_metadata(
                    serial,
                    with_current_state=True,
                    scope_packages=selection.packages,
                )
                if latest_metadata:
                    guard_metadata = latest_metadata
                refresh_requested = True
                break
            if action == "quick":
                harvest_mode = _prompt_harvest_mode(
                    prefer_quick=_prefer_quick_mode(guard_metadata)
                )
                if not harvest_mode:
                    continue
                pull_mode, verbose = harvest_mode
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
        return

    adb_path = adb_utils.get_adb_binary()
    if not adb_path:
        error_panels.print_error_panel(
            "APK Pull",
            "adb binary not found on PATH.",
            hint="Install platform-tools and ensure adb is accessible.",
        )
        prompt_utils.press_enter_to_continue()
        return

    session_stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dest_root = Path(app_config.DATA_DIR) / "apks" / "device_apks" / serial
    dest_root.mkdir(parents=True, exist_ok=True)

    if pull_mode == "quick":
        results = harvest.quick_harvest(
            active_plan.packages,
            adb_path=adb_path,
            dest_root=dest_root,
            session_stamp=session_stamp,
            config=app_config,
            serial=serial,
            verbose=verbose,
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
        )

    if verbose:
        for result in results:
            harvest.print_package_result(result, verbose=True)
    else:
        for result in results:
            harvest.print_package_result(result, verbose=False)

    harvest.render_harvest_summary(
        active_plan,
        results,
        selection=active_selection,
        pull_mode=pull_mode,
        serial=serial,
        run_timestamp=session_stamp,
        guard_brief=active_selection.metadata.get("inventory_guard_brief"),
    )
    _maybe_save_watchlist(active_selection)
    prompt_utils.press_enter_to_continue()


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


def _prompt_plan_action() -> str:
    print()
    print(text_blocks.headline("Plan actions", width=70))
    options = {
        "1": "Quick harvest (no sync)",
        "2": "Use last snapshot",
        "3": "Refresh scope only (fast)",
        "4": "Refresh full inventory (slow)",
        "5": "Dry-run preview",
        "6": "Change scope",
        "0": "Cancel",
    }
    menu_utils.print_menu(options, is_main=False, default="1", exit_label="Cancel")
    choice = prompt_utils.get_choice(list(options.keys()), default="1")
    if choice == "1":
        return "quick"
    if choice == "2":
        return "use_snapshot"
    if choice == "3":
        return "refresh_subset"
    if choice == "4":
        return "refresh_full"
    if choice == "5":
        return "dry-run"
    if choice == "6":
        return "rescope"
    return "cancel"


def _prompt_harvest_mode(*, prefer_quick: bool) -> Optional[Tuple[str, bool]]:
    print()
    print(text_blocks.headline("Harvest execution", width=70))
    options = {
        "1": "Quick pull (quiet)",
        "2": "Quick pull (verbose adb, stream output)",
        "3": "Legacy pull (quiet)",
        "4": "Legacy pull (verbose adb, stream output)",
        "0": "Back",
    }
    default_choice = "1" if prefer_quick else "3"
    menu_utils.print_menu(options, is_main=False, default=default_choice, exit_label="Back")
    choice = prompt_utils.get_choice(list(options.keys()), default=default_choice)
    if choice == "1":
        return ("quick", False)
    if choice == "2":
        return ("quick", True)
    if choice == "3":
        return ("legacy", False)
    if choice == "4":
        return ("legacy", True)
    return None


def _device_is_rooted(serial: str) -> bool:
    try:
        completed = adb_utils.run_shell_command(serial, ["id", "-u"])
    except RuntimeError as exc:
        log.warning(f"Failed to determine root state for {serial}: {exc}", category="device")
        return False
    if completed.returncode != 0:
        return False
    return completed.stdout.strip() == "0"


def _prefer_quick_mode(metadata: Optional[Dict[str, object]]) -> bool:
    decision = get_last_guard_decision()
    policy = decision.get("policy") if isinstance(decision, dict) else None
    if policy == "quick":
        return True

    stale_level = decision.get("stale_level") if isinstance(decision, dict) else None
    if stale_level == "soft":
        return True

    if not metadata:
        return False

    metadata_stale_level = metadata.get("stale_level")
    if isinstance(metadata_stale_level, str) and metadata_stale_level == "soft":
        return True

    timestamp = metadata.get("timestamp")
    if not isinstance(timestamp, datetime):
        return False

    now = datetime.now(timezone.utc)
    age_seconds = (now - timestamp).total_seconds()
    if age_seconds < 0:
        age_seconds = 0

    stale = age_seconds > INVENTORY_STALE_SECONDS
    state_changed = bool(metadata.get("state_changed"))
    return stale and not state_changed


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
