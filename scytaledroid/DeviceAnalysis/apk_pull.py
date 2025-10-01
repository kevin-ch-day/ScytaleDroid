"""apk_pull.py - Pull APK artifacts from a connected device and persist metadata."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import adb_utils, harvest, inventory
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

    while True:
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

        action = _prompt_plan_action()
        if action == "dry-run":
            harvest.preview_plan(plan)
            prompt_utils.press_enter_to_continue()
            continue
        if action == "rescope":
            continue
        if action == "cancel":
            print(status_messages.status("APK pull cancelled by user.", level="warn"))
            prompt_utils.press_enter_to_continue()
            return
        if action == "pull_verbose":
            verbose = True
        elif action == "pull_quiet":
            verbose = False
        else:
            continue

        active_plan = plan
        active_selection = selection
        break

    if not active_plan or not active_selection:
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

    results = harvest.execute_harvest(
        serial=serial,
        adb_path=adb_path,
        dest_root=dest_root,
        session_stamp=session_stamp,
        plans=active_plan.packages,
        verbose=verbose,
    )

    if verbose:
        for result in results:
            harvest.print_package_result(result, verbose=True)
    else:
        for result in results:
            harvest.print_package_result(result, verbose=False)

    harvest.render_harvest_summary(active_plan, results, selection=active_selection)
    _maybe_save_watchlist(active_selection)
    prompt_utils.press_enter_to_continue()


def _prompt_plan_action() -> str:
    print()
    print(text_blocks.headline("Plan actions", width=70))
    options = {
        "1": "Start pull (quiet)",
        "2": "Start pull (verbose adb)",
        "3": "Dry-run preview",
        "4": "Change scope",
        "0": "Cancel",
    }
    menu_utils.print_menu(options, is_main=False, default="1", exit_label="Cancel")
    choice = prompt_utils.get_choice(list(options.keys()), default="1")
    if choice == "1":
        return "pull_quiet"
    if choice == "2":
        return "pull_verbose"
    if choice == "3":
        return "dry-run"
    if choice == "4":
        return "rescope"
    return "cancel"


def _device_is_rooted(serial: str) -> bool:
    try:
        completed = adb_utils.run_shell_command(serial, ["id", "-u"])
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
