"""Menu action handlers for the Device Analysis menu."""

from __future__ import annotations

from importlib import import_module

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.services import device_service, info_service
from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .formatters import (
    format_battery,
    format_device_line,
)
from .inventory_guard import ensure_recent_inventory

# Keep menu routing aligned with handle_choice to avoid accidental swaps in the CLI.
_HELPER_ROUTES = {
    "3": ("inventory", "run_device_summary", True, "Collect detailed device summary"),
    "4": ("logcat", "stream_logcat", True, "Stream logcat output"),
    "5": ("shell", "open_shell", True, "Open interactive adb shell"),
    "6": ("report", "generate_device_report", True, "Export the device dossier"),
    "7": ("watchlist_manager", "manage_watchlists", False, "Manage harvest watchlists"),
}


def _print_action_feedback(
    *,
    action_name: str,
    summary: str,
    info_lines: list[str] | None = None,
) -> None:
    print(status_messages.status(action_name, level="progress"))
    print(status_messages.status(summary, level="success"))
    for line in info_lines or []:
        print(status_messages.status(line, level="info"))


def _print_inventory_feedback(action_name: str, result, *, scoped_label: str | None = None) -> None:
    if result is None or not hasattr(result, "stats"):
        return
    if scoped_label:
        summary = f"Scoped inventory refreshed: {result.stats.total_packages} package(s) for {scoped_label}."
    else:
        summary = f"Inventory refreshed: {result.stats.total_packages} package(s)."
    _print_action_feedback(
        action_name=action_name,
        summary=summary,
        info_lines=[
            f"Snapshot ID: {result.snapshot_id if result.snapshot_id is not None else '—'}",
            f"Inventory snapshot: {result.snapshot_path}",
        ],
    )


def handle_choice(
    choice: str,
    devices: list[dict[str, str | None]],
    summaries: list[dict[str, str | None]],
    active_device: dict[str, str | None | None],
    active_details: dict[str, str | None | None],
) -> bool:
    if choice == "9":
        # Jump to the full devices hub for consistent list/switch UX.
        from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

        devices_hub()
    elif choice == "1":
        _run_inventory_sync(active_device)
    elif choice == "2":
        _run_apk_pull(active_device, auto_scope=False)
    elif choice in {"3", "4", "5", "6", "7"}:
        _forward_to_helper(choice, active_device)
    elif choice == "8":
        _open_apk_library_filtered(active_device)
    else:
        error_panels.print_error_panel(
            "Device Analysis",
            f"Device option {choice} is not implemented yet.",
            hint="Track the roadmap for availability of this action.",
        )
        prompt_utils.press_enter_to_continue()

    return False


def build_main_menu_options(
    active_details: dict[str, str | None | None]
) -> list[menu_utils.MenuOption]:
    """
    Single source of truth for the Device Analysis menu.
    Any change to menu ordering/labels must be reflected here and in handlers.
    """
    serial = active_details.get("serial") if active_details else device_manager.get_active_serial()
    has_device = bool(serial)

    inv_status_obj = device_service.fetch_inventory_metadata(serial) if serial else None
    # Derive compact badges from status strings
    inv_badge: str | None = None
    if inv_status_obj:
        if inv_status_obj.is_stale:
            inv_badge = "recommended"
        elif inv_status_obj.status_label == "NONE":
            inv_badge = "not run"

    needs_active = None if has_device else "needs active"

    options: list[menu_utils.MenuOption] = [
        menu_utils.MenuOption(
            "1",
            "Refresh Inventory",
            badge=inv_badge or needs_active,
        ),
        menu_utils.MenuOption(
            "2",
            "Execute Harvest",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "3",
            "View device details",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "4",
            "Open device logcat",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "5",
            "Open ADB shell",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "6",
            "Export device dossier",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption("7", "Manage harvest watchlists"),
        menu_utils.MenuOption("8", "Browse APK library"),
        menu_utils.MenuOption("9", "Switch device"),
    ]

    return options


def _list_devices(summaries: list[dict[str, str | None]]) -> None:
    # Instead of an inline list + extra prompt, jump to the full devices hub.
    from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

    devices_hub()


def _connect_to_device(
    devices: list[dict[str, str | None]],
    summaries: list[dict[str, str | None]],
) -> None:
    if not devices:
        error_panels.print_info_panel(
            "Connect to Device",
            "No devices detected by adb.",
            hint="Attach a device and ensure adb recognizes it (adb devices).",
        )
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Select Device", subtitle="Available adb devices")
    numbered_devices = {str(idx): summary for idx, summary in enumerate(summaries, start=1)}
    options = []
    for idx, summary in numbered_devices.items():
        label = format_device_line(summary, include_release=True)
        description = format_battery(summary)
        options.append(menu_utils.MenuOption(str(idx), label, description=description))
    menu_utils.print_menu(options)

    choice = prompt_utils.get_choice(list(numbered_devices.keys()) + ["0"], default="1")
    if choice == "0":
        return

    summary = numbered_devices[choice]
    serial = summary.get("serial")
    if not serial:
        error_panels.print_warning_panel(
            "Connect to Device",
            "Selected device has no serial identifier.",
        )
        prompt_utils.press_enter_to_continue()
        return

    from scytaledroid.DeviceAnalysis.services import device_service

    if device_service.set_active_serial(serial):
        label = format_device_line(summary, include_release=True)
        print(f"\nActive device set to {label}.")
        log.info(f"Active device set to {serial}.", category="device")
    else:
        error_panels.print_warning_panel(
            "Connect to Device",
            f"Failed to activate device with serial {serial}.",
            hint="Retry after verifying adb authorization on the device.",
        )
        log.warning(f"Failed to activate device {serial}.", category="device")
    prompt_utils.press_enter_to_continue()


def _show_device_info(
    active_device: dict[str, str | None | None],
    active_details: dict[str, str | None | None],
) -> None:
    info_rows = info_service.fetch_device_info(active_details)
    if not info_rows:
        error_panels.print_error_panel(
            "Device Info",
            "No active device. Use option 9 to select a device first.",
        )
        prompt_utils.press_enter_to_continue()
        return

    print("\nDevice information:")
    table_utils.render_table(["Field", "Value"], [[field, value] for field, value in info_rows.items()])
    prompt_utils.press_enter_to_continue()


def _disconnect_device() -> None:
    if device_manager.get_active_serial():
        device_manager.disconnect()
        log.info("Active device cleared by user.", category="device")
    else:
        log.info("Disconnect request received but no active device was set.", category="device")
    # Immediately return to the devices hub for a clean navigation model.
    from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

    devices_hub()


def _open_apk_library_filtered(active_device: dict[str, str | None | None]) -> None:
    serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
    if not serial:
        print(status_messages.status("No active device. Select a device first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        from scytaledroid.DeviceAnalysis.apk_library_menu import apk_library_menu

        apk_library_menu(device_filter=serial)
    except Exception as exc:
        log.error(f"Failed to open APK library for {serial}: {exc}", category="application")
        print(status_messages.status("Unable to open APK library. Check logs for details.", level="error"))
        prompt_utils.press_enter_to_continue()


def _forward_to_helper(option: str, active_device: dict[str, str | None | None]) -> None:
    module_name, func_name, requires_device, description = _HELPER_ROUTES[option]

    if requires_device and not active_device:
        error_panels.print_error_panel(
            description,
            "This action requires an active device. Please connect first.",
        )
        prompt_utils.press_enter_to_continue()
        return

    try:
        module = import_module(f"scytaledroid.DeviceAnalysis.{module_name}")
    except ModuleNotFoundError:
        error_panels.print_error_panel(
            description,
            f"[{module_name}] helper not available yet.",
            hint="Check that the module has been implemented before running this option.",
        )
        prompt_utils.press_enter_to_continue()
        return

    handler = getattr(module, func_name, None)
    if not callable(handler):
        error_panels.print_error_panel(
            description,
            f"[{module_name}] is missing the '{func_name}' handler.",
        )
        prompt_utils.press_enter_to_continue()
        return

    serial = active_device.get("serial") if active_device else None
    handler(serial=serial)  # type: ignore[arg-type,call-arg]


def _run_apk_pull(
    active_device: dict[str, str | None | None],
    *,
    auto_scope: bool = False,
) -> None:
    serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
    if not serial:
        error_panels.print_error_panel(
            "Execute Harvest",
            "No active device. Connect first to execute a harvest.",
        )
        prompt_utils.press_enter_to_continue()
        return

    status = device_service.fetch_inventory_metadata(serial)
    if status is None or status.status_label.upper() == "NONE":
        print()
        menu_utils.print_header("Execute Harvest")
        print(status_messages.status("No inventory snapshot found. Run Refresh Inventory first.", level="warn"))
        from scytaledroid.DeviceAnalysis.workflows import inventory_workflow
        try:
            result = inventory_workflow.run_inventory_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
            _print_inventory_feedback("Refresh Inventory", result)
            status = device_service.fetch_inventory_metadata(serial)
        except Exception as exc:
            print(status_messages.status(f"Refresh Inventory failed: {exc}", level="error"))
            return
        if status is None or status.status_label.upper() == "NONE":
            return
    # Detect change vs snapshot (if metadata carries change flags) or age-based staleness
    # Defer change-based gating to inventory_guard to avoid duplicate/noisy prompts.
    changed = False
    if status.is_stale:
        print()
        menu_utils.print_header("Execute Harvest")
        print(
            status_messages.status(
                f"Current inventory: {status.status_label} ({status.age_display}) • {status.package_count or 'unknown'} packages",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "Pulling APKs now may miss recently added or removed apps (stale by age).",
                level="warn",
            )
        )
        options = {
            "1": "Run Refresh Inventory first (recommended)",
            "2": "Proceed with stale inventory",
            "0": "Cancel",
        }
        menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
        choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
        if choice == "0":
            return
        if choice == "1":
            from scytaledroid.DeviceAnalysis.workflows import inventory_workflow
            try:
                result = inventory_workflow.run_inventory_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                _print_inventory_feedback("Refresh Inventory", result)
                status = device_service.fetch_inventory_metadata(serial)
            except Exception as exc:
                print(status_messages.status(f"Refresh Inventory failed: {exc}", level="error"))
                return
        # fall through to pull if choice == "2" or after sync
    elif changed:
        print()
        menu_utils.print_header("Execute Harvest")
        print(
            status_messages.status(
                "Device packages changed since the last inventory snapshot.",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Proceeding without sync may miss newly installed or metadata-changed packages.",
                level="warn",
            )
        )
        options = {
            "1": "Run Refresh Inventory now (recommended)",
            "2": "Use last snapshot anyway",
            "0": "Cancel",
        }
        menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
        choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
        if choice == "0":
            return
        if choice == "1":
            from scytaledroid.DeviceAnalysis.workflows import inventory_workflow
            try:
                result = inventory_workflow.run_inventory_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                _print_inventory_feedback("Refresh Inventory", result)
                status = device_service.fetch_inventory_metadata(serial)
            except Exception as exc:
                print(status_messages.status(f"Refresh Inventory failed: {exc}", level="error"))
                return

    if not ensure_recent_inventory(serial, device_context=active_device):
        return

    # Proceed to APK harvesting flow.
    try:
        from scytaledroid.DeviceAnalysis.workflows import apk_pull_workflow

        result = apk_pull_workflow.run_apk_pull(serial, auto_scope=auto_scope)
        if hasattr(result, "ok") and not result.ok:
            error_panels.print_error_panel(
                "Execute Harvest",
                result.user_message or "Execute Harvest failed.",
                hint=result.log_hint or "See logs for traceback.",
            )
            return False
        context = getattr(result, "context", {}) or {}
        _print_action_feedback(
            action_name="Execute Harvest",
            summary=f"Harvest complete: {context.get('packages', '—')} package(s).",
            info_lines=[
                f"Run ID: {context.get('run_id', '—')}",
                f"Session: {context.get('session_stamp', '—')}",
                f"Inventory snapshot ID: {context.get('snapshot_id', '—')}",
                f"Artifacts root: {context.get('artifacts_root', '—')}",
                f"Receipts root: {context.get('receipts_root', '—')}",
            ],
        )
    except Exception as exc:
        logging_engine.get_error_logger().exception(
            "APK harvest failed",
            extra=logging_engine.ensure_trace(
                {
                    "event": "apk_harvest.start_failed",
                    "device_serial": serial,
                    "device_model": (active_device or {}).get("model") if active_device else None,
                }
            ),
        )
        error_panels.print_error_panel(
            "Execute Harvest",
            f"Failed to start APK harvest: {exc}",
            hint="See logs for traceback.",
        )
        prompt_utils.press_enter_to_continue()


def _run_inventory_sync(active_device: dict[str, str | None | None]) -> None:
    serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
    if not serial:
        error_panels.print_error_panel(
            "Refresh Inventory",
            "No active device. Connect first to refresh inventory.",
        )
        prompt_utils.press_enter_to_continue()
        return

    from scytaledroid.DeviceAnalysis.runtime_flags import set_allow_inventory_fallbacks
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    status = device_service.fetch_inventory_metadata(serial)
    try:
        root_state = (active_device or {}).get("is_rooted") or "Unknown"
        allow_fallbacks = str(root_state).strip().lower() != "yes"
        set_allow_inventory_fallbacks(allow_fallbacks)
        print()
        # Keep the operator contract simple: canonical full sync, or scoped sync
        # against one of the currently active app profiles.
        menu_utils.print_header("Refresh Inventory", "Choose sync scope")
        sync_opts = [
            menu_utils.MenuOption("1", "Full device inventory refresh (canonical)"),
            menu_utils.MenuOption("2", "Scoped refresh: app profile"),
        ]
        menu_utils.render_menu(
            menu_utils.MenuSpec(items=sync_opts, exit_label="Back", show_exit=True, show_descriptions=False, compact=True)
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(sync_opts, include_exit=True),
            default="1",
            prompt="Select refresh mode (or 0): ",
        )
        if choice == "0":
            return

        if choice == "1":
            # Full sync is the slow path; if the inventory is already fresh, ask once.
            if status and status.status_label.upper() == "FRESH" and not status.is_stale:
                print()
                if not prompt_utils.prompt_yes_no(
                    f"Inventory is already FRESH. Re-sync full inventory for {serial}?",
                    default=False,
                ):
                    return
            result = inventory_workflow.run_inventory_sync(
                serial,
                ui_prefs=None,
                progress_sink="cli",
                allow_fallbacks=allow_fallbacks,
            )
            _print_inventory_feedback("Refresh Inventory", result)
        else:
            selected_profile = _select_inventory_sync_profile()
            if selected_profile is None:
                return
            packages = set(selected_profile["packages"])
            if not packages:
                print(status_messages.status("Scoped refresh cancelled: selected profile has no packages.", level="warn"))
                prompt_utils.press_enter_to_continue()
                return
            result = inventory_workflow.run_inventory_scoped_sync(
                serial=serial,
                scope_id=str(selected_profile["scope_id"]),
                packages=packages,
                ui_prefs=None,
                progress_sink="cli",
                allow_fallbacks=allow_fallbacks,
            )
            _print_inventory_feedback(
                "Refresh Inventory",
                result,
                scoped_label=str(selected_profile["display_name"]),
            )
    except Exception as exc:
        error_panels.print_error_panel(
            "Refresh Inventory",
            str(exc),
        )
        prompt_utils.press_enter_to_continue()
        return


def _select_inventory_sync_profile() -> dict[str, object] | None:
    from scytaledroid.DynamicAnalysis.profile_loader import load_db_profiles, load_profile_packages

    raw_profiles = load_db_profiles()
    profiles: list[dict[str, object]] = []
    for profile in raw_profiles:
        profile_key = str(profile.get("profile_key") or "").strip()
        if not profile_key:
            continue
        display_name = str(profile.get("display_name") or profile_key).strip() or profile_key
        packages = {
            str(package).strip().lower()
            for package in load_profile_packages(profile_key)
            if str(package).strip()
        }
        profiles.append(
            {
                "profile_key": profile_key,
                "display_name": display_name,
                "scope_id": f"profile::{profile_key.lower()}",
                "packages": packages,
                "app_count": len(packages),
            }
        )

    profiles = [profile for profile in profiles if profile["packages"]]
    profiles.sort(key=lambda profile: str(profile["display_name"]).lower())

    if not profiles:
        print(status_messages.status("No active app profiles are available for scoped inventory refresh.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    if len(profiles) == 1:
        selected = profiles[0]
        print(
            status_messages.status(
                f"Only one active profile is available; selecting {selected['display_name']}.",
                level="info",
            )
        )
        return selected

    print()
    menu_utils.print_header("Refresh Inventory · Scope (Profile)")
    rows = [
        [str(idx), str(profile["display_name"]), str(int(profile["app_count"]))]
        for idx, profile in enumerate(profiles, start=1)
    ]
    table_utils.render_table(["#", "Profile", "Apps"], rows, compact=True)
    print(status_messages.status(f"Status: profiles={len(profiles)}", level="info"))
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(profiles) + 1)] + ["0"],
        default="1",
        prompt="Select profile # [1] ",
    )
    if choice == "0":
        return None
    return profiles[int(choice) - 1]

__all__ = ["handle_choice", "build_main_menu_options"]
