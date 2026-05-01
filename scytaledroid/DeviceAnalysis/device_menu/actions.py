"""Menu action handlers for the Device Analysis menu."""

from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.inventory import cli_labels as inventory_cli_labels
from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .dashboard import _compact_age_display
from .harvest_entry import run_execute_harvest_menu_precheck
from .inventory_guard import ensure_recent_inventory
from .inventory_sync_feedback import print_inventory_run_feedback

# Keep menu routing aligned with handle_choice to avoid accidental swaps in the CLI.
_HELPER_ROUTES = {
    "4": ("logcat", "stream_logcat", True, "Stream logcat output"),
    "5": ("shell", "open_shell", True, "Open interactive adb shell"),
    "7": ("report", "generate_device_report", True, "Export the device summary"),
    "9": ("watchlist_manager", "manage_watchlists", False, "Manage harvest scope/watchlists"),
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


def _harvest_run_context_detail_lines(context: Mapping[str, object] | None) -> list[str]:
    ctx = context or {}
    lines: list[str] = []
    for key, label in (
        ("run_id", "Run ID"),
        ("session_stamp", "Session"),
        ("snapshot_id", "Inventory snapshot ID"),
        ("artifacts_root", "Artifacts root"),
        ("receipts_root", "Receipts root"),
    ):
        val = ctx.get(key)
        if val is None or str(val).strip() == "":
            continue
        lines.append(f"{label}: {val}")
    return lines


def _print_harvest_success_menu_feedback(result_context: Mapping[str, object] | None) -> None:
    """Full menu rollup; skipped in harvest simple-mode to avoid repeating the transcript block."""

    from scytaledroid.DeviceAnalysis import harvest as harvest_pkg

    ctx = dict(result_context or {})
    if harvest_pkg.is_harvest_simple_mode():
        print()
        print(
            status_messages.status(
                "Harvest session closed · menus: 8) Browse harvested APKs · 3) Inventory & harvest details",
                level="info",
            )
        )
        return

    harvested = ctx.get("packages", "—")
    total_scope = ctx.get("packages_total")
    blocked = ctx.get("packages_blocked")
    if total_scope not in (None, "—") and blocked not in (None, "—"):
        harvest_summary = (
            f"Harvest complete: {harvested} harvested / {total_scope} in scope "
            f"({blocked} blocked)."
        )
    else:
        harvest_summary = f"Harvest complete: {harvested} package(s)."
    _print_action_feedback(
        action_name="Execute Harvest",
        summary=harvest_summary,
        info_lines=_harvest_run_context_detail_lines(ctx),
    )


def handle_choice(
    choice: str,
    devices: list[dict[str, str | None]],
    summaries: list[dict[str, str | None]],
    active_device: dict[str, str | None | None],
    active_details: dict[str, str | None | None],
) -> bool:
    if choice == "6":
        # Jump to the full devices hub for consistent list/switch UX.
        from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

        devices_hub()
    elif choice == "1":
        _run_inventory_sync(active_device)
    elif choice == "2":
        _run_apk_pull(active_device, auto_scope=False)
    elif choice == "3":
        _show_inventory_harvest_details(active_details)
    elif choice in {"4", "5", "7", "9"}:
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
            "Refresh inventory",
            description="Refresh the current device inventory and snapshot state.",
            badge=inv_badge or needs_active,
        ),
        menu_utils.MenuOption(
            "2",
            "Execute harvest",
            description="Harvest APK artifacts using the current inventory scope.",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "3",
            "View inventory and harvest details",
            description="Open the full device, pipeline, and evidence detail view.",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "4",
            "Open device logcat",
            description="Stream logcat from the active device.",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "5",
            "Open ADB shell",
            description="Open an interactive adb shell on the active device.",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "6",
            "Switch device",
            description="Select or switch the active device.",
        ),
        menu_utils.MenuOption(
            "7",
            "Export device summary",
            description="Generate the current device summary report.",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "8",
            "Browse harvested APKs",
            description="Browse harvested APK artifacts for the active device.",
        ),
        menu_utils.MenuOption(
            "9",
            "Manage harvest scope/watchlists",
            description="Manage watchlists and scope filters.",
        ),
    ]

    return options


def _show_inventory_harvest_details(
    active_details: dict[str, str | None | None],
) -> None:
    if not active_details or not active_details.get("serial"):
        error_panels.print_error_panel(
            "Inventory and harvest details",
            "No active device. Choose 6) Switch device from this menu.",
        )
        prompt_utils.press_enter_to_continue()
        return

    from .dashboard import print_device_details

    inventory_metadata = device_service.fetch_inventory_metadata(
        active_details.get("serial"),
        with_current_state=True,
    )
    print()
    menu_utils.print_header("Inventory and harvest details")
    print_device_details(active_details, inventory_metadata)
    prompt_utils.press_enter_to_continue()


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

    precheck = run_execute_harvest_menu_precheck(serial)
    if precheck is None:
        return
    accept_age_stale_harvest = precheck

    if not ensure_recent_inventory(
        serial,
        device_context=active_device,
        accept_age_stale_harvest=accept_age_stale_harvest,
    ):
        return

    # Proceed to APK harvesting flow.
    try:
        from scytaledroid.DeviceAnalysis.apk.workflow import run_apk_pull

        result = run_apk_pull(serial, auto_scope=auto_scope)
        ctx = getattr(result, "context", {}) or {}
        code = getattr(result, "error_code", "") or ""
        if code == "apk_pull_cancelled":
            print()
            print(status_messages.status(result.user_message or "Harvest cancelled.", level="info"))
            prompt_utils.press_enter_to_continue()
            return
        if not result.ok and getattr(result, "status", "") == "PARTIAL":
            error_panels.print_warning_panel(
                "Execute Harvest",
                result.user_message or "Harvest partially completed.",
                hint=result.log_hint or "See logs.",
            )
            for line in _harvest_run_context_detail_lines(ctx):
                print(status_messages.status(line, level="info"))
            prompt_utils.press_enter_to_continue()
            return
        if not result.ok:
            error_panels.print_error_panel(
                "Execute Harvest",
                result.user_message or "Execute Harvest failed.",
                hint=result.log_hint or "See logs for traceback.",
            )
            prompt_utils.press_enter_to_continue()
            return
        _print_harvest_success_menu_feedback(ctx)
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
            inventory_cli_labels.ERROR_SECTION,
            "No active device. Connect a device first.",
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
        menu_utils.print_header(inventory_cli_labels.SECTION_HEADLINE, inventory_cli_labels.SCOPE_MENU_SUBTITLE)
        sync_opts = [
            menu_utils.MenuOption("1", inventory_cli_labels.MENU_OPTION_FULL),
            menu_utils.MenuOption("2", inventory_cli_labels.MENU_OPTION_SCOPED),
        ]
        menu_utils.render_menu(
            menu_utils.MenuSpec(items=sync_opts, exit_label="Back", show_exit=True, show_descriptions=False, compact=True)
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(sync_opts, include_exit=True),
            default="1",
            prompt="Scope [1]: ",
        )
        if choice == "0":
            return

        if choice == "1":
            # Full sync is the slow path; if the inventory is already fresh, ask once.
            if status and status.status_label.upper() == "FRESH" and not status.is_stale:
                print()
                age_raw = getattr(status, "age_display", None)
                age_compact = _compact_age_display(age_raw) if age_raw else "recent"
                pkg_note = (
                    f"{status.package_count} pkgs"
                    if getattr(status, "package_count", None) is not None
                    else "pkgs on snapshot"
                )
                print(
                    status_messages.status(
                        f"Snapshot is fresh ({age_compact} · {pkg_note}). Run full refresh anyway?",
                        level="info",
                    )
                )
                if not prompt_utils.prompt_yes_no(
                    "Continue",
                    default=False,
                ):
                    return
            result = inventory_workflow.run_inventory_sync(
                serial,
                ui_prefs=None,
                progress_sink="cli",
                allow_fallbacks=allow_fallbacks,
            )
            print_inventory_run_feedback(result)
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
            print_inventory_run_feedback(
                result,
                scoped_label=str(selected_profile["display_name"]),
            )
    except Exception as exc:
        error_panels.print_error_panel(
            inventory_cli_labels.ERROR_SECTION,
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
                f"Only one active profile is available. Using {selected['display_name']}.",
                level="info",
            )
        )
        return selected

    print()
    menu_utils.print_header(f"{inventory_cli_labels.SECTION_HEADLINE} · profile")
    rows = [
        [str(idx), str(profile["display_name"]), str(int(profile["app_count"]))]
        for idx, profile in enumerate(profiles, start=1)
    ]
    table_utils.render_table(["#", "Profile", "Apps"], rows, compact=True)
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(profiles) + 1)] + ["0"],
        default="1",
        prompt="Profile [1]: ",
    )
    if choice == "0":
        return None
    return profiles[int(choice) - 1]

__all__ = ["handle_choice", "build_main_menu_options"]
