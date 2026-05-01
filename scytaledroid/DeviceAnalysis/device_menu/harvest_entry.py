"""Execute Harvest entry UX: staleness prompts and lightweight inventory refresh."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory import cli_labels as inventory_cli_labels
from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis.services.models import InventoryStatus
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, text_blocks

from .inventory_sync_feedback import print_inventory_run_feedback


def inventory_live_drift(status: InventoryStatus | None) -> bool:
    """True when live device metadata disagrees with last snapshot (beyond age staleness)."""
    if status is None:
        return False
    return bool(
        status.packages_changed
        or status.scope_changed
        or status.state_changed
        or status.fingerprint_changed
    )


def refresh_inventory_for_harvest_menu(serial: str) -> tuple[bool, InventoryStatus | None]:
    """Run full inventory sync from Execute Harvest UX; shared by staleness prompts."""
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    try:
        result = inventory_workflow.run_inventory_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
        print_inventory_run_feedback(result)
        return True, device_service.fetch_inventory_metadata(serial)
    except Exception as exc:
        print(
            status_messages.status(
                f"{inventory_cli_labels.FEEDBACK_ACTION} failed: {exc}",
                level="error",
            )
        )
        return False, None


def run_execute_harvest_menu_precheck(serial: str) -> bool | None:
    """
    Prompt for refresh when inventory is missing, age-stale, or drifted.

    Returns ``None`` when the operator aborts or a required refresh fails.
    Otherwise returns the ``accept_age_stale_harvest`` flag for ``ensure_recent_inventory``.
    """
    status = device_service.fetch_inventory_metadata(serial)
    if status is None or status.status_label.upper() == "NONE":
        print()
        menu_utils.print_header("Execute Harvest")
        print(status_messages.status(inventory_cli_labels.SNAPSHOT_NOT_FOUND, level="warn"))
        ok, status = refresh_inventory_for_harvest_menu(serial)
        if not ok:
            return None
        if status is None or status.status_label.upper() == "NONE":
            return None

    accept_age_stale_harvest = False
    changed = inventory_live_drift(status)
    if status.is_stale:
        print()
        menu_utils.print_header("Execute Harvest")
        print(
            status_messages.status(
                f"Current inventory: {status.status_label} ({status.age_display}) • "
                f"{status.package_count or 'unknown'} packages",
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
            "1": "Run refresh inventory first (recommended)",
            "2": "Proceed with stale inventory",
            "0": "Cancel",
        }
        menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
        choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
        if choice == "0":
            return None
        if choice == "1":
            ok, status = refresh_inventory_for_harvest_menu(serial)
            if not ok:
                return None
        elif choice == "2":
            accept_age_stale_harvest = True
    elif changed:
        print()
        menu_utils.print_header("Execute Harvest")
        print(
            status_messages.status(
                "Device state differs from the last inventory snapshot "
                "(packages, scope, fingerprint, or runtime state).",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Refreshing inventory first is recommended so harvest targets the right APK set.",
                level="warn",
            )
        )
        options = {
            "1": "Run refresh inventory now (recommended)",
            "2": "Use last snapshot anyway",
            "0": "Cancel",
        }
        menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
        choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
        if choice == "0":
            return None
        if choice == "1":
            ok, status = refresh_inventory_for_harvest_menu(serial)
            if not ok:
                return None

    return accept_age_stale_harvest


__all__ = [
    "inventory_live_drift",
    "refresh_inventory_for_harvest_menu",
    "run_execute_harvest_menu_precheck",
]
