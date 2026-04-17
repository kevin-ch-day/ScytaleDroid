"""CLI views for inventory using the shared formatter (forensic style)."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory import snapshot_io
from scytaledroid.Utils.DisplayUtils import menu_utils, summary_cards

from .summary import render_sync_summary_box


def print_inventory_run_start(*, serial: str, mode_label: str, mode_key: str) -> None:
    menu_utils.print_header("Refresh Inventory · RUN START")
    print(
        summary_cards.format_summary_card(
            "Run Context",
            [
                summary_cards.summary_item("Device", serial, value_style="accent"),
                summary_cards.summary_item("Mode", f"{mode_key} ({mode_label})", value_style="info"),
            ],
            footer="Collecting a fresh inventory snapshot from the connected device.",
        )
    )
    print()


def print_inventory_run_summary_from_result(result) -> None:
    """
    Render a structured summary from the existing InventoryResult object.
    Keeps compatibility while we migrate to richer domain models.
    """
    render_sync_summary_box(result)

    # Phase A closure visibility: show bounded retention status (operator-visible).
    serial = getattr(result, "serial", None)
    if serial:
        status = snapshot_io.get_inventory_retention_status(str(serial))
        print(
            "Retention: "
            f"policy=N={status.get('policy_keep_last')} "
            f"db_snapshots={status.get('db_snapshots')} "
            f"fs_snapshots={status.get('fs_snapshots')}"
        )
        inv_dir = status.get("inventory_dir")
        if inv_dir:
            print(f"Inventory dir: {inv_dir}")
        print()
    menu_utils.print_hint("Next: review inventory drift, then proceed to harvest or static analysis.")
