"""CLI views for inventory using the shared formatter (forensic style)."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory import cli_labels as inventory_cli_labels, snapshot_io
from scytaledroid.DeviceAnalysis.inventory.cli_labels import (
    RUN_START_CARD_FOOTER,
    RUN_START_HEADER,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, summary_cards

from .summary import render_sync_summary_box


def print_inventory_run_start(*, serial: str, mode_label: str, mode_key: str) -> None:
    menu_utils.print_header(RUN_START_HEADER)
    print(
        summary_cards.format_summary_card(
            "Run Context",
            [
                summary_cards.summary_item("Device", serial, value_style="accent"),
                summary_cards.summary_item("Mode", f"{mode_key} ({mode_label})", value_style="info"),
            ],
            footer=RUN_START_CARD_FOOTER,
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
            f"{status.get('policy_keep_last')} kept "
            f"(DB {status.get('db_snapshots')}, FS {status.get('fs_snapshots')})"
        )
    stats = getattr(result, "stats", None)
    rows = getattr(result, "rows", None) or []
    total_pkgs = int(getattr(stats, "total_packages", len(rows)) or len(rows))
    sid = getattr(result, "snapshot_id", None)
    sid_label = str(sid) if sid is not None else "—"
    print()
    print(
        status_messages.status(
            (
                f"{inventory_cli_labels.SECTION_HEADLINE} complete · snapshot {sid_label} · "
                f"{total_pkgs} packages on this snapshot"
            ),
            level="success",
        )
    )
