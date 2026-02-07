"""CLI views for inventory using the shared formatter (forensic style)."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory import snapshot_io
from scytaledroid.Utils.DisplayUtils import menu_utils

from .diagnostics import compute_inventory_metrics


def print_inventory_run_start(*, serial: str, mode_label: str, mode_key: str) -> None:
    menu_utils.print_header("Inventory Sync · RUN START")
    print(f"Device: {serial}")
    print(f"Mode: {mode_key} ({mode_label})")
    print()


def print_inventory_run_summary_from_result(result) -> None:
    """
    Render a structured summary from the existing InventoryResult object.
    Keeps compatibility while we migrate to richer domain models.
    """
    metrics = compute_inventory_metrics(result)

    menu_utils.print_header("Inventory Sync · RUN SUMMARY")
    snapshot_path = getattr(result, "snapshot_path", None)
    snapshot_id = getattr(result, "snapshot_id", None)
    snapshot_label = snapshot_path or (f"id={snapshot_id}" if snapshot_id is not None else "—")
    print(f"[RUN] Snapshot: {snapshot_label}")
    summary = (
        f"Inventory sync complete · {metrics.total_packages} packages · "
        f"snapshot id={snapshot_id if snapshot_id is not None else '—'} · "
        f"{metrics.scan_duration}"
    )
    print(f"✔ {summary}")
    print(f"Packages: {metrics.total_packages}")
    print(
        "Delta vs previous: "
        f"new={metrics.delta_new} removed={metrics.delta_removed} updated={metrics.delta_updated}"
    )
    print(f"[RESULT] User apps (candidates): {metrics.user_scope_candidates}")
    print()

    # Phase A closure visibility: show bounded retention status (operator-visible).
    serial = getattr(result, "serial", None)
    if serial:
        status = snapshot_io.get_inventory_retention_status(str(serial))
        print(
            "Retention: "
            f"policy=N={status.get('policy_keep_last')} "
            f"db_snapshots={status.get('db_snapshots')} "
            f"fs_history_files={status.get('fs_history_files')}"
        )
        inv_dir = status.get("inventory_dir")
        if inv_dir:
            print(f"Inventory dir: {inv_dir}")
        print()
