"""CLI views for inventory using the shared formatter (forensic style)."""

from __future__ import annotations

from typing import Mapping

from .diagnostics import compute_inventory_metrics


def print_inventory_run_start(*, serial: str, mode_label: str, mode_key: str) -> None:
    formatter.print_header("Inventory Sync · RUN START")
    print(
        formatter.format_kv_block(
            "[RUN]",
            {
                "Device": serial,
                "Mode": f"{mode_key} ({mode_label})",
            },
        )
    )
    print()


def print_inventory_run_summary_from_result(result) -> None:
    """
    Render a structured summary from the existing InventoryResult object.
    Keeps compatibility while we migrate to richer domain models.
    """
    metrics = compute_inventory_metrics(result)

    snapshot_id = getattr(result, "snapshot_id", None)
    summary = (
        f"Inventory sync complete · {metrics.total_packages} packages · "
        f"snapshot id={snapshot_id if snapshot_id is not None else '—'} · "
        f"{metrics.scan_duration}"
    )
    print(f"✔ {summary}")
    if metrics.delta_new or metrics.delta_removed or metrics.delta_updated:
        print(
            f"Delta: new={metrics.delta_new} removed={metrics.delta_removed} updated={metrics.delta_updated}"
        )
    print()
