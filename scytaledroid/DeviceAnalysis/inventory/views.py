"""CLI views for inventory using the shared formatter (forensic style)."""

from __future__ import annotations

from typing import Mapping

from scytaledroid.ui import formatter
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

    formatter.print_header("Inventory Sync · RUN SUMMARY")
    print(
        formatter.format_kv_block(
            "[RUN]",
            {
                "Snapshot": str(getattr(result, "snapshot_path", "unknown")),
                "Packages": str(metrics.total_packages),
                "Split APK packages": str(metrics.split_apk_packages),
            },
        )
    )
    print()
    print(
        formatter.format_kv_block(
            "[RESULT]",
            {
                "Delta vs previous": (
                    f"new={metrics.delta_new}  removed={metrics.delta_removed}  updated={metrics.delta_updated}"
                ),
                "App defs synced": str(getattr(result, "synced_app_definitions", 0)),
                "Scan duration": metrics.scan_duration,
            },
        )
    )
    print()

    if metrics.by_install_source:
        print("By install source (user apps only)")
        print("----------------------------------")
        print(
            formatter.format_kv_block(
                "[SRC]",
                {k: str(v) for k, v in sorted(metrics.by_install_source.items())},
            )
        )
        print()

    if metrics.by_role:
        print("By role / owner")
        print("---------------")
        print(
            formatter.format_kv_block(
                "[ROLE]", {k: str(v) for k, v in sorted(metrics.by_role.items())}
            )
        )
        print()

    if metrics.by_partition:
        print("By partition")
        print("------------")
        print(
            formatter.format_kv_block(
                "[PART]", {k: str(v) for k, v in sorted(metrics.by_partition.items())}
            )
        )
        print()

    print(
        formatter.format_kv_block(
            "[RESULT]",
            {"User apps (candidates)": str(metrics.user_scope_candidates)},
        )
    )
    print()
