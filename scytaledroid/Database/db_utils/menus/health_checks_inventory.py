"""Inventory health-check helpers for Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def run_inventory_health_check(
    *,
    menu_utils: Any,
    run_sql: Callable[..., Any],
    scalar: Callable[..., Any],
    print_status_line: Callable[..., None],
    run_inventory_snapshot_checks: Callable[..., None],
) -> None:
    menu_utils.print_section("Inventory DB health")

    snapshot_headers_total = scalar("SELECT COUNT(*) FROM device_inventory_snapshots") or 0
    orphan_headers = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory_snapshots s
        LEFT JOIN device_inventory i ON i.snapshot_id = s.snapshot_id
        WHERE i.snapshot_id IS NULL
        """
    ) or 0

    latest = run_sql(
        """
        SELECT snapshot_id, package_count
        FROM device_inventory_snapshots
        ORDER BY captured_at DESC
        LIMIT 1
        """,
        fetch="one",
    )
    latest_snapshot_id = int(latest[0]) if latest else 0
    latest_expected = int(latest[1]) if latest else 0
    latest_rows = 0
    latest_is_orphan = False
    if latest_snapshot_id:
        latest_rows = scalar(
            "SELECT COUNT(*) FROM device_inventory WHERE snapshot_id = %s",
            (latest_snapshot_id,),
        ) or 0
        latest_is_orphan = latest_rows == 0

    run_inventory_snapshot_checks(
        scalar=scalar,
        latest_snapshot_id=latest_snapshot_id,
        snapshot_headers_total=snapshot_headers_total,
        orphan_headers=orphan_headers,
        latest_is_orphan=latest_is_orphan,
        latest_rows=latest_rows,
        latest_expected=latest_expected,
        print_status_line=print_status_line,
    )

