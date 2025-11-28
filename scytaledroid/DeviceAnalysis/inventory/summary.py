"""CLI summary rendering for inventory sync."""

from __future__ import annotations

from typing import Dict, List

from scytaledroid.Utils.DisplayUtils import status_messages, table_utils, text_blocks


def _format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "--"
    total_seconds = int(round(seconds))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes or hours:
        parts.append(f"{minutes:02d}m")
    parts.append(f"{secs:02d}s")
    return " ".join(parts)


def _format_delta_text(delta_value: int, *, first_snapshot: bool = False) -> str:
    if first_snapshot:
        return "(first snapshot)"
    if delta_value == 0:
        return "(identical to previous snapshot)"
    sign = "+" if delta_value > 0 else "-"
    return f"(Δ {sign}{abs(delta_value)} vs previous snapshot)"


def render_sync_summary_box(result) -> None:
    """Render the completion box for a sync."""
    delta = getattr(result, "delta", None)
    first_snapshot = bool(getattr(result, "first_snapshot", False))
    split_delta = result.stats.split_packages - (result.previous_split or 0)
    new_count = getattr(delta, "new_count", 0) if delta else 0
    removed_count = getattr(delta, "removed_count", 0) if delta else 0
    updated_count = getattr(delta, "updated_count", 0) if delta else 0
    changed_total = getattr(delta, "changed_packages_count", 0) if delta else 0
    net_count_delta = result.stats.total_packages - (result.previous_total or 0)

    lines = [
        status_messages.status("Inventory sync complete", level="success"),
        status_messages.status(
            f"Snapshot saved to {result.snapshot_path}",
            show_icon=False,
            show_prefix=False,
        ),
        status_messages.status(
            (
                f"Packages captured: {result.stats.total_packages} "
                f"{_format_delta_text(net_count_delta if not first_snapshot else 0, first_snapshot=first_snapshot)}"
            ),
            show_icon=False,
            show_prefix=False,
        ),
        status_messages.status(
            f"Split APKs: {result.stats.split_packages} {_format_delta_text(split_delta, first_snapshot=first_snapshot)}",
            show_icon=False,
            show_prefix=False,
        ),
        status_messages.status(
            (
                "Delta vs previous snapshot: "
                f"new={new_count}, removed={removed_count}, updated={updated_count}, "
                f"changed_packages={changed_total}"
            ),
            show_icon=False,
            show_prefix=False,
        ),
        status_messages.status(
            f"New packages: {new_count} • Removed: {removed_count} • Updated: {updated_count}",
            show_icon=False,
            show_prefix=False,
        ),
        status_messages.status(
            f"App definitions synced to DB: {getattr(result, 'synced_app_definitions', 0)}",
            show_icon=False,
            show_prefix=False,
        ),
        status_messages.status(
            f"Scan duration: {_format_duration(result.elapsed_seconds)}",
            show_icon=False,
            show_prefix=False,
        ),
    ]
    print(text_blocks.boxed(lines, width=70))


def render_inventory_summary(result) -> None:
    """Render inventory summary tables."""
    rows = getattr(result, "rows", None)
    # If rows are not attached, skip.
    if not rows:
        return

    total = len(rows)
    from collections import Counter

    def _get_owner_role(entry: Dict[str, object]) -> str:
        value = entry.get("owner_role")
        if value not in {None, ""}:
            return str(value)
        # Fall back to partition-derived label if owner_role is missing
        return _partition_label(entry)

    def _partition_label(entry: Dict[str, object]) -> str:
        primary_path = str(entry.get("primary_path") or "")
        if primary_path.startswith("/data/"):
            return "Data (/data)"
        if primary_path.startswith("/product/"):
            return "Product (/product)"
        if primary_path.startswith("/system/") or primary_path.startswith("/system_ext/"):
            return "System (/system, /system_ext)"
        if primary_path.startswith("/apex/"):
            return "Apex (/apex)"
        if primary_path.startswith("/vendor/"):
            return "Vendor (/vendor)"
        if primary_path:
            return "Other"
        return "Unknown"

    category_counts = Counter(_get_owner_role(entry) for entry in rows)
    # Install source is only meaningful for user-space apps; scope it accordingly.
    user_entries = [entry for entry in rows if _get_owner_role(entry) == "User"]
    source_counts = Counter(str(entry.get("source") or "Unknown") for entry in user_entries)
    split_packages = sum(1 for entry in rows if int(entry.get("split_count") or 1) > 1)
    profile_counts = Counter(str(entry.get("profile_name") or "Unclassified") for entry in rows)
    partition_counts = Counter(_partition_label(entry) for entry in rows)
    user_scope_count = len(user_entries)

    print()
    print(text_blocks.headline("Inventory summary", width=70))
    table_utils.render_table(
        ["Metric", "Count"],
        [
            ["Total packages", str(total)],
            ["Split APK packages", str(split_packages)],
            ["User-scope candidates", str(user_scope_count)],
        ],
    )

    print()
    # Show a concise source breakdown that matches the user-scope count.
    play_installs = source_counts.get("Play Store", 0)
    sideload_installs = source_counts.get("Sideload", 0)
    unknown_installs = max(user_scope_count - play_installs - sideload_installs, 0)

    print(
        text_blocks.headline(
            f"By install source (user apps: {user_scope_count})", width=70
        )
    )
    table_utils.render_table(
        ["Source", "Count"],
        [
            ["Play Store installs", str(play_installs)],
            ["Sideload", str(sideload_installs)],
            ["Unknown / other", str(unknown_installs)],
        ],
    )

    print()
    print(text_blocks.headline("By role / owner", width=70))
    table_utils.render_table(
        ["Role", "Count"],
        [
            ["User apps", str(category_counts.get("User", 0))],
            ["OEM overlays", str(category_counts.get("OEM", 0))],
            ["System core", str(category_counts.get("System", 0))],
            ["Google mainline", str(category_counts.get("Mainline", 0))],
            ["Vendor modules", str(category_counts.get("Vendor", 0))],
            ["Unclassified / Unknown", str(category_counts.get("Unknown", 0))],
        ],
    )

    print()
    print(text_blocks.headline("By partition", width=70))
    partition_rows = [
        ["Data (/data)", str(partition_counts.get("Data (/data)", 0))],
        ["Product (/product)", str(partition_counts.get("Product (/product)", 0))],
        ["System (/system)", str(partition_counts.get("System (/system, /system_ext)", 0))],
        ["Apex (/apex)", str(partition_counts.get("Apex (/apex)", 0))],
        ["Vendor (/vendor)", str(partition_counts.get("Vendor (/vendor)", 0))],
    ]
    table_utils.render_table(["Partition", "Packages"], partition_rows)

    notable_profiles = [
        (name, count)
        for name, count in profile_counts.items()
        if name != "Unclassified" and count > 0
    ]
    if notable_profiles:
        print()
        print(text_blocks.headline("Category matches", width=70))
        category_rows = [
            [name, str(count)]
            for name, count in sorted(notable_profiles, key=lambda item: (-item[1], item[0]))
        ]
        table_utils.render_table(["Profile", "Packages"], category_rows)


__all__ = ["render_sync_summary_box", "render_inventory_summary"]
