"""CLI summary rendering for inventory sync."""

from __future__ import annotations

from scytaledroid.ui import formatter
from scytaledroid.Utils.DisplayUtils import table_utils, text_blocks


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
    """Render the completion summary for a sync (plain text, forensic style)."""
    rows = getattr(result, "rows", None) or []
    stats = getattr(result, "stats", None)
    total_packages = int(getattr(stats, "total_packages", len(rows)) or len(rows))
    stats_split_packages = getattr(stats, "split_packages", None)
    delta = getattr(result, "delta", None)
    first_snapshot = bool(getattr(result, "first_snapshot", False))
    new_count = getattr(delta, "new_count", 0) if delta else 0
    removed_count = getattr(delta, "removed_count", 0) if delta else 0
    updated_count = getattr(delta, "updated_count", 0) if delta else 0
    net_count_delta = total_packages - (getattr(result, "previous_total", 0) or 0)
    elapsed_seconds = float(getattr(result, "elapsed_seconds", 0.0) or 0.0)
    avg_rate = (total_packages / elapsed_seconds) if elapsed_seconds > 0 else 0.0
    fallback_used = bool(getattr(result, "fallback_used", False))

    user_scope_candidates = 0
    split_packages = int(stats_split_packages or 0)
    if rows:
        user_scope_candidates = sum(
            1 for row in rows if str((row or {}).get("primary_path") or "").startswith("/data/")
        )
        if split_packages <= 0:
            split_packages = sum(1 for row in rows if int((row or {}).get("split_count") or 1) > 1)

    formatter.print_header("Refresh Inventory · RUN SUMMARY")
    print(
        formatter.format_kv_block(
            "[RUN]",
            {
                "Snapshot": str(result.snapshot_path),
                "Snapshot ID": str(getattr(result, "snapshot_id", None) if getattr(result, "snapshot_id", None) is not None else "—"),
                "Packages": f"{total_packages}",
                "Split APK packages": f"{split_packages}",
                "Avg rate": f"{avg_rate:.2f} pkg/s",
                "Fallback mode": "enabled" if fallback_used else "disabled",
                "User apps (candidates)": str(user_scope_candidates),
            },
        )
    )
    print()
    print(
        formatter.format_kv_block(
            "[RESULT]",
            {
                "Delta vs previous": (
                    f"new={new_count}  removed={removed_count}  updated={updated_count} "
                    f"{_format_delta_text(net_count_delta if not first_snapshot else 0, first_snapshot=first_snapshot)}"
                ),
                "App defs synced": f"{getattr(result, 'synced_app_definitions', 0)}",
                "Scan duration": _format_duration(elapsed_seconds),
            },
        )
    )
    snapshot_id = getattr(result, "snapshot_id", None)
    expected_rows = getattr(result, "expected_rows", None)
    persisted_rows = getattr(result, "persisted_rows", None)
    if snapshot_id is not None and expected_rows is not None and persisted_rows is not None:
        status = "OK" if persisted_rows == expected_rows else "FAIL"
        print()
        print(
            formatter.format_kv_block(
                "[DB]",
                {
                    "Snapshot ID": str(snapshot_id),
                    "Expected rows": str(expected_rows),
                    "Persisted rows": str(persisted_rows),
                    "Integrity": status,
                },
            )
        )
    print()


def render_inventory_summary(result) -> None:
    """Render inventory summary tables."""
    rows = None
    if isinstance(result, (list, tuple)):
        rows = list(result)
    else:
        rows = getattr(result, "rows", None)
    # If rows are not attached, skip.
    if not rows:
        return

    total = len(rows)
    from collections import Counter

    def _get_owner_role(entry: dict[str, object]) -> str:
        value = entry.get("owner_role")
        if value not in {None, ""}:
            return str(value)
        # Fall back to partition-derived label if owner_role is missing
        return _partition_label(entry)

    def _partition_label(entry: dict[str, object]) -> str:
        primary_path = str(entry.get("primary_path") or "")
        if primary_path.startswith("/data/"):
            return "Data (/data)"
        if primary_path.startswith("/product/"):
            return "Product (/product)"
        if primary_path.startswith("/system/") or primary_path.startswith("/system_ext/"):
            return "System (/system)"
        if primary_path.startswith("/apex/"):
            return "Apex (/apex)"
        if primary_path.startswith("/vendor/"):
            return "Vendor (/vendor)"
        partition_field = str(entry.get("partition") or "").lower()
        if partition_field == "data":
            return "Data (/data)"
        if partition_field == "product":
            return "Product (/product)"
        if partition_field == "system":
            return "System (/system)"
        if partition_field == "apex":
            return "Apex (/apex)"
        if partition_field == "vendor":
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
    label_is_package = 0
    for entry in rows:
        package = str(entry.get("package_name") or "").strip().lower()
        label = str(entry.get("app_label") or "").strip().lower()
        if package and label and package == label:
            label_is_package += 1

    print()
    print(text_blocks.headline("Inventory summary", width=70))
    metric_rows = [["Total packages", str(total)]]
    if split_packages:
        metric_rows.append(["Split APK packages", str(split_packages)])
    if user_scope_count:
        metric_rows.append(["User apps (candidates)", str(user_scope_count)])
    if total:
        friendly = total - label_is_package
        metric_rows.append(["Friendly labels", str(friendly)])
        metric_rows.append(["Package labels", str(label_is_package)])
    table_utils.render_table(["Metric", "Count"], metric_rows)

    print()
    # Show a concise source breakdown that matches the user-scope count.
    play_installs = source_counts.get("Play Store", 0)
    sideload_installs = source_counts.get("Sideload", 0)
    unknown_installs = max(user_scope_count - play_installs - sideload_installs, 0)

    source_rows = []
    if play_installs:
        source_rows.append(["Play Store installs", str(play_installs)])
    if sideload_installs:
        source_rows.append(["Sideload", str(sideload_installs)])
    if unknown_installs:
        source_rows.append(["Unknown / other", str(unknown_installs)])
    if source_rows:
        print(
            text_blocks.headline(
                f"By install source (user apps: {user_scope_count})", width=70
            )
        )
        table_utils.render_table(["Source", "Count"], source_rows)

    role_rows = []
    for label, key in [
        ("User apps", "User"),
        ("OEM overlays", "OEM"),
        ("System core", "System"),
        ("Google mainline", "Mainline"),
        ("Vendor modules", "Vendor"),
        ("Unclassified / Unknown", "Unknown"),
    ]:
        count = category_counts.get(key, 0)
        if count:
            role_rows.append([label, str(count)])
    if role_rows:
        print()
        print(text_blocks.headline("By role / owner", width=70))
        table_utils.render_table(["Role", "Count"], role_rows)

    partition_rows = []
    for label in [
        "Data (/data)",
        "Product (/product)",
        "System (/system)",
        "Apex (/apex)",
        "Vendor (/vendor)",
    ]:
        count = partition_counts.get(label, 0)
        if count:
            partition_rows.append([label, str(count)])
    if partition_rows:
        print()
        print(text_blocks.headline("By partition", width=70))
        table_utils.render_table(["Partition", "Packages"], partition_rows)

    notable_profiles = [
        (name, count)
        for name, count in profile_counts.items()
        if name != "Unclassified" and count > 0
    ]
    if notable_profiles:
        print()
        print(text_blocks.headline("Profile matches", width=70))
        category_rows = [
            [name, str(count)]
            for name, count in sorted(notable_profiles, key=lambda item: (-item[1], item[0]))
        ]
        table_utils.render_table(["Profile", "Packages"], category_rows)


__all__ = ["render_sync_summary_box", "render_inventory_summary"]
