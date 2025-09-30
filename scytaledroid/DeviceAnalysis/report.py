"""report.py - Generate device reports combining telemetry and inventory."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from collections import Counter

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils, text_blocks
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_utils, inventory, package_profiles


def generate_device_report(serial: Optional[str]) -> None:
    """Create a markdown report for the active device."""
    if not serial:
        print(status_messages.status("No active device. Connect to a device first.", level="warn"))
        menu_utils.press_enter_to_continue()
        return

    device_entry = _get_device_entry(serial)
    if not device_entry:
        print(status_messages.status("Unable to locate the active device via adb.", level="error"))
        menu_utils.press_enter_to_continue()
        return

    summary = adb_utils.build_device_summary(device_entry)
    inventory_payload = inventory.load_latest_inventory(serial)
    if not inventory_payload:
        if menu_utils.prompt_yes_no("No inventory data found. Run a new inventory sync now?", default=True):
            inventory.run_inventory_sync(serial)
            inventory_payload = inventory.load_latest_inventory(serial)
        else:
            inventory_payload = {"packages": [], "package_count": 0}

    report_path = _write_report(serial, summary, inventory_payload)

    print()
    print(text_blocks.headline("Device overview", width=70))
    overview_pairs = _summary_pairs(summary)
    table_utils.render_key_value_pairs(overview_pairs)

    package_count = inventory_payload.get("package_count", 0)
    packages: List[Dict[str, object]] = inventory_payload.get("packages", [])  # type: ignore[assignment]
    if packages:
        print()
        print(text_blocks.headline(f"Installed packages ({package_count})", width=70))
        preview = _inventory_preview(packages)
        table_utils.render_table(["Package", "App", "Version", "Category", "Source", "Profile", "Split"], preview)
        if len(packages) > len(preview):
            print(status_messages.status(f"Full list saved in {report_path.name}", level="info"))
    else:
        print(status_messages.status("No inventory entries included.", level="warn"))

    profile_section = _profile_guidance(packages)
    if profile_section:
        print()
        print(text_blocks.headline("App categories of interest", width=70))
        for block in profile_section:
            print(block)
            print()

    print()
    resolved = report_path.resolve()
    try:
        display_path = resolved.relative_to(Path.cwd())
    except ValueError:
        display_path = resolved

    print(status_messages.status(f"Report written to {display_path}", level="success"))
    log.info(f"Device report generated at {report_path}", category="device")
    menu_utils.press_enter_to_continue("Press Enter to return to the Device Analysis menu...")


def _get_device_entry(serial: str) -> Optional[Dict[str, Optional[str]]]:
    devices = adb_utils.list_devices()
    for device in devices:
        if device.get("serial") == serial:
            return device
    return None


def _summary_pairs(summary: Dict[str, Optional[str]]) -> List[tuple[str, str]]:
    return [
        ("Serial", summary.get("serial") or "Unknown"),
        ("Model", summary.get("model") or summary.get("device") or "Unknown"),
        ("Manufacturer", summary.get("manufacturer") or summary.get("brand") or "Unknown"),
        ("Android", summary.get("android_version") or "Unknown"),
        ("Build", summary.get("build_id") or "Unknown"),
        ("Battery", summary.get("battery_level") or "Unknown"),
        ("Wi-Fi", summary.get("wifi_state") or "Unknown"),
        ("Root", summary.get("is_rooted") or "Unknown"),
        ("Emulator", "Yes" if summary.get("device_type") == "Emulator" else "No"),
    ]


def _inventory_preview(packages: List[Dict[str, object]]) -> List[List[str]]:
    max_preview = 15
    preview_rows: List[List[str]] = []
    for pkg in packages[:max_preview]:
        package_name = str(pkg.get("package_name") or "?")
        app_label = str(pkg.get("app_label") or package_name)
        version = str(pkg.get("version_name") or pkg.get("version_code") or "?")
        category = str(pkg.get("category") or "Unknown")
        source = str(pkg.get("source") or category)
        profile = str(pkg.get("profile_name") or "-")
        split_flag = "Yes" if inventory._split_count(pkg) > 1 else "No"
        preview_rows.append([package_name, app_label, version, category, source, profile, split_flag])
    return preview_rows


def _write_report(
    serial: str,
    summary: Dict[str, Optional[str]],
    inventory_payload: Dict[str, object],
) -> Path:
    report_dir = Path(app_config.OUTPUT_DIR) / "reports" / serial
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    report_path = report_dir / f"device_report_{timestamp}.md"

    lines: List[str] = []
    model = summary.get("model") or summary.get("device") or "Unknown"
    lines.append(f"# Device Report — {model} ({serial})")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    lines.append("## Device Overview")
    lines.append("")
    lines.extend(_markdown_table(["Field", "Value"], _summary_pairs(summary)))
    lines.append("")

    packages: List[Dict[str, object]] = inventory_payload.get("packages", [])  # type: ignore[assignment]
    package_count = inventory_payload.get("package_count", len(packages))
    lines.append(f"## Installed Packages ({package_count})")
    lines.append("")
    package_rows = [
        [
            pkg.get("package_name") or "?",
            pkg.get("app_label") or pkg.get("package_name") or "?",
            pkg.get("version_name") or pkg.get("version_code") or "?",
            pkg.get("category") or "Unknown",
            pkg.get("source") or pkg.get("category") or "Unknown",
            pkg.get("profile_name") or "-",
            "Yes" if inventory._split_count(pkg) > 1 else "No",
            (pkg.get("primary_path") or "?"),
        ]
        for pkg in packages
    ]
    lines.extend(
        _markdown_table(
            ["Package", "App", "Version", "Category", "Source", "Profile", "Split", "Primary Path"],
            package_rows,
        )
    )

    profile_counts = Counter(str(pkg.get("profile_id") or "") for pkg in packages)
    active_profiles = [profile for profile in package_profiles.PROFILES if profile_counts.get(profile.id, 0)]
    if active_profiles:
        lines.append("")
        lines.append("## App Categories of Interest")
        lines.append("")
        for profile in active_profiles:
            count = profile_counts.get(profile.id, 0)
            lines.append(f"### {profile.name} ({count})")
            lines.append(profile.description)
            lines.append("")
            lines.append("Artifacts to review:")
            lines.extend([f"- {item}" for item in profile.artifacts])
            lines.append("")
            lines.append("Suggested acquisition steps:")
            lines.extend([f"- {item}" for item in profile.pull_strategy])
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def _profile_guidance(packages: List[Dict[str, object]]) -> List[str]:
    if not packages:
        return []

    counts = Counter(str(pkg.get("profile_id") or "") for pkg in packages)
    blocks: List[str] = []
    for profile in package_profiles.PROFILES:
        count = counts.get(profile.id, 0)
        if count == 0:
            continue

        lines = [text_blocks.headline(f"{profile.name} applications ({count})", width=60)]
        lines.append(profile.description)
        lines.append("")
        lines.append("Artifacts of interest:")
        lines.append(text_blocks.bullet_list(profile.artifacts, bullet="  - "))
        lines.append("")
        lines.append("Suggested acquisition steps:")
        lines.append(text_blocks.bullet_list(profile.pull_strategy, bullet="  - "))
        blocks.append("\n".join(lines))

    return blocks


def _markdown_table(headers: List[str], rows: List[Iterable[str]]) -> List[str]:
    if not rows:
        return ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |", "| *(no data)* |"]

    header_line = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join(["---"] * len(headers)) + " |"
    body = ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return [header_line, divider, *body]
