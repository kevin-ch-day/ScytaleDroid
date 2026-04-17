"""Dashboard rendering helpers for the Device Analysis menu.

This module focuses on compact, badge-driven output that fits reliably
within narrow terminals and avoids multi-line hint panels. The dashboard
header is rendered as a single line with concise status tokens; detailed
cards are discoverable via menu actions rather than always-on panels.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
    INVENTORY_STALE_SECONDS,
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.Utils.DisplayUtils import (
    colors,
    error_panels,
    menu_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.DisplayUtils.terminal import use_ascii_ui
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .formatters import (
    format_android_release,
    format_battery,
    format_device_line,
    format_timestamp_utc,
    format_wifi_state,
    prettify_manufacturer,
    prettify_model,
)


# -------------------------
# Badge helpers
# -------------------------
def _status_badge(label: str, tone: str = "info") -> str:
    """Return a coloured status chip for quick scanning."""

    palette = colors.get_palette()
    style_map = {
        "success": palette.success,
        "warning": palette.warning,
        "error": palette.error,
        "blocked": palette.blocked,
        "info": palette.info,
    }
    style = style_map.get(tone, palette.info)
    cleaned = (label or "").strip() or "UNKNOWN"
    # Prefer a solid bullet when colours are enabled; fall back to ASCII
    # depending on terminal capability otherwise.
    # When colours are enabled (e.g., tests via FORCE_COLOR), prefer a solid bullet
    # to ensure consistent snapshots regardless of Unicode heuristics.
    if colors.colors_enabled():
        marker = "●"
    else:
        marker = "*" if use_ascii_ui() else "●"
    token = f"{marker} {cleaned.upper()}"
    return colors.apply(token, style, bold=True)


def _connection_badge(status: str | None) -> str:
    """Colour-code the aggregate connection status."""

    normalised = (status or "Unknown").strip().upper()
    if normalised in {"CONNECTED", "DEVICE"}:
        tone = "success"
    elif normalised in {"DISCONNECTED", "OFFLINE"}:
        tone = "error"
    else:
        tone = "warning"
    return _status_badge(normalised, tone)


def _state_badge(state: str | None) -> str:
    """Colour-code individual device states."""

    normalised = (state or "unknown").strip().upper()
    if normalised in {"DEVICE", "ONLINE"}:
        normalised = "READY"
        tone = "success"
    elif normalised in {"UNAUTHORIZED", "RECOVERY", "SIDELOAD"}:
        tone = "warning"
    elif normalised in {"OFFLINE"}:
        tone = "error"
    else:
        tone = "info"
    return _status_badge(normalised, tone)


def _root_badge(root_state: str | None) -> str:
    """Return a compact capability label for the root detection result."""

    normalised = (root_state or "Unknown").strip().upper()
    if normalised == "YES":
        label = "ROOTED"
        style = colors.get_palette().success
    elif normalised == "NO":
        label = "NON-ROOT"
        style = colors.get_palette().info
    else:
        label = "UNKNOWN"
        style = colors.get_palette().muted
    return colors.apply(label, style, bold=True)


def _device_count_badge(count: int) -> str:
    label = f"{count} device{'s' if count != 1 else ''}"
    tone = "success" if count else "warning"
    return _status_badge(label.upper(), tone)


def _styled_summary_value(value: object, *, tone: str = "text", bold: bool = True) -> str:
    text = _format_summary_value(value)
    palette = colors.get_palette()
    style = getattr(palette, tone, palette.text)
    return colors.apply(text, style, bold=bold)


def _styled_count_phrase(count: object, noun: str, *, tone: str = "text") -> str:
    text = f"{_format_summary_value(count)} {noun}"
    palette = colors.get_palette()
    style = getattr(palette, tone, palette.text)
    return colors.apply(text, style, bold=True)


def _inventory_status_text(status_label: str) -> str:
    tone = "success"
    if status_label == "STALE":
        tone = "warning"
    elif status_label not in {"FRESH", "STALE"}:
        tone = "muted"
    return _styled_summary_value(status_label, tone=tone)


def _evidence_alignment_tone(
    *,
    latest_harvest: dict[str, object] | None,
    inventory_snapshot_id: object,
) -> str:
    if not latest_harvest:
        return "muted"
    harvest_snapshot_id = latest_harvest.get("snapshot_id")
    if harvest_snapshot_id is None:
        return "warning"
    if inventory_snapshot_id is not None and harvest_snapshot_id == inventory_snapshot_id:
        return "success"
    return "warning"


# -------------------------
# Compact header
# -------------------------

def _compact_header(
    *,
    refreshed: str,
    adb_status: str,
    devices_found: int,
    active_line: str | None,
    width: int | None = None,
) -> str:
    """Render a single-line dashboard header within the terminal width.

    Example (Unicode mode):
    Device Dashboard — 2025-10-15 11:52:06   ADB: CONNECTED   Detected: 1   Active: moto g 5G (ZY22…)
    """

    palette = colors.get_palette()
    term_width = width or text_blocks.visible_width(" " * 80) or 80
    sep = " - " if use_ascii_ui() else " — "

    title = colors.apply("Device Dashboard", palette.header, bold=True)
    ts = colors.apply(refreshed, palette.accent, bold=True)
    adb = colors.apply(f"ADB: {adb_status}", palette.info, bold=True)
    det = colors.apply(f"Detected: {devices_found}", palette.text)

    parts = [f"{title}{sep}{ts}", adb, det]
    if active_line:
        active_token = colors.apply("Active:", palette.muted, bold=True)
        parts.append(f"{active_token} {colors.apply(active_line, palette.text, bold=True)}")

    joined = "   ".join(parts)
    # Clamp to width without breaking ANSI sequences
    return text_blocks.truncate_visible(joined, term_width)

def _format_metric_line(label: str, value: str, *, width: int = 16) -> str:
    palette = colors.get_palette()
    label_token = colors.apply(label.ljust(width), palette.muted, bold=True)
    return f"{label_token} {value}"


def _no_device_line(devices_found: int) -> str:
    """Single-line guidance shown when there is no active device."""
    if devices_found:
        return "No active device. Use 3 to connect (Enter to refresh)."
    return "No devices detected. Attach a device and press Enter to refresh."


def _styled_value(value: str | None, *, highlight: bool = False) -> str:
    palette = colors.get_palette()
    text = value or "Unknown"
    if not value or value.strip().lower() == "unknown":
        return colors.apply("Unknown", palette.muted, bold=True)
    style = palette.accent if highlight else palette.text
    return colors.apply(text, style, bold=highlight)


def _active_device_brief(details: dict[str, str | None], *, width: int) -> str:
    """Return a concise active device line suitable for the header."""
    label = format_device_line(details, include_release=False)
    return text_blocks.truncate_visible(label, max(10, width // 3))


def _last_seen_brief(
    last_summary: dict[str, str | None | None], last_serial: str | None
) -> str | None:
    if last_summary:
        return format_device_line(last_summary, include_release=True)
    if last_serial:
        return last_serial
    return None


def _device_table_rows(
    summaries: list[dict[str, str | None]]
) -> list[tuple[str, str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str, str]] = []
    for summary in summaries:
        model = prettify_model(summary.get("model") or summary.get("device"))
        serial = summary.get("serial") or "Unknown"
        label = f"{model} ({serial})" if model != "Unknown" else serial
        device_type = summary.get("device_type")
        if device_type:
            label = f"{label} | {device_type}"
        oem = prettify_manufacturer(summary.get("manufacturer") or summary.get("brand"))
        android = format_android_release(summary)
        if android.startswith("Android "):
            android = android.replace("Android ", "", 1)
        battery = format_battery(summary)
        wifi = format_wifi_state(summary.get("wifi_state"))
        root_badge = _root_badge(summary.get("is_rooted"))
        rows.append((label, oem, android, battery, wifi, root_badge))
    return rows


def _render_active_device_summary(details: dict[str, str | None]) -> None:
    print(colors.apply("Device", colors.style("header"), bold=True))
    print(text_blocks.divider(width=6, style="divider"))
    model = prettify_model(details.get("model") or details.get("device"))
    serial = details.get("serial") or "Unknown"
    identity = f"{model} ({serial})" if model != "Unknown" else serial
    print(colors.apply(identity, colors.style("banner_primary"), bold=True))
    summary_bits = [
        colors.apply(
            prettify_manufacturer(details.get("manufacturer") or details.get("brand")),
            colors.style("muted"),
        ),
        colors.apply(format_android_release(details), colors.style("accent"), bold=True),
        colors.apply(details.get("device_type") or "Unknown", colors.style("text")),
        _root_badge(details.get("is_rooted")),
    ]
    print(" | ".join(bit for bit in summary_bits if bit))


def _build_delta_items(delta: object, *, limit: int = 5) -> list[str]:
    """Format top-N added/removed/updated packages for display."""

    if not isinstance(delta, dict):
        return []

    palette = colors.get_palette()
    messages: list[str] = []

    added_list = delta.get("added") if isinstance(delta.get("added"), list) else []
    removed_list = delta.get("removed") if isinstance(delta.get("removed"), list) else []
    updated_list = delta.get("updated") if isinstance(delta.get("updated"), list) else []

    def _join_names(names: list[str]) -> str:
        if not names:
            return ""
        if len(names) > limit:
            names = names[:limit] + ["…"]
        return ", ".join(names)

    added_names = [name for name in added_list if isinstance(name, str) and name]
    if added_names:
        messages.append(
            colors.apply("Added: ", palette.success, bold=True)
            + _join_names(added_names)
        )

    removed_names = [name for name in removed_list if isinstance(name, str) and name]
    if removed_names:
        messages.append(
            colors.apply("Removed: ", palette.error, bold=True)
            + _join_names(removed_names)
        )

    if updated_list:
        formatted_updates: list[str] = []
        for entry in updated_list[:limit]:
            if not isinstance(entry, dict):
                continue
            pkg = entry.get("package") if isinstance(entry.get("package"), str) else None
            before = entry.get("before") if isinstance(entry.get("before"), str) else None
            after = entry.get("after") if isinstance(entry.get("after"), str) else None
            if not pkg:
                continue
            token = pkg
            if before or after:
                token = f"{pkg} ({before or '?'} → {after or '?'})"
            formatted_updates.append(token)
        if formatted_updates:
            if len(updated_list) > limit:
                formatted_updates.append("…")
            messages.append(
                colors.apply("Updated: ", palette.warning, bold=True)
                + ", ".join(formatted_updates)
            )

    return messages


def _safe_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _load_latest_harvest_overview(serial: str | None) -> dict[str, object]:
    if not serial:
        return {}
    root = artifact_store.legacy_harvest_root() / serial
    if not root.exists():
        return {}
    session_dirs = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name)
    if not session_dirs:
        return {}
    session_dir = session_dirs[-1]
    manifests = list(session_dir.rglob("harvest_package_manifest.json"))
    blocked_policy = 0
    blocked_scope = 0
    executed = 0
    harvest_snapshot_id: int | None = None
    for manifest_path in manifests:
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if harvest_snapshot_id is None and isinstance(payload, dict):
            package_ctx = payload.get("package") if isinstance(payload.get("package"), dict) else {}
            snap_id = package_ctx.get("snapshot_id") if isinstance(package_ctx, dict) else None
            if isinstance(snap_id, int):
                harvest_snapshot_id = snap_id
            elif isinstance(snap_id, str) and snap_id.isdigit():
                harvest_snapshot_id = int(snap_id)
        planning = payload.get("planning") if isinstance(payload, dict) else {}
        reason = str(planning.get("preflight_reason") or "").strip()
        if reason == "policy_non_root":
            blocked_policy += 1
        elif reason:
            blocked_scope += 1
        else:
            executed += 1
    receipts_root = artifact_store.harvest_receipts_root() / session_dir.name
    receipt_count = len(list(receipts_root.glob("*.json"))) if receipts_root.exists() else 0
    return {
        "session_label": session_dir.name,
        "executed": executed,
        "blocked_policy": blocked_policy,
        "blocked_scope": blocked_scope,
        "manifest_count": len(manifests),
        "receipt_count": receipt_count,
        "snapshot_id": harvest_snapshot_id,
        "artifacts_root": artifact_store.repo_relative_path(session_dir),
        "receipts_root": artifact_store.repo_relative_path(receipts_root) if receipts_root.exists() else None,
    }


def _compute_pipeline_state(serial: str | None) -> dict[str, object]:
    state = {
        "inventory_snapshot_id": None,
        "inventoried": None,
        "in_scope": None,
        "policy_eligible": None,
        "scheduled": None,
        "harvested": None,
        "persisted": None,
        "blocked_policy": None,
        "blocked_scope": None,
    }
    if not serial:
        return state
    try:
        from scytaledroid.DeviceAnalysis import harvest
        from scytaledroid.DeviceAnalysis.inventory.snapshot_io import load_latest_inventory

        snapshot = load_latest_inventory(serial)
        snapshot_id = snapshot.get("snapshot_id") if isinstance(snapshot, dict) else None
        packages = snapshot.get("packages") if isinstance(snapshot, dict) else None
        if isinstance(packages, list):
            rows = harvest.build_inventory_rows(packages)
            plan = harvest.build_harvest_plan(rows, include_system_partitions=False)
            scheduled = sum(1 for pkg in plan.packages if not pkg.skip_reason)
            blocked_policy = sum(1 for pkg in plan.packages if pkg.skip_reason == "policy_non_root")
            blocked_scope = sum(1 for pkg in plan.packages if pkg.skip_reason and pkg.skip_reason != "policy_non_root")
            state.update(
                {
                    "inventory_snapshot_id": snapshot_id if isinstance(snapshot_id, int) else None,
                    "inventoried": len(rows),
                    "in_scope": len(plan.packages),
                    "policy_eligible": scheduled,
                    "scheduled": scheduled,
                    "blocked_policy": blocked_policy,
                    "blocked_scope": blocked_scope,
                }
            )
    except Exception:
        pass

    harvest_overview = _load_latest_harvest_overview(serial)
    if harvest_overview:
        state["harvested"] = _safe_int(harvest_overview.get("executed"))
        state["persisted"] = _safe_int(harvest_overview.get("receipt_count"))
        state["latest_harvest"] = harvest_overview
    return state


def _render_inventory_status(metadata: object) -> None:
    """Render a compact inventory status block with delta hints."""

    # Accept both legacy dict metadata and InventoryStatus dataclass
    ts = None
    package_count = None
    stale = False
    age_text = None
    delta = {}
    if isinstance(metadata, dict):
        ts = metadata.get("timestamp")
        package_count = metadata.get("package_count")
        delta = metadata.get("package_delta_summary") or {}
    else:
        # InventoryStatus dataclass support
        ts = getattr(metadata, "last_run_ts", None)
        package_count = getattr(metadata, "package_count", None)
        stale = bool(getattr(metadata, "is_stale", False))
        age_text = getattr(metadata, "age_display", None)

    timestamp_display = "Unknown"
    if isinstance(ts, datetime):
        ts_utc = ts.astimezone(UTC)
        timestamp_display = format_timestamp_utc(ts_utc)
        if age_text is None:
            age_seconds = max(0, (datetime.now(UTC) - ts_utc).total_seconds())
            age_text = humanize_seconds(age_seconds)
            stale = stale or age_seconds > INVENTORY_STALE_SECONDS

    count_text = f"{package_count} packages" if isinstance(package_count, int) else None

    if isinstance(delta, dict):
        added = delta.get("total_added", 0)
        removed = delta.get("total_removed", 0)
        updated = delta.get("total_updated", 0)
    else:
        added = removed = updated = 0
    has_changes = any(val for val in (added, removed, updated))

    palette = colors.get_palette()
    status_chip = _status_badge("STALE" if stale else "FRESH", "warning" if stale else "success")
    lines: list[str] = []
    lines.append(
        f"{status_chip} Last run: {timestamp_display}"
        + (f" ({age_text} ago)" if age_text else "")
    )
    if count_text:
        lines.append(colors.apply(f"Packages: {count_text}", palette.text, bold=True))
    if has_changes:
        changes = []
        if added:
            changes.append(colors.apply(f"+{added}", palette.success, bold=True))
        if removed:
            changes.append(colors.apply(f"-{removed}", palette.error, bold=True))
        if updated:
            changes.append(colors.apply(f"Δ{updated}", palette.warning, bold=True))
        lines.append(f"Changes since last inventory: {' / '.join(changes)}")
        lines.extend(_build_delta_items(delta))

    if not lines:
        return

    print()
    print(text_blocks.headline("Inventory status", width=74))
    for line in lines:
        print(line)


def _format_summary_value(value: object, *, fallback: str = "—") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def _compact_age_display(age_display: object) -> str:
    text = _format_summary_value(age_display, fallback="unknown").strip()
    replacements = {
        " Hrs ": "h ",
        " Hr ": "h ",
        " Mins": "m",
        " Min": "m",
        " Secs": "s",
        " Sec": "s",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _evidence_alignment_text(
    *,
    latest_harvest: dict[str, object] | None,
    inventory_snapshot_id: object,
) -> str:
    if not latest_harvest:
        return "not harvested yet"

    harvest_snapshot_id = latest_harvest.get("snapshot_id")
    if harvest_snapshot_id is None:
        return "present (snapshot unknown)"
    if inventory_snapshot_id is not None and harvest_snapshot_id == inventory_snapshot_id:
        return f"aligned with snapshot {harvest_snapshot_id}"
    if inventory_snapshot_id is not None:
        return f"snapshot {harvest_snapshot_id} vs inventory {inventory_snapshot_id}"
    return f"linked to snapshot {harvest_snapshot_id}"


def _summary_next_step(
    *,
    inventory_status: str,
    inventory_snapshot_id: object,
    harvest_snapshot_id: object,
    has_harvest: bool,
) -> str:
    if inventory_status == "NONE":
        return "Run Refresh Inventory to establish current device scope."
    if inventory_status == "STALE":
        return "Inventory is stale; refresh recommended before harvest."
    if not has_harvest:
        return "Inventory is current. Execute harvest when you are ready."
    if harvest_snapshot_id is not None and inventory_snapshot_id is not None and harvest_snapshot_id != inventory_snapshot_id:
        return "Harvest is based on an older inventory snapshot. Refresh inventory before harvesting again."
    return "Inventory and harvest are aligned. Static analysis can proceed."


def _render_compact_status(
    details: dict[str, str | None],
    inventory_metadata: object,
    pipeline: dict[str, object],
) -> None:
    status_label = str(getattr(inventory_metadata, "status_label", "UNKNOWN")).upper()
    age_display = _compact_age_display(getattr(inventory_metadata, "age_display", None) or "unknown")
    pkg_count = getattr(inventory_metadata, "package_count", None)
    persisted_count = pipeline.get("persisted")
    blocked_policy = pipeline.get("blocked_policy")
    blocked_scope = pipeline.get("blocked_scope")
    latest_harvest = pipeline.get("latest_harvest") if isinstance(pipeline, dict) else None
    inventory_snapshot_id = pipeline.get("inventory_snapshot_id")
    harvest_snapshot_id = latest_harvest.get("snapshot_id") if isinstance(latest_harvest, dict) else None
    evidence_alignment = _evidence_alignment_text(
        latest_harvest=latest_harvest,
        inventory_snapshot_id=inventory_snapshot_id,
    )

    print()
    print(colors.apply("Summary", colors.style("header"), bold=True))
    print(text_blocks.divider(width=7, style="divider"))
    print(
        f"{'Inventory':<12} : {_inventory_status_text(status_label)} | "
        f"{_styled_count_phrase(pkg_count, 'packages', tone='accent')} | "
        f"{colors.apply(f'{age_display} ago', colors.style('muted'))}"
    )
    print(
        f"{'Harvest':<12} : {_styled_count_phrase(persisted_count, 'persisted', tone='success')} | "
        f"{_styled_count_phrase(blocked_policy, 'policy blocked', tone='blocked')} | "
        f"{_styled_count_phrase(blocked_scope, 'scope blocked', tone='warning')}"
    )
    print(
        f"{'Evidence':<12} : "
        f"{colors.apply(evidence_alignment, colors.style(_evidence_alignment_tone(latest_harvest=latest_harvest, inventory_snapshot_id=inventory_snapshot_id)), bold=True)}"
    )

    print()
    print(colors.apply("Next Step", colors.style("header"), bold=True))
    print(text_blocks.divider(width=9, style="divider"))
    print(
        status_messages.highlight(
            _summary_next_step(
            inventory_status=status_label,
            inventory_snapshot_id=inventory_snapshot_id,
            harvest_snapshot_id=harvest_snapshot_id,
            has_harvest=bool(latest_harvest),
            )
        )
    )


def _render_grouped_actions(options: list[menu_utils.MenuOption]) -> None:
    print()
    print(colors.apply("Actions", colors.style("header"), bold=True))
    print(text_blocks.divider(width=7, style="divider"))
    ordered = sorted(options, key=lambda option: int(option.key) if option.key.isdigit() else 999)
    menu_utils.print_menu(
        ordered,
        show_exit=True,
        exit_label="Back",
        show_descriptions=False,
        compact=True,
    )


def print_device_details(
    active_details: dict[str, str | None | None],
    inventory_metadata: object | None = None,
) -> None:
    if not active_details:
        return

    _render_active_device_summary(active_details)
    print()
    print(colors.apply("Device Capability", colors.style("header"), bold=True))
    print(text_blocks.divider(width=17, style="divider"))
    print(f"{'Wi-Fi':<12} : {colors.apply(format_wifi_state(active_details.get('wifi_state')), colors.style('info'), bold=True)}")
    print(f"{'Battery':<12} : {colors.apply(format_battery(active_details), colors.style('accent'), bold=True)}")
    print(f"{'Root access':<12} : {_root_badge(active_details.get('is_rooted'))}")

    if not inventory_metadata:
        return

    status_label = str(getattr(inventory_metadata, "status_label", "UNKNOWN")).upper()
    age_display = _compact_age_display(getattr(inventory_metadata, "age_display", None) or "unknown")
    pkg_count = getattr(inventory_metadata, "package_count", None)
    serial = active_details.get("serial") if isinstance(active_details, dict) else None
    pipeline = _compute_pipeline_state(serial)
    latest_harvest = pipeline.get("latest_harvest") if isinstance(pipeline, dict) else None

    print()
    print(colors.apply("Inventory and Harvest", colors.style("header"), bold=True))
    print(text_blocks.divider(width=21, style="divider"))
    print(
        f"{'Status':<12} : {_inventory_status_text(status_label)} | "
        f"Last sync : {colors.apply(f'{age_display} ago', colors.style('muted'))} | "
        f"Packages : {_styled_summary_value(pkg_count if isinstance(pkg_count, int) else '—', tone='accent')}"
    )
    print(
        f"{'Inventory':<12} : {_styled_count_phrase(pipeline.get('inventoried'), 'inventoried', tone='accent')} | "
        f"{_styled_count_phrase(pipeline.get('in_scope'), 'in scope', tone='text')} | "
        f"{_styled_count_phrase(pipeline.get('policy_eligible'), 'eligible', tone='success')}"
    )
    print(
        f"{'Harvest':<12} : {_styled_count_phrase(pipeline.get('scheduled'), 'scheduled', tone='accent')} | "
        f"{_styled_count_phrase(pipeline.get('harvested'), 'harvested', tone='info')} | "
        f"{_styled_count_phrase(pipeline.get('persisted'), 'persisted', tone='success')}"
    )
    print(
        f"{'Blocked':<12} : {_styled_count_phrase(pipeline.get('blocked_policy'), 'policy', tone='blocked')} | "
        f"{_styled_count_phrase(pipeline.get('blocked_scope'), 'scope', tone='warning')}"
    )

    if isinstance(latest_harvest, dict):
        session_label = latest_harvest.get("session_label") or "unknown"
        print()
        print(colors.apply("Evidence and Paths", colors.style("header"), bold=True))
        print(text_blocks.divider(width=18, style="divider"))
        print(f"{'Latest harvest':<15} : {colors.apply(str(session_label), colors.style('accent'), bold=True)}")
        harvest_snapshot_id = latest_harvest.get("snapshot_id")
        inventory_snapshot_id = pipeline.get("inventory_snapshot_id")
        if harvest_snapshot_id is not None:
            if harvest_snapshot_id == inventory_snapshot_id:
                print(f"{'Snapshot link':<15} : {colors.apply(f'inventory snapshot {harvest_snapshot_id}', colors.style('text'), bold=True)}")
                print(f"{'Alignment':<15} : {colors.apply('current', colors.style('success'), bold=True)}")
            else:
                print(f"{'Snapshot link':<15} : {colors.apply(f'harvest snapshot {harvest_snapshot_id}', colors.style('text'), bold=True)}")
                print(f"{'Alignment':<15} : {colors.apply('stale vs latest inventory', colors.style('warning'), bold=True)}")
        artifacts_root = latest_harvest.get("artifacts_root")
        receipts_root = latest_harvest.get("receipts_root")
        if artifacts_root:
            print(f"{'Artifacts root':<15} : {colors.apply(str(artifacts_root), colors.style('muted'))}")
        if receipts_root:
            print(f"{'Receipts root':<15} : {colors.apply(str(receipts_root), colors.style('muted'))}")


def build_device_summaries(
    devices: list[dict[str, str | None]],
    summary_cache: dict[str, dict[str, str | None]],
    *,
    refresh_threshold: int = 60,
) -> tuple[list[dict[str, str | None]], dict[str, dict[str, str | None]]]:
    summaries, serial_map = device_service.build_device_summaries(
        devices,
        summary_cache,
        refresh_threshold=refresh_threshold,
    )
    log.info(
        f"Refreshed device dashboard: {len(summaries)} device(s) detected.",
        category="device",
    )
    return summaries, serial_map


def print_dashboard(
    summaries: list[dict[str, str | None]],
    active_details: dict[str, str | None | None],
    warnings: list[str],
    last_refresh_ts: float | None,
    serial_map: dict[str, dict[str, str | None]],
    *,
    show_device_table: bool = True,
    inventory_metadata: dict[str, object | None] = None,
    context: str | None = None,
) -> None:
    devices_found = len(summaries)
    print()

    # One-line guidance when disconnected
    if not active_details:
        last_serial = device_service.get_last_serial()
        last_summary = serial_map.get(last_serial) if last_serial else None
        last_seen = _last_seen_brief(last_summary, last_serial)
        line = _no_device_line(devices_found)
        if last_seen:
            line = f"{line} Last seen: {last_seen}"
        print(colors.apply(line, colors.get_palette().hint))

    # Prefer a lighter single-device summary when an active device is selected.
    if active_details:
        _render_active_device_summary(active_details)
    elif show_device_table and summaries:
        rows = _device_table_rows(summaries)
        table_utils.render_table(
            ["Device", "OEM", "Android", "Battery", "Wi-Fi", "Root access"],
            rows,
            padding=3,
            accent_first_column=True,
        )

    # Inventory status (inline)
    if active_details and inventory_metadata:
        serial = active_details.get("serial") if isinstance(active_details, dict) else None
        pipeline = _compute_pipeline_state(serial)
        _render_compact_status(active_details, inventory_metadata, pipeline)

    # Device Analysis menu (sequential, no gaps)
    from .actions import build_main_menu_options
    options = build_main_menu_options(active_details)
    _render_grouped_actions(options)

    # ADB warnings
    if warnings:
        distinct_warnings = list(dict.fromkeys(warnings))
        for warning in distinct_warnings:
            log.warning(warning, category="device")
        panel = error_panels.format_panel(
            "ADB warnings",
            "Review the following issues detected during the scan.",
            details=distinct_warnings,
            tone="warning",
            width=74,
        )
        print()
        print(panel)


def resolve_active_device(
    devices: list[dict[str, str | None]]
) -> dict[str, str | None | None]:
    return device_service.resolve_active_device(devices)


__all__ = [
    "build_device_summaries",
    "print_device_details",
    "print_dashboard",
    "resolve_active_device",
    # Exposed for tests
    "_connection_badge",
    "_status_badge",
    "_device_table_rows",
    "_no_device_line",
]
