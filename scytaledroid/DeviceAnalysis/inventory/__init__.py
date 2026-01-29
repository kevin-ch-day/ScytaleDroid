"""
Public facade for inventory internals.

Notes for new code:
- Prefer calling services.inventory_service.run_full_sync from controllers/menus.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)

from .runner import InventoryResult, InventorySyncStats, run_full_sync
from .snapshot_io import (
    hash_rows,
    load_canonical_metadata,
    load_latest_inventory,
    load_latest_snapshot_meta,
    persist_snapshot,
)
from .views import print_inventory_run_summary_from_result


def _owner_role(entry: Dict[str, object]) -> str:
    role = str(entry.get("owner_role") or "").strip()
    if role:
        return role
    primary_path = str(entry.get("primary_path") or "")
    if primary_path.startswith("/data/"):
        return "User"
    if primary_path:
        return "System"
    return "Unknown"


def _preview_rows(packages: List[Dict[str, object]], *, role: str, limit: int) -> List[List[str]]:
    rows: List[List[str]] = []
    for entry in packages:
        if _owner_role(entry) != role:
            continue
        rows.append(
            [
                str(entry.get("package_name") or ""),
                str(entry.get("app_label") or ""),
                str(entry.get("version_name") or entry.get("version_code") or ""),
                str(entry.get("profile_name") or "Unclassified"),
                str(entry.get("primary_path") or ""),
            ]
        )
        if len(rows) >= limit:
            break
    return rows


def run_device_summary(serial: Optional[str]) -> None:
    """Display the latest inventory snapshot with highlighted insights."""

    if not serial:
        error_panels.print_error_panel(
            "Detailed device report",
            "No active device. Connect first to show the report.",
        )
        prompt_utils.press_enter_to_continue()
        return

    snapshot = load_latest_inventory(serial)
    if not snapshot:
        error_panels.print_error_panel(
            "Detailed device report",
            "No inventory snapshot found for this device.",
            hint="Run a full inventory sync first.",
        )
        if prompt_utils.prompt_yes_no("Run a new inventory sync now?", default=True):
            try:
                from scytaledroid.DeviceAnalysis.services import inventory_service

                inventory_service.run_full_sync(serial=serial, ui_prefs=None, progress_sink="cli")
            except Exception as exc:  # pragma: no cover - defensive
                status_messages.print_status(f"Inventory sync failed: {exc}", level="error")
                prompt_utils.press_enter_to_continue()
        return

    packages: List[Dict[str, object]] = snapshot.get("packages", [])  # type: ignore[assignment]
    generated_at = snapshot.get("generated_at")

    print()
    print(text_blocks.headline("Device inventory overview", width=70))
    if generated_at:
        status_messages.print_status(f"Snapshot captured {generated_at}", level="info")

    if not packages:
        status_messages.print_status("Snapshot contains no package entries.", level="warn")
        prompt_utils.press_enter_to_continue()
        return

    try:
        from .summary import render_inventory_summary

        render_inventory_summary(packages)
    except Exception as exc:  # pragma: no cover - defensive
        status_messages.print_status(f"Unable to render inventory summary: {exc}", level="error")
        prompt_utils.press_enter_to_continue()
        return

    user_preview = _preview_rows(packages, role="User", limit=12)
    if user_preview:
        print()
        print(text_blocks.headline("User applications (preview)", width=70))
        table_utils.render_table(["Package", "App", "Version", "Profile", "Path"], user_preview)

    system_preview = _preview_rows(packages, role="System", limit=8)
    if system_preview:
        print()
        print(text_blocks.headline("System components (preview)", width=70))
        table_utils.render_table(["Package", "Component", "Version", "Profile", "Path"], system_preview)

    prompt_utils.press_enter_to_continue()


def _render_inventory_summary(packages: List[Dict[str, object]]) -> None:
    """Compatibility wrapper for tests; delegates to summary renderer."""
    from .summary import render_inventory_summary

    render_inventory_summary(packages)

__all__ = [
    # Preferred API
    "run_full_sync",
    "InventoryResult",
    "InventorySyncStats",
    "load_latest_snapshot_meta",
    "persist_snapshot",
    "hash_rows",
    "load_canonical_metadata",
    "load_latest_inventory",
    "print_inventory_run_summary_from_result",
    "run_device_summary",
]
