"""Subpackage for Device Analysis menu components."""

from .dashboard import build_device_summaries, print_dashboard, resolve_active_device
from .actions import handle_choice, build_main_menu_options
from .inventory_guard import (
    ensure_recent_inventory,
    format_inventory_status,
    format_pull_hint,
)

__all__ = [
    "build_device_summaries",
    "print_dashboard",
    "resolve_active_device",
    "handle_choice",
    "build_main_menu_options",
    "ensure_recent_inventory",
    "format_inventory_status",
    "format_pull_hint",
]
