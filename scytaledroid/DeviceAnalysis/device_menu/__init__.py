"""Subpackage for Device Analysis menu components.

Heavy modules (dashboard, actions, inventory guard glue) load on demand when
referenced via ``from scytaledroid.DeviceAnalysis.device_menu import …``. Importing a
subpackage module directly — e.g. ``device_menu.dashboard`` — skips these re-exports
and pulls only that file after this minimal ``__init__`` runs.
"""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.lazy_pkg import lazy_getattr as _lazy_getattr

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "build_main_menu_options": (".actions", "build_main_menu_options"),
    "handle_choice": (".actions", "handle_choice"),
    "build_device_summaries": (".dashboard", "build_device_summaries"),
    "print_dashboard": (".dashboard", "print_dashboard"),
    "resolve_active_device": (".dashboard", "resolve_active_device"),
    "ensure_recent_inventory": (".inventory_guard", "ensure_recent_inventory"),
    "format_inventory_status": (".inventory_guard", "format_inventory_status"),
    "format_pull_hint": (".inventory_guard", "format_pull_hint"),
    "device_menu": (".menu", "device_menu"),
}


def __getattr__(name: str) -> object:
    return _lazy_getattr(__name__, _LAZY_EXPORTS, globals(), name)


__all__ = [
    "build_device_summaries",
    "print_dashboard",
    "resolve_active_device",
    "device_menu",
    "handle_choice",
    "build_main_menu_options",
    "ensure_recent_inventory",
    "format_inventory_status",
    "format_pull_hint",
]
