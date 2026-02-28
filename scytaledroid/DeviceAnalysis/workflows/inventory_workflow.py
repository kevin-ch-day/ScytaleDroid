"""Workflow wrapper for inventory orchestration."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.services import inventory_service


def run_inventory_sync(
    serial: str,
    ui_prefs,
    *,
    progress_sink: str = "cli",
    mode: str | None = None,
    allow_fallbacks: bool | None = None,
):
    """Workflow entrypoint; delegates to inventory_service.run_full_sync."""
    return inventory_service.run_full_sync(
        serial=serial,
        ui_prefs=ui_prefs,
        progress_sink=progress_sink,
        mode=mode,
        allow_fallbacks=allow_fallbacks,
    )


def run_inventory_scoped_sync(
    *,
    serial: str,
    scope_id: str,
    packages: set[str],
    ui_prefs,
    progress_sink: str = "cli",
    mode: str | None = None,
    allow_fallbacks: bool | None = None,
):
    """Workflow entrypoint for scoped inventory sync (filesystem-only)."""
    return inventory_service.run_scoped_sync(
        serial=serial,
        scope_id=scope_id,
        packages=packages,
        ui_prefs=ui_prefs,
        progress_sink=progress_sink,
        mode=mode,
        allow_fallbacks=allow_fallbacks,
    )


__all__ = ["run_inventory_sync", "run_inventory_scoped_sync"]
