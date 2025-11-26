"""Inventory subpackage public API."""

# NOTE: This file re-exports helpers for compatibility.
# Preferred entry point: scytaledroid.DeviceAnalysis.services.inventory_service.

import importlib.util
from pathlib import Path

run_inventory_sync = None
InventoryResult = None
InventorySyncStats = None
load_latest_snapshot = None
load_latest_snapshot_meta = None
persist_snapshot = None
hash_rows = None
load_canonical_metadata = None
run_full_sync = None
_render_inventory_summary = None

# Legacy-compatible wrapper for tests expecting _render_inventory_summary(rows)
def _render_inventory_summary_compat(rows):
    class _Tmp:
        pass
    tmp = _Tmp()
    tmp.rows = rows
    try:
        from . import summary as _summary_mod
        _summary_mod.render_inventory_summary(tmp)
    except Exception:
        return None
    return None

# Legacy compatibility: load the old inventory.py so existing imports still work.
_legacy_path = Path(__file__).resolve().parent.parent / "inventory.py"
if _legacy_path.exists():
    spec = importlib.util.spec_from_file_location(
        "scytaledroid.DeviceAnalysis.inventory_legacy", _legacy_path
    )
    if spec and spec.loader:
        _legacy_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_legacy_module)  # type: ignore[arg-type]
        run_inventory_sync = getattr(_legacy_module, "run_inventory_sync", None)

try:
    from .runner import run_full_sync, InventoryResult, InventorySyncStats
    from .snapshot_io import (
        load_latest_inventory,
        load_latest_inventory as load_latest_snapshot,
        load_latest_snapshot_meta,
        persist_snapshot,
        hash_rows,
        load_canonical_metadata,
    )
    load_latest_snapshot = load_latest_inventory
    from . import summary as _summary_mod
except Exception:
    _summary_mod = None

# Always expose a rows->summary wrapper for compatibility with existing tests.
def _render_inventory_summary(rows):
    class _Tmp:
        pass
    tmp = _Tmp()
    tmp.rows = rows
    if _summary_mod is not None:
        return _summary_mod.render_inventory_summary(tmp)
    return _render_inventory_summary_compat(rows)

__all__ = [
    "run_inventory_sync",
    "run_full_sync",
    "InventoryResult",
    "InventorySyncStats",
    "load_latest_inventory",
    "load_latest_snapshot",
    "load_latest_snapshot_meta",
    "persist_snapshot",
    "hash_rows",
    "load_canonical_metadata",
    "_render_inventory_summary",
]
