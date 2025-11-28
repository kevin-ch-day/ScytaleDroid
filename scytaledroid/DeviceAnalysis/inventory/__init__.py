"""
Public facade for inventory internals.

Notes for new code:
- Prefer calling services.inventory_service.run_full_sync from controllers/menus.
- This module keeps a thin compat surface so legacy imports keep working
  (load_latest_inventory, render_inventory_summary, etc).
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from .runner import InventoryResult, InventorySyncStats, run_full_sync
from .snapshot_io import (
    hash_rows,
    load_canonical_metadata,
    load_latest_inventory,
    load_latest_snapshot_meta,
    persist_snapshot,
)

# Compat alias used by older callers
load_latest_snapshot = load_latest_inventory

# Optional: compat render wrapper
try:
    from . import summary as _summary_mod
except Exception:
    _summary_mod = None


def _render_inventory_summary(obj) -> None:
    """
    Compatibility helper for legacy callers expecting render_inventory_summary.
    Accepts any object with `.rows` attribute (e.g., InventoryResult or
    LegacyInventoryResult). New code should import summary.render_inventory_summary
    directly.
    """
    if _summary_mod is None:
        raise RuntimeError("summary module unavailable; cannot render inventory summary")
    _summary_mod.render_inventory_summary(obj)


# Legacy support: allow opting into the old inventory.py via env flag
run_inventory_sync = None
if os.getenv("SCYTALEDROID_LOAD_LEGACY_INVENTORY") == "1":
    legacy_path = Path(__file__).resolve().parent / "inventory.py"
    if legacy_path.exists():
        spec = importlib.util.spec_from_file_location("scytaledroid.DeviceAnalysis.inventory_legacy", legacy_path)
        if spec and spec.loader:
            legacy_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(legacy_mod)
            run_inventory_sync = getattr(legacy_mod, "run_inventory_sync", None)

__all__ = [
    # Preferred API
    "run_full_sync",
    "InventoryResult",
    "InventorySyncStats",
    "load_latest_snapshot",
    "load_latest_snapshot_meta",
    "persist_snapshot",
    "hash_rows",
    "load_canonical_metadata",
    # Compat aliases
    "load_latest_inventory",
    "_render_inventory_summary",
    "run_inventory_sync",
]
