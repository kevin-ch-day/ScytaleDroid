"""Guards for lightweight ``DeviceAnalysis.inventory`` package loading."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_inventory_facade_symbols_are_lazy_clean_interpreter() -> None:
    """Fresh process: facade names load on demand after sibling submodule imports."""

    script = """\
import scytaledroid.DeviceAnalysis.inventory as inv_pkg
expected = ('run_full_sync', 'InventoryResult', 'load_latest_inventory',
            'print_inventory_run_summary_from_result')
assert all(n not in inv_pkg.__dict__ for n in expected), sorted(inv_pkg.__dict__.keys())
import scytaledroid.DeviceAnalysis.inventory.db_sync
assert 'run_full_sync' not in inv_pkg.__dict__
assert callable(inv_pkg.run_full_sync)
assert callable(inv_pkg.load_latest_inventory)
"""
    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_inventory_facade_cache_after_first_resolve() -> None:
    """In-process sanity: resolving a lazy name binds it on the module."""

    import scytaledroid.DeviceAnalysis.inventory as inv_pkg

    _ = inv_pkg.InventoryResult
    assert "InventoryResult" in inv_pkg.__dict__
