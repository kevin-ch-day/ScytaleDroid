"""Sanity checks for shared DeviceAnalysis facade helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scytaledroid.DeviceAnalysis import lazy_pkg

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_device_menu_facade_symbols_are_lazy_clean_interpreter() -> None:
    script = """\
import scytaledroid.DeviceAnalysis.device_menu as dm
heavy = ('handle_choice', 'print_dashboard', 'ensure_recent_inventory', 'device_menu')
assert all(n not in dm.__dict__ for n in heavy), sorted(dm.__dict__)
import scytaledroid.DeviceAnalysis.device_menu.actions
assert 'handle_choice' not in dm.__dict__
assert callable(dm.handle_choice)
assert callable(dm.device_menu)
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


def test_lazy_getattr_miss_raises() -> None:
    with pytest.raises(AttributeError):
        lazy_pkg.lazy_getattr(
            "fake_pkg",
            {"a": (".missing", "b")},
            {},
            "z",
        )


def test_device_analysis_settings_aliases_guard_constants() -> None:
    from scytaledroid.DeviceAnalysis import device_analysis_settings as central
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard import constants as guard

    assert central.INVENTORY_STALE_SECONDS == guard.INVENTORY_STALE_SECONDS
    assert central.INVENTORY_DELTA_SUPPRESS_SECONDS == guard.INVENTORY_DELTA_SUPPRESS_SECONDS
