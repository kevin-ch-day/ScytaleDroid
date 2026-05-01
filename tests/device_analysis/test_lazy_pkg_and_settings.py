"""Sanity checks for shared DeviceAnalysis facade helpers."""

from __future__ import annotations

import pytest

from scytaledroid.DeviceAnalysis import lazy_pkg


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
