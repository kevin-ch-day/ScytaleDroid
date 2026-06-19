from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory.mode_labels import (
    inventory_mode_label,
    inventory_mode_suffix,
)


def test_inventory_mode_label_maps_known_modes() -> None:
    assert inventory_mode_label("bulk") == "harvest-ready"
    assert inventory_mode_label("baseline") == "full device"
    assert inventory_mode_label("user_only") == "profile-only"


def test_inventory_mode_label_normalizes_unknown_values() -> None:
    assert inventory_mode_label(" custom_mode ") == "custom-mode"
    assert inventory_mode_label(None) is None


def test_inventory_mode_suffix_uses_requested_prefix() -> None:
    assert inventory_mode_suffix("baseline") == " full device"
    assert inventory_mode_suffix("bulk", prefix=", ") == ", harvest-ready"
    assert inventory_mode_suffix(None) == ""
