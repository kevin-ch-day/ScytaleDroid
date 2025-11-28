from datetime import datetime, timedelta, timezone
from importlib import import_module

from scytaledroid.DeviceAnalysis.inventory.runner import InventoryDelta
guard_module = import_module(
    "scytaledroid.DeviceAnalysis.device_menu.inventory_guard.ensure_recent_inventory"
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.prompts import (
    describe_inventory_state,
)


def test_fresh_no_changes_has_no_warning():
    delta = InventoryDelta(0, 0, 0, 0)
    msg = describe_inventory_state(
        status="FRESH",
        delta=delta,
        age=timedelta(minutes=1),
        threshold=timedelta(hours=24),
    )
    assert msg.severity == "none"
    assert "changed" not in msg.short.lower()


def test_fresh_with_changes_is_info():
    delta = InventoryDelta(1, 1, 3, 5)
    msg = describe_inventory_state(
        status="FRESH",
        delta=delta,
        age=timedelta(minutes=1),
        threshold=timedelta(hours=24),
    )
    assert msg.severity == "info"
    assert "5" in msg.short
    assert "changed" in msg.short.lower()


def test_stale_by_age_is_warn_even_with_no_changes():
    delta = InventoryDelta(0, 0, 0, 0)
    msg = describe_inventory_state(
        status="FRESH",
        delta=delta,
        age=timedelta(hours=48),
        threshold=timedelta(hours=24),
    )
    assert msg.severity == "warn"


def test_guard_allows_pull_when_fresh_and_no_changes(monkeypatch):
    now = datetime.now(timezone.utc)

    def _fake_inventory(_serial):
        return {"packages": []}

    def _fake_metadata(_serial, with_current_state=False, scope_packages=None):
        return {
            "timestamp": now,
            "delta": InventoryDelta(0, 0, 0, 0),
            "scope_changed": False,
            "scope_hash_changed": False,
        }

    def _fail_if_prompted(*_args, **_kwargs):  # pragma: no cover - guardrail
        raise AssertionError("Guard should not prompt when inventory is fresh and unchanged")

    monkeypatch.setattr(
        guard_module.inventory_module,
        "load_latest_inventory",
        _fake_inventory,
    )
    monkeypatch.setattr(
        guard_module,
        "get_latest_inventory_metadata",
        _fake_metadata,
    )
    monkeypatch.setattr(
        guard_module.prompt_utils,
        "get_choice",
        _fail_if_prompted,
    )

    assert guard_module.ensure_recent_inventory(serial="ABC123") is True


def test_guard_handles_dict_delta_without_prompt(monkeypatch):
    now = datetime.now(timezone.utc)

    def _fake_inventory(_serial):
        return {"packages": []}

    def _fake_metadata(_serial, with_current_state=False, scope_packages=None):
        return {
            "timestamp": now,
            "delta": {
                "new": 0,
                "removed": 0,
                "updated": 0,
                "changed": 0,
            },
            "scope_changed": False,
            "scope_hash_changed": False,
        }

    def _fail_if_prompted(*_args, **_kwargs):  # pragma: no cover - guardrail
        raise AssertionError("Guard should not prompt when delta reports no changes")

    monkeypatch.setattr(
        guard_module.inventory_module,
        "load_latest_inventory",
        _fake_inventory,
    )
    monkeypatch.setattr(
        guard_module,
        "get_latest_inventory_metadata",
        _fake_metadata,
    )
    monkeypatch.setattr(
        guard_module.prompt_utils,
        "get_choice",
        _fail_if_prompted,
    )

    assert guard_module.ensure_recent_inventory(serial="ABC123") is True
