from datetime import UTC, datetime, timedelta
from importlib import import_module
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.prompts import (
    describe_inventory_state,
)
from scytaledroid.DeviceAnalysis.inventory.runner import InventoryDelta

guard_module = import_module(
    "scytaledroid.DeviceAnalysis.device_menu.inventory_guard.ensure_recent_inventory"
)
loader_module = import_module(
    "scytaledroid.DeviceAnalysis.device_menu.inventory_guard.metadata.loader"
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
    now = datetime.now(UTC)

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


def test_guard_allows_precheck_age_stale_when_operator_already_confirmed(monkeypatch):
    old = datetime.now(UTC) - timedelta(days=2)

    def _fake_metadata(_serial, with_current_state=False, scope_packages=None):
        return {
            "timestamp": old,
            "delta": {"new": 0, "removed": 0, "updated": 0, "changed": 0},
            "scope_changed": False,
            "scope_hash_changed": False,
        }

    def _fail_if_prompted(*_args, **_kwargs):  # pragma: no cover
        raise AssertionError("Guard should bypass prompt when Execute Harvest accepted age-stale")

    monkeypatch.setattr(guard_module, "get_latest_inventory_metadata", _fake_metadata)
    monkeypatch.setattr(guard_module.prompt_utils, "get_choice", _fail_if_prompted)

    assert guard_module.ensure_recent_inventory(
        serial="ABC123",
        accept_age_stale_harvest=True,
    ) is True
    decision = guard_module.get_last_guard_decision()
    assert decision["reason_code"] == "precheck_stale_proceed"
    assert decision["decision_enum"] == "allow"


def test_guard_handles_dict_delta_without_prompt(monkeypatch):
    now = datetime.now(UTC)

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


def test_guard_decision_is_stable_for_identical_input(monkeypatch):
    now = datetime.now(UTC)

    def _fake_metadata(_serial, with_current_state=False, scope_packages=None):
        return {
            "timestamp": now,
            "delta": {"new": 0, "removed": 0, "updated": 0, "changed": 0},
            "scope_changed": False,
            "scope_hash_changed": False,
        }

    monkeypatch.setattr(guard_module, "get_latest_inventory_metadata", _fake_metadata)
    assert guard_module.ensure_recent_inventory(serial="ABC123") is True
    first = guard_module.get_last_guard_decision()
    assert guard_module.ensure_recent_inventory(serial="ABC123") is True
    second = guard_module.get_last_guard_decision()

    assert first["decision_enum"] == second["decision_enum"]
    assert first["reason_code"] == second["reason_code"]
    assert first["next_action"] == second["next_action"]
    assert first["prompt_key"] == second["prompt_key"]
    assert first["decision_enum"] in guard_module.GUARD_DECISION_ENUMS
    assert first["next_action"] in guard_module.GUARD_NEXT_ACTIONS
    assert first["prompt_key"] in guard_module.GUARD_PROMPT_KEYS
    assert first["reason_code"] in guard_module.GUARD_REASON_CODES


def test_guard_decision_schema_and_cancel_path(monkeypatch):
    old = datetime.now(UTC) - timedelta(days=2)

    def _fake_metadata(_serial, with_current_state=False, scope_packages=None):
        return {
            "timestamp": old,
            "delta": {"new": 0, "removed": 0, "updated": 0, "changed": 0},
            "scope_changed": False,
            "scope_hash_changed": False,
        }

    monkeypatch.setattr(guard_module, "get_latest_inventory_metadata", _fake_metadata)
    monkeypatch.setattr(guard_module.prompt_utils, "get_choice", lambda *_args, **_kwargs: "0")
    assert guard_module.ensure_recent_inventory(serial="ABC123") is False
    decision = guard_module.get_last_guard_decision()

    expected_keys = {
        "policy",
        "stale_level",
        "reason",
        "scope_changed",
        "scope_hash_changed",
        "packages_changed",
        "age_seconds",
        "package_delta",
        "package_delta_brief",
        "guard_brief",
        "decision_enum",
        "reason_code",
        "next_action",
        "prompt_key",
    }
    assert expected_keys.issubset(decision.keys())
    assert decision["decision_enum"] == "deny"
    assert decision["reason_code"] == "user_cancelled"
    assert decision["next_action"] == "cancel"
    assert decision["prompt_key"] == "inventory_guard_choice"


def test_metadata_loader_read_path_does_not_write_scope_hash(monkeypatch):
    now = datetime.now(UTC)
    snapshot_meta = SimpleNamespace(
        captured_at=now,
        package_count=10,
        snapshot_id=7,
        package_list_hash="abc",
        package_signature_hash="def",
        build_fingerprint="fp",
        duration_seconds=1.0,
        scope_hashes={"last_scope": "old"},
        snapshot_type="full",
        scope_hash=None,
        scope_size=None,
        delta_new=0,
        delta_removed=0,
        delta_updated=0,
        delta_changed_count=0,
        delta_split_delta=0,
        delta_details=None,
    )

    write_calls = {"count": 0}

    def _fake_update_scope_hash(_serial, _scope_id, _scope_hash):
        write_calls["count"] += 1
        return {}

    monkeypatch.setattr(
        loader_module.inventory_service,
        "load_latest_snapshot_meta",
        lambda _serial: snapshot_meta,
    )
    monkeypatch.setattr(
        loader_module.inventory_service,
        "update_scope_hash",
        _fake_update_scope_hash,
    )

    metadata = loader_module.get_latest_inventory_metadata(
        "ABC123",
        with_current_state=False,
        scope_packages=["com.example.app"],
    )

    assert isinstance(metadata, dict)
    assert write_calls["count"] == 0
