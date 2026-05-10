from __future__ import annotations

from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.Database.db_utils.action_groups import status_actions


def test_permissions_schema_gate_checks_local_and_permission_intel_tables(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_check_module_schema(module: str, **kwargs):
        captured["module"] = module
        captured["required_tables"] = list(kwargs.get("required_tables", []))
        return True, "OK", ""

    checked: list[str] = []

    monkeypatch.setattr(schema_gate, "check_module_schema", _fake_check_module_schema)
    monkeypatch.setattr(schema_gate.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        schema_gate.intel_db,
        "intel_table_exists",
        lambda table: checked.append(table) or True,
    )

    ok, msg, detail = schema_gate.permissions_schema_gate()

    assert ok is True
    assert msg == "OK"
    assert detail == ""
    assert captured["module"] == "Permission Cohorts"
    assert captured["required_tables"] == [
        "permission_audit_apps",
        "permission_audit_snapshots",
        "permission_signal_observations",
    ]
    assert checked == list(schema_gate.MANAGED_TABLES)


def test_permissions_schema_gate_fails_when_permission_intel_table_missing(monkeypatch):
    monkeypatch.setattr(schema_gate, "check_module_schema", lambda *args, **kwargs: (True, "OK", ""))
    monkeypatch.setattr(schema_gate.intel_db, "is_permission_intel_configured", lambda: True)
    missing = schema_gate.MANAGED_TABLES[0]
    monkeypatch.setattr(
        schema_gate.intel_db,
        "intel_table_exists",
        lambda table: table != missing,
    )

    ok, msg, detail = schema_gate.permissions_schema_gate()

    assert ok is False
    assert msg == "Permission-intel schema mismatch."
    assert missing in detail


def test_permissions_schema_gate_skips_intel_when_not_configured(monkeypatch):
    monkeypatch.setattr(schema_gate, "check_module_schema", lambda *args, **kwargs: (True, "OK", ""))
    monkeypatch.setattr(schema_gate.intel_db, "is_permission_intel_configured", lambda: False)

    ok, msg, detail = schema_gate.permissions_schema_gate()

    assert ok is True
    assert msg == "OK_SKIPPED"
    assert detail == (
        "Permission Intel DSN not configured; core DB permission cohort tables checked; "
        "PI catalog/governance table presence not assessed."
    )


def test_permission_intel_snapshot_block_skips_describe_target_when_intel_unset(monkeypatch):
    def _must_not_describe() -> dict[str, object]:
        raise AssertionError("describe_target must not be called when PI is not configured")

    monkeypatch.setattr(status_actions.intel_db, "is_permission_intel_configured", lambda: False)
    monkeypatch.setattr(status_actions.intel_db, "describe_target", _must_not_describe)
    monkeypatch.setattr(status_actions, "list_operational_managed_tables", lambda: [])

    block = status_actions._permission_intel_snapshot_block()

    assert block["configured"] is False
    assert block["target"] is None
    assert block["detail"] == (
        "Permission Intel DSN not configured; PI target and governance checks skipped."
    )
    assert block["operational_duplicates"] == []


def test_permission_intel_snapshot_block_pi_unset_duplicate_scan_raises(monkeypatch):
    monkeypatch.setattr(status_actions.intel_db, "is_permission_intel_configured", lambda: False)
    monkeypatch.setattr(
        status_actions,
        "list_operational_managed_tables",
        lambda: (_ for _ in ()).throw(RuntimeError("core db down")),
    )

    block = status_actions._permission_intel_snapshot_block()

    assert block["configured"] is False
    assert block["operational_duplicates"] == []
    assert block["operational_duplicate_scan_warning"] == (
        "Operational duplicate scan failed; see debug logs."
    )


def test_permission_intel_snapshot_block_configured_duplicate_scan_raises(monkeypatch):
    monkeypatch.setattr(status_actions.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        status_actions.intel_db,
        "describe_target",
        lambda: {"database": "pi", "compatibility_mode": False},
    )
    monkeypatch.setattr(
        status_actions,
        "list_operational_managed_tables",
        lambda: (_ for _ in ()).throw(OSError("scan failed")),
    )

    block = status_actions._permission_intel_snapshot_block()

    assert block["target"] == {"database": "pi", "compatibility_mode": False}
    assert block["operational_duplicates"] == []
    assert block["operational_duplicate_scan_warning"] == (
        "Operational duplicate scan failed; see debug logs."
    )


def test_permission_intel_snapshot_block_resolves_target_when_intel_configured(monkeypatch):
    calls: list[int] = []

    def _describe() -> dict[str, object]:
        calls.append(1)
        return {"engine": "mysql"}

    monkeypatch.setattr(status_actions.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(status_actions.intel_db, "describe_target", _describe)
    monkeypatch.setattr(status_actions, "list_operational_managed_tables", lambda: [{"table": "android_permission_dict"}])

    block = status_actions._permission_intel_snapshot_block()

    assert calls == [1]
    assert block["target"] == {"engine": "mysql"}
    assert block["operational_duplicates"] == [{"table": "android_permission_dict"}]
    assert "configured" not in block


def test_permission_intel_snapshot_block_configured_describe_target_raises(monkeypatch):
    monkeypatch.setattr(status_actions.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        status_actions.intel_db,
        "describe_target",
        lambda: (_ for _ in ()).throw(RuntimeError("target resolution failed")),
    )
    monkeypatch.setattr(status_actions, "list_operational_managed_tables", lambda: [{"table": "x", "exists": False}])

    block = status_actions._permission_intel_snapshot_block()

    assert block["configured"] is True
    assert block["target"] is None
    assert block["status"] == "error"
    assert block["detail"] == "Permission Intel target inspection failed; see debug logs."
    assert block["operational_duplicates"] == [{"table": "x", "exists": False}]


def test_permission_intel_snapshot_block_configured_describe_raises_duplicate_scan_raises(monkeypatch):
    monkeypatch.setattr(status_actions.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        status_actions.intel_db,
        "describe_target",
        lambda: (_ for _ in ()).throw(ValueError("bad")),
    )
    monkeypatch.setattr(
        status_actions,
        "list_operational_managed_tables",
        lambda: (_ for _ in ()).throw(OSError("dup")),
    )

    block = status_actions._permission_intel_snapshot_block()

    assert block["status"] == "error"
    assert block["operational_duplicates"] == []
    assert block["operational_duplicate_scan_warning"] == (
        "Operational duplicate scan failed; see debug logs."
    )
