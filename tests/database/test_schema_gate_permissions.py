from __future__ import annotations

from scytaledroid.Database.db_utils import schema_gate


def test_permissions_schema_gate_checks_local_and_permission_intel_tables(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_check_module_schema(module: str, **kwargs):
        captured["module"] = module
        captured["required_tables"] = list(kwargs.get("required_tables", []))
        return True, "OK", ""

    checked: list[str] = []

    monkeypatch.setattr(schema_gate, "check_module_schema", _fake_check_module_schema)
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
