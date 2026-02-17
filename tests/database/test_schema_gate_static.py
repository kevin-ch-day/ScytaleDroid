from __future__ import annotations

from scytaledroid.Database.db_utils import schema_gate


def test_static_schema_gate_requires_vnext_table(monkeypatch):
    captured: dict[str, object] = {}

    def _capture(*_args, **kwargs):
        captured.update(kwargs)
        return (True, "OK", "")

    monkeypatch.setattr(
        schema_gate,
        "check_module_schema",
        _capture,
    )

    ok, msg, detail = schema_gate.static_schema_gate()
    assert ok is True
    assert msg == "OK"
    assert detail == ""
    required_tables = list(captured.get("required_tables") or [])
    assert "static_permission_risk_vnext" in required_tables
    assert "static_permission_risk" not in required_tables


def test_static_schema_gate_propagates_module_schema_failure(monkeypatch):
    monkeypatch.setattr(
        schema_gate,
        "check_module_schema",
        lambda *_args, **_kwargs: (False, "bad", "missing table x"),
    )

    ok, msg, detail = schema_gate.static_schema_gate()
    assert ok is False
    assert msg == "bad"
    assert detail == "missing table x"
