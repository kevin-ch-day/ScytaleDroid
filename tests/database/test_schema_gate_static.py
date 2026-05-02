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
    assert "static_analysis_runs" in required_tables
    assert "static_analysis_findings" in required_tables
    assert "static_session_run_links" in required_tables
    assert "static_session_rollups" in required_tables
    assert "v_static_handoff_v1" in required_tables
    assert "findings" not in required_tables
    assert "runs" not in required_tables
    required_columns = dict(captured.get("required_columns") or {})
    static_columns = list(required_columns.get("static_analysis_runs") or [])
    assert "identity_mode" in static_columns
    assert "identity_conflict_flag" in static_columns
    assert "static_handoff_hash" in static_columns
    assert "static_handoff_json_path" in static_columns
    assert "masvs_mapping_hash" in static_columns
    assert "run_class" in static_columns
    assert "non_canonical_reasons" in static_columns
    assert list(required_columns.get("static_string_summary") or ()) == [
        "package_name",
        "session_stamp",
        "scope_label",
        "static_run_id",
    ]


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
