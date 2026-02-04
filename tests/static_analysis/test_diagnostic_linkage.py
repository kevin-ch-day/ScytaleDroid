from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult
from scytaledroid.StaticAnalysis.cli.execution import diagnostics


def _app(
    package: str,
    signature: str | None = None,
    signature_version: str | None = None,
) -> AppRunResult:
    app = AppRunResult(package_name=package, category="test")
    app.run_signature = signature
    if signature and signature_version is None:
        signature_version = "v1"
    app.run_signature_version = signature_version
    return app


def test_linkage_valid_run_map():
    run_map = {
        "apps": [
            {"package": "com.example.app", "static_run_id": 7, "pipeline_version": "2.0.0-alpha"}
        ]
    }
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"), run_map=run_map, session_stamp="20260130-000000"
    )
    assert status == "VALID (run_map)"
    assert note == "static_run_id=7"


def test_linkage_valid_db_link(monkeypatch):
    def fake_run_sql(query, params=None, fetch="none", **kwargs):
        if "static_session_run_links" in query:
            return {
                "static_run_id": 11,
                "pipeline_version": "2.0.0-alpha",
                "run_signature": "sig",
                "run_signature_version": "v1",
            }
        return None

    monkeypatch.setattr(diagnostics.core_q, "run_sql", fake_run_sql)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"),
        run_map=None,
        session_stamp="20260130-000000",
    )
    assert status == "VALID (db_link)"
    assert note == "static_run_id=11"


def test_linkage_valid_db_lookup(monkeypatch):
    def fake_run_sql(query, params=None, fetch="none", **kwargs):
        if "static_session_run_links" in query:
            return None
        if "static_analysis_runs" in query:
            return {
                "static_run_id": 21,
                "pipeline_version": "2.0.0-alpha",
                "run_signature": "sig",
                "run_signature_version": "v1",
            }
        return None

    monkeypatch.setattr(diagnostics.core_q, "run_sql", fake_run_sql)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app", signature="sig"),
        run_map=None,
        session_stamp="20260130-000000",
    )
    assert status == "VALID (db_lookup)"
    assert note == "static_run_id=21"


def test_linkage_db_lookup_blocked_for_unsupported_version(monkeypatch):
    monkeypatch.setattr(diagnostics.core_q, "run_sql", lambda *args, **kwargs: None)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app", signature="sig", signature_version="v0"),
        run_map=None,
        session_stamp="20260130-000000",
    )
    assert status == "UNAVAILABLE"
    assert "unsupported_signature_version" in (note or "")


def test_linkage_invalid_mismatch(monkeypatch):
    def fake_run_sql(query, params=None, fetch="none", **kwargs):
        if "static_session_run_links" in query:
            return {
                "static_run_id": 2,
                "pipeline_version": "2.0.0-alpha",
                "run_signature": "sig",
                "run_signature_version": "v1",
            }
        return None

    monkeypatch.setattr(diagnostics.core_q, "run_sql", fake_run_sql)
    run_map = {
        "apps": [
            {"package": "com.example.app", "static_run_id": 1, "pipeline_version": "2.0.0-alpha"}
        ]
    }
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"),
        run_map=run_map,
        session_stamp="20260130-000000",
    )
    assert status == "INVALID"
    assert "run_map/db_link mismatch" in (note or "")


def test_linkage_unavailable(monkeypatch):
    monkeypatch.setattr(diagnostics.core_q, "run_sql", lambda *args, **kwargs: None)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"),
        run_map=None,
        session_stamp="20260130-000000",
    )
    assert status == "UNAVAILABLE"
    assert "no run_map; no db link" in (note or "")


def test_linkage_invalid_run_map_shape(monkeypatch):
    monkeypatch.setattr(diagnostics.core_q, "run_sql", lambda *args, **kwargs: None)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"),
        run_map={"apps": "bad"},
        session_stamp="20260130-000000",
    )
    assert status == "INVALID"
    assert "run_map missing apps list" in (note or "")


def test_linkage_unavailable_run_map_missing_fields(monkeypatch):
    monkeypatch.setattr(diagnostics.core_q, "run_sql", lambda *args, **kwargs: None)
    run_map = {"apps": [{"package": "com.example.app", "static_run_id": 1, "pipeline_version": ""}]}
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"),
        run_map=run_map,
        session_stamp="20260130-000000",
    )
    assert status == "UNAVAILABLE"
    assert "static_run_id/pipeline_version" in (note or "")


def test_linkage_invalid_db_link_missing_pipeline(monkeypatch):
    def fake_run_sql(query, params=None, fetch="none", **kwargs):
        if "static_session_run_links" in query:
            return {
                "static_run_id": 9,
                "pipeline_version": "",
                "run_signature": "sig",
                "run_signature_version": "v1",
            }
        return None

    monkeypatch.setattr(diagnostics.core_q, "run_sql", fake_run_sql)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app"),
        run_map=None,
        session_stamp="20260130-000000",
    )
    assert status == "INVALID"
    assert "db_link missing pipeline_version" in (note or "")


def test_linkage_skips_db_lookup_without_signature(monkeypatch):
    monkeypatch.setattr(diagnostics.core_q, "run_sql", lambda *args, **kwargs: None)
    status, note = diagnostics._diagnostic_linkage_status(
        _app("com.example.app", signature=None),
        run_map=None,
        session_stamp="20260130-000000",
    )
    assert status == "UNAVAILABLE"
    assert "no run_map; no db link" in (note or "")
