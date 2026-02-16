from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.persistence import run_summary as rs


class _DummyReport:
    def __init__(self) -> None:
        self.metadata = {}
        self.manifest = SimpleNamespace(
            package_name="com.example.app",
            app_label="Example",
            version_name="1.0",
            version_code=1,
            min_sdk=24,
            target_sdk=34,
        )
        self.detector_results = []
        self.hashes = {}
        self.analysis_version = "test"
        self.exported_components = None


class _FakeDBSession:
    def __init__(self, state: dict[str, object]) -> None:
        self._state = state

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    @contextmanager
    def transaction(self):
        self._state["in_tx"] = True
        try:
            yield
        finally:
            self._state["in_tx"] = False


def _stub_metrics_bundle() -> SimpleNamespace:
    return SimpleNamespace(
        code_http_hosts=0,
        asset_http_hosts=0,
        permission_detail={},
        dangerous_permissions=0,
        signature_permissions=0,
        oem_permissions=0,
        permission_score=0.0,
        permission_grade="A",
        buckets=[],
        contributors=[],
    )


def test_static_run_created_inside_transaction(monkeypatch):
    state: dict[str, object] = {"in_tx": False, "create_called_in_tx": False}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)

    def _create_static_run(**_kwargs):
        state["create_called_in_tx"] = bool(state["in_tx"])
        return 202

    monkeypatch.setattr(rs, "_create_static_run", _create_static_run)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-atomic-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert state["create_called_in_tx"] is True
    assert outcome.persistence_failed is False
    assert outcome.static_run_id == 202


def test_static_run_create_failure_does_not_produce_authoritative_id(monkeypatch):
    state: dict[str, object] = {"in_tx": False}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-atomic-2",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert outcome.persistence_failed is True
    assert outcome.static_run_id is None
    assert outcome.errors

