from __future__ import annotations

from contextlib import contextmanager
from collections import Counter
from types import SimpleNamespace

from scytaledroid.Database.db_core import db_engine
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
        self._dialect = str(state.get("dialect", "mysql"))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None, **_kwargs):
        executed = self._state.setdefault("executed_sql", [])
        if isinstance(executed, list):
            executed.append((str(sql), params))

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
    state: dict[str, object] = {
        "in_tx": False,
        "create_called_in_tx": False,
        "legacy_create_called_in_tx": False,
    }
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)
    monkeypatch.setattr(
        rs._dw,
        "create_run",
        lambda **_kwargs: state.__setitem__("legacy_create_called_in_tx", bool(state["in_tx"])) or 303,
    )

    def _create_static_run(**_kwargs):
        state["create_called_in_tx"] = bool(state["in_tx"])
        return 202

    monkeypatch.setattr(rs, "_create_static_run", _create_static_run)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
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
    assert state["legacy_create_called_in_tx"] is True
    assert outcome.persistence_failed is False
    assert outcome.static_run_id == 202
    assert outcome.run_id == 303


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
    monkeypatch.setattr(rs._dw, "create_run", lambda **_kwargs: 404)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
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


def test_legacy_run_create_failure_marks_transaction_failed(monkeypatch):
    state: dict[str, object] = {"in_tx": False}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(
        rs._dw,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("legacy run insert failed")),
    )
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-atomic-3",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert outcome.persistence_failed is True
    assert outcome.run_id is None
    assert any("run.create" in err for err in outcome.errors)


def test_persist_run_summary_rejects_missing_scope_identity(monkeypatch):
    called = {"db_session": False}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)

    def _db_session_fail(*_args, **_kwargs):
        called["db_session"] = True
        raise AssertionError("database_session should not run for identity validation failure")

    monkeypatch.setattr(rs, "database_session", _db_session_fail)
    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-identity-1",
        scope_label="",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )
    assert called["db_session"] is False
    assert outcome.errors
    assert any("identity_validation_failed" in err for err in outcome.errors)


def test_persist_run_summary_retries_transient_transaction_failure(monkeypatch):
    state: dict[str, object] = {"in_tx": False, "attempts": 0}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(rs.app_config, "STATIC_PERSIST_TRANSIENT_RETRIES", 2, raising=False)
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)

    def _create_run(**_kwargs):
        state["attempts"] = int(state["attempts"]) + 1
        if int(state["attempts"]) == 1:
            raise db_engine.TransientDbError("Lost connection to MySQL server during query (2013)")
        return 9001

    monkeypatch.setattr(rs._dw, "create_run", _create_run)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: 202)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-retry-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert int(state["attempts"]) == 2
    assert outcome.persistence_failed is False
    assert outcome.run_id == 9001
    assert outcome.static_run_id == 202


def test_persist_run_summary_exhausts_transient_retries(monkeypatch):
    state: dict[str, object] = {"in_tx": False, "attempts": 0}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(rs.app_config, "STATIC_PERSIST_TRANSIENT_RETRIES", 2, raising=False)
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())

    def _create_run(**_kwargs):
        state["attempts"] = int(state["attempts"]) + 1
        raise db_engine.TransientDbError("Lost connection to MySQL server during query (2013)")

    monkeypatch.setattr(rs._dw, "create_run", _create_run)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-retry-2",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert int(state["attempts"]) == 2
    assert outcome.persistence_failed is True
    assert outcome.static_run_id is None
    assert any("Static persistence transaction failed" in err for err in outcome.errors)


def test_persist_run_summary_applies_mysql_lock_wait_timeout(monkeypatch):
    state: dict[str, object] = {"in_tx": False, "attempts": 0, "dialect": "mysql"}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(rs.app_config, "STATIC_PERSIST_LOCK_WAIT_TIMEOUT_S", 17, raising=False)
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)
    monkeypatch.setattr(rs._dw, "create_run", lambda **_kwargs: 404)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: 505)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-lock-timeout-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert outcome.persistence_failed is False
    executed = list(state.get("executed_sql", []))
    assert any("SET SESSION innodb_lock_wait_timeout" in sql and params == (17,) for sql, params in executed)


def test_persist_run_summary_limits_lock_wait_retries(monkeypatch):
    state: dict[str, object] = {"in_tx": False, "attempts": 0, "dialect": "mysql"}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(rs.app_config, "STATIC_PERSIST_TRANSIENT_RETRIES", 4, raising=False)
    monkeypatch.setattr(rs.app_config, "STATIC_PERSIST_LOCK_WAIT_RETRIES", 1, raising=False)
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())

    def _create_run(**_kwargs):
        state["attempts"] = int(state["attempts"]) + 1
        raise db_engine.TransientDbError("(1205, 'Lock wait timeout exceeded; try restarting transaction')")

    monkeypatch.setattr(rs._dw, "create_run", _create_run)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-lock-retry-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert int(state["attempts"]) == 1
    assert outcome.persistence_failed is True
    assert any("db_lock_wait=1" in err for err in outcome.errors)


def test_persist_run_summary_reuses_identity_on_retry_after_bucket_failure(monkeypatch):
    state: dict[str, object] = {"in_tx": False, "run_create_calls": 0, "static_create_calls": 0, "bucket_calls": 0}
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(rs.app_config, "STATIC_PERSIST_TRANSIENT_RETRIES", 2, raising=False)
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)

    def _create_run(**_kwargs):
        state["run_create_calls"] = int(state["run_create_calls"]) + 1
        return 7001

    def _create_static_run(**_kwargs):
        state["static_create_calls"] = int(state["static_create_calls"]) + 1
        return 8001

    def _write_buckets(*_args, **_kwargs):
        state["bucket_calls"] = int(state["bucket_calls"]) + 1
        if int(state["bucket_calls"]) == 1:
            raise db_engine.TransientDbError("(1205, 'Lock wait timeout exceeded; try restarting transaction')")
        return True

    monkeypatch.setattr(rs._dw, "create_run", _create_run)
    monkeypatch.setattr(rs, "_create_static_run", _create_static_run)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", _write_buckets)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-reuse-id-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert int(state["run_create_calls"]) == 1
    assert int(state["static_create_calls"]) == 1
    assert int(state["bucket_calls"]) == 2
    assert outcome.persistence_failed is False
    assert outcome.run_id == 7001
    assert outcome.static_run_id == 8001


def test_persist_run_summary_marks_started_row_failed_on_rollback(monkeypatch):
    state: dict[str, object] = {"in_tx": False}
    status_updates: list[dict[str, object]] = []
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(rs, "_ensure_app_version", lambda **_kwargs: 101)
    monkeypatch.setattr(rs._dw, "create_run", lambda **_kwargs: 404)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: 505)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "record_static_persistence_failure", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs.core_q, "run_sql", lambda *_args, **_kwargs: [])

    def _update_status(**kwargs):
        status_updates.append(dict(kwargs))

    monkeypatch.setattr(rs, "update_static_run_status", _update_status)

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-failed-close-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert outcome.persistence_failed is True
    assert outcome.static_run_id is None
    assert status_updates
    assert status_updates[-1]["static_run_id"] == 505
    assert status_updates[-1]["status"] == "FAILED"


def test_canonical_enforcement_scope_resolution_failure_is_fail_safe(monkeypatch):
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
    monkeypatch.setattr(rs._dw, "create_run", lambda **_kwargs: 7001)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: 8001)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)

    def _run_sql(sql, params=None, fetch=None):
        text = str(sql)
        if "SELECT session_label FROM static_analysis_runs WHERE id=%s" in text:
            return ("sess-canon-failsafe",)
        if "COUNT(*) AS run_rows" in text and "COUNT(DISTINCT sar.app_version_id)" in text:
            raise RuntimeError("simulated scope-resolution failure")
        return []

    monkeypatch.setattr(rs.core_q, "run_sql", _run_sql)

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-canon-failsafe",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=True,
        dry_run=False,
    )

    assert outcome.persistence_failed is False
    assert outcome.canonical_failed is False
    assert not any("canonical_enforcement_failed" in err for err in outcome.errors)


def test_canonical_enforcement_skips_profile_scope_fast_path(monkeypatch):
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
    monkeypatch.setattr(rs._dw, "create_run", lambda **_kwargs: 7002)
    monkeypatch.setattr(rs, "_create_static_run", lambda **_kwargs: 8002)
    monkeypatch.setattr(rs, "_update_static_run_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "write_buckets", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "write_metrics", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(rs, "persist_permission_matrix", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "persist_permission_risk", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)

    def _run_sql(sql, params=None, fetch=None):
        text = str(sql)
        if "SELECT session_label FROM static_analysis_runs WHERE id=%s" in text:
            return ("sess-profile",)
        if "COUNT(*) AS run_rows" in text and "COUNT(DISTINCT sar.app_version_id)" in text:
            raise AssertionError("Group-scope fast-path should skip singleton count query")
        if "WHERE session_label=%s AND is_canonical=1" in text:
            return (0,)
        return []

    monkeypatch.setattr(rs.core_q, "run_sql", _run_sql)

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-profile",
        scope_label="Research Dataset Alpha",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=True,
        dry_run=False,
    )

    assert outcome.persistence_failed is False
    assert outcome.canonical_failed is False
    assert not any("canonical_enforcement_failed" in err for err in outcome.errors)


def test_persist_run_summary_rolls_up_persisted_findings_total(monkeypatch):
    state: dict[str, object] = {"in_tx": False}
    updates: list[tuple[object, object]] = []
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(rs, "database_session", lambda: _FakeDBSession(state))
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(rs, "compute_metrics_bundle", lambda *_args, **_kwargs: _stub_metrics_bundle())
    monkeypatch.setattr(
        rs,
        "_prepare_findings_persistence_context",
        lambda **_kwargs: rs._PreparedFindingsPersistenceContext(
            finding_rows=[
                {"rule_id": "RULE-1", "severity": "High"},
                {"rule_id": "RULE-2", "severity": "Low"},
            ],
            canonical_finding_rows=[],
            correlation_rows=[],
            control_summary=[],
            control_entry_count=0,
            total_findings=2,
            persisted_totals=Counter({"high": 1, "low": 1}),
            downgraded_high=0,
            capped_by_detector=Counter(),
            taxonomy_counter=Counter(),
            rule_assigned=2,
            base_vector_count=0,
            bte_vector_count=0,
            preview_assigned=2,
            path_assigned=2,
            missing_masvs=0,
        ),
    )
    monkeypatch.setattr(
        rs,
        "_bootstrap_persistence_transaction",
        lambda **_kwargs: rs._TransactionBootstrapResult(
            run_id=7001,
            static_run_id=8001,
            created_run_id=False,
            created_static_run_id=False,
        ),
    )
    monkeypatch.setattr(rs, "_persist_findings_and_correlations_stage", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_persist_permission_and_storage_stage", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_persist_metrics_and_sections_stage", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "_finalize_static_handoff_stage", lambda **_kwargs: False)
    monkeypatch.setattr(rs, "update_static_run_status", lambda **_kwargs: None)
    monkeypatch.setattr(rs, "export_dep_json", lambda *_args, **_kwargs: None)

    def _run_sql(sql, params=None, fetch=None):
        text = str(sql)
        if "FROM static_analysis_runs sar" in text:
            return []
        if "SELECT session_label FROM static_analysis_runs WHERE id=%s" in text:
            return ("sess-rollup-1",)
        if "UPDATE static_analysis_runs SET findings_total=%s" in text:
            updates.append(params)
            return None
        return []

    monkeypatch.setattr(rs.core_q, "run_sql", _run_sql)

    outcome = rs.persist_run_summary(
        _DummyReport(),
        {},
        "com.example.app",
        session_stamp="sess-rollup-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        paper_grade_requested=False,
        dry_run=False,
    )

    assert outcome.persistence_failed is False
    assert outcome.persisted_findings == 2
    assert updates == [(2, 8001)]


def test_redact_finding_evidence_payload_masks_jwt_like_tokens() -> None:
    raw = (
        '{"detail":"eyJhbGciOiJSU0EtU0hBMjU2IiwidmVyIjoiMSJ9.'
        'eyJhIjoiYiJ9.c2lnbi1wYXlsb2Fk","path":"assets/api_key.txt"}'
    )
    redacted = rs._redact_finding_evidence_payload(raw)  # noqa: SLF001 - contract guard
    assert "eyJhbGci" not in redacted
    assert "[REDACTED:JWT]" in redacted
