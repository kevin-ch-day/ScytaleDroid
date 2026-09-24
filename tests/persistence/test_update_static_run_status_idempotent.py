"""Regression tests for post-commit static_analysis_runs status assertion."""

from __future__ import annotations

import pytest
from scytaledroid.StaticAnalysis.cli.persistence import run_writers as rw
from scytaledroid.StaticAnalysis.cli.persistence.finalization_flow import (
    StaticRunFinalizationCallbacks,
    finalize_persisted_static_run,
)
from scytaledroid.StaticAnalysis.cli.persistence.persistence_context import PersistenceOutcome


def _status_row(status: str | None):
    if status is None:
        return None
    return (status,)


@pytest.mark.unit
def test_first_transition_to_completed_is_success(monkeypatch) -> None:
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_a, **_k: 1)

    assert rw.update_static_run_status(static_run_id=7356, status="COMPLETED") is True


@pytest.mark.unit
def test_idempotent_completed_update_with_affected_rows_zero_is_success(monkeypatch) -> None:
    warnings: list[str] = []
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_a, **_k: 0)
    monkeypatch.setattr(rw.core_q, "run_sql", lambda *_a, **_k: _status_row("COMPLETED"))
    monkeypatch.setattr(
        rw.log,
        "warning",
        lambda message, **_k: warnings.append(str(message)),
    )

    assert rw.update_static_run_status(static_run_id=7356, status="COMPLETED") is True
    assert warnings == []


@pytest.mark.unit
def test_completed_update_missing_row_is_failure(monkeypatch) -> None:
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_a, **_k: 0)
    monkeypatch.setattr(rw.core_q, "run_sql", lambda *_a, **_k: None)

    assert rw.update_static_run_status(static_run_id=404, status="COMPLETED") is False


@pytest.mark.unit
def test_completed_update_database_exception_is_failure(monkeypatch) -> None:
    def _fail(*_a, **_k):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(rw, "run_sql_rowcount", _fail)

    assert rw.update_static_run_status(static_run_id=7, status="COMPLETED") is False


@pytest.mark.unit
def test_completed_update_unexpected_status_is_state_mismatch(monkeypatch) -> None:
    warnings: list[str] = []
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_a, **_k: 0)
    monkeypatch.setattr(rw.core_q, "run_sql", lambda *_a, **_k: _status_row("STARTED"))
    monkeypatch.setattr(
        rw.log,
        "warning",
        lambda message, **_k: warnings.append(str(message)),
    )

    assert rw.update_static_run_status(static_run_id=8, status="COMPLETED") is False
    assert any("STATE_MISMATCH" in msg and "STARTED" in msg for msg in warnings)


@pytest.mark.unit
def test_failed_update_lookup_exception_is_failure(monkeypatch) -> None:
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_a, **_k: 0)

    def _boom(*_a, **_k):
        raise RuntimeError("select failed")

    monkeypatch.setattr(rw.core_q, "run_sql", _boom)

    assert rw.update_static_run_status(static_run_id=9, status="FAILED") is False


@pytest.mark.unit
def test_finalize_idempotent_completed_does_not_add_db_write_failed(monkeypatch) -> None:
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_a, **_k: 0)
    monkeypatch.setattr(rw.core_q, "run_sql", lambda *_a, **_k: _status_row("COMPLETED"))
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.finalization_flow.maybe_refresh_static_analysis_session_summary",
        lambda *_a, **_k: None,
    )

    outcome = PersistenceOutcome(static_run_id=7356, persisted_findings=21)
    callbacks = StaticRunFinalizationCallbacks(
        run_sql=lambda *_a, **_k: None,
        export_dep_json=lambda *_a, **_k: None,
        maybe_set_canonical_static_run=lambda **_k: None,
        update_static_run_metadata=lambda *_a, **_k: None,
        update_static_run_status=rw.update_static_run_status,
        normalize_run_status=lambda status: str(status or "").upper(),
    )

    status = finalize_persisted_static_run(
        static_run_id=7356,
        dry_run=False,
        package_for_run="ai.x.grok",
        session_stamp="20260919-all-full",
        scope_label="All harvested apps",
        run_package="ai.x.grok",
        run_status="COMPLETED",
        paper_grade_requested=False,
        canonical_action=None,
        persistence_failed=False,
        outcome=outcome,
        ended_at_utc=None,
        abort_reason=None,
        abort_signal=None,
        callbacks=callbacks,
    )

    assert status == "COMPLETED"
    assert outcome.success is True
    assert outcome.canonical_failed is False
    assert outcome.errors == []
    assert not any("db_write_failed:static_run.status_update" in err for err in outcome.errors)


@pytest.mark.unit
def test_finalize_real_status_write_failure_still_records_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.finalization_flow.maybe_refresh_static_analysis_session_summary",
        lambda *_a, **_k: None,
    )
    outcome = PersistenceOutcome(static_run_id=101)
    callbacks = StaticRunFinalizationCallbacks(
        run_sql=lambda *_a, **_k: None,
        export_dep_json=lambda *_a, **_k: None,
        maybe_set_canonical_static_run=lambda **_k: None,
        update_static_run_metadata=lambda *_a, **_k: None,
        update_static_run_status=lambda **_k: False,
        normalize_run_status=lambda status: str(status or "").upper(),
    )

    status = finalize_persisted_static_run(
        static_run_id=101,
        dry_run=False,
        package_for_run="com.example",
        session_stamp="sess-1",
        scope_label="com.example",
        run_package="com.example",
        run_status="COMPLETED",
        paper_grade_requested=False,
        canonical_action=None,
        persistence_failed=False,
        outcome=outcome,
        ended_at_utc=None,
        abort_reason=None,
        abort_signal=None,
        callbacks=callbacks,
    )

    assert status == "FAILED"
    assert outcome.success is False
    assert outcome.canonical_failed is True
    assert outcome.errors == ["db_write_failed:static_run.status_update:static_run_id=101"]
