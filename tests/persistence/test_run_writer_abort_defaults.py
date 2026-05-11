from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import run_writers as rw


def test_update_static_run_status_sets_default_abort_for_failed(monkeypatch) -> None:
    batches: list[tuple[object, ...]] = []

    def _capture(sql: object, params: tuple[object, ...]) -> None:
        batches.append(params)

    monkeypatch.setattr(rw, "run_sql_write", _capture)

    rw.update_static_run_status(static_run_id=42, status="FAILED", abort_reason=None, abort_signal=None)
    assert batches
    canonical, _ended, abort_reason, abort_signal, sid = batches[0]
    assert canonical == "FAILED"
    assert abort_reason == "unspecified_failure"
    assert abort_signal is None
    assert sid == 42


def test_update_static_run_status_keeps_explicit_abort(monkeypatch) -> None:
    batches: list[tuple[object, ...]] = []

    monkeypatch.setattr(rw, "run_sql_write", lambda _sql, params: batches.append(params))

    rw.update_static_run_status(static_run_id=99, status="FAILED", abort_reason="persist_error")
    assert batches[0][2] == "persist_error"


def test_update_static_run_status_completed_does_not_force_abort(monkeypatch) -> None:
    batches: list[tuple[object, ...]] = []

    monkeypatch.setattr(rw, "run_sql_write", lambda _sql, params: batches.append(params))

    rw.update_static_run_status(static_run_id=7, status="COMPLETED", abort_reason=None)
    assert batches[0][2] is None
