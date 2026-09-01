from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import run_writers as rw


def test_update_static_run_status_sets_default_abort_for_failed(monkeypatch) -> None:
    batches: list[tuple[object, ...]] = []

    def _capture(sql: object, params: tuple[object, ...], **_kwargs: object) -> int:
        batches.append(params)
        return 1

    monkeypatch.setattr(rw, "run_sql_rowcount", _capture)

    assert rw.update_static_run_status(
        static_run_id=42, status="FAILED", abort_reason=None, abort_signal=None
    ) is True
    assert batches
    canonical, _ended, abort_reason, abort_signal, sid = batches[0]
    assert canonical == "FAILED"
    assert abort_reason == "unspecified_failure"
    assert abort_signal is None
    assert sid == 42


def test_update_static_run_status_keeps_explicit_abort(monkeypatch) -> None:
    batches: list[tuple[object, ...]] = []

    def _capture(_sql: object, params: tuple[object, ...], **_kwargs: object) -> int:
        batches.append(params)
        return 1

    monkeypatch.setattr(rw, "run_sql_rowcount", _capture)

    rw.update_static_run_status(static_run_id=99, status="FAILED", abort_reason="persist_error")
    assert batches[0][2] == "persist_error"


def test_update_static_run_status_completed_does_not_force_abort(monkeypatch) -> None:
    batches: list[tuple[object, ...]] = []

    def _capture(_sql: object, params: tuple[object, ...], **_kwargs: object) -> int:
        batches.append(params)
        return 1

    monkeypatch.setattr(rw, "run_sql_rowcount", _capture)

    rw.update_static_run_status(static_run_id=7, status="COMPLETED", abort_reason=None)
    assert batches[0][2] is None


def test_update_static_run_status_reports_write_failure(monkeypatch) -> None:
    def _fail(_sql: object, _params: tuple[object, ...], **_kwargs: object) -> int:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(rw, "run_sql_rowcount", _fail)

    assert rw.update_static_run_status(static_run_id=7, status="COMPLETED") is False


def test_update_static_run_status_rejects_missing_row(monkeypatch) -> None:
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_args, **_kwargs: 0)

    assert rw.update_static_run_status(static_run_id=404, status="COMPLETED") is False
