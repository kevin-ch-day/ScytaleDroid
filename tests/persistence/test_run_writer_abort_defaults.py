from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import run_writers as rw


def test_normalize_datetime_strips_offset_plus_z() -> None:
    assert rw._normalize_datetime_value("2026-09-18T04:44:18+00:00Z") == "2026-09-18 04:44:18"
    assert rw._normalize_datetime_value("2026-09-18T04:44:18Z") == "2026-09-18 04:44:18"


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


def test_update_static_run_status_failed_clears_is_canonical(monkeypatch) -> None:
    captured: list[str] = []

    def _capture(sql: object, _params: tuple[object, ...], **_kwargs: object) -> int:
        captured.append(str(sql))
        return 1

    monkeypatch.setattr(rw, "run_sql_rowcount", _capture)
    assert rw.update_static_run_status(static_run_id=42, status="FAILED", abort_reason="persist_error")
    assert any("is_canonical=0" in sql for sql in captured)
    assert any("<> 'COMPLETED'" in sql for sql in captured)


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


def test_update_static_run_status_completed_does_not_clear_is_canonical(monkeypatch) -> None:
    captured: list[str] = []

    def _capture(sql: object, _params: tuple[object, ...], **_kwargs: object) -> int:
        captured.append(str(sql))
        return 1

    monkeypatch.setattr(rw, "run_sql_rowcount", _capture)
    rw.update_static_run_status(static_run_id=7, status="COMPLETED")
    assert captured
    assert all("is_canonical=0" not in sql for sql in captured)


def test_update_static_run_status_reports_write_failure(monkeypatch) -> None:
    def _fail(_sql: object, _params: tuple[object, ...], **_kwargs: object) -> int:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(rw, "run_sql_rowcount", _fail)

    assert rw.update_static_run_status(static_run_id=7, status="COMPLETED") is False


def test_update_static_run_status_rejects_missing_row(monkeypatch) -> None:
    monkeypatch.setattr(rw, "run_sql_rowcount", lambda *_args, **_kwargs: 0)

    assert rw.update_static_run_status(static_run_id=404, status="COMPLETED") is False


def test_update_static_run_status_refuses_completed_demotion(monkeypatch) -> None:
    captured: list[str] = []

    def _capture(sql: object, _params: tuple[object, ...], **_kwargs: object) -> int:
        captured.append(str(sql))
        return 0

    monkeypatch.setattr(rw, "run_sql_rowcount", _capture)
    monkeypatch.setattr(rw.core_q, "run_sql", lambda *_a, **_k: ("COMPLETED",))

    assert rw.update_static_run_status(
        static_run_id=7348, status="FAILED", abort_reason="persist_error"
    ) is True
    assert any("<> 'COMPLETED'" in sql for sql in captured)
    assert any("is_canonical=0" in sql for sql in captured)


def test_finalize_open_static_runs_failed_clears_is_canonical(monkeypatch) -> None:
    captured: list[str] = []

    def _write(sql: object, _params: tuple[object, ...] = (), **_kwargs: object) -> None:
        captured.append(str(sql))

    monkeypatch.setattr(rw, "run_sql_write", _write)
    monkeypatch.setattr(rw.core_q, "run_sql", lambda *_a, **_k: (1,))
    rw.finalize_open_static_runs([9], status="FAILED", abort_reason="SIGINT")
    assert any("is_canonical=0" in sql for sql in captured)
    assert any("STARTED" in sql for sql in captured)
