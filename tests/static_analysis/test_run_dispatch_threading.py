from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


def test_execute_run_spec_detailed_skips_sigint_handler_in_worker_thread(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="app", label="Example", groups=tuple()),
        base_dir=Path("."),
    )

    monkeypatch.setattr(
        run_dispatch,
        "_resolve_unique_session_stamp",
        lambda session_stamp, **_kwargs: (session_stamp, session_stamp, "first_run"),
    )
    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok", ""))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_build_session_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "configure_logging_for_cli", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_acquire_static_run_lock", lambda _params: None)
    monkeypatch.setattr(run_dispatch, "_release_static_run_lock", lambda _lock_path: None)

    def _unexpected_signal(*_args, **_kwargs):
        raise AssertionError("signal.signal must not be called from worker-thread execution")

    monkeypatch.setattr(run_dispatch.signal, "signal", _unexpected_signal)
    monkeypatch.setattr(run_dispatch.signal, "getsignal", lambda *_args, **_kwargs: None)

    spec = build_static_run_spec(
        selection=ScopeSelection(scope="app", label="Example", groups=tuple()),
        params=RunParameters(
            profile="full",
            scope="app",
            scope_label="Example",
            session_stamp="thread-safe-session",
            dry_run=False,
            permission_snapshot_refresh=False,
            paper_grade_requested=False,
        ),
        base_dir=Path("."),
        run_mode="batch",
        quiet=True,
        noninteractive=True,
    )

    captured: dict[str, object] = {}
    errors: list[BaseException] = []

    def _worker() -> None:
        try:
            captured["result"] = run_dispatch.execute_run_spec_detailed(spec)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    worker = threading.Thread(target=_worker)
    worker.start()
    worker.join()

    assert errors == []
    result = captured["result"]
    assert result.completed is True
    assert result.outcome is outcome
    assert result.params.session_stamp == "thread-safe-session"
