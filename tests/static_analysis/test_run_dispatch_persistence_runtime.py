from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult
from scytaledroid.StaticAnalysis.cli.core.run_specs import StaticRunSpec
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch
from scytaledroid.StaticAnalysis.cli.flows import session_finalizer
from tests.static_analysis._run_dispatch_support import (
    make_outcome,
    make_params,
    make_post_summary,
    make_selection,
    patch_launch_scan_flow_defaults,
    patch_static_run_lock,
)


@pytest.fixture(autouse=True)
def _isolate_static_run_lock(monkeypatch, tmp_path) -> None:
    patch_static_run_lock(monkeypatch, tmp_path)


def test_launch_scan_flow_dry_run_skips_runtime_persistence(monkeypatch) -> None:
    outcome = make_outcome(scope="app", label="Example")
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome, persistence_enabled=False)

    def _unexpected_bootstrap(**_kwargs):
        raise AssertionError("dry-run must not bootstrap runtime persistence")

    def _unexpected_refresh(**_kwargs):
        raise AssertionError("dry-run must not refresh runtime persistence views")

    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", _unexpected_bootstrap)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", _unexpected_refresh)
    params = make_params(scope="app", scope_label="Example", session_stamp="sess-dry", dry_run=True)
    selection = make_selection(scope="app", label="Example")

    run_dispatch.launch_scan_flow(selection, params, Path("."))


def test_launch_scan_flow_announces_postprocessing_boundary(monkeypatch, capsys) -> None:
    outcome = make_outcome()
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-postprocessing")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    out = capsys.readouterr().out
    assert "Scan complete. Persisting findings/risk/session outputs now..." in out


def test_launch_scan_flow_updates_heartbeat_phases(monkeypatch) -> None:
    outcome = make_outcome()

    phases: list[tuple[str, str | None, bool]] = []

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: make_post_summary(),
    )
    monkeypatch.setattr(run_dispatch, "_hb_set_run", lambda session_stamp, phase="scan": phases.append(("run", session_stamp, phase == "scan")))
    monkeypatch.setattr(
        run_dispatch,
        "_hb_set_phase",
        lambda phase, keep_app=True: phases.append((phase, None, keep_app)),
    )

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-heartbeat")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    phase_names = [row[0] for row in phases]
    assert phase_names[0] == "run"
    assert "persist_summary" in phase_names
    assert "postprocess" in phase_names
    assert "refresh_views" in phase_names
    assert phase_names[-1] == "completed"


def test_launch_scan_flow_emits_phase_logs(monkeypatch) -> None:
    outcome = make_outcome()

    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: make_post_summary(),
    )
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-phase-log")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    phase_names = [
        str(record.get("phase"))
        for record in records
        if record.get("event") == run_dispatch.log_events.RUN_PHASE
    ]
    assert "scan" in phase_names
    assert "persist_summary" in phase_names
    assert "postprocess" in phase_names
    assert "refresh_views" in phase_names
    assert phase_names[-1] == "completed"
    assert all(record.get("execution_id") == params.execution_id for record in records)


def test_launch_scan_flow_blocks_when_another_static_run_is_active(monkeypatch, capsys) -> None:
    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok", ""))
    monkeypatch.setattr(
        run_dispatch,
        "_acquire_static_run_lock",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("Another static analysis run is already active.")),
    )

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-lock")
    selection = make_selection(scope="all", label="All apps")

    outcome = run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert outcome is None
    out = capsys.readouterr().out
    assert "Another static analysis run is already active." in out


def test_launch_scan_flow_sigint_marks_aborting_and_logs_abort_event(monkeypatch, capsys) -> None:
    outcome = make_outcome(
        aborted=True,
        abort_reason="SIGINT",
        abort_signal="SIGINT",
    )

    records: list[dict[str, object]] = []
    phases: list[str] = []
    installed: dict[str, object] = {}

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    def _signal(sig, handler):
        installed["handler"] = handler

    def _execute_scan(*_args, **_kwargs):
        handler = installed.get("handler")
        assert callable(handler)
        handler(run_dispatch.signal.SIGINT, None)
        return outcome

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(run_dispatch, "execute_scan", _execute_scan)
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())
    monkeypatch.setattr(run_dispatch.signal, "getsignal", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.signal, "signal", _signal)
    monkeypatch.setattr(run_dispatch, "_hb_set_phase", lambda phase, keep_app=True: phases.append(phase))

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-sigint")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    out = capsys.readouterr().out
    assert "Interrupt received — stopping safely…" in out
    assert "Safe stop requested. Current artifact will finish/abort, then partial persistence will run." in out
    assert "aborting" in phases
    abort_events = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_ABORT_REQUESTED]
    assert abort_events
    assert abort_events[-1]["abort_signal"] == "SIGINT"
    phase_events = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_PHASE]
    assert any(record.get("phase") == "aborting" and record.get("status") == "requested" for record in phase_events)


def test_launch_scan_flow_run_end_uses_postprocessing_failure_status(monkeypatch) -> None:
    outcome = make_outcome()

    records: list[dict[str, object]] = []
    phases: list[str] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    def _render_results(*_args, **_kwargs):
        outcome.persistence_failed = True
        outcome.failures.append("PERSISTENCE_ERROR")

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", _render_results)
    monkeypatch.setattr(run_dispatch, "run_post_summary_postprocessing", lambda **_k: make_post_summary())
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())
    monkeypatch.setattr(run_dispatch, "_hb_set_phase", lambda phase, keep_app=True: phases.append(phase))

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-run-end-failed")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    run_end = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_END]
    assert run_end
    assert run_end[-1]["status"] == "failed"
    assert run_end[-1]["persistence_failed"] is True
    assert "PERSISTENCE_ERROR" in run_end[-1]["failure_codes"]


def test_launch_scan_flow_emits_persist_end_for_deferred_footer(monkeypatch) -> None:
    outcome = make_outcome()

    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: make_post_summary(run_map_built=False),
    )
    monkeypatch.setattr(run_dispatch, "_session_finalization_issues", lambda **_k: [])
    monkeypatch.setattr(run_dispatch.logging_engine, "get_static_logger", lambda: _Logger())
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-persist-end")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    persist_end = [record for record in records if record.get("event") == run_dispatch.log_events.PERSIST_END]
    assert persist_end
    assert persist_end[-1]["status"] == "completed"
    event_order = [record.get("event") for record in records]
    assert event_order.index(run_dispatch.log_events.PERSIST_END) < event_order.index(run_dispatch.log_events.RUN_END)


def test_launch_scan_flow_marks_run_failed_when_session_finalization_is_incomplete(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=7)],
    )

    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: make_post_summary(run_map_built=True),
    )
    monkeypatch.setattr(run_dispatch, "_session_finalization_issues", lambda **_k: ["run_map_missing", "session_links_missing"])
    monkeypatch.setattr(run_dispatch.logging_engine, "get_static_logger", lambda: _Logger())
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-finalization-failed")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    run_end = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_END]
    assert run_end
    assert run_end[-1]["status"] == "failed"
    assert "run_map_missing" in run_end[-1]["failure_codes"]
    assert "session_links_missing" in run_end[-1]["failure_codes"]
    phase_events = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_PHASE]
    assert any(record.get("phase") == "failed" and record.get("status") == "failed" for record in phase_events)


def test_persist_static_session_links_normalizes_package_name(monkeypatch) -> None:
    refresh_calls: list[str | None] = []

    def _track_refresh(stamp: str | None) -> None:
        refresh_calls.append(stamp)

    monkeypatch.setattr(session_finalizer, "refresh_session_summaries_after_link_writes", _track_refresh)

    writes: list[tuple[str, tuple[object, ...] | None]] = []

    def _run_sql(query, params=None, **kwargs):
        normalized = " ".join(str(query).split())
        if normalized.startswith("SELECT id FROM static_analysis_runs WHERE id IN"):
            return [(77,)]
        writes.append((normalized, params))
        return None

    result = session_finalizer.persist_static_session_links(
        "sess-links",
        {
            "apps": [
                {
                    "package": "mnn.Android",
                    "static_run_id": 77,
                    "run_origin": "created",
                    "origin_session_stamp": "sess-links",
                    "identity_valid": True,
                }
            ]
        },
        run_sql=_run_sql,
        get_table_columns=lambda _table: ["session_stamp", "package_name", "static_run_id", "run_origin"],
    )

    assert result.links_written == 1
    insert_sql, insert_params = writes[-1]
    assert "INSERT INTO static_session_run_links" in insert_sql
    assert refresh_calls == ["sess-links"]


def test_session_finalization_outputs_flags_incomplete_link_coverage(monkeypatch, tmp_path) -> None:
    from scytaledroid.StaticAnalysis.cli.flows import run_session_map

    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))
    session_dir = tmp_path / "sessions" / "sess-links"
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "run_map.json").write_text('{"apps": []}', encoding="utf-8")

    monkeypatch.setattr(run_session_map, "_session_completed_run_count", lambda _stamp: 120)
    counts = iter([30, 30])
    monkeypatch.setattr(run_session_map, "_session_run_link_count", lambda _stamp: next(counts))
    monkeypatch.setattr(run_session_map, "_rebuild_session_run_map_from_db", lambda _stamp: None)

    issues = run_dispatch._ensure_session_finalization_outputs("sess-links")

    assert "session_links_incomplete" in issues


def test_execute_run_spec_detailed_uses_session_cache_finalizer(monkeypatch) -> None:
    outcome = make_outcome()

    cache_calls: list[str] = []

    monkeypatch.setattr(run_dispatch, "_resolve_effective_run_params", lambda *args, **kwargs: (args[0], None))
    monkeypatch.setattr(run_dispatch, "_launch_scan_flow_resolved", lambda *_a, **_k: outcome)
    monkeypatch.setattr(
        run_dispatch,
        "refresh_static_session_cache",
        lambda **_k: cache_calls.append("called") or session_finalizer.SessionFinalizationResult(
            cache_rows=12,
            cache_materialized_at="2026-04-28T12:00:00Z",
        ),
    )

    spec = StaticRunSpec(
        selection=make_selection(scope="all", label="All apps"),
        params=make_params(
            scope="all",
            scope_label="All apps",
            session_stamp="sess-cache",
        ),
        base_dir=Path("."),
        run_mode="interactive",
        quiet=True,
        noninteractive=False,
    )

    result = run_dispatch.execute_run_spec_detailed(spec)

    assert result.completed is True
    assert cache_calls == ["called"]
