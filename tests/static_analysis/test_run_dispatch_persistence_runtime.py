from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.core.run_specs import StaticRunSpec
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch
from scytaledroid.StaticAnalysis.cli.flows import session_finalizer


@pytest.fixture(autouse=True)
def _isolate_static_run_lock(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(run_dispatch, "_acquire_static_run_lock", lambda *_a, **_k: tmp_path / "static_analysis.lock")
    monkeypatch.setattr(run_dispatch, "_release_static_run_lock", lambda *_a, **_k: None)


def test_launch_scan_flow_dry_run_skips_runtime_persistence(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="app", label="Example", groups=tuple()),
        base_dir=Path("."),
    )

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_postprocessing_step", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)

    def _unexpected_bootstrap(**_kwargs):
        raise AssertionError("dry-run must not bootstrap runtime persistence")

    def _unexpected_refresh(**_kwargs):
        raise AssertionError("dry-run must not refresh runtime persistence views")

    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", _unexpected_bootstrap)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", _unexpected_refresh)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: False)

    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="Example",
        session_stamp="sess-dry",
        dry_run=True,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="app", label="Example", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))


def test_launch_scan_flow_announces_postprocessing_boundary(monkeypatch, capsys) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_postprocessing_step", lambda *_a, **_k: None)

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-postprocessing",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    out = capsys.readouterr().out
    assert "Scan complete. Persisting findings/risk/session outputs now..." in out


def test_launch_scan_flow_updates_heartbeat_phases(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    phases: list[tuple[str, str | None, bool]] = []

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: type("PostSummary", (), {"permission_refresh_error": None})(),
    )
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_hb_set_run", lambda session_stamp, phase="scan": phases.append(("run", session_stamp, phase == "scan")))
    monkeypatch.setattr(
        run_dispatch,
        "_hb_set_phase",
        lambda phase, keep_app=True: phases.append((phase, None, keep_app)),
    )

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-heartbeat",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    phase_names = [row[0] for row in phases]
    assert phase_names[0] == "run"
    assert "persist_summary" in phase_names
    assert "postprocess" in phase_names
    assert "refresh_views" in phase_names
    assert phase_names[-1] == "completed"


def test_launch_scan_flow_emits_phase_logs(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: type("PostSummary", (), {"permission_refresh_error": None})(),
    )
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-phase-log",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

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
    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(
        run_dispatch,
        "_acquire_static_run_lock",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("Another static analysis run is already active.")),
    )

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-lock",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    outcome = run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert outcome is None
    out = capsys.readouterr().out
    assert "Another static analysis run is already active." in out


def test_launch_scan_flow_sigint_marks_aborting_and_logs_abort_event(monkeypatch, capsys) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
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

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", _execute_scan)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_postprocessing_step", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())
    monkeypatch.setattr(run_dispatch.signal, "getsignal", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.signal, "signal", _signal)
    monkeypatch.setattr(run_dispatch, "_hb_set_phase", lambda phase, keep_app=True: phases.append(phase))

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-sigint",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

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
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    records: list[dict[str, object]] = []
    phases: list[str] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    class _PostSummary:
        permission_refresh_error = None

    def _render_results(*_args, **_kwargs):
        outcome.persistence_failed = True
        outcome.failures.append("PERSISTENCE_ERROR")

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", _render_results)
    monkeypatch.setattr(run_dispatch, "run_post_summary_postprocessing", lambda **_k: _PostSummary())
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_postprocessing_step", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())
    monkeypatch.setattr(run_dispatch, "_hb_set_phase", lambda phase, keep_app=True: phases.append(phase))

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-run-end-failed",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    run_end = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_END]
    assert run_end
    assert run_end[-1]["status"] == "failed"
    assert run_end[-1]["persistence_failed"] is True
    assert "PERSISTENCE_ERROR" in run_end[-1]["failure_codes"]


def test_launch_scan_flow_emits_persist_end_for_deferred_footer(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: type("PostSummary", (), {"permission_refresh_error": None, "linkage_blocked_reason": None, "run_map_built": False})(),
    )
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_session_finalization_issues", lambda **_k: [])
    monkeypatch.setattr(run_dispatch.logging_engine, "get_static_logger", lambda: _Logger())
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-persist-end",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    persist_end = [record for record in records if record.get("event") == run_dispatch.log_events.PERSIST_END]
    assert persist_end
    assert persist_end[-1]["status"] == "completed"
    event_order = [record.get("event") for record in records]
    assert event_order.index(run_dispatch.log_events.PERSIST_END) < event_order.index(run_dispatch.log_events.RUN_END)


def test_launch_scan_flow_marks_run_failed_when_session_finalization_is_incomplete(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=7)],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    records: list[dict[str, object]] = []

    class _Logger:
        def info(self, _message, *, extra=None):
            records.append(dict(extra or {}))

        def warning(self, _message, *, extra=None):
            records.append(dict(extra or {}))

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: True)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: type("PostSummary", (), {"permission_refresh_error": None, "linkage_blocked_reason": None, "run_map_built": True})(),
    )
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_session_finalization_issues", lambda **_k: ["run_map_missing", "session_links_missing"])
    monkeypatch.setattr(run_dispatch.logging_engine, "get_static_logger", lambda: _Logger())
    monkeypatch.setattr(run_dispatch, "get_run_logger", lambda *_a, **_k: _Logger())

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-finalization-failed",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    run_end = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_END]
    assert run_end
    assert run_end[-1]["status"] == "failed"
    assert "run_map_missing" in run_end[-1]["failure_codes"]
    assert "session_links_missing" in run_end[-1]["failure_codes"]
    phase_events = [record for record in records if record.get("event") == run_dispatch.log_events.RUN_PHASE]
    assert any(record.get("phase") == "failed" and record.get("status") == "failed" for record in phase_events)


def test_persist_static_session_links_normalizes_package_name() -> None:
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


def test_session_finalization_outputs_flags_incomplete_link_coverage(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))
    session_dir = tmp_path / "sessions" / "sess-links"
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "run_map.json").write_text('{"apps": []}', encoding="utf-8")

    monkeypatch.setattr(run_dispatch, "_session_completed_run_count", lambda _stamp: 120)
    counts = iter([30, 30])
    monkeypatch.setattr(run_dispatch, "_session_run_link_count", lambda _stamp: next(counts))
    monkeypatch.setattr(run_dispatch, "_rebuild_session_run_map_from_db", lambda _stamp: None)

    issues = run_dispatch._ensure_session_finalization_outputs("sess-links")

    assert "session_links_incomplete" in issues


def test_execute_run_spec_detailed_uses_session_cache_finalizer(monkeypatch) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

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
        selection=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        params=RunParameters(
            profile="full",
            scope="all",
            scope_label="All apps",
            session_stamp="sess-cache",
            dry_run=False,
            persistence_ready=True,
            permission_snapshot_refresh=False,
            paper_grade_requested=False,
        ),
        base_dir=Path("."),
        run_mode="interactive",
        quiet=True,
        noninteractive=False,
    )

    result = run_dispatch.execute_run_spec_detailed(spec)

    assert result.completed is True
    assert cache_calls == ["called"]
