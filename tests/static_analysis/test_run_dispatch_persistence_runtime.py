from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


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

