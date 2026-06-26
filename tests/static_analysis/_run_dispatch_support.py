from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


def make_outcome(
    *,
    results: list[AppRunResult] | None = None,
    scope: str = "all",
    label: str = "All apps",
    aborted: bool = False,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
    base_dir: Path | None = None,
) -> RunOutcome:
    now = datetime.now(UTC)
    return RunOutcome(
        results=results or [],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope=scope, label=label, groups=tuple()),
        base_dir=base_dir or Path("."),
        aborted=aborted,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )


def make_params(
    *,
    profile: str = "full",
    scope: str = "all",
    scope_label: str = "All apps",
    session_stamp: str = "sess-test",
    dry_run: bool = False,
    persistence_ready: bool = True,
    permission_snapshot_refresh: bool = False,
    strict_persistence: bool = False,
    paper_grade_requested: bool = False,
    session_label: str | None = None,
) -> RunParameters:
    return RunParameters(
        profile=profile,
        scope=scope,
        scope_label=scope_label,
        session_stamp=session_stamp,
        session_label=session_label,
        dry_run=dry_run,
        persistence_ready=persistence_ready,
        permission_snapshot_refresh=permission_snapshot_refresh,
        strict_persistence=strict_persistence,
        paper_grade_requested=paper_grade_requested,
    )


def make_selection(*, scope: str = "all", label: str = "All apps") -> ScopeSelection:
    return ScopeSelection(scope=scope, label=label, groups=tuple())


def make_post_summary(
    *,
    permission_refresh_error=None,
    linkage_blocked_reason=None,
    run_map_built: bool = False,
):
    return SimpleNamespace(
        permission_refresh_error=permission_refresh_error,
        linkage_blocked_reason=linkage_blocked_reason,
        run_map_built=run_map_built,
    )


def patch_static_run_lock(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(run_dispatch, "_acquire_static_run_lock", lambda *_a, **_k: tmp_path / "static_analysis.lock")
    monkeypatch.setattr(run_dispatch, "_release_static_run_lock", lambda *_a, **_k: None)


def patch_launch_scan_flow_defaults(
    monkeypatch,
    *,
    outcome: RunOutcome,
    persistence_enabled: bool = True,
) -> None:
    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok", ""))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: None)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "persistence_enabled", lambda **_k: persistence_enabled)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_static_run_preflight_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_postprocessing_step", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_build_session_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "validate_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_session_run_links", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_session_finalization_issues", lambda **_k: [])


def patch_execute_run_spec_defaults(monkeypatch, *, params: RunParameters, launch_result=object()) -> None:
    monkeypatch.setattr(run_dispatch.output_prefs, "snapshot", lambda: {})
    monkeypatch.setattr(run_dispatch.output_prefs, "get_run_context", lambda: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "set_quiet", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "set_batch", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "set_run_mode", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "set_noninteractive", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "set_show_splits", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "set_run_context", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch.output_prefs, "restore", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_resolve_effective_run_params", lambda *_a, **_k: (params, None))
    monkeypatch.setattr(run_dispatch, "_launch_scan_flow_resolved", lambda *_a, **_k: launch_result)
