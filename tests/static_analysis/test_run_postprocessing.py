from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import postprocessing
from scytaledroid.StaticAnalysis.cli.flows.postprocessing import build_linkage_plan
from scytaledroid.StaticAnalysis.cli.flows.session_finalizer import finalize_session_run_map


def _make_outcome(*results: AppRunResult) -> RunOutcome:
    now = datetime.now(UTC)
    return RunOutcome(
        results=list(results),
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )


def test_build_linkage_plan_blocks_on_summary_render_failure() -> None:
    outcome = _make_outcome(AppRunResult(package_name="com.example.app", category="Test", static_run_id=7))

    plan = build_linkage_plan(
        outcome,
        persistence_ready=True,
        summary_render_failed=True,
    )

    assert plan.blocked_reason == "Run summary finalization failed; skipping run_map and permission refresh."
    assert plan.missing_id_packages == ()


def test_build_linkage_plan_blocks_when_persistence_not_ready() -> None:
    outcome = _make_outcome(AppRunResult(package_name="com.example.app", category="Test", static_run_id=7))

    plan = build_linkage_plan(
        outcome,
        persistence_ready=False,
        summary_render_failed=False,
    )

    assert plan.blocked_reason == "Persistence gate failed; skipping run_map and permission refresh."


def test_build_linkage_plan_collects_missing_static_run_ids() -> None:
    outcome = _make_outcome(
        AppRunResult(package_name="com.ok", category="Test", static_run_id=7),
        AppRunResult(package_name="com.missing", category="Test", static_run_id=None),
    )

    plan = build_linkage_plan(
        outcome,
        persistence_ready=True,
        summary_render_failed=False,
    )

    assert plan.blocked_reason == (
        "static_run_id missing for one or more apps; skipping run_map and permission refresh."
    )
    assert plan.missing_id_packages == ("com.missing",)


def test_build_linkage_plan_blocks_when_run_interrupted() -> None:
    outcome = _make_outcome(AppRunResult(package_name="com.example.app", category="Test", static_run_id=7))
    outcome.aborted = True
    outcome.abort_reason = "SIGINT"
    outcome.abort_signal = "SIGINT"

    plan = build_linkage_plan(
        outcome,
        persistence_ready=True,
        summary_render_failed=False,
    )

    assert plan.blocked_reason == "Run interrupted; skipping run_map and permission refresh."
    assert plan.missing_id_packages == ()


def test_finalize_session_run_map_builds_validates_and_persists() -> None:
    calls: list[str] = []

    result = finalize_session_run_map(
        _make_outcome(AppRunResult(package_name="com.example.app", category="Test", static_run_id=7)),
        "sess-1",
        allow_overwrite=False,
        required_fields=("pipeline_version",),
        build_session_run_map=lambda *_a, **_k: {
            "apps": [
                {
                    "package": "com.example.app",
                    "static_run_id": 7,
                    "pipeline_version": "2.0.0-alpha",
                }
            ]
        },
        validate_run_map=lambda *_a, **_k: calls.append("validate"),
        persist_session_run_links_cb=lambda *_a, **_k: calls.append("persist"),
    )

    assert result.run_map is not None
    assert calls == ["validate", "persist"]


def test_run_post_summary_postprocessing_uses_session_finalizer(monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(
        postprocessing,
        "finalize_session_run_map",
        lambda *_a, **_k: calls.append("finalize") or type("Result", (), {"run_map": None})(),
    )

    outcome = _make_outcome(AppRunResult(package_name="com.example.app", category="Test", static_run_id=7))
    params = type(
        "Params",
        (),
        {
            "persistence_ready": True,
            "session_stamp": "sess-1",
            "run_map_overwrite": False,
            "strict_persistence": False,
            "permission_snapshot_refresh": False,
            "profile": "full",
        },
    )()
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())
    run_ctx = type("RunCtx", (), {})()

    postprocessing.run_post_summary_postprocessing(
        outcome=outcome,
        params=params,
        selection=selection,
        run_ctx=run_ctx,
        summary_render_failed=False,
        required_fields=("pipeline_version",),
        emit_postprocessing_step=lambda *_a, **_k: None,
        build_session_run_map=lambda *_a, **_k: None,
        validate_run_map=lambda *_a, **_k: None,
        persist_session_run_links=lambda *_a, **_k: None,
        emit_missing_run_ids_artifact=lambda **_k: None,
        execute_permission_scan=lambda *_a, **_k: None,
    )

    assert calls == ["finalize"]
