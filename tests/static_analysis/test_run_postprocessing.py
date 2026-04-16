from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows.postprocessing import build_linkage_plan


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

