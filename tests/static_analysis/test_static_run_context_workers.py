from __future__ import annotations

from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext, build_static_run_context
from scytaledroid.StaticAnalysis.cli.core.run_specs import StaticRunSpec


def test_build_static_run_context_resolves_worker_budget() -> None:
    spec = StaticRunSpec(
        selection=ScopeSelection(scope="all", label="x", groups=()),
        params=RunParameters(profile="full", scope="all", scope_label="x", workers="4"),
        base_dir=Path("."),
    )
    ctx = build_static_run_context(spec)
    assert ctx.resolved_worker_count == 4


def test_static_run_context_defaults_worker_budget_to_none() -> None:
    ctx = StaticRunContext(
        run_mode="interactive",
        quiet=False,
        batch=False,
        noninteractive=False,
        show_splits=False,
        session_stamp=None,
        persistence_ready=True,
        paper_grade_requested=True,
    )
    assert ctx.resolved_worker_count is None
