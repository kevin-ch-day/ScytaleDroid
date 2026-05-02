from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution import results as results_mod
from scytaledroid.StaticAnalysis.cli.execution.results import prompt_deferred_post_run_diagnostics


@pytest.fixture
def _patch_prompt_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Utils.DisplayUtils.prompt_utils.prompt_text",
        lambda *_a, **_k: "1",
    )


def test_prompt_deferred_post_run_diagnostics_passes_render_callbacks(
    monkeypatch: pytest.MonkeyPatch,
    _patch_prompt_choice: object,
) -> None:
    captured: dict[str, object] = {}

    def _fake_menu(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(results_mod, "render_post_run_diagnostics_menu", _fake_menu)

    sel = ScopeSelection(scope="app", label="X", groups=tuple())
    outcome = RunOutcome(
        [],
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp"),
        [],
        [],
        deferred_diagnostics={
            "permission_profiles": [],
            "component_profiles": [],
            "masvs_matrix": {},
            "static_risk_rows": [],
            "secret_profiles": [],
            "finding_profiles": [],
            "trend_deltas": [],
            "persist_enabled": True,
            "compact_mode": False,
        },
    )
    params = RunParameters(profile="full", scope="app", scope_label="X", dry_run=False)

    prompt_deferred_post_run_diagnostics(outcome, params)

    assert captured
    for key in (
        "render_db_severity_table_fn",
        "render_post_run_views_fn",
        "render_db_masvs_summary_fn",
        "render_cross_app_insights_fn",
    ):
        assert key in captured, f"missing required kwarg {key}"
    assert outcome.deferred_diagnostics == {}


def test_prompt_deferred_skips_when_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_k: object) -> None:
        raise AssertionError("menu must not open in dry-run")

    monkeypatch.setattr(results_mod, "render_post_run_diagnostics_menu", _boom)

    sel = ScopeSelection(scope="app", label="X", groups=tuple())
    outcome = RunOutcome([], datetime.now(UTC), datetime.now(UTC), sel, Path("."), [], [], deferred_diagnostics={"x": 1})
    params = RunParameters(profile="full", scope="app", scope_label="X", dry_run=True)
    prompt_deferred_post_run_diagnostics(outcome, params)
    assert outcome.deferred_diagnostics
