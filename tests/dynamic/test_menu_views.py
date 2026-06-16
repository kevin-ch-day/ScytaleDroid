from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis import menu_views


def test_build_dynamic_menu_sections_uses_active_research_cohort_label(monkeypatch) -> None:
    sections = menu_views.build_dynamic_menu_sections()

    assert sections.primary_actions[0].key == "1"
    assert sections.primary_actions[0].label == "Focused app run"
    assert sections.primary_actions[1].key == "2"
    assert sections.primary_actions[1].label == "Cohort run"
    assert sections.validation[0].key == "3"
    assert sections.validation[0].label == "State summary"
    assert sections.validation[1].key == "4"
    assert sections.validation[1].label == "Archive readiness"
    assert sections.maintenance[0].key == "5"
    assert sections.maintenance[0].label == "Verify capture environment"
    assert sections.maintenance[1].key == "6"
    assert sections.maintenance[1].label == "Maintenance tools"


def test_render_dynamic_menu_overview_shows_quota_progress_without_dataset_focus(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        menu_views,
        "run_freeze_readiness_audit",
        lambda: SimpleNamespace(
            total_runs=1,
            valid_runs=1,
            quota_runs_counted=1,
            can_freeze=False,
            first_failing_reason="QUOTA_NOT_SATISFIED",
            expected_valid_runs=60,
        ),
    )
    monkeypatch.setattr(
        menu_views,
        "build_static_handoff_plan_summary",
        lambda: {
            "dataset_packages_with_plan": 12,
            "dataset_packages_total": 12,
            "ready_for_guided_dataset_run": True,
        },
    )

    menu_views.render_dynamic_menu_overview()

    out = capsys.readouterr().out
    assert "Quota-valid runs" in out
    assert "1 / 60" in out
    assert "quota not satisfied — 59 quota-valid runs remaining" in out
    assert "Supplemental valid" not in out
    assert "ready (12/12 plans)" in out
    assert "Research cohort" not in out
    assert "Next" not in out


def test_render_dynamic_menu_overview_surfaces_supplemental_valid_runs(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        menu_views,
        "run_freeze_readiness_audit",
        lambda: SimpleNamespace(
            total_runs=19,
            valid_runs=18,
            quota_runs_counted=15,
            can_freeze=False,
            first_failing_reason="QUOTA_NOT_SATISFIED",
            expected_valid_runs=80,
        ),
    )
    monkeypatch.setattr(
        menu_views,
        "build_static_handoff_plan_summary",
        lambda: {
            "dataset_packages_with_plan": 16,
            "dataset_packages_total": 16,
            "ready_for_guided_dataset_run": True,
        },
    )

    menu_views.render_dynamic_menu_overview()

    out = capsys.readouterr().out
    assert "Evidence" in out
    assert "19 packs (18 valid)" in out
    assert "Quota-valid runs" in out
    assert "15 / 80" in out
    assert "Supplemental valid" in out
    assert "3 outside quota" in out
    assert "quota not satisfied — 65 quota-valid runs remaining" in out
