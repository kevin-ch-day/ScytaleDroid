from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.menus import menu_overview as menu_views


def test_build_dynamic_menu_sections_uses_active_research_cohort_label(monkeypatch) -> None:
    sections = menu_views.build_dynamic_menu_sections()

    assert sections.primary_actions[0].key == "1"
    assert sections.primary_actions[0].label == "Current-build collection queue"
    assert sections.primary_actions[1].key == "2"
    assert sections.primary_actions[1].label == "Paper-freeze readiness"
    assert sections.primary_actions[2].key == "3"
    assert sections.primary_actions[2].label == "Focused app workbench"
    assert sections.validation[0].key == "4"
    assert sections.validation[0].label == "Verify capture environment"
    assert sections.validation[1].key == "5"
    assert sections.validation[1].label == "State summary"
    assert sections.validation[2].key == "6"
    assert sections.validation[2].label == "Archive readiness"
    assert sections.validation[3].key == "7"
    assert sections.validation[3].label == "Change cohort"
    assert sections.maintenance[0].key == "8"
    assert sections.maintenance[0].label == "Maintenance / Advanced"


def test_render_dynamic_menu_overview_shows_quota_progress_without_dataset_focus(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(menu_views, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        menu_views.device_manager,
        "describe_active_device",
        lambda: "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical",
    )
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
    monkeypatch.setattr(
        menu_views,
        "resolve_active_cohort_evidence_quota_summary",
        lambda: {"quota_runs_counted": 1, "extra_eligible_runs": 0},
    )

    menu_views.render_dynamic_menu_overview()

    out = capsys.readouterr().out
    assert "Research Dataset Beta" in out
    assert "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical" in out
    assert "Archive" in out
    assert "blocked" in out
    assert "Archive quota" not in out
    assert "Why blocked" not in out
    assert "Supplemental" not in out
    assert "ready (12/12 plans)" in out
    assert "Device" in out
    assert "Evidence" in out
    assert "1 packs / 1 valid" in out
    assert "Next:" not in out


def test_render_dynamic_menu_overview_surfaces_retained_extra_valid_runs(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(menu_views, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(menu_views.device_manager, "describe_active_device", lambda: "None")
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
    monkeypatch.setattr(
        menu_views,
        "resolve_active_cohort_evidence_quota_summary",
        lambda: {"quota_runs_counted": 15, "extra_eligible_runs": 3},
    )

    menu_views.render_dynamic_menu_overview()

    out = capsys.readouterr().out
    assert "Evidence" in out
    assert "none selected" in out
    assert "19 packs / 18 valid" in out
    assert "Archive quota" not in out
    assert "Retained extra" not in out
    assert "Current Device:" not in out
    assert "Remaining quota-valid runs" in out
    assert "65" in out
    assert "Archive readiness is blocked." not in out
    assert "Next:" not in out
