from __future__ import annotations

from scytaledroid.DynamicAnalysis import menu_reports


def test_render_cohort_status_details_includes_historical_context(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_details(
        dataset_apps_total=16,
        dataset_apps_complete=0,
        dataset_valid_runs_total=12,
        historical_valid_runs_total=3,
        historical_build_count_total=2,
        mixed_identity_app_count=1,
        legacy_only_app_count=0,
        expected_runs=80,
        evidence_summary={
            "apps_satisfied": 0,
            "quota_runs_counted": 12,
            "paper_eligible_runs": 17,
            "extra_eligible_runs": 5,
            "excluded_runs": 2,
        },
    )

    out = capsys.readouterr().out
    assert "Historical context (informational)" in out
    assert "Mixed apps      : 1" in out
    assert "Legacy-only apps: 0" in out
    assert "Legacy valid    : 3" in out
    assert "Older builds    : 2" in out


def test_render_cohort_status_help_mentions_supplemental_and_historical(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_help()

    out = capsys.readouterr().out
    assert "Supplemental runs" in out
    assert "Historical context" in out
