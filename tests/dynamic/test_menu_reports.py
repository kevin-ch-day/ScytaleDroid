from __future__ import annotations

import os
from types import SimpleNamespace

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
        row_models=[
            SimpleNamespace(need_baseline=3, need_interactive=2),
            SimpleNamespace(need_baseline=0, need_interactive=2),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    out = capsys.readouterr().out
    assert "Progress" in out
    assert "Quota-valid remaining : 68" in out
    assert "Baseline runs needed  : 3" in out
    assert "Manual runs needed    : 4" in out
    assert "Evidence-authoritative quota" in out
    assert "Quota-valid runs      : 12 / 80" in out
    assert "Tracker-scoped latest-run state" in out
    assert "Historical context" in out
    assert "Mixed apps            : 1" in out
    assert "Legacy valid runs     : 3" in out
    assert "Meaning" in out
    assert "Evidence-authoritative quota drives archive/freeze readiness." in out
    assert "Tracker-scoped latest-run state describes active-build queue posture." in out


def test_render_cohort_status_help_mentions_supplemental_and_historical(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_help()

    out = capsys.readouterr().out
    assert "locked" in out
    assert "mixed" in out
    assert "valid+L" in out
    assert "+ extra" in out
    out_lc = out.lower()
    assert "evidence-authoritative quota" in out_lc
    assert "tracker-scoped latest-run state" in out_lc


def test_render_cohort_build_history_explains_extra_and_legacy(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(menu_reports.shutil, "get_terminal_size", lambda fallback=(120, 40): os.terminal_size((120, 40)))

    menu_reports.render_cohort_build_history(
        [
            SimpleNamespace(
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="mixed",
                qa_label="valid (L)",
                historical_valid_runs_count=1,
            )
        ],
        [["Facebook", "472143276 / abcdef1234", "4", "1", "1"]],
    )

    out = capsys.readouterr().out
    assert "History" in out
    assert "Build lineage and why an app looks current, mixed, or legacy" in out
    assert "Baseline" in out
    assert "Manual" in out
    assert "Build identity detail" in out
    assert "extra baseline outside quota" in out
    assert "legacy evidence" in out
    assert "present" in out
    assert "3/3 +1 extra" in out
    assert "0/2 need 2" in out


def test_render_cohort_build_history_wraps_multiple_notes(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(menu_reports.shutil, "get_terminal_size", lambda fallback=(120, 40): os.terminal_size((78, 40)))

    menu_reports.render_cohort_build_history(
        [
            SimpleNamespace(
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="mixed",
                qa_label="valid (id_mismatch) (L)",
                historical_valid_runs_count=1,
            )
        ],
        [],
    )

    out = capsys.readouterr().out
    assert "extra baseline outside" in out
    assert "quota" in out
    assert "legacy evidence" in out
    assert "present" in out
    assert "identity" in out
    assert "mismatch" in out
    assert "latest QA invalid" not in out


def test_render_cohort_status_debug_preserves_dense_view(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_debug(
        [["1", "Facebook", "3/3 complete (+1 extra)", "0/2 need 2", "2I", "manual interaction", "mixed", "3/5 need 2", "1", "valid (L)"]],
        [
            SimpleNamespace(
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                historical_valid_runs_count=1,
                historical_build_count=1,
                need_baseline=0,
                need_interactive=2,
            )
        ],
    )

    out = capsys.readouterr().out
    assert "Dense raw/debug view" in out
    assert "Full table including legacy and QA fields" not in out
    assert "tracker-scoped latest-run state" in out
    assert "Raw state extract" in out
