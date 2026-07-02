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
        current_build_ready_count=9,
        current_build_in_progress_count=1,
        current_build_review_count=1,
        stale_app_count=2,
        current_build_db_only_count=1,
        historical_valid_runs_total=3,
        historical_build_count_total=2,
        mixed_identity_app_count=1,
        legacy_only_app_count=0,
        historical_local_only_app_count=2,
        historical_db_only_app_count=5,
        no_evidence_anywhere_count=1,
        expected_runs=80,
        evidence_summary={
            "apps_satisfied": 0,
            "quota_runs_counted": 12,
            "paper_eligible_runs": 17,
            "extra_eligible_runs": 5,
            "excluded_runs": 2,
        },
        row_models=[
            SimpleNamespace(need_baseline=3, need_interactive=2, live_build_drift=False),
            SimpleNamespace(need_baseline=0, need_interactive=2, live_build_drift=True),
        ],
        baseline_required=3,
        interactive_required=4,
    )

    out = capsys.readouterr().out
    assert "Cohort summary" in out
    assert "Quota-valid remaining: 68" in out
    assert "Static refresh needed: 1" in out
    assert "Baseline runs needed: 3" in out
    assert "Interactive needed: 4" in out
    assert "Evidence-authoritative quota" in out
    assert "Quota-valid runs: 12 / 80" in out
    assert "Tracker-scoped latest-run state" in out
    assert "Historical context" in out
    assert "Current-build complete: 9 / 16" in out
    assert "Current-build active: 1" in out
    assert "Current-build review: 1" in out
    assert "Current-build stale: 2" in out
    assert "Current-build DB-only: 1" in out
    assert "Mixed apps: 1" in out
    assert "Historical local-only: 2" in out
    assert "Historical DB-only: 5" in out
    assert "No evidence anywhere: 1" in out
    assert "Legacy valid runs: 3" in out
    assert "Meaning" in out
    assert "Evidence-authoritative quota drives archive/freeze readiness." in out
    assert "Tracker-scoped latest-run state describes active-build queue posture." in out
    assert "Current-build stale means older evidence exists" in out
    assert "Current-build DB-only means the DB knows current-build sessions" in out
    assert "Historical DB-only means older dynamic lineage exists in the DB" in out


def test_render_cohort_status_help_mentions_retained_extra_and_historical(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_help()

    out = capsys.readouterr().out
    assert "locked" in out
    assert "mixed" in out
    assert "+L" in out
    assert "3/3" in out
    assert "+1 extra" in out
    assert "Next" in out
    assert "Build" in out
    assert "db-only" in out
    assert "Status=restore + DB-only evidence" in out
    assert "refresh steps" in out
    assert "installed app build differs from the newest static plan" in out
    assert "identity mismatch" in out
    assert "baseline gap" in out
    assert "interactive gap" in out
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
                need_interactive=4,
                prep_label="mixed",
                qa_label="valid (L)",
                historical_valid_runs_count=1,
                lineage_state="historical_db_only",
                live_build_drift=False,
            )
        ],
        [["Facebook", "472143276 / abcdef1234", "4", "1", "1"]],
    )

    out = capsys.readouterr().out
    out_flat = " ".join(out.split())
    assert "Build history" in out
    assert "Build lineage and why an app looks current, mixed, or legacy" in out
    assert "Baseline" in out
    assert "Interactive" in out
    assert "Build identity detail" in out
    assert "only historical DB lineage exists" in out
    assert "exists; extra" in out
    assert "baseline retained beyond quota cap" in out_flat
    assert "legacy evidence" in out_flat
    assert "present" in out
    assert "historical DB-only evidence" in out
    assert "3/3 (+1 extra)" not in out or "4/3" in out
    assert "4/3" in out
    assert "0/4" in out


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
                need_interactive=4,
                prep_label="mixed",
                qa_label="valid (id_mismatch) (L)",
                historical_valid_runs_count=1,
                lineage_state="current_build_db_only",
                live_build_drift=False,
            )
        ],
        [],
    )

    out = capsys.readouterr().out
    out_flat = " ".join(out.split())
    assert "current-build" in out
    assert "current-build evidence" in out
    assert "missing locally" in out
    assert "extra" in out
    assert "baseline retained beyond quota cap" in out_flat
    assert "legacy evidence" in out_flat
    assert "present" in out
    assert "DB-only" in out
    assert "evidence" in out
    assert "identity" in out
    assert "mismatch" in out
    assert "latest QA invalid" not in out


def test_render_cohort_build_history_explains_stale_and_review_rows(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(menu_reports.shutil, "get_terminal_size", lambda fallback=(120, 40): os.terminal_size((120, 40)))

    menu_reports.render_cohort_build_history(
        [
            SimpleNamespace(
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=4,
                prep_label="stale",
                qa_label="valid (L)",
                historical_valid_runs_count=1,
                lineage_state="current_build_stale",
                live_build_drift=True,
            ),
            SimpleNamespace(
                display_name="CNN",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=4,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=0,
                prep_label="current",
                qa_label="invalid",
                historical_valid_runs_count=0,
                lineage_state="current_build_observed",
                live_build_drift=False,
            ),
        ],
        [],
    )

    out = capsys.readouterr().out
    assert "installed build drifted" in out
    assert "newest static" in out
    assert "plan" in out
    assert "latest current-build QA invalid" in out or ("latest current-build QA" in out and "invalid" in out)


def test_render_cohort_status_debug_preserves_dense_view(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_debug(
        [
            SimpleNamespace(
                full_row=["1"],
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                historical_valid_runs_count=1,
                historical_build_count=1,
                need_baseline=0,
                need_interactive=4,
                prep_label="mixed",
                qa_label="valid (L)",
                next_label="manual interaction",
                lineage_state="historical_db_only",
                db_active_sessions=0,
                db_historical_sessions=11,
            )
        ],
        baseline_required=3,
        interactive_required=4,
    )

    out = capsys.readouterr().out
    assert "Dense raw/debug view" in out
    assert "Full table including legacy and QA fields" not in out
    assert "tracker-scoped latest-run state" in out
    assert "Operator summary" in out
    assert "only historical DB lineage exists" in out
    assert "hist=11" in out
    assert "Raw state extract" in out
    assert "3/3" in out
    assert "4I" in out


def test_render_cohort_status_debug_summarizes_review_and_refresh_states(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    captured_tables = []
    monkeypatch.setattr(
        menu_reports.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured_tables.append((headers, rows)),
    )

    menu_reports.render_cohort_status_debug(
        [
            SimpleNamespace(
                full_row=["1"],
                display_name="CNN",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=4,
                interactive_extra=0,
                historical_valid_runs_count=0,
                historical_build_count=0,
                need_baseline=0,
                need_interactive=0,
                prep_label="current",
                qa_label="invalid",
                next_label="review QA",
                lineage_state="current_build_observed",
                db_active_sessions=6,
                db_historical_sessions=0,
                live_build_drift=False,
            ),
            SimpleNamespace(
                full_row=["2"],
                display_name="Facebook",
                package_name="com.facebook.katana",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                historical_valid_runs_count=1,
                historical_build_count=1,
                need_baseline=0,
                need_interactive=4,
                prep_label="stale",
                qa_label="valid (L)",
                next_label="refresh static",
                lineage_state="current_build_stale",
                db_active_sessions=4,
                db_historical_sessions=20,
                live_build_drift=True,
                live_expected_version_code="472143276",
                live_expected_version_name="565.0.0.49.74",
                live_observed_version_code="472224766",
                live_static_run_id="4290",
            ),
        ],
        baseline_required=3,
        interactive_required=4,
    )

    out = capsys.readouterr().out
    assert "Build refresh required" in out
    assert "Refresh harvest/static before continuing dataset-mode dynamic capture." in out
    assert "Package     : com.facebook.katana" in out
    assert "Installed   : 472224766" in out
    assert "Static plan : 565.0.0.49.74 (472143276)" in out
    assert "Static run  : 4290" in out
    assert "Operator summary" in out
    summary_headers, summary_rows = captured_tables[1]
    assert summary_headers == ["App", "Status", "Reason", "DB lineage", "Latest QA"]
    assert summary_rows[0] == ["CNN", "review", "latest current-build QA invalid", "active=6", "invalid"]
    assert summary_rows[1] == ["Facebook", "refresh", "installed build drifted from newest static plan", "active=4 hist=20", "valid (L)"]
