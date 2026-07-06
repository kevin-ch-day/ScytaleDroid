from __future__ import annotations

import os
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.menus import status_reports as menu_reports


def test_render_cohort_status_details_includes_historical_context(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        menu_reports,
        "_paper_freeze_summary",
        lambda: {
            "ready": 4,
            "ready_current": 1,
            "ready_prior": 3,
            "needs_interactive": 8,
            "needs_baseline": 0,
            "insufficient": 3,
            "merged_targets": 6,
            "refresh_candidates": 8,
        },
    )

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
    assert "Paper-target freeze readiness" in out
    assert "Ready prior-build: 3" in out
    assert "Merged build-hash targets: 6" in out
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
    assert "Paper-target freeze readiness describes the strongest build-backed paper candidate" in out
    assert "Current-build stale means older evidence exists" in out
    assert "Current-build DB-only means the DB knows current-build sessions" in out
    assert "Historical DB-only means older dynamic lineage exists in the DB" in out


def test_render_cohort_status_help_mentions_retained_extra_and_historical(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_help()

    out = capsys.readouterr().out
    assert "locked" in out
    assert "mixed" in out
    assert "+L" in out
    assert "identity mismatch" in out
    assert "prior-only" in out
    assert "Retained" in out
    assert "drift" in out
    assert "3/3" in out
    assert "Strict Idle" in out
    assert "Quiescent FG" in out
    assert "Interactive" in out
    assert "Build" in out
    assert "db-only" in out
    assert "none yet" in out
    assert "Status=restore + DB-only evidence" in out
    assert "refresh steps" in out
    assert "installed app build differs from the newest static plan" in out
    assert "identity mismatch" in out
    assert "baseline gap" in out
    assert "interactive gap" in out
    assert "Quiescent FG baseline" in out
    assert "retained outside strict-idle quota" in out
    assert "feed/media refresh can trigger it" in out
    assert "quiescent fg retained baselines do not unlock interactive" in out.lower()
    assert "classifier treated the traffic as too active for strict-idle quota" in out.lower()
    out_lc = out.lower()
    assert "evidence-authoritative quota" in out_lc
    assert "tracker-scoped latest-run state" in out_lc
    assert "paper-target freeze readiness" in out_lc


def test_render_paper_freeze_readiness_brief_shows_summary(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        menu_reports,
        "build_paper_freeze_decision_board",
        lambda: {
            "top_note": "Paper-freeze readiness is draft-oriented.",
            "draft_decision_mode": "heuristic default; no explicit draft target set configured.",
            "summary": {
                "ready": 4,
                "ready_current": 1,
                "ready_prior": 3,
                "needs_interactive": 8,
                "needs_baseline": 0,
                "insufficient": 3,
            },
            "sections": {
                "MUST_RUN_NOW": [
                    {
                        "package_name": "org.reddit.frontpage",
                        "selected_version_code": "20260701",
                        "installed_version_code": "20260701",
                        "relation": "current",
                        "strict_idle_count": 3,
                        "quiescent_fg_count": 0,
                        "baseline_count": 3,
                        "interactive_count": 1,
                        "missing_baseline_runs": 0,
                        "missing_interactive_runs": 3,
                        "valid_pcap_count": 4,
                        "baseline_class_note": "Strict Idle is the quota baseline lane for paper readiness.",
                        "draft_role": "current_gap",
                        "collectability": "collectable_now",
                        "action": "interactive",
                        "rough_draft_blocker": "yes",
                        "reason": "Selected current build is collectable now and missing interactive evidence.",
                    }
                ],
                "READY_DO_NOT_TOUCH": [
                    {
                        "package_name": "com.whatsapp",
                        "selected_version_code": "262408020",
                        "installed_version_code": "262508000",
                        "relation": "prior-build",
                        "strict_idle_count": 3,
                        "quiescent_fg_count": 0,
                        "baseline_count": 3,
                        "interactive_count": 5,
                        "missing_baseline_runs": 0,
                        "missing_interactive_runs": 0,
                        "valid_pcap_count": 8,
                        "baseline_class_note": "Strict Idle is the quota baseline lane for paper readiness.",
                        "draft_role": "ready_coverage",
                        "collectability": "ready_prior_build",
                        "action": "leave frozen",
                        "rough_draft_blocker": "no",
                        "reason": "Paper target is ready on selected build; current build is refresh work.",
                    }
                ],
                "SWITCH_TARGET_CANDIDATE": [],
                "RUN_ONLY_IF_EASY": [],
                "DEFER_REFRESH_WAVE": [],
            },
            "rows": [
                {"package_name": "org.reddit.frontpage"},
                {"package_name": "com.whatsapp"},
            ],
        },
    )
    monkeypatch.setattr(
        menu_reports,
        "_load_paper_freeze_labels",
        lambda _rows: {
            "org.reddit.frontpage": "Reddit",
            "com.whatsapp": "WhatsApp",
        },
    )
    monkeypatch.setattr(
        menu_reports,
        "_latest_paper_freeze_export_path",
        lambda: "output/paper/dynamic_paper_freeze_latest",
    )

    menu_reports.render_paper_freeze_readiness_brief()

    out = capsys.readouterr().out
    assert "Paper-Freeze Readiness" in out
    assert "draft-oriented" in out.lower()
    assert "Draft decision mode: heuristic default; no explicit draft target set configured." in out
    assert "Ready targets: 4" in out
    assert "Ready prior-build: 3" in out
    assert "MUST RUN NOW" in out
    assert "READY DO NOT TOUCH" in out
    assert "Strict Idle is the quota baseline lane" in out
    assert "Reddit" in out
    assert "WhatsApp" in out
    assert "collectable" in out.lower()
    assert "ready_prior" in out.lower()
    assert "Latest export: output/paper/dynamic_paper_freeze_latest" in out
    assert "report_dynamic_paper_freeze_readiness.py" in out


def test_render_cohort_build_history_explains_extra_and_legacy(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        menu_reports.shutil,
        "get_terminal_size",
        lambda fallback=(120, 40): os.terminal_size((120, 40)),
    )

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
    assert "Build lineage and why an app looks current, mixed, or historical" in out
    assert "Baseline" in out
    assert "Interactive" in out
    assert "Build identity detail" in out
    assert "only historical DB lineage exists" in out
    assert "exists; extra" in out
    assert "baseline retained beyond quota cap" in out_flat
    assert "historical evidence" in out_flat
    assert "present" in out
    assert "historical DB-only evidence" in out
    assert "3/3 (+1 extra)" not in out or "4/3" in out
    assert "4/3" in out
    assert "0/4" in out


def test_render_cohort_build_history_wraps_multiple_notes(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        menu_reports.shutil,
        "get_terminal_size",
        lambda fallback=(120, 40): os.terminal_size((78, 40)),
    )

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
    assert "historical evidence" in out_flat
    assert "present" in out
    assert "DB-only" in out
    assert "evidence" in out
    assert "identity" in out
    assert "mismatch" in out
    assert "latest QA invalid" not in out


def test_render_cohort_build_history_explains_stale_and_review_rows(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        menu_reports.shutil,
        "get_terminal_size",
        lambda fallback=(120, 40): os.terminal_size((120, 40)),
    )

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
    assert "latest current-build QA invalid" in out or (
        "latest current-build QA" in out and "invalid" in out
    )


def test_render_cohort_status_debug_preserves_dense_view(monkeypatch, capsys) -> None:
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
    assert "Raw state extract" in out
    summary_headers, summary_rows = captured_tables[1]
    assert summary_headers == ["App", "Status", "Reason", "DB lineage", "Latest QA"]
    assert summary_rows[0] == [
        "Facebook",
        "baseline",
        "only historical DB lineage exists",
        "hist=11",
        "valid (L)",
    ]
    raw_headers, raw_rows = captured_tables[-1]
    assert raw_headers == [
        "App",
        "Base ct",
        "Base ex",
        "Base low",
        "Base qfg",
        "Inter ct",
        "Inter ex",
        "Inter low",
        "Legacy",
        "L builds",
        "Need B",
        "Need I",
        "Lineage",
        "DB active",
        "DB hist",
    ]
    assert raw_rows[0][10] == "0"
    assert raw_rows[0][11] == "4"


def test_render_cohort_status_debug_summarizes_review_and_refresh_states(
    monkeypatch, capsys
) -> None:
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
    assert summary_rows[0] == [
        "CNN",
        "review",
        "latest current-build QA invalid",
        "active=6",
        "invalid",
    ]
    assert summary_rows[1] == [
        "Facebook",
        "refresh",
        "installed build drifted from newest static plan",
        "active=4 hist=20",
        "valid (L)",
    ]
