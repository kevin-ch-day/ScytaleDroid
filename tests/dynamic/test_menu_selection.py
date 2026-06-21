from __future__ import annotations

from scytaledroid.DynamicAnalysis import menu_selection
from scytaledroid.DynamicAnalysis import tracker_scope


class _Cfg:
    baseline_required = 3
    interactive_required = 2


def test_run_package_selection_menu_uses_operator_friendly_progress_labels(monkeypatch, capsys) -> None:
    rows = [
        menu_selection.PreparedPackageSelectionRow(
            full_row=["1", "BBC News", "3/3 complete (+1 extra)", "2/2 complete", "0", "—", "current", "5/5 complete (+1 extra)", "0", "valid"],
            op_row=["1", "BBC News", "3/3 complete (+1 extra)", "2/2 complete", "5/5 complete (+1 extra)", "current", "valid", "—"],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=1,
            dataset_valid_runs_count=5,
            package_name="bbc.mobile.news.ww",
            display_name="BBC News",
            baseline_countable=3,
            baseline_extra=1,
            interactive_countable=2,
            interactive_extra=0,
            need_baseline=0,
            need_interactive=0,
            prep_label="current",
            qa_label="valid",
            next_label="—",
        ),
        menu_selection.PreparedPackageSelectionRow(
            full_row=["2", "CNN", "3/3 complete", "0/2 need 2", "2I", "manual interaction", "current", "3/5 need 2", "0", "valid"],
            op_row=["2", "CNN", "3/3 complete", "0/2 need 2", "3/5 need 2", "current", "valid", "manual interaction"],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=0,
            dataset_valid_runs_count=3,
            package_name="com.cnn.mobile.android.phone",
            display_name="CNN",
            baseline_countable=3,
            baseline_extra=0,
            interactive_countable=0,
            interactive_extra=0,
            need_baseline=0,
            need_interactive=2,
            prep_label="current",
            qa_label="valid",
            next_label="manual interaction",
        ),
        menu_selection.PreparedPackageSelectionRow(
            full_row=["3", "ESPN", "0/3 need 3", "locked", "3B 2I", "baseline", "ready", "0/5 need 5", "0", "invalid"],
            op_row=["3", "ESPN", "0/3 need 3", "locked", "0/5 need 5", "ready", "invalid", "baseline"],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=0,
            dataset_valid_runs_count=0,
            package_name="com.espn.score_center",
            display_name="ESPN",
            baseline_countable=0,
            baseline_extra=0,
            interactive_countable=0,
            interactive_extra=0,
            need_baseline=3,
            need_interactive=2,
            prep_label="ready",
            qa_label="invalid",
            next_label="baseline",
        ),
    ]
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[("bbc.mobile.news.ww", None, None, "BBC News")],
        dataset_pkgs={"bbc.mobile.news.ww"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[row.op_row for row in rows],
        build_rows=[],
        dataset_apps_total=3,
        dataset_apps_complete=1,
        dataset_valid_runs_total=8,
        current_build_ready_count=1,
        current_build_in_progress_count=1,
        current_build_review_count=1,
        stale_app_count=0,
        mixed_identity_app_count=0,
        legacy_only_app_count=0,
        historical_local_only_app_count=1,
        row_models=rows,
        expected_runs=5,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 8,
            "apps_satisfied": 1,
            "extra_eligible_runs": 2,
        },
    )

    monkeypatch.setattr(menu_selection.menu_utils, "print_header", lambda *_a, **_k: None)
    captured = {}
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rendered, **_k: captured.update({"headers": headers, "rows": rendered}),
    )
    monkeypatch.setattr(menu_selection.prompt_utils, "prompt_text", lambda *_a, **_k: "b")

    result = menu_selection.run_package_selection_menu(
        prepared,
        summarize_evidence_quota_fn=lambda *_a, **_k: prepared.evidence_summary,
    )

    assert result is None
    out = capsys.readouterr().out
    assert "Quota: 8/5 valid | 1/3 complete | 0 remaining | 2 supplemental" in out
    assert "Current build: 1/3 complete | 1 in progress | 1 review" in out
    assert "History      : 1 local-only" in out
    assert "Archive: blocked" in out
    assert "Next : CNN — scripted interaction" in out
    assert "Warnings: ESPN QA invalid. 1 app needs baseline." in out
    assert "Attention needed" not in out
    assert "Ready for manual interaction" not in out
    assert "Needs baseline capture" not in out
    assert "Complete / over-quota" not in out
    assert "Legend" not in out
    assert "Freeze/export" not in out
    assert "Next recommended run" not in out
    assert "Select an app by number or name." in out
    assert "S summary" in out
    assert "Y history" in out
    assert "H help" in out
    assert "D diagnostics" in out
    assert "B back" in out
    assert captured["headers"] == ["#", "App", "Status", "Missing", "Quota", "Build/QA", "Template", "Action"]
    assert captured["rows"][0][1:] == ["BBC News", "complete", "—", "5/5+1", "current/✓", "news", "—"]
    assert captured["rows"][1][1:] == ["CNN", "manual", "manual 0/2", "3/5 n2", "current/✓", "news", "script"]
    assert captured["rows"][2][1:] == ["ESPN", "review", "review QA", "0/5 n5", "ready/inv", "none", "base"]


def test_compact_queue_table_distinguishes_historical_db_only_from_empty(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["1"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.facebook.orca",
                display_name="Facebook Messenger",
                baseline_countable=0,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=2,
                prep_label="hist-db",
                qa_label="—",
                next_label="baseline",
                lineage_state="historical_db_only",
                db_historical_sessions=11,
            ),
            menu_selection.PreparedPackageSelectionRow(
                full_row=["2"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.guardian",
                display_name="The Guardian",
                baseline_countable=0,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=2,
                prep_label="ready",
                qa_label="—",
                next_label="baseline",
                lineage_state="no_evidence_anywhere",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == ["#", "App", "Status", "Missing", "Quota", "Build/QA", "Template", "Action"]
    assert captured["rows"][0] == ["1", "Facebook Messenger", "legacy", "local+curr", "0/5 n5", "hist-db/—", "gen", "base"]
    assert captured["rows"][1] == ["2", "The Guardian", "baseline", "base 0/3", "0/5 n5", "ready/—", "news", "base"]


def test_display_action_label_uses_review_for_invalid_complete_row() -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=1,
        dataset_valid_runs_count=5,
        package_name="com.cnn.mobile.android.phone",
        display_name="CNN",
        baseline_countable=3,
        interactive_countable=2,
        need_baseline=0,
        need_interactive=0,
        prep_label="current",
        qa_label="invalid",
        next_label="review QA",
        lineage_state="current_build_observed",
    )

    assert menu_selection._display_action_label(row) == "review"
    assert menu_selection._display_next_line_action_label(row) == "review QA"


def test_next_recommended_row_prioritizes_review_over_manual_and_refresh() -> None:
    manual_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.zhiliaoapp.musically",
        display_name="TikTok",
        baseline_countable=3,
        interactive_countable=0,
        need_baseline=0,
        need_interactive=2,
        prep_label="current",
        qa_label="valid",
        next_label="manual interaction",
        lineage_state="current_build_observed",
    )
    refresh_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["2"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.facebook.katana",
        display_name="Facebook",
        baseline_countable=3,
        interactive_countable=0,
        need_baseline=0,
        need_interactive=2,
        prep_label="stale",
        qa_label="valid (L)",
        next_label="refresh static",
        lineage_state="current_build_stale",
        live_build_drift=True,
    )
    review_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["3"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=1,
        dataset_valid_runs_count=5,
        package_name="com.cnn.mobile.android.phone",
        display_name="CNN",
        baseline_countable=3,
        interactive_countable=2,
        need_baseline=0,
        need_interactive=0,
        prep_label="current",
        qa_label="invalid",
        next_label="review QA",
        lineage_state="current_build_observed",
    )

    picked = menu_selection._next_recommended_row([manual_row, refresh_row, review_row])
    assert picked is review_row


def test_next_recommended_row_prioritizes_empty_baseline_over_historical_baseline() -> None:
    historical_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        package_name="com.facebook.orca",
        display_name="Facebook Messenger",
        baseline_countable=0,
        interactive_countable=0,
        need_baseline=3,
        need_interactive=2,
        prep_label="hist-db",
        qa_label="—",
        next_label="baseline",
        lineage_state="historical_db_only",
    )
    empty_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["2"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        package_name="com.guardian",
        display_name="The Guardian",
        baseline_countable=0,
        interactive_countable=0,
        need_baseline=3,
        need_interactive=2,
        prep_label="ready",
        qa_label="—",
        next_label="baseline",
        lineage_state="no_evidence_anywhere",
    )

    picked = menu_selection._next_recommended_row([historical_row, empty_row])
    assert picked is empty_row


def test_render_package_table_shows_full_list_when_only_one_row_exceeds_preview(monkeypatch, capsys) -> None:
    rows = [
        [str(index), f"App {index}", "0/3 need 3", "locked", "0/5", "ready", "—", "baseline"]
        for index in range(1, 17)
    ]
    monkeypatch.setattr(menu_selection.table_utils, "render_table", lambda headers, rendered, **_k: print(f"rows={len(rendered)}"))

    truncated = menu_selection.render_package_table(
        rows,
        headers=["#", "App", "Baseline", "Manual", "Quota", "Static prep", "Last QA", "Next action"],
    )

    assert truncated is False
    out = capsys.readouterr().out
    assert "rows=16" in out
    assert "Showing first" not in out


def test_render_package_table_still_truncates_for_longer_lists(monkeypatch, capsys) -> None:
    rows = [
        [str(index), f"App {index}", "0/3 need 3", "locked", "0/5", "ready", "—", "baseline"]
        for index in range(1, 18)
    ]
    monkeypatch.setattr(menu_selection.table_utils, "render_table", lambda headers, rendered, **_k: print(f"rows={len(rendered)}"))

    truncated = menu_selection.render_package_table(
        rows,
        headers=["#", "App", "Baseline", "Manual", "Quota", "Static prep", "Last QA", "Next action"],
    )

    assert truncated is True
    out = capsys.readouterr().out
    assert "rows=15" in out
    assert "Showing first 15 of 17 apps." in out


def test_build_scoped_dataset_counts_prefers_active_plan_identity_over_latest_tracker_run() -> None:
    class _Cfg2:
        baseline_required = 3
        interactive_required = 2

    runs = [
        {
            "run_id": "legacy-facebook",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "471216151",
            "base_apk_sha256": "oldsha",
            "ended_at": "2026-05-14T20:54:11+00:00",
        }
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.facebook.katana",
        runs,
        cfg=_Cfg2(),
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        active_identity_fn=lambda _pkg: ("472143276", "newsha"),
    )

    assert scoped["baseline_countable"] == 0
    assert scoped["interactive_countable"] == 0
    assert scoped["legacy_valid"] == 1
    assert scoped["active_version_code"] == "472143276"
    assert scoped["active_base_sha"] == "newsha"


def test_render_package_table_uses_manual_column_and_extra_counts(monkeypatch, capsys) -> None:
    captured = {}
    rows = [[
        "1",
        "BBC News",
        "3/3 complete (+1 extra)",
        "0/2 need 2",
        "3/5 need 2 (+1 extra)",
        "ready",
        "valid",
        "manual interaction",
    ]]
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rendered, **_k: captured.update({"headers": headers, "rows": rendered}),
    )

    truncated = menu_selection.render_package_table(
        rows,
        headers=["#", "App", "Baseline", "Manual", "Quota", "Static prep", "Last QA", "Next action"],
    )

    assert truncated is False
    assert captured["headers"] == ["#", "App", "Base", "Manual", "Quota", "Prep", "QA", "Next"]
    assert captured["rows"] == [[
        "1",
        "BBC News",
        "4/3",
        "0/2 n2",
        "3/5 n2",
        "ready",
        "valid",
        "manual",
    ]]


def test_main_progress_label_prefers_extra_suffix_over_rolled_fraction() -> None:
    assert menu_selection._main_progress_label(3, 1, required=3) == "3/3 +1 extra"
    assert menu_selection._main_progress_label(5, 1, required=5) == "5/5 +1 extra"
    assert menu_selection._main_progress_label(0, 0, required=2, missing=2) == "0/2 need 2"


def test_manual_progress_label_uses_locked_until_baseline_complete() -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=[],
        op_row=[],
        build_row=None,
        dataset_app_count=0,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        need_baseline=1,
        need_interactive=2,
        interactive_countable=0,
        interactive_extra=0,
    )
    assert menu_selection._manual_progress_label(row, interactive_required=2) == "locked"


def test_compact_qa_label_captures_legacy_and_identity_variants() -> None:
    assert menu_selection._compact_qa_label("valid (L)") == "valid+L"
    assert menu_selection._compact_qa_label("valid (id_mismatch)") == "valid+id"
    assert menu_selection._compact_qa_label("valid (id_mismatch) (L)") == "valid+id+L"


def test_render_queue_section_table_preserves_mixed_validl_and_invalid_states(monkeypatch) -> None:
    captured = {}

    def _capture(headers, rows, **_kwargs):
        captured["headers"] = headers
        captured["rows"] = rows

    monkeypatch.setattr(menu_selection.table_utils, "render_table", _capture)

    menu_selection._render_queue_section_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["4"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="mixed",
                qa_label="valid (L)",
                next_label="manual interaction",
            ),
            menu_selection.PreparedPackageSelectionRow(
                full_row=["3"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                display_name="ESPN",
                baseline_countable=0,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=2,
                prep_label="ready",
                qa_label="invalid",
                next_label="baseline",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
        show_all=True,
    )

    assert captured["headers"] == ["#", "App", "Baseline", "Manual", "Quota", "Prep", "QA", "Action"]
    assert captured["rows"][0][2] == "3/3 +1 extra"
    assert captured["rows"][0][3] == "0/2 need 2"
    assert captured["rows"][0][5] == "mixed"
    assert captured["rows"][0][6] == "valid+L"
    assert captured["rows"][1][2] == "0/3 need 3"
    assert captured["rows"][1][3] == "locked"
    assert captured["rows"][1][6] == "invalid"


def test_compact_queue_table_shows_all_apps_together_and_script_labels(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["1"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="bbc.mobile.news.ww",
                display_name="BBC News",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=2,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=0,
                prep_label="current",
                qa_label="valid",
                next_label="—",
            ),
            menu_selection.PreparedPackageSelectionRow(
                full_row=["2"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.facebook.katana",
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="mixed",
                qa_label="valid (L)",
                next_label="manual interaction",
            ),
            menu_selection.PreparedPackageSelectionRow(
                full_row=["3"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.espn.score_center",
                display_name="ESPN",
                baseline_countable=0,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=2,
                prep_label="ready",
                qa_label="invalid",
                next_label="baseline",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == ["#", "App", "Status", "Missing", "Quota", "Build/QA", "Template", "Action"]
    assert captured["rows"][0] == ["1", "BBC News", "complete", "—", "5/5+1", "current/✓", "news", "—"]
    assert captured["rows"][1] == ["2", "Facebook", "manual", "manual 0/2", "3/5 n2", "mixed/+L", "acct", "manual"]
    assert captured["rows"][2] == ["3", "ESPN", "review", "review QA", "0/5 n5", "ready/inv", "none", "base"]


def test_compact_queue_table_marks_live_build_drift_as_refresh(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["4"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.facebook.katana",
                display_name="Facebook",
                baseline_countable=3,
                baseline_extra=1,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="stale",
                qa_label="valid (L)",
                next_label="refresh static",
                live_build_drift=True,
                live_expected_version_code="472143276",
                live_observed_version_code="472224766",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == ["#", "App", "Status", "Missing", "Quota", "Build/QA", "Template", "Action"]
    assert captured["rows"][0] == ["4", "Facebook", "refresh", "refresh", "3/5 n2", "stale/+L", "acct", "refresh"]


def test_compact_queue_table_marks_current_build_db_only_as_restore(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["5"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.example.current",
                display_name="Current App",
                baseline_countable=0,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=2,
                prep_label="db-only",
                qa_label="—",
                next_label="baseline",
                lineage_state="current_build_db_only",
                db_active_sessions=4,
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["rows"][0] == ["5", "Current App", "restore", "local pack", "0/5 n5", "db-only/—", "none", "restore"]


def test_compact_warning_line_mentions_static_refresh_need() -> None:
    warning = menu_selection._compact_warning_line(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=[],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                display_name="Facebook",
                live_build_drift=True,
                prep_label="stale",
                qa_label="valid (L)",
                next_label="refresh static",
            )
        ]
    )
    assert warning == "Facebook needs static refresh."


def test_compact_warning_line_mentions_historical_db_only() -> None:
    warning = menu_selection._compact_warning_line(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=[],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                display_name="Facebook Messenger",
                lineage_state="historical_db_only",
                prep_label="hist-db",
                qa_label="—",
                next_label="baseline",
            )
        ]
    )
    assert warning == "Facebook Messenger historical DB-only."


def test_run_package_selection_menu_shows_current_build_refresh_summary(monkeypatch, capsys) -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1", "Facebook", "3/3 complete (+1 extra)", "0/2 need 2", "2I", "refresh static", "stale", "3/5 need 2", "1", "valid (L)"],
        op_row=["1", "Facebook", "3/3 complete (+1 extra)", "0/2 need 2", "3/5 need 2", "stale", "valid (L)", "refresh static"],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.facebook.katana",
        display_name="Facebook",
        baseline_countable=3,
        baseline_extra=1,
        interactive_countable=0,
        interactive_extra=0,
        need_baseline=0,
        need_interactive=2,
        prep_label="stale",
        qa_label="valid (L)",
        next_label="refresh static",
        live_build_drift=True,
        live_expected_version_code="472143276",
        live_observed_version_code="472224766",
    )
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[("com.facebook.katana", None, None, "Facebook")],
        dataset_pkgs={"com.facebook.katana"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[row.op_row],
        build_rows=[],
        dataset_apps_total=1,
        dataset_apps_complete=0,
        dataset_valid_runs_total=3,
        current_build_ready_count=0,
        current_build_in_progress_count=0,
        current_build_review_count=0,
        stale_app_count=1,
        row_models=[row],
        expected_runs=5,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 3,
            "apps_satisfied": 0,
            "extra_eligible_runs": 1,
        },
    )
    monkeypatch.setattr(menu_selection.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_selection.table_utils, "render_table", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_selection.prompt_utils, "prompt_text", lambda *_a, **_k: "b")

    result = menu_selection.run_package_selection_menu(
        prepared,
        summarize_evidence_quota_fn=lambda *_a, **_k: prepared.evidence_summary,
    )

    assert result is None
    out = capsys.readouterr().out
    assert "Current build: 0/1 complete | 1 stale" in out
