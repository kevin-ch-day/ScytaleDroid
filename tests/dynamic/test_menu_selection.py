from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.menus import queue_data_sources
from scytaledroid.DynamicAnalysis.menus import queue_selection as menu_selection

_QUEUE_TABLE_HEADERS = [
    "#",
    "App",
    "Status",
    "QA",
    "Build",
    "Strict Idle",
    "Quiescent FG",
    "Interactive",
    "Retained",
    "ML Pool",
]
_QUEUE_TABLE_HEADERS_STANDARD = [
    "#",
    "App",
    "Status",
    "QA",
    "Build",
    "Idle",
    "QFG",
    "Interactive",
    "Retained",
]
_QUEUE_TABLE_HEADERS_NARROW = ["#", "App", "St", "QA", "Bld", "Idle", "QFG", "Int", "Ret"]


class _Cfg:
    baseline_required = 3
    interactive_required = 2


class _CfgFourInteractive:
    baseline_required = 3
    interactive_required = 4


@pytest.fixture(autouse=True)
def _wide_queue_layout(monkeypatch) -> None:
    monkeypatch.setattr(menu_selection.terminal, "get_terminal_width", lambda *args, **kwargs: 140)
    monkeypatch.setattr(menu_selection._app_queue_rendering, "_paper_cutoff_summary_label", lambda: "")


def test_queue_table_marks_next_recommended_row(monkeypatch) -> None:
    captured = {}
    rows = [
        menu_selection.PreparedPackageSelectionRow(
            full_row=["1"],
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
    ]
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rendered, **_kwargs: captured.update(
            {"headers": headers, "rows": rendered}
        ),
    )
    menu_selection._render_compact_queue_table(
        rows,
        baseline_required=3,
        interactive_required=2,
        next_row=rows[0],
    )
    assert captured["rows"][0][0] == ">1"


def test_queue_layout_mode_uses_standard_with_build_column(monkeypatch) -> None:
    monkeypatch.setattr(menu_selection.terminal, "get_terminal_width", lambda *args, **kwargs: 118)
    from scytaledroid.DynamicAnalysis import app_queue_rendering

    assert app_queue_rendering.queue_layout_mode(terminal_mod=menu_selection.terminal) == "standard"
    assert (
        app_queue_rendering.queue_compact_table_headers(layout="standard")
        == _QUEUE_TABLE_HEADERS_STANDARD
    )


def test_queue_layout_mode_uses_standard_at_80_columns(monkeypatch) -> None:
    monkeypatch.setattr(menu_selection.terminal, "get_terminal_width", lambda *args, **kwargs: 80)
    from scytaledroid.DynamicAnalysis import app_queue_rendering

    assert app_queue_rendering.queue_layout_mode(terminal_mod=menu_selection.terminal) == "standard"


def test_run_package_selection_menu_uses_operator_friendly_progress_labels(
    monkeypatch, capsys
) -> None:
    rows = [
        menu_selection.PreparedPackageSelectionRow(
            full_row=[
                "1",
                "BBC News",
                "3/3 complete (+1 extra)",
                "2/2 complete",
                "0",
                "—",
                "current",
                "5/5 complete (+1 extra)",
                "0",
                "valid",
            ],
            op_row=[
                "1",
                "BBC News",
                "3/3 complete (+1 extra)",
                "2/2 complete",
                "5/5 complete (+1 extra)",
                "current",
                "valid",
                "—",
            ],
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
            full_row=[
                "2",
                "CNN",
                "3/3 complete",
                "0/2 need 2",
                "2I",
                "manual interaction",
                "current",
                "3/5 need 2",
                "0",
                "valid",
            ],
            op_row=[
                "2",
                "CNN",
                "3/3 complete",
                "0/2 need 2",
                "3/5 need 2",
                "current",
                "valid",
                "manual interaction",
            ],
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
            full_row=[
                "3",
                "ESPN",
                "0/3 need 3",
                "locked",
                "3B 2I",
                "baseline",
                "ready",
                "0/5 need 5",
                "0",
                "invalid",
            ],
            op_row=[
                "3",
                "ESPN",
                "0/3 need 3",
                "locked",
                "0/5 need 5",
                "ready",
                "invalid",
                "baseline",
            ],
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
    assert "Cohort status" in out
    assert "1/3 current-build complete" in out
    assert "8/5 valid" in out
    assert "retained extra" in out
    assert "current-build collection queue" in out
    assert "Paper cutoff" not in out
    assert "paper-freeze readiness" in out
    assert "Current build" in out
    assert "1/3 complete" in out
    assert "blocked" in out
    assert "Remaining:" not in out
    assert "Capture plan:" not in out
    assert "Next: ESPN" not in out
    assert "Warnings:" not in out
    assert "Notes   :" not in out
    assert "Attention needed" not in out
    assert "Ready for manual interaction" not in out
    assert "Needs baseline capture" not in out
    assert "Complete / over-quota" not in out
    assert "Queue key" not in out
    assert "Freeze/export" not in out
    assert "Next recommended run" not in out
    assert "Select an app by number or name" in out
    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0][1:] == [
        "BBC News",
        "complete",
        "valid",
        "current",
        "3/3",
        "0",
        "2/2",
        "0",
        "1",
    ]
    assert captured["rows"][1][1:] == [
        "CNN",
        "interactive",
        "valid",
        "current",
        "3/3",
        "0",
        "0/2",
        "0",
        "0",
    ]
    assert captured["rows"][2] == [
        ">3",
        "ESPN",
        "review",
        "invalid",
        "none yet",
        "0/3",
        "0",
        "0/2 held",
        "0",
        "0",
    ]


def test_run_package_selection_menu_surfaces_paper_cutoff_summary(monkeypatch, capsys) -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=1,
        dataset_valid_runs_count=7,
        historical_valid_runs_count=0,
        package_name="com.pinterest",
        display_name="Pinterest",
        baseline_countable=3,
        interactive_countable=2,
        need_baseline=0,
        need_interactive=2,
        prep_label="current",
        qa_label="valid",
        next_label="manual interaction",
        lineage_state="current_build_observed",
    )
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[("com.pinterest", None, None, "Pinterest")],
        dataset_pkgs={"com.pinterest"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[row.op_row],
        build_rows=[],
        dataset_apps_total=15,
        dataset_apps_complete=5,
        dataset_valid_runs_total=87,
        current_build_ready_count=5,
        current_build_in_progress_count=7,
        current_build_review_count=0,
        stale_app_count=0,
        mixed_identity_app_count=0,
        legacy_only_app_count=0,
        historical_local_only_app_count=0,
        row_models=[row],
        expected_runs=105,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 87,
            "apps_satisfied": 7,
            "extra_eligible_runs": 137,
        },
    )
    monkeypatch.setattr(menu_selection.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_selection.table_utils, "render_table", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_selection.prompt_utils, "prompt_text", lambda *_a, **_k: "b")
    monkeypatch.setattr(
        menu_selection._app_queue_rendering,
        "_paper_cutoff_summary_label",
        lambda: "15/15 paper-usable · ready targets 10 · holes 0 · needs interactive 5",
    )

    result = menu_selection.run_package_selection_menu(
        prepared,
        summarize_evidence_quota_fn=lambda *_a, **_k: prepared.evidence_summary,
    )

    assert result is None
    out = capsys.readouterr().out
    assert "Paper cutoff" in out
    assert "15/15 paper-usable" in out
    assert "ready targets 10" in out
    assert "holes 0" in out
    assert "needs interactive 5" in out
    assert "P paper freeze" in out
    assert "S summary" in out
    assert "V grouped" in out
    assert "Y history" in out
    assert "H help" in out
    assert "D diagnostics" in out
    assert "B back" in out


def test_queue_summary_without_selected_device_uses_tracked_build_wording(capsys) -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=[],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.pinterest",
        display_name="Pinterest",
        baseline_countable=3,
        baseline_extra=0,
        interactive_countable=0,
        interactive_extra=0,
        need_baseline=0,
        need_interactive=4,
        prep_label="current",
        qa_label="valid",
        next_label="manual interaction",
        lineage_state="current_build_observed",
    )
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[("com.pinterest", None, None, "Pinterest")],
        dataset_pkgs={"com.pinterest"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[],
        build_rows=[],
        dataset_apps_total=1,
        dataset_apps_complete=0,
        dataset_valid_runs_total=3,
        current_build_ready_count=0,
        current_build_in_progress_count=1,
        current_build_review_count=0,
        stale_app_count=0,
        row_models=[row],
        expected_runs=5,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 3,
            "apps_satisfied": 0,
            "extra_eligible_runs": 0,
        },
        capture_device_selected=False,
    )

    menu_selection._render_queue_summary_block(
        prepared=prepared,
        quota=3,
        apps_ok=0,
        remaining=2,
        extra_runs=0,
        freeze_ok=False,
        next_row=row,
        capture_device_selected=False,
    )

    out = capsys.readouterr().out
    assert "tracked-build collection queue" in out
    assert "paper-freeze readiness" in out
    assert "0/1 tracked-build complete" in out
    assert "Tracked-build queue" in out
    assert "Tracked build" in out
    assert "Select a device to verify live build drift and enable capture guidance." in out
    assert "Capture plan:" not in out
    assert "Plan priority:" not in out


def test_queue_footer_block_surfaces_attention_notes_and_shortcuts(capsys) -> None:
    from scytaledroid.DynamicAnalysis import app_queue_rendering

    app_queue_rendering.render_queue_footer_block(
        warnings_line="Pinterest drifted build. Press D.",
        notes_line="7 history-only apps. Press D.",
    )

    out = capsys.readouterr().out
    assert "Diagnostics available: press D." in out
    assert "Pinterest drifted build" not in out
    assert "7 history-only apps" not in out
    assert "Select an app by number or name" in out
    assert "Shortcuts:" in out
    assert "P paper freeze" in out
    assert "S summary" in out
    assert "D diagnostics" in out
    assert "Evidence lineage and historical/debug detail are in Diagnostics (D)." in out


def test_run_package_selection_menu_routes_paper_shortcut(monkeypatch) -> None:
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[("bbc.mobile.news.ww", None, None, "BBC News")],
        dataset_pkgs={"bbc.mobile.news.ww"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[],
        build_rows=[],
        dataset_apps_total=1,
        dataset_apps_complete=0,
        dataset_valid_runs_total=0,
        row_models=[],
        expected_runs=5,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 0,
            "apps_satisfied": 0,
            "extra_eligible_runs": 0,
        },
    )
    seen = {"paper": 0}
    choices = iter(["p", "b"])
    monkeypatch.setattr(
        menu_selection.prompt_utils,
        "prompt_text",
        lambda *_a, **_k: next(choices),
    )
    monkeypatch.setattr(
        menu_selection._status_reports,
        "render_paper_freeze_readiness_brief",
        lambda: seen.__setitem__("paper", seen["paper"] + 1),
    )
    monkeypatch.setattr(menu_selection.table_utils, "render_table", lambda *_a, **_k: None)

    assert (
        menu_selection.run_package_selection_menu(
            prepared,
            summarize_evidence_quota_fn=lambda *_a, **_k: prepared.evidence_summary,
        )
        is None
    )
    assert seen["paper"] == 1


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

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "1",
        "Facebook Msg",
        "baseline",
        "—",
        "prior-only",
        "0/3",
        "0",
        "0/2 held",
        "0",
        "0",
    ]
    assert captured["rows"][1] == [
        "2",
        "Guardian",
        "baseline",
        "—",
        "none yet",
        "0/3",
        "0",
        "0/2 held",
        "0",
        "0",
    ]


def test_compact_queue_table_shows_non_idle_baseline_supplemental(monkeypatch) -> None:
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
                package_name="com.reddit.frontpage",
                display_name="Reddit",
                baseline_countable=0,
                baseline_extra=0,
                baseline_not_idle_supplemental=3,
                interactive_countable=2,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=0,
                prep_label="current",
                qa_label="valid",
                next_label="baseline",
                lineage_state="current_build_observed",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "4",
        "Reddit",
        "baseline",
        "valid",
        "current",
        "0/3",
        "3",
        "2/2 held",
        "0",
        "0",
    ]


def test_render_package_table_shows_full_list_when_only_one_row_exceeds_preview(
    monkeypatch, capsys
) -> None:
    rows = [
        [str(index), f"App {index}", "0/3 need 3", "locked", "0/5", "ready", "—", "baseline"]
        for index in range(1, 17)
    ]
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rendered, **_k: print(f"rows={len(rendered)}"),
    )

    truncated = menu_selection.render_package_table(
        rows,
        headers=[
            "#",
            "App",
            "Baseline",
            "Interactive",
            "Quota",
            "Static prep",
            "Last QA",
            "Next action",
        ],
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
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rendered, **_k: print(f"rows={len(rendered)}"),
    )

    truncated = menu_selection.render_package_table(
        rows,
        headers=[
            "#",
            "App",
            "Baseline",
            "Interactive",
            "Quota",
            "Static prep",
            "Last QA",
            "Next action",
        ],
    )

    assert truncated is True
    out = capsys.readouterr().out
    assert "rows=15" in out
    assert "Showing first 15 of 17 apps." in out


def test_render_package_table_uses_manual_column_and_extra_counts(monkeypatch, capsys) -> None:
    captured = {}
    rows = [
        [
            "1",
            "BBC News",
            "3/3 complete (+1 extra)",
            "0/2 need 2",
            "3/5 need 2 (+1 extra)",
            "ready",
            "valid",
            "manual interaction",
        ]
    ]
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rendered, **_k: captured.update({"headers": headers, "rows": rendered}),
    )

    truncated = menu_selection.render_package_table(
        rows,
        headers=[
            "#",
            "App",
            "Baseline",
            "Interactive",
            "Quota",
            "Static prep",
            "Last QA",
            "Next action",
        ],
    )

    assert truncated is False
    assert captured["headers"] == ["#", "App", "Base", "Int", "Quota", "Prep", "QA", "Next"]
    assert captured["rows"] == [
        [
            "1",
            "BBC News",
            "4/3",
            "0/2 n2",
            "3/5 n2",
            "ready",
            "valid",
            "interactive",
        ]
    ]


def test_main_progress_label_prefers_extra_suffix_over_rolled_fraction() -> None:
    assert menu_selection._main_progress_label(3, 1, required=3) == "3/3 (+1 extra)"
    assert menu_selection._main_progress_label(5, 1, required=5) == "5/5 (+1 extra)"
    assert menu_selection._main_progress_label(0, 0, required=2, missing=2) == "0/2 need 2"


def test_manual_progress_label_surfaces_raw_interactive_progress_when_strict_idle_holds() -> None:
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
    assert menu_selection._manual_progress_label(row, interactive_required=2) == "0/2 held"


def test_compact_qa_label_captures_legacy_and_identity_variants() -> None:
    assert menu_selection._compact_qa_label("valid (L)") == "valid+L"
    assert menu_selection._compact_qa_label("valid (id_mismatch)") == "valid+id"
    assert menu_selection._compact_qa_label("valid (id_mismatch) (L)") == "valid+id+L"


def test_queue_table_display_labels_use_friendlier_operator_text() -> None:
    prior_row = menu_selection.PreparedPackageSelectionRow(
        full_row=[],
        op_row=[],
        build_row=None,
        dataset_app_count=0,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        prep_label="hist-db",
        qa_label="valid (id_mismatch) (L)",
    )
    locked_row = menu_selection.PreparedPackageSelectionRow(
        full_row=[],
        op_row=[],
        build_row=None,
        dataset_app_count=0,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        need_baseline=1,
        interactive_countable=0,
        interactive_extra=0,
        interactive_low_signal_supplemental=0,
    )

    assert menu_selection._app_queue_state.queue_table_qa_label(prior_row) == "valid+id"
    assert menu_selection._app_queue_state.queue_table_build_label(prior_row) == "prior-only"
    assert (
        menu_selection._app_queue_state.queue_interactive_total_label(
            locked_row, interactive_required=4
        )
        == "0/4 held"
    )


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

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "4",
        "Facebook",
        "interactive",
        "valid",
        "current",
        "3/3",
        "0",
        "0/2",
        "0",
        "1",
    ]
    assert captured["rows"][1] == [
        "3",
        "ESPN",
        "review",
        "invalid",
        "none yet",
        "0/3",
        "0",
        "0/2 held",
        "0",
        "0",
    ]


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

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "1",
        "BBC News",
        "complete",
        "valid",
        "current",
        "3/3",
        "0",
        "2/2",
        "0",
        "1",
    ]
    assert captured["rows"][1] == [
        "2",
        "Facebook",
        "interactive",
        "valid",
        "current",
        "3/3",
        "0",
        "0/2",
        "0",
        "1",
    ]
    assert captured["rows"][2] == [
        "3",
        "ESPN",
        "review",
        "invalid",
        "none yet",
        "0/3",
        "0",
        "0/2 held",
        "0",
        "0",
    ]


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
                historical_valid_runs_count=1,
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "4",
        "Facebook",
        "refresh",
        "valid",
        "drift",
        "3/3",
        "0",
        "0/2",
        "1",
        "1",
    ]


def test_compact_queue_table_uses_short_app_labels(monkeypatch) -> None:
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
                package_name="com.facebook.orca",
                display_name="Facebook Messenger",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=3,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=1,
                prep_label="current",
                qa_label="valid",
                next_label="manual interaction",
            ),
        ],
        baseline_required=3,
        interactive_required=4,
    )

    assert captured["rows"][0][1] == "Facebook Msg"


def test_compact_queue_table_shows_supplemental_suffixes_without_inflating_quota(
    monkeypatch,
) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["2"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=1,
                dataset_valid_runs_count=5,
                package_name="com.cnn.mobile.android.phone",
                display_name="CNN",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=2,
                interactive_extra=1,
                need_baseline=0,
                need_interactive=0,
                prep_label="current",
                qa_label="valid",
                next_label="—",
                lineage_state="current_build_observed",
            ),
            menu_selection.PreparedPackageSelectionRow(
                full_row=["15"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=2,
                package_name="com.twitter.android",
                display_name="X (Twitter)",
                baseline_countable=2,
                baseline_extra=0,
                baseline_low_signal_supplemental=2,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=1,
                need_interactive=2,
                prep_label="current",
                qa_label="valid (L)",
                next_label="baseline",
                lineage_state="current_build_observed",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "2",
        "CNN",
        "complete",
        "valid",
        "current",
        "3/3",
        "0",
        "3/2",
        "0",
        "0",
    ]
    assert captured["rows"][1] == [
        "15",
        "X",
        "baseline",
        "valid",
        "current",
        "2/3",
        "0",
        "0/2 held",
        "0",
        "2",
    ]


def test_compact_queue_table_marks_low_signal_valid_as_supplemental_qa(
    monkeypatch,
) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["7"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.pinterest",
                display_name="Pinterest",
                baseline_countable=0,
                baseline_extra=0,
                baseline_low_signal_supplemental=1,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=3,
                need_interactive=4,
                prep_label="current",
                qa_label="valid",
                next_label="baseline",
                lineage_state="current_build_observed",
            ),
        ],
        baseline_required=3,
        interactive_required=4,
    )

    assert captured["rows"][0] == [
        "7",
        "Pinterest",
        "baseline",
        "valid+low",
        "current",
        "0/3",
        "0",
        "0/4 held",
        "0",
        "1",
    ]


def test_compact_queue_table_shows_x_baseline_against_baseline_target(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["15"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.twitter.android",
                display_name="X (Twitter)",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="stale",
                qa_label="valid (L)",
                next_label="refresh static",
                lineage_state="current_build_observed",
                live_build_drift=True,
                live_expected_version_code="312021000",
                live_observed_version_code="312031000",
                historical_valid_runs_count=17,
                technical_valid_active=3,
                db_active_sessions=3,
                db_historical_sessions=17,
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == _QUEUE_TABLE_HEADERS
    assert captured["rows"][0] == [
        "15",
        "X",
        "refresh",
        "valid",
        "drift",
        "3/3",
        "0",
        "0/2",
        "17",
        "0",
    ]


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

    assert captured["rows"][0] == [
        "5",
        "Current App",
        "restore",
        "—",
        "db-only",
        "0/3",
        "0",
        "0/2 held",
        "0",
        "0",
    ]


def test_compact_queue_table_uses_standard_layout_at_80_columns(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(menu_selection.terminal, "get_terminal_width", lambda *args, **kwargs: 80)
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["2"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.cnn.mobile.android.phone",
                display_name="CNN",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="current",
                qa_label="invalid",
                next_label="review QA",
                lineage_state="current_build_observed",
            ),
            menu_selection.PreparedPackageSelectionRow(
                full_row=["3"],
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
                lineage_state="current_build_observed",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == _QUEUE_TABLE_HEADERS_STANDARD
    assert captured["rows"][0] == ["2", "CNN", "review", "invalid", "current", "3/3", "0", "0/2", "0"]
    assert captured["rows"][1] == [
        "3",
        "Facebook",
        "interactive",
        "valid",
        "current",
        "3/3",
        "0",
        "0/2",
        "0",
    ]


def test_compact_queue_table_uses_narrow_layout_when_terminal_is_very_tight(monkeypatch) -> None:
    captured = {}

    monkeypatch.setattr(menu_selection.terminal, "get_terminal_width", lambda *args, **kwargs: 79)
    monkeypatch.setattr(
        menu_selection.table_utils,
        "render_table",
        lambda headers, rows, **_kwargs: captured.update({"headers": headers, "rows": rows}),
    )

    menu_selection._render_compact_queue_table(
        [
            menu_selection.PreparedPackageSelectionRow(
                full_row=["2"],
                op_row=[],
                build_row=None,
                dataset_app_count=0,
                dataset_complete_count=0,
                dataset_valid_runs_count=0,
                package_name="com.cnn.mobile.android.phone",
                display_name="CNN",
                baseline_countable=3,
                baseline_extra=0,
                interactive_countable=0,
                interactive_extra=0,
                need_baseline=0,
                need_interactive=2,
                prep_label="current",
                qa_label="invalid",
                next_label="review QA",
                lineage_state="current_build_observed",
            ),
        ],
        baseline_required=3,
        interactive_required=2,
    )

    assert captured["headers"] == _QUEUE_TABLE_HEADERS_NARROW


def test_run_package_selection_menu_shows_current_build_refresh_summary(
    monkeypatch, capsys
) -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=[
            "1",
            "Facebook",
            "3/3 complete (+1 extra)",
            "0/2 need 2",
            "2I",
            "refresh static",
            "stale",
            "3/5 need 2",
            "1",
            "valid (L)",
        ],
        op_row=[
            "1",
            "Facebook",
            "3/3 complete (+1 extra)",
            "0/2 need 2",
            "3/5 need 2",
            "stale",
            "valid (L)",
            "refresh static",
        ],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        historical_valid_runs_count=1,
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
    assert "Current build" in out
    assert "1 drift" in out
    assert "drift changes provenance labels, not evidence availability" in out
    assert "freeze build-scoped evidence or refresh drifted apps" in out
    assert "Remaining:" not in out


def test_run_package_selection_menu_guides_non_drift_capture_before_redoing_drift(
    monkeypatch, capsys
) -> None:
    rows = [
        menu_selection.PreparedPackageSelectionRow(
            full_row=["1"],
            op_row=[],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=0,
            dataset_valid_runs_count=3,
            historical_valid_runs_count=1,
            package_name="com.reddit.frontpage",
            display_name="Reddit",
            baseline_countable=3,
            interactive_countable=1,
            need_baseline=0,
            need_interactive=3,
            prep_label="stale",
            qa_label="valid",
            next_label="refresh static",
            lineage_state="current_build_observed",
            live_build_drift=True,
        ),
        menu_selection.PreparedPackageSelectionRow(
            full_row=["2"],
            op_row=[],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=0,
            dataset_valid_runs_count=3,
            historical_valid_runs_count=1,
            package_name="org.telegram.messenger",
            display_name="Telegram",
            baseline_countable=3,
            interactive_countable=1,
            need_baseline=0,
            need_interactive=3,
            prep_label="current",
            qa_label="valid",
            next_label="manual interaction",
            lineage_state="current_build_observed",
        ),
    ]
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[
            ("com.reddit.frontpage", None, None, "Reddit"),
            ("org.telegram.messenger", None, None, "Telegram"),
        ],
        dataset_pkgs={"com.reddit.frontpage", "org.telegram.messenger"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[],
        build_rows=[],
        dataset_apps_total=2,
        dataset_apps_complete=0,
        dataset_valid_runs_total=6,
        current_build_ready_count=0,
        current_build_in_progress_count=1,
        current_build_review_count=0,
        stale_app_count=1,
        row_models=rows,
        expected_runs=10,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 6,
            "apps_satisfied": 0,
            "extra_eligible_runs": 0,
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
    assert "capture non-drift quota-impact rows first" in out
    assert "drift changes provenance labels, not evidence availability" in out


def test_resolve_live_build_drift_map_uses_identity_static_run_id_fallback(monkeypatch) -> None:
    monkeypatch.setattr(
        queue_data_sources,
        "load_plan_candidates",
        lambda package_name: (
            [
                {
                    "generated_at": "2026-06-30T00:00:00Z",
                    "version_name": "12.3.1-release.0",
                    "version_code": "312031000",
                    "identity": {
                        "version_code": "312031000",
                        "static_run_id": "5207",
                    },
                }
            ],
            None,
        ),
    )
    monkeypatch.setattr(
        queue_data_sources,
        "read_observed_version_code_details",
        lambda *_args, **_kwargs: {"version_code": "312040000"},
    )

    drift_map = queue_data_sources.resolve_live_build_drift_map(
        ["com.twitter.android"],
        device_serial="ZY22JK89DR",
    )

    assert drift_map == {
        "com.twitter.android": {
            "expected_version_code": "312031000",
            "expected_version_name": "12.3.1-release.0",
            "observed_version_code": "312040000",
            "static_run_id": "5207",
        }
    }


def test_build_package_selection_row_accepts_live_build_drift_for_refresh_action() -> None:
    row = menu_selection.build_package_selection_row(
        idx=2,
        package="com.cnn.mobile.android.phone",
        app_label="CNN",
        collisions=set(),
        dataset_pkgs={"com.cnn.mobile.android.phone"},
        tracker_apps={
            "com.cnn.mobile.android.phone": {
                "runs": [
                    {
                        "run_id": "run-1",
                        "version_code": "19127521",
                        "base_sha256": "abc123",
                    }
                ]
            }
        },
        cfg=_CfgFourInteractive(),
        recent_tracker_runs=lambda _package, limit=1: [
            SimpleNamespace(
                valid=False,
                run_id="run-1",
                invalid_reason_code="PCAP_MISSING",
                pcap_failure_detail="PCAP_LOCAL_FILE_MISSING",
            )
        ],
        live_build_drift={
            "observed_version_code": "19250507",
            "expected_version_code": "19127521",
            "expected_version_name": "8.4.50",
            "static_run_id": 4701,
        },
        db_lineage_context={
            "db_active_sessions": 1,
            "db_historical_sessions": 0,
            "db_total_sessions": 1,
        },
        truncate_visible_fn=lambda value, _limit: value,
        bucket_progress_label_fn=lambda count, required, extra_count=0, low_signal=0, need=0: (
            f"{count + extra_count + low_signal}/{required}" + (f" need {need}" if need else "")
        ),
        quota_progress_label_fn=lambda count, required, extra_count=0, low_signal=0: (
            f"{count}/{required}"
            + (f" +{extra_count + low_signal}" if (extra_count + low_signal) else "")
        ),
        static_build_label_fn=lambda active_runs, legacy_valid: (
            "current" if active_runs or not legacy_valid else "legacy"
        ),
        next_action_from_need_fn=lambda need: need,
        build_scoped_dataset_counts_fn=lambda _package, _runs, cfg: {
            "baseline_countable": 3,
            "baseline_extra": 0,
            "interactive_countable": 4,
            "interactive_extra": 0,
            "legacy_valid": 0,
            "legacy_builds": 0,
            "active_version_code": "19127521",
            "active_base_sha": "abc123",
            "technical_valid_active": 7,
        },
        resolve_tracker_run_identity_fn=lambda _package, run: (
            str(run.get("version_code") or "") or None,
            str(run.get("base_sha256") or "") or None,
        ),
    )

    assert row.live_build_drift is True
    assert row.full_row[5] == "refresh"
    assert row.next_label == "refresh static"
    assert row.prep_label == "stale"
