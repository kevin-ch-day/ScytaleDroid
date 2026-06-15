from __future__ import annotations

from scytaledroid.DynamicAnalysis import menu_selection
from scytaledroid.DynamicAnalysis import tracker_scope


class _Cfg:
    baseline_required = 3
    interactive_required = 2


def test_run_package_selection_menu_uses_operator_friendly_progress_labels(monkeypatch, capsys) -> None:
    prepared = menu_selection.PreparedPackageSelectionView(
        packages=[("bbc.mobile.news.ww", None, None, "BBC News")],
        dataset_pkgs={"bbc.mobile.news.ww"},
        cfg=_Cfg(),
        rows=[],
        op_rows=[["1", "BBC News", "0/3 need 3", "locked", "0/5", "ready", "—", "baseline"]],
        build_rows=[],
        dataset_apps_total=1,
        dataset_apps_complete=0,
        dataset_valid_runs_total=0,
        expected_runs=5,
        evidence_summary={
            "evidence_root_exists": True,
            "quota_runs_counted": 1,
            "apps_satisfied": 0,
            "extra_eligible_runs": 2,
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
    assert "Runs complete     : 1 / 5" in out
    assert "Apps complete     : 0 / 1" in out
    assert "Archive readiness : blocked — 4 runs remaining" in out
    assert "Supplemental runs : 2 extra valid run(s) retained outside quota" in out
    assert "Recommended next  : BBC News — baseline" in out
    assert "Freeze/export" not in out
    assert "Next recommended run" not in out
    assert "Select an app by number or name." in out
    assert "S summary" in out
    assert "Y history" in out
    assert "H help" in out
    assert "D diagnostics" in out
    assert "B back" in out


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
