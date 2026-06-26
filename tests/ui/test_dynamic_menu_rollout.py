from __future__ import annotations

from types import SimpleNamespace

import pytest


pytestmark = [pytest.mark.ui_contract]


def test_dynamic_prepare_package_selection_view_uses_menu_adapter_without_extra_text_blocks_arg(monkeypatch):
    from scytaledroid.DynamicAnalysis import menu as menu_module
    from scytaledroid.DynamicAnalysis import menu_selection as menu_selection_module

    monkeypatch.setattr(
        menu_module,
        "list_packages",
        lambda _groups: [("com.example.app", None, None, "Example App")],
    )
    monkeypatch.setattr(menu_module, "active_research_cohort_packages", lambda: ("com.example.app",))
    monkeypatch.setattr(menu_module, "_summarize_evidence_quota", lambda _pkgs, _cfg: None)
    monkeypatch.setattr(
        menu_module,
        "_build_package_selection_row_impl",
        lambda **_kwargs: menu_module._PreparedPackageSelectionRow(
            full_row=["1", "Example App"],
            op_row=["Example App"],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=0,
            dataset_valid_runs_count=0,
        ),
    )

    from scytaledroid.DynamicAnalysis.pcap import dataset_tracker as tracker_module
    from scytaledroid.DynamicAnalysis.utils import run_cleanup as cleanup_module

    class _Cfg:
        baseline_required = 3
        interactive_required = 2

    monkeypatch.setattr(tracker_module, "DatasetTrackerConfig", _Cfg)
    monkeypatch.setattr(tracker_module, "load_dataset_tracker", lambda: {"apps": {}})
    monkeypatch.setattr(cleanup_module, "recent_tracker_runs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        menu_selection_module,
        "_resolve_db_dynamic_lineage_context_map",
        lambda *_args, **_kwargs: {},
    )

    prepared = menu_module._prepare_package_selection_view([SimpleNamespace(package_name="com.example.app")])

    assert prepared is not None
    assert prepared.rows == [["1", "Example App"]]
    assert prepared.dataset_apps_total == 1


def test_dynamic_choose_active_research_cohort_uses_simplified_wording(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis import menu as menu_module

    monkeypatch.setattr(
        menu_module,
        "chooseable_active_research_cohorts",
        lambda: [
            {
                "cohort_key": "research_dataset_alpha",
                "display_name": "Research Dataset Alpha",
                "active_member_count": 12,
            },
            {
                "cohort_key": "research_dataset_beta",
                "display_name": "Research Dataset Beta",
                "active_member_count": 15,
            },
        ],
    )
    monkeypatch.setattr(menu_module, "active_research_cohort_key", lambda: "research_dataset_beta")
    monkeypatch.setattr(menu_module, "persist_active_research_cohort_key", lambda *_a, **_k: "receipt.json")
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "2")

    selected = menu_module._choose_active_research_cohort()

    assert selected is not None
    out = capsys.readouterr().out
    assert "Select Cohort" in out
    assert "Choose the DB-backed app cohort used for dynamic runs and readiness review." in out
    assert "Research cohort" not in out
    assert "Select research cohort #" not in out
    assert "Cohort unchanged" not in out


def test_dynamic_state_summary_uses_shared_hint(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis import menu_reports as menu_module

    monkeypatch.setenv("SCYTALEDROID_UI_LEVEL", "")
    summary = SimpleNamespace(
        can_freeze=False,
        total_runs=1,
        paper_eligible_runs=0,
        first_failing_reason="NO_VALID_RUNS",
        report_path="output/report.json",
    )

    menu_module.run_state_summary_report(
        summary=summary,
        payload={},
        state_payload={},
        delta_rows=[],
        priorities=[],
    )

    out = capsys.readouterr().out
    assert "State Summary" in out
    assert "Compare tracker state" in out


def test_dynamic_state_summary_surfaces_repeatability_section(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis import menu_reports as menu_module

    monkeypatch.setenv("SCYTALEDROID_UI_LEVEL", "")
    summary = SimpleNamespace(
        can_freeze=False,
        total_runs=2,
        valid_runs=1,
        missing_run_manifest_dirs=0,
        evidence_root_exists=True,
        evidence_root="output/evidence/dynamic",
        tracker_runs_hint=0,
        report_path="output/report.json",
        reasons=(),
        first_failing_reason="NO_VALID_RUNS",
    )

    menu_module.run_state_summary_report(
        summary=summary,
        payload={},
        state_payload={
            "repeatability_summary": {
                "runs_repeatability_ready": 1,
                "runs_total": 2,
                "freeze_role": "canonical",
                "publication_manifests_present": True,
            }
        },
        delta_rows=[],
        priorities=[],
    )

    out = capsys.readouterr().out
    assert "Repeatability" in out
    assert "runs ready" in out
    assert "publication manifests" in out


def test_dynamic_state_summary_surfaces_active_research_cohort(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis import menu_reports as menu_module

    monkeypatch.setenv("SCYTALEDROID_UI_LEVEL", "")
    monkeypatch.setattr(menu_module, "active_research_cohort_label", lambda: "Research Dataset Beta")
    summary = SimpleNamespace(
        can_freeze=False,
        total_runs=1,
        valid_runs=1,
        missing_run_manifest_dirs=0,
        evidence_root_exists=True,
        evidence_root="output/evidence/dynamic",
        tracker_runs_hint=0,
        report_path="output/report.json",
        reasons=(),
        first_failing_reason="QUOTA_NOT_SATISFIED",
    )

    menu_module.run_state_summary_report(
        summary=summary,
        payload={},
        state_payload={},
        delta_rows=[],
        priorities=[],
    )

    out = capsys.readouterr().out
    assert "Research cohort" in out
    assert "Research Dataset Beta" in out
