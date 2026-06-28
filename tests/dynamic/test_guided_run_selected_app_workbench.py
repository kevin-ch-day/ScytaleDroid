from __future__ import annotations

import pytest

from scytaledroid.DynamicAnalysis.controllers import guided_run

from tests.dynamic._guided_run_state_support import (
    make_dataset_state,
    make_protocol_options_app,
    make_recent_summary,
    one_shot_package_selector,
    patch_guided_run_context,
)


pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_uses_dataset_state_for_summary_and_default(monkeypatch, capsys) -> None:
    package = "com.google.android.apps.messaging"
    select_package_calls, select_package = one_shot_package_selector(package)
    device_calls = {"select": 0, "preflight": 0}

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name=None,
    )
    monkeypatch.setattr(
        guided_run,
        "select_device",
        lambda: device_calls.__setitem__("select", device_calls["select"] + 1) or ("ZY22JK89DR", "moto"),
    )
    monkeypatch.setattr(
        guided_run,
        "_device_preflight_checks",
        lambda _serial: device_calls.__setitem__("preflight", device_calls["preflight"] + 1) or True,
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=2,
            valid_runs=1,
            baseline_valid_runs=0,
            interactive_valid_runs=1,
            quota_met=False,
            local_evidence_dir_count=1,
            paper_eligible_local=1,
            quota_counted_local=1,
            exclusion_reason_top=(("EXCLUDED_LOW_SIGNAL", 1),),
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
            recent_runs=(
                make_recent_summary(
                    ended_at="2026-04-16T12:00:00Z",
                    run_profile="baseline_idle",
                    interaction_level="minimal",
                    valid=False,
                    invalid_reason_code="PCAP_MISSING",
                    run_id="run12345",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
        ),
    )

    def _fake_choice(choices, *, default=None, disabled=None, **_kwargs):
        del choices
        assert default == "1"
        assert "X" in (disabled or [])
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )
    out = capsys.readouterr().out

    assert select_package_calls["count"] == 2
    assert "Selected app: com.google.android.apps.messaging" in out
    assert "App Queue / Next Action" not in out
    assert "Run readiness:" not in out
    assert "Press Enter to continue, V for details, or B to go back" not in out
    assert "Run Option" in out
    assert "1) Baseline run [default]" in out
    assert "Reason:" not in out
    assert device_calls == {"select": 0, "preflight": 0}


def test_selected_app_protocol_options_hold_interaction_until_baseline_complete() -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=0,
        interactive_valid_runs=0,
        scripted_template_ready=True,
    )

    options = {option.key: option for option in guided_run._build_selected_app_protocol_options(app)}

    assert str(options["1"].description) == "suggested · counts toward quota"
    assert str(options["2"].description) == "held until baseline complete"
    assert str(options["3"].description) == "no saving"


def test_selected_app_protocol_options_mark_completed_quota_as_supplemental() -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=3,
        interactive_valid_runs=2,
        scripted_template_ready=True,
    )

    options = {option.key: option for option in guided_run._build_selected_app_protocol_options(app)}

    assert str(options["1"].description) == "supplemental · outside quota"
    assert str(options["2"].description) == "supplemental · outside quota"
    assert str(options["3"].description) == "no saving"


def test_selected_app_workbench_groups_review_run_and_maintenance_actions(monkeypatch, capsys) -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=3,
        interactive_valid_runs=2,
        scripted_template_ready=True,
    )
    app = guided_run._with_selected_app_display(
        app,
        package_name=app.package_name,
        display_label="CNN",
    )
    app = guided_run.replace(
        app,
        can_reset=True,
        queue_action="—",
        latest_valid=True,
        suggested_default_key="3",
        suggested_is_interactive=True,
    )

    def _fake_choice(_choices, *, default=None, **_kwargs):
        assert default == "2"
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    guided_run._render_selected_app_workbench(
        app=app,
        print_tier1_qa_result=None,
    )

    out = capsys.readouterr().out
    assert "CNN" in out
    assert "Current build · current-build evidence (local+db) · QA valid · quota 5/5" in out
    assert "Run Option" in out
    assert "2) Interactive run [default]" in out
    assert "Reason:" not in out
    assert "1) Baseline run" in out
    assert "3) Test app" in out
    assert "Review / inspect" in out
    assert "A) Review QA" in out
    assert "H) Run history" in out
    assert "G) Diagnostics" in out
    assert "X) Reset app" in out
    assert "X) Reset app [default]" not in out
    assert "D) Reset app" not in out


def test_selected_app_workbench_allows_b_for_back(monkeypatch) -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=3,
        interactive_valid_runs=2,
        scripted_template_ready=True,
    )
    app = guided_run._with_selected_app_display(
        app,
        package_name=app.package_name,
        display_label="CNN",
    )
    app = guided_run.replace(
        app,
        queue_action="—",
        latest_valid=True,
        suggested_default_key="3",
        suggested_is_interactive=True,
    )

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "B")

    selected = guided_run._render_selected_app_workbench(
        app=app,
        print_tier1_qa_result=None,
    )

    assert selected == "0"


def test_guided_run_defaults_to_manual_when_script_template_missing(monkeypatch, capsys) -> None:
    package = "bbc.mobile.news.ww"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="BBC News",
    )
    monkeypatch.setattr(guided_run, "resolved_template_for_package", lambda _pkg: None)
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=3,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            quota_met=False,
            local_evidence_dir_count=3,
            paper_eligible_local=3,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
        ),
    )

    def _fake_choice(_choices, *, default=None, disabled=None, **_kwargs):
        assert default == "2"
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "BBC News" in out
    assert "2) Interactive run [default]" in out
    assert "3) Test app" in out
    assert "Reason:" not in out


def test_guided_run_reports_review_queue_action_for_invalid_complete_current_build(monkeypatch, capsys) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
        lineage_context={"db_active_sessions": 6, "db_historical_sessions": 0, "db_total_sessions": 6},
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=6,
            valid_runs=5,
            baseline_valid_runs=3,
            interactive_valid_runs=2,
            quota_met=True,
            local_evidence_dir_count=6,
            reset_available=True,
            paper_eligible_local=5,
            quota_counted_local=5,
            suggested_profile_from_tracker="interaction_scripted",
            effective_suggested_profile="interaction_scripted",
            suggested_slot=None,
            recent_runs=(
                make_recent_summary(
                    ended_at="2026-06-19T10:00:00Z",
                    run_profile="interaction_scripted",
                    interaction_level="scripted",
                    valid=False,
                    invalid_reason_code="PCAP_MISSING",
                    pcap_failure_detail="PCAP_DEVICE_FILE_MISSING",
                    run_id="cnnrun1",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Current build · current-build evidence (local+db) · QA needs review · quota 5/5" in out
    assert "A) Review QA [default]" in out
    assert "Reason: QA needs review; latest current-build QA invalid (PCAP_DEVICE_FILE_MISSING)." in out
    assert "2) Interactive run" in out
    assert "2) Interactive run [default]" not in out


def test_selected_app_latest_recent_summary_prefers_scoped_state_over_unscoped_recent_tracker(monkeypatch) -> None:
    package = "com.cnn.mobile.android.phone"
    state = make_dataset_state(
        package,
        total_runs=6,
        valid_runs=5,
        baseline_valid_runs=3,
        interactive_valid_runs=2,
        quota_met=True,
        recent_runs=(
            make_recent_summary(
                ended_at="2026-06-19T10:00:00Z",
                run_profile="interaction_scripted",
                interaction_level="scripted",
                valid=False,
                invalid_reason_code="PCAP_MISSING",
                pcap_failure_detail="PCAP_DEVICE_FILE_MISSING",
                run_id="cnnrun1",
                status_label="INVALID:PCAP_MISSING",
            ),
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "recent_tracker_runs",
        lambda _package_name, limit=1: [
            guided_run.SimpleNamespace(
                ended_at="2026-06-19T10:05:00Z",
                run_profile="baseline_idle",
                interaction_level="minimal",
                messaging_activity=None,
                valid=True,
                invalid_reason_code=None,
                pcap_failure_detail=None,
                low_signal=False,
                run_id="other-valid-run",
            )
        ],
    )

    summary = guided_run._selected_app_latest_recent_summary(package_name=package, state=state)

    assert getattr(summary, "run_id", None) == "cnnrun1"
    assert getattr(summary, "valid", None) is False
    assert getattr(summary, "invalid_reason_code", None) == "PCAP_MISSING"
