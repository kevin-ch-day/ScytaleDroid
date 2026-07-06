from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.controllers import guided_run
from scytaledroid.DynamicAnalysis.services.paper_freeze_readiness import (
    PaperFreezeBuildCandidate,
    PaperFreezeRecommendation,
)
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
        lambda: (
            device_calls.__setitem__("select", device_calls["select"] + 1) or ("ZY22JK89DR", "moto")
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "_device_preflight_checks",
        lambda _serial: (
            device_calls.__setitem__("preflight", device_calls["preflight"] + 1) or True
        ),
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
        assert default == "A"
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
    assert "A) Review QA" in out
    assert "(default)" in out
    assert "PCAP_DEVICE_FILE_MISSING" in out or "QA needs review" in out
    assert device_calls == {"select": 0, "preflight": 0}


def test_selected_app_protocol_options_allow_interaction_even_when_baseline_incomplete() -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=0,
        interactive_valid_runs=0,
        scripted_template_ready=True,
    )

    options = {
        option.key: option for option in guided_run._build_selected_app_protocol_options(app)
    }

    assert options["1"].description is None
    assert options["2"].description is None
    assert options["2"].disabled is False
    assert options["3"].description is None


def test_selected_app_workbench_accepts_interactive_selection_before_baseline_complete(
    monkeypatch,
) -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=0,
        interactive_valid_runs=0,
        scripted_template_ready=True,
    )
    app = guided_run._with_selected_app_display(
        app,
        package_name=app.package_name,
        display_label="TikTok",
    )
    app = guided_run.replace(app, queue_action="baseline", suggested_default_key="1")

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "2")

    choice = guided_run._render_selected_app_workbench(
        app=app,
        print_tier1_qa_result=None,
    )

    assert choice == "2"


def test_selected_app_protocol_options_mark_completed_quota_as_retained_extra() -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=3,
        interactive_valid_runs=4,
        scripted_template_ready=True,
    )

    options = {
        option.key: option for option in guided_run._build_selected_app_protocol_options(app)
    }

    assert options["1"].description is None
    assert options["2"].description is None
    assert options["2"].disabled is False
    assert options["3"].description is None


def test_supplemental_baseline_capture_skips_retained_extra_confirmation() -> None:
    cfg = SimpleNamespace(baseline_required=3, interactive_required=4)
    assert guided_run._is_supplemental_baseline_capture(
        selected_protocol="1",
        run_profile="baseline_idle",
        baseline_valid_runs=3,
        cfg=cfg,
    )
    assert not guided_run._is_supplemental_baseline_capture(
        selected_protocol="2",
        run_profile="interaction_scripted",
        baseline_valid_runs=3,
        cfg=cfg,
    )


def test_queue_action_suggests_supplemental_baseline_when_quota_met() -> None:
    from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
        selected_app_queue_action,
    )

    action, reason = selected_app_queue_action(
        baseline_valid_runs=3,
        interactive_valid_runs=4,
        baseline_required=3,
        interactive_required=4,
        scripted_template_ready=True,
        latest_valid=True,
        latest_invalid_reason=None,
        latest_pcap_failure_detail=None,
        db_active_sessions=1,
        active_valid_runs=7,
    )
    assert action == "supplemental baseline"
    assert "ML training" in str(reason or "")


def test_selected_app_workbench_groups_review_run_and_maintenance_actions(
    monkeypatch, capsys
) -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=3,
        interactive_valid_runs=4,
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
        assert default == "1"
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    guided_run._render_selected_app_workbench(
        app=app,
        print_tier1_qa_result=None,
    )

    out = capsys.readouterr().out
    assert "CNN" in out
    assert "Target build" in out
    assert "Evidence state" in out
    assert "QA valid" in out
    assert "quota 7/7" in out
    assert "Run Option" in out
    assert "1) Baseline run" in out
    assert "(default)" in out
    assert "ML training pool" in out
    assert "Reason:" not in out
    assert "suggested · counts toward quota" not in out
    assert "held until baseline complete" not in out
    assert "no saving" not in out
    assert "no device" not in out
    assert "enabled" not in out
    assert "1) Baseline run" in out
    assert "3) Test app" in out
    assert "Review / inspect" in out
    assert "A) Review QA" in out
    assert "H) Run history" in out
    assert "G) Diagnostics" in out
    assert "X) Reset app" in out
    assert "X) Reset app" in out
    assert "X) Reset app (default)" not in out
    assert "D) Reset app" not in out
    assert out.count("0) Back") == 1


def test_selected_app_workbench_allows_b_for_back(monkeypatch) -> None:
    app = make_protocol_options_app(
        baseline_valid_runs=0,
        interactive_valid_runs=0,
        scripted_template_ready=False,
    )
    app = guided_run._with_selected_app_display(
        app,
        package_name=app.package_name,
        display_label="LinkedIn",
    )
    app = guided_run.replace(app, can_reset=False, queue_action="baseline")

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "B")

    choice = guided_run._render_selected_app_workbench(app=app, print_tier1_qa_result=None)

    assert choice == "0"


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
    assert "2) Interactive run" in out
    assert "(default)" in out
    assert "3) Test app" in out
    assert "Reason:" not in out


def test_guided_run_reports_review_queue_action_for_invalid_complete_current_build(
    monkeypatch, capsys
) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
        lineage_context={
            "db_active_sessions": 6,
            "db_historical_sessions": 0,
            "db_total_sessions": 6,
        },
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=8,
            valid_runs=7,
            baseline_valid_runs=3,
            interactive_valid_runs=4,
            quota_met=True,
            local_evidence_dir_count=8,
            reset_available=True,
            paper_eligible_local=7,
            quota_counted_local=7,
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
    assert "Current build" in out
    assert "QA needs review" in out
    assert "A) Review QA" in out
    assert "(default)" in out
    assert "2) Interactive run" in out
    assert "2) Interactive run (default)" not in out


def test_selected_app_workbench_retained_prior_build_evidence_does_not_label_target_lost(
    monkeypatch, capsys
) -> None:
    package = "com.twitter.android"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="X (Twitter)",
        lineage_context={
            "db_active_sessions": 0,
            "db_historical_sessions": 14,
            "db_total_sessions": 14,
        },
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=3,
            valid_runs=3,
            baseline_valid_runs=0,
            interactive_valid_runs=0,
            local_evidence_dir_count=3,
            paper_eligible_local=0,
            quota_counted_local=0,
            historical_valid_runs=3,
            historical_build_count=1,
            historical_pcap_count=3,
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
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
    assert (
        "Retained prior-build evidence: 3 valid run(s) across 1 prior build(s) retained for analysis; not counted toward current-build quota."
        in out
    )
    assert "Target build    : unknown" in out
    assert "Current baseline: 0/3" in out
    assert "Current inter.  : 0/4" in out
    assert "Retained runs   : 3 valid prior-build run(s)" in out
    assert "Retained builds : 1" in out
    assert "Retained PCAPs  : 3" in out
    assert "retained prior-build evidence (local-only)" in out
    assert "Legacy build · historical evidence" not in out


def test_selected_app_workbench_whatsapp_like_prior_build_state_shows_retained_counts(
    monkeypatch, capsys
) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
        lineage_context={
            "db_active_sessions": 0,
            "db_historical_sessions": 8,
            "db_total_sessions": 8,
        },
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=8,
            valid_runs=0,
            baseline_valid_runs=0,
            interactive_valid_runs=0,
            local_evidence_dir_count=8,
            paper_eligible_local=0,
            quota_counted_local=0,
            active_version_code="262508000",
            historical_valid_runs=8,
            historical_build_count=1,
            historical_pcap_count=8,
            paper_freeze=PaperFreezeRecommendation(
                package_name=package,
                installed_target_version_code="262508000",
                installed_target_version_name="2.26.25.80",
                installed_target_static_run_id="5837",
                installed_target_base_apk_sha256="b696" * 16,
                selected_build=PaperFreezeBuildCandidate(
                    package_name=package,
                    version_code="262408020",
                    version_name="2.26.24.80",
                    static_run_id="5700",
                    base_apk_sha256="a" * 64,
                    strict_idle_runs=3,
                    quiescent_fg_runs=0,
                    baseline_valid_runs=3,
                    interactive_valid_runs=5,
                    valid_pcap_count=8,
                    qa_valid_count=8,
                    first_capture_at="2026-07-01T10:00:00Z",
                    last_capture_at="2026-07-01T10:35:00Z",
                    relation_to_active_target="prior-build",
                    missing_baseline_runs=0,
                    missing_interactive_runs=0,
                    status="ready",
                    static_run_ids=("5700", "5835"),
                ),
                build_candidates=(),
                refresh_candidate=True,
                retained_prior_build_selected=True,
            ),
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
            suggested_slot=1,
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
    assert "Target build    : 262508000" in out
    assert "Current baseline: 0/3" in out
    assert "Current inter.  : 0/4" in out
    assert "Retained runs   : 8 valid prior-build run(s)" in out
    assert "Retained builds : 1" in out
    assert "Retained PCAPs  : 8" in out
    assert "Paper target" in out
    assert "262408020 (prior-build, ready)" in out
    assert "Paper provenance" in out
    assert "2 static runs merged (5700, 5835)" in out
    assert "Paper target    : 262408020 (prior-build)" in out
    assert "Paper strict    : 3" in out
    assert "Paper q-fg      : 0" in out
    assert "Paper inter.    : 5" in out
    assert "Refresh candid. : yes" in out
    assert "Paper static IDs: 5700, 5835" in out
    assert "Paper provenance: merged across 2 static runs for the same build hash" in out
    assert "Retained prior-build evidence exists locally" in out
    assert "lost" not in out.lower()
