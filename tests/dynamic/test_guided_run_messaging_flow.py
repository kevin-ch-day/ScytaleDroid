from __future__ import annotations

import pytest

from scytaledroid.DynamicAnalysis.controllers import guided_run

from tests.dynamic._guided_run_state_support import (
    make_dataset_state,
    make_recent_summary,
    one_shot_package_selector,
    patch_guided_run_context,
)


pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_messaging_connected_baseline_wording_is_explicit(monkeypatch, capsys) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)
    choice_iter = iter(["1", "0"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *a, **k: next(choice_iter))

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Messaging Baseline Setup" in out
    assert "This app uses the messaging baseline policy." in out
    assert "Countable baseline evidence requires:" in out
    assert "1) Run connected-idle baseline" in out
    assert "2) Switch to manual interaction" in out
    assert "0) Cancel" in out
    assert "Ready now?" not in out
    assert "Connected-thread baseline is not ready." not in out
    assert "Run canceled. Start again when the app is ready for a connected-idle baseline or choose manual interaction." in out


def test_guided_run_messaging_baseline_setup_can_switch_to_manual(monkeypatch, capsys) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)
    choice_iter = iter(["1", "2"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter))

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: [],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Messaging Baseline Setup" in out
    assert "Switched to manual interaction." in out
    assert "Select at least one observer." in out


def test_guided_run_workbench_surfaces_messaging_connected_baseline_note(monkeypatch, capsys) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
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
        "Messaging baseline uses connected idle: open an existing conversation thread and keep it visible; no send/call."
        in out
    )


def test_guided_run_capture_setup_does_not_repeat_recent_tracker_runs(monkeypatch, capsys) -> None:
    package = "bbc.mobile.news.ww"
    select_package_calls, select_package = one_shot_package_selector(package)
    choices = iter(["1", "1"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="BBC News",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=1,
            valid_runs=0,
            baseline_valid_runs=0,
            interactive_valid_runs=0,
            local_evidence_dir_count=1,
            reset_available=True,
            exclusion_reason_top=(("EXCLUDED_LOW_SIGNAL", 1),),
            recent_runs=(
                make_recent_summary(
                    ended_at="2026-06-24T10:00:00Z",
                    run_profile="baseline_idle",
                    interaction_level="minimal",
                    messaging_activity=None,
                    valid=False,
                    invalid_reason_code="PCAP_MISSING",
                    run_id="bbc-run-1",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
            baseline_idle_pcap_missing_streak=1,
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices))
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)
    monkeypatch.setattr(guided_run, "ensure_plan_or_error", lambda *args, **kwargs: None)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Capture Setup" in out
    assert "Recent Tracker Runs" not in out
