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
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto")
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
    assert (
        "Run canceled. Start again when the app is ready for a connected-idle baseline or choose manual interaction."
        in out
    )


def test_guided_run_messaging_baseline_setup_can_switch_to_manual(monkeypatch, capsys) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)
    choice_iter = iter(["1", "2"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto")
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
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )

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


def test_guided_run_workbench_surfaces_messaging_connected_baseline_note(
    monkeypatch, capsys
) -> None:
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
    assert (
        "If login/setup is still in the way, use Interactive run -> Manual first. That preparation run is retained as extra evidence outside baseline quota."
        in out
    )


def test_guided_run_messaging_manual_preparation_flow_replaces_double_warning(
    monkeypatch, capsys
) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)
    choices = iter(["2", "1", "1"])
    yes_no_calls: list[tuple[str, bool]] = []

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            baseline_valid_runs=0,
            interactive_valid_runs=0,
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "prompt_yes_no",
        lambda prompt, default=False, **_kwargs: (
            yes_no_calls.append((prompt, bool(default))) or True
        ),
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: [],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Messaging preparation run" in out
    assert "Baseline progress" in out
    assert "Counts toward quota" in out
    assert "Retained as" in out
    assert "Manual preparation run is allowed for setup-sensitive messaging apps." in out
    assert (
        "This run will be retained as extra evidence; return afterward for a clean baseline capture."
        in out
    )
    assert "Proceed with interaction anyway?" not in out
    assert "Proceed with retained extra run anyway?" not in out
    assert yes_no_calls == [("Start manual preparation run?", True)]
    assert "Messaging Activity (Tag)" in out
    assert "Select at least one observer." in out


def test_guided_run_manual_messaging_activity_menu_is_freeform_first(monkeypatch, capsys) -> None:
    package = "com.whatsapp"
    select_package_calls, select_package = one_shot_package_selector(package)
    choices = iter(["2", "1", "1"])
    captured_menu: dict[str, object] = {}

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
        ),
    )
    monkeypatch.setattr(
        guided_run.menu_utils,
        "render_menu",
        lambda spec: captured_menu.setdefault(
            "items",
            [(str(item.key), str(item.label), str(item.description or "")) for item in spec.items],
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: [],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Messaging Activity (Tag)" in out
    assert "Choose the primary manual activity tag." in out
    assert "Use Voice/Video Call for dedicated call captures" in out
    assert captured_menu["items"] == [
        (
            "1",
            "Freeform / setup",
            "unstructured setup, account recovery, browsing, or exploratory use; not a specific text/call claim",
        ),
        ("2", "Text", "manual text/chat-focused interaction"),
        ("3", "Voice Call", "manual call-focused interaction"),
        ("4", "Video Call", "manual video-call-focused interaction"),
        (
            "5",
            "Mixed known activities",
            "intentional multi-activity capture, such as text plus voice/video in one run",
        ),
    ]
    assert "Select at least one observer." in out


def test_guided_run_manual_messaging_activity_warns_when_mixed_selected(
    monkeypatch, capsys
) -> None:
    package = "org.telegram.messenger"
    select_package_calls, select_package = one_shot_package_selector(package)
    choices = iter(["2", "1", "5"])
    recorded: dict[str, object] = {}

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Telegram",
    )
    monkeypatch.setattr(
        guided_run,
        "_prepare_selected_app_capture",
        lambda **_k: ("ZY22JK89DR", "moto"),
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices))
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)
    monkeypatch.setattr(guided_run.time, "sleep", lambda *_args, **_kwargs: None)

    def _capture_spec(**kwargs):
        recorded.update(kwargs)
        raise RuntimeError("stop after spec")

    monkeypatch.setattr(guided_run, "build_dynamic_run_spec", _capture_spec)

    with pytest.raises(RuntimeError, match="stop after spec"):
        guided_run.run_guided_dataset_run(
            select_package_from_groups=select_package,
            select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
            print_device_badge=lambda *_args: None,
        )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 1
    assert recorded["messaging_activity"] == "manual_mixed"
    assert "Mixed is for intentional multi-activity captures." in out
    assert "choose Voice Call or Video Call so the call outcome is recorded directly" in out


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
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(guided_run, "ensure_plan_or_error", lambda *args, **kwargs: None)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Capture setup" in out
    assert "Recent Tracker Runs" not in out


def test_guided_run_non_messaging_interaction_shows_baseline_requirement_card(
    monkeypatch, capsys
) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)
    choices = iter(["2", "1"])
    yes_no_calls: list[tuple[str, bool]] = []

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_k: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            baseline_valid_runs=1,
            interactive_valid_runs=0,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "prompt_yes_no",
        lambda prompt, default=False, **_kwargs: (
            yes_no_calls.append((prompt, bool(default))) or False
        ),
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Baseline requirement" in out
    assert "Baseline progress" in out
    assert "Recommended next run" in out
    assert "Recommended next run is baseline." in out
    assert yes_no_calls == [("Proceed with interaction anyway?", False)]
