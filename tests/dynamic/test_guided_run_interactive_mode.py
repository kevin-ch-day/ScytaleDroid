from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.controllers import guided_run
from tests.dynamic._guided_run_state_support import (
    make_dataset_state,
    make_recent_summary,
    one_shot_package_selector,
    patch_guided_run_context,
)

pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_choose_interactive_mode_shows_manual_and_scripted_when_template_available(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "news_reader_basic_v1"
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

    choice = guided_run._choose_interactive_mode(
        package_name="com.cnn.mobile.android.phone",
        scripted_template_ready=True,
    )

    out = capsys.readouterr().out
    assert choice == "interaction_manual"
    assert "Interactive Mode" in out
    assert "1) Manual interactive run" in out
    assert "(default)" in out
    assert "2) Scripted interactive run: news_reader_basic_v1" in out
    assert "0) Back" in out


def test_choose_interactive_mode_shows_scripted_unavailable_without_template(
    monkeypatch, capsys
) -> None:
    captured: dict[str, object] = {}

    def _fake_choice(_choices, *, default=None, disabled=None, **_kwargs):
        captured["default"] = default
        captured["disabled"] = list(disabled or [])
        return "1"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    choice = guided_run._choose_interactive_mode(
        package_name="com.example.no.script",
        scripted_template_ready=False,
    )

    out = capsys.readouterr().out
    assert choice == "interaction_manual"
    assert "2) Scripted interactive run (unavailable" in out
    assert "unavailable" in out
    assert "no template" in out
    assert captured["default"] == "1"
    assert captured["disabled"] == ["2"]


def test_guided_run_interactive_manual_path_builds_manual_spec(monkeypatch) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)
    recorded: dict[str, object] = {}

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "news_reader_basic_v1"
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            local_evidence_dir_count=3,
            paper_eligible_local=3,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
        ),
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_kwargs: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *args, **kwargs: {"plan_path": "/tmp/fake-plan.json", "static_run_id": 5065},
    )
    monkeypatch.setattr(guided_run, "print_plan_selection_banner", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guided_run, "_pre_run_scientific_checks", lambda **_kwargs: True)
    monkeypatch.setattr(guided_run.time, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)
    choice_iter = iter(["2", "1"])
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )

    def _capture_spec(**kwargs):
        recorded.update(kwargs)
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(guided_run, "build_dynamic_run_spec", _capture_spec)
    monkeypatch.setattr(
        guided_run,
        "execute_dynamic_run_spec",
        lambda _spec: (_ for _ in ()).throw(RuntimeError("stop after spec")),
    )

    with pytest.raises(RuntimeError, match="stop after spec"):
        guided_run.run_guided_dataset_run(
            select_package_from_groups=select_package,
            select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
            print_device_badge=lambda *_args: None,
        )

    assert select_package_calls["count"] == 1
    assert recorded["run_profile"] == "interaction_manual"
    assert recorded["interaction_level"] == "manual"
    assert recorded["interactive"] is True


def test_guided_run_interactive_scripted_path_builds_scripted_spec(monkeypatch) -> None:
    package = "com.cnn.mobile.android.phone"
    recorded: dict[str, object] = {}
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "news_reader_basic_v1"
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            local_evidence_dir_count=3,
            paper_eligible_local=3,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_scripted",
            effective_suggested_profile="interaction_scripted",
            suggested_slot=4,
        ),
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_kwargs: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *args, **kwargs: {"plan_path": "/tmp/fake-plan.json", "static_run_id": 5065},
    )
    monkeypatch.setattr(guided_run, "print_plan_selection_banner", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guided_run, "_pre_run_scientific_checks", lambda **_kwargs: True)
    monkeypatch.setattr(guided_run.time, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)
    choice_iter = iter(["2", "2"])
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )

    def _capture_spec(**kwargs):
        recorded.update(kwargs)
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(guided_run, "build_dynamic_run_spec", _capture_spec)
    monkeypatch.setattr(
        guided_run,
        "execute_dynamic_run_spec",
        lambda _spec: (_ for _ in ()).throw(RuntimeError("stop after spec")),
    )

    with pytest.raises(RuntimeError, match="stop after spec"):
        guided_run.run_guided_dataset_run(
            select_package_from_groups=select_package,
            select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
            print_device_badge=lambda *_args: None,
        )

    assert select_package_calls["count"] == 1
    assert recorded["run_profile"] == "interaction_scripted"
    assert recorded["interaction_level"] == "scripted"
    assert recorded["interactive"] is True


def test_guided_run_manual_messaging_path_builds_freeform_tagged_spec(monkeypatch) -> None:
    package = "com.whatsapp"
    recorded: dict[str, object] = {}
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="WhatsApp",
    )
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "whatsapp_basic_v1"
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            local_evidence_dir_count=3,
            paper_eligible_local=3,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
        ),
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_kwargs: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *args, **kwargs: {"plan_path": "/tmp/fake-plan.json", "static_run_id": 5215},
    )
    monkeypatch.setattr(guided_run, "print_plan_selection_banner", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guided_run, "_pre_run_scientific_checks", lambda **_kwargs: True)
    monkeypatch.setattr(guided_run.time, "sleep", lambda *_args, **_kwargs: None)
    choice_iter = iter(["2", "1", "1"])
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    def _capture_spec(**kwargs):
        recorded.update(kwargs)
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(guided_run, "build_dynamic_run_spec", _capture_spec)
    monkeypatch.setattr(
        guided_run,
        "execute_dynamic_run_spec",
        lambda _spec: (_ for _ in ()).throw(RuntimeError("stop after spec")),
    )

    with pytest.raises(RuntimeError, match="stop after spec"):
        guided_run.run_guided_dataset_run(
            select_package_from_groups=select_package,
            select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
            print_device_badge=lambda *_args: None,
        )

    assert select_package_calls["count"] == 1
    assert recorded["run_profile"] == "interaction_manual"
    assert recorded["interaction_level"] == "manual"
    assert recorded["messaging_activity"] == "manual_freeform"


def test_guided_run_interactive_mode_back_returns_without_capture(monkeypatch) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)
    prepare_calls = {"count": 0}

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "news_reader_basic_v1"
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            local_evidence_dir_count=3,
            paper_eligible_local=3,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "_prepare_selected_app_capture",
        lambda **_kwargs: (
            prepare_calls.__setitem__("count", prepare_calls["count"] + 1) or ("ZY22JK89DR", "moto")
        ),
    )
    choice_iter = iter(["2", "0"])
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )


def test_guided_run_qfg_held_interactive_warning_uses_retained_interactive_language(
    monkeypatch, capsys
) -> None:
    package = "com.zhiliaoapp.musically"
    select_package_calls, select_package = one_shot_package_selector(package)
    prompts: list[tuple[str, bool]] = []
    answers = iter([True, False])
    choices = iter(["2", "1"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="TikTok",
    )
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "tiktok_basic_v1"
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            valid_runs=9,
            baseline_valid_runs=0,
            interactive_valid_runs=2,
            baseline_not_idle_valid=7,
            local_evidence_dir_count=9,
            paper_eligible_local=9,
            quota_counted_local=2,
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
        ),
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_kwargs: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "prompt_yes_no",
        lambda prompt, default=False, **_kwargs: (
            prompts.append((prompt, bool(default))) or next(answers)
        ),
    )
    monkeypatch.setattr(guided_run, "ensure_plan_or_error", lambda *_a, **_k: pytest.fail("should not reach plan selection"))

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Strict Idle progress" in out
    assert "0/3" in out
    assert "Quiescent FG evidence" in out
    assert "7 valid no-touch run(s)" in out
    assert "Recommended strict-quota run" in out
    assert "strict-idle baseline" in out
    assert "Strict quota" in out
    assert "held until Strict Idle is complete" in out
    assert "Interactive run" in out
    assert "retained as current-build evidence" in out
    assert "Baseline progress: 0/3 valid baseline runs" not in out
    assert "Recommended next run is baseline." not in out
    assert "Counts toward quota: not until baseline is complete" not in out
    assert "Interactive run allowed under strict-idle hold." in out
    assert "retained as current-build interactive evidence" in out
    assert "Selected intent is not quota-suggested and will be saved as retained extra evidence" not in out
    assert prompts == [
        ("Proceed with interaction anyway?", False),
        ("Proceed with retained interactive evidence run anyway?", False),
    ]
    assert "Run canceled. Strict Idle is still incomplete; choose baseline if you want strict quota progress." in out


def test_guided_run_qfg_held_interactive_quota_line_uses_current_build_evidence_language(
    monkeypatch, capsys
) -> None:
    package = "com.zhiliaoapp.musically"
    select_package_calls, select_package = one_shot_package_selector(package)
    prompts: list[tuple[str, bool]] = []
    answers = iter([True, True])
    choices = iter(["2", "1"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="TikTok",
    )
    monkeypatch.setattr(
        guided_run, "resolved_template_for_package", lambda _pkg: "tiktok_basic_v1"
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            valid_runs=9,
            baseline_valid_runs=0,
            interactive_valid_runs=2,
            baseline_not_idle_valid=7,
            local_evidence_dir_count=9,
            paper_eligible_local=9,
            quota_counted_local=2,
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
        ),
    )
    monkeypatch.setattr(
        guided_run, "_prepare_selected_app_capture", lambda **_kwargs: ("ZY22JK89DR", "moto")
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "prompt_yes_no",
        lambda prompt, default=False, **_kwargs: (
            prompts.append((prompt, bool(default))) or next(answers)
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *_a, **_k: pytest.fail("stop after quota line"),
    )

    with pytest.raises(pytest.fail.Exception):
        guided_run.run_guided_dataset_run(
            select_package_from_groups=select_package,
            select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
            print_device_badge=lambda *_args: None,
        )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 1
    assert prompts == [
        ("Proceed with interaction anyway?", False),
        ("Proceed with retained interactive evidence run anyway?", False),
    ]
    assert "Cohort quota: NO · retained current-build interactive evidence (strict-idle hold)" in out


def test_selected_app_latest_recent_summary_prefers_scoped_state_over_unscoped_recent_tracker(
    monkeypatch,
) -> None:
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
