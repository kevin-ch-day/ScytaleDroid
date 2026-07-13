from __future__ import annotations

from scytaledroid.DynamicAnalysis.scenarios.adb_automation import (
    AutomationAction,
    DeviceGeometry,
    adb_input_text,
    build_safe_fuzz_plan,
    build_x_twitter_plan,
    foreground_package_from_window_dump,
    parse_wm_size,
    run_automation_actions,
)


def test_parse_wm_size_returns_geometry() -> None:
    geometry = parse_wm_size("Physical size: 720x1612\n")

    assert geometry.width == 720
    assert geometry.height == 1612


def test_foreground_package_from_window_dump_parses_current_focus() -> None:
    output = "mCurrentFocus=Window{abc u0 com.twitter.android/com.twitter.app.main.MainActivity}"

    assert foreground_package_from_window_dump(output) == "com.twitter.android"


def test_foreground_package_from_window_dump_parses_top_resumed_activity() -> None:
    output = (
        "topResumedActivity=ActivityRecord{2c684ee u0 "
        "com.instagram.android/com.instagram.mainactivity.MainActivity t70}"
    )

    assert foreground_package_from_window_dump(output) == "com.instagram.android"


def test_ratio_actions_scale_to_device_geometry() -> None:
    action = AutomationAction("tap center", "tap", (0.5, 0.25))

    assert action.adb_command(DeviceGeometry(width=1000, height=2000)) == [
        "input",
        "tap",
        "500",
        "500",
    ]


def test_adb_input_text_escapes_spaces_and_percent() -> None:
    assert adb_input_text("android privacy 100%") == "android%sprivacy%s100%25"


def test_x_plan_is_non_mutating_by_default() -> None:
    actions = build_x_twitter_plan(duration_s=60)
    labels = [action.label for action in actions]

    assert "open search/explore tab" in labels
    assert "open Grok tab" in labels
    assert "open compose" not in labels
    assert not any(action.mutation_candidate for action in actions)


def test_x_plan_requires_explicit_mutation_for_compose() -> None:
    actions = build_x_twitter_plan(duration_s=80, allow_mutation=True)
    labels = [action.label for action in actions]

    assert "open compose" in labels
    assert "type labeled test draft" in labels
    assert "submit labeled test post" not in labels
    assert any(action.mutation_candidate for action in actions)


def test_x_plan_submit_test_post_is_separate_flag() -> None:
    actions = build_x_twitter_plan(duration_s=80, allow_mutation=True, submit_test_post=True)

    assert "submit labeled test post" in [action.label for action in actions]


def test_safe_fuzz_is_deterministic_and_non_mutating_by_default() -> None:
    actions_a = build_safe_fuzz_plan(duration_s=20, seed=42)
    actions_b = build_safe_fuzz_plan(duration_s=20, seed=42)

    assert actions_a == actions_b
    assert actions_a
    assert not any(action.mutation_candidate for action in actions_a)


def test_run_automation_actions_dry_run_does_not_execute() -> None:
    executed: list[list[str]] = []
    counts = run_automation_actions(
        serial="SERIAL",
        actions=[AutomationAction("tap", "tap", (0.5, 0.5), 0.0)],
        geometry=DeviceGeometry(width=100, height=200),
        dry_run=True,
        run_shell=lambda _serial, command: executed.append(command) or "",
        sleep=lambda _seconds: None,
    )

    assert executed == []
    assert counts["planned"] == 1
    assert counts["executed"] == 0
    assert counts["skipped_dry_run"] == 1


def test_run_automation_actions_executes_scaled_command() -> None:
    executed: list[list[str]] = []
    counts = run_automation_actions(
        serial="SERIAL",
        actions=[AutomationAction("tap", "tap", (0.5, 0.5), 0.0)],
        geometry=DeviceGeometry(width=100, height=200),
        dry_run=False,
        run_shell=lambda _serial, command: executed.append(command) or "",
        sleep=lambda _seconds: None,
    )

    assert executed == [["input", "tap", "50", "100"]]
    assert counts["planned"] == 1
    assert counts["executed"] == 1


def test_run_automation_actions_recovers_foreground_before_action() -> None:
    executed: list[list[str]] = []
    foreground = iter(["com.android.chrome", "com.twitter.android", "com.twitter.android"])

    counts = run_automation_actions(
        serial="SERIAL",
        actions=[AutomationAction("tap", "tap", (0.5, 0.5), 0.0)],
        geometry=DeviceGeometry(width=100, height=200),
        expected_package="com.twitter.android",
        run_shell=lambda _serial, command: executed.append(command) or "",
        foreground_reader=lambda _serial: next(foreground),
        sleep=lambda _seconds: None,
    )

    assert executed == [["input", "keyevent", "BACK"], ["input", "tap", "50", "100"]]
    assert counts["executed"] == 1
    assert counts["foreground_recoveries"] == 1
    assert counts["blocked_foreground"] == 0


def test_run_automation_actions_blocks_action_when_foreground_cannot_recover() -> None:
    executed: list[list[str]] = []

    counts = run_automation_actions(
        serial="SERIAL",
        actions=[AutomationAction("tap", "tap", (0.5, 0.5), 0.0)],
        geometry=DeviceGeometry(width=100, height=200),
        expected_package="com.twitter.android",
        run_shell=lambda _serial, command: executed.append(command) or "",
        foreground_reader=lambda _serial: "com.android.chrome",
        sleep=lambda _seconds: None,
    )

    assert executed == [
        ["input", "keyevent", "BACK"],
        ["input", "keyevent", "BACK"],
        [
            "monkey",
            "-p",
            "com.twitter.android",
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
    ]
    assert counts["executed"] == 0
    assert counts["foreground_recoveries"] == 3
    assert counts["blocked_foreground"] == 1


def test_run_automation_actions_dry_run_skips_foreground_checks() -> None:
    counts = run_automation_actions(
        serial="SERIAL",
        actions=[AutomationAction("tap", "tap", (0.5, 0.5), 0.0)],
        geometry=DeviceGeometry(width=100, height=200),
        dry_run=True,
        expected_package="com.twitter.android",
        foreground_reader=lambda _serial: (_ for _ in ()).throw(AssertionError("no check")),
        sleep=lambda _seconds: None,
    )

    assert counts["skipped_dry_run"] == 1
    assert counts["foreground_checks"] == 0
