from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.manual import (
    ManualScenarioRunner,
    _build_baseline_connected_schedule,
    _build_template_hash,
    _extra_hold_timer_message,
    _parse_timing_action,
    _resolve_script_template,
    _run_messaging_connected_baseline,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import template_steps_for_id
from tests.dynamic._manual_protocol_support import _ctx


def test_whatsapp_text_activity_uses_behavior_v2_template(tmp_path: Path) -> None:
    ctx = replace(_ctx(tmp_path), package_name="com.whatsapp", messaging_activity="text_only")

    template_id, steps = _resolve_script_template(ctx)

    assert template_id == "whatsapp_text_behavior_v2"
    assert [step[0] for step in steps] == [
        "open_app",
        "open_control_chat",
        "send_text_1",
        "hold_15s_1",
        "send_text_2",
        "hold_15s_2",
        "send_text_3",
        "hold_15s_3",
        "receive_reply_or_wait",
        "send_emoji_optional",
        "send_small_image_optional",
        "return_chat_list",
        "hold_foreground",
    ]
    assert template_steps_for_id("whatsapp_text_behavior_v2") == steps


def test_whatsapp_text_behavior_v2_emits_message_metadata(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = replace(_ctx(tmp_path), package_name="com.whatsapp", messaging_activity="text_only")
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.get_choice",
        lambda *args, **kwargs: "3",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_yes_no",
        lambda *args, **kwargs: False,
    )

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )

    protocol = result.protocol or {}
    assert protocol["template_id"] == "whatsapp_text_behavior_v2"
    send_text_2 = next(
        details
        for event_type, details in events
        if event_type == "STEP_END" and details.get("step_id") == "send_text_2"
    )
    assert send_text_2["message_type"] == "text"
    assert send_text_2["traffic_phase"] == "text_send"
    assert send_text_2["repeat_group"] == "text_message"
    assert send_text_2["repeat_index"] == 2
    assert send_text_2["mutation_candidate"] is True
    assert send_text_2["mutation_performed"] is True
    reply_wait = next(
        details
        for event_type, details in events
        if event_type == "STEP_END" and details.get("step_id") == "receive_reply_or_wait"
    )
    assert reply_wait["message_type"] == "reply_or_sync"
    assert reply_wait["traffic_phase"] == "reply_or_sync_wait"


def test_facebook_behavior_v3_emits_traffic_phase_metadata(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)
    events: list[tuple[str, dict[str, object]]] = []
    choices = iter(["3", "0", "0"])

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.get_choice",
        lambda *args, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_yes_no",
        lambda *args, **kwargs: False,
    )

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )

    protocol = result.protocol or {}
    assert protocol["template_id"] == "facebook_behavior_v3"
    home_feed = next(
        details
        for event_type, details in events
        if event_type == "STEP_END" and details.get("step_id") == "home_feed"
    )
    assert home_feed["traffic_phase"] == "home_feed_hold"
    text_post = next(
        details
        for event_type, details in events
        if event_type == "STEP_END" and details.get("step_id") == "text_post_submit_1"
    )
    assert text_post["traffic_phase"] == "text_post_flow"
    assert text_post["mutation_candidate"] is True


def test_facebook_behavior_v3_has_consolidated_step_count() -> None:
    steps = template_steps_for_id("facebook_behavior_v3")
    assert steps is not None
    assert len(steps) == 44


def test_facebook_behavior_v3_merged_open_hold_pairs_use_view_pattern() -> None:
    steps = template_steps_for_id("facebook_behavior_v3")
    assert steps is not None
    step_map = {step_id: duration for step_id, _desc, duration in steps}
    legacy_split_ids = {
        "friend_suggestions_open",
        "friend_suggestions_hold",
        "friends_return",
        "friends_return_hold",
        "profile_return_settle",
        "marketplace_open",
        "marketplace_hold",
        "notifications_open",
        "notifications_hold",
    }
    merged_open_hold = {
        "friend_suggestions_view": 20,
        "friends_return_view": 20,
        "profile_return_home": 20,
        "marketplace_view": 25,
        "notifications_view": 20,
    }
    assert legacy_split_ids.isdisjoint(step_map)
    assert step_map.items() >= merged_open_hold.items()
    step_ids = [step_id for step_id, _desc, _duration in steps]
    for left, right in zip(step_ids, step_ids[1:], strict=False):
        assert not (left.endswith("_open") and right.endswith("_hold"))


def test_baseline_connected_v2_protocol_metadata(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r2",
        package_name="com.whatsapp",
        duration_seconds=1,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="baseline_connected",
        interaction_level="minimal",
        messaging_activity="connected_idle",
        device_serial="SERIAL",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_messaging_connected_baseline",
        lambda **_kwargs: datetime.now(UTC),
    )

    result = runner.run(ctx, on_protocol_event=lambda *_args, **_kwargs: None)
    protocol = result.protocol or {}
    assert protocol.get("baseline_protocol_id") == "baseline_connected_v2"
    assert protocol.get("baseline_protocol_version") == 2
    assert (
        isinstance(protocol.get("baseline_protocol_hash"), str)
        and len(str(protocol.get("baseline_protocol_hash"))) == 64
    )


def test_baseline_connected_schedule_is_deterministic_and_bounded() -> None:
    schedule_a, refresh_a = _build_baseline_connected_schedule(run_id="abc", target_duration_s=240)
    schedule_b, refresh_b = _build_baseline_connected_schedule(run_id="abc", target_duration_s=240)
    assert schedule_a == schedule_b
    assert refresh_a == refresh_b
    assert 90 <= int(refresh_a) <= 150
    for idx, t in enumerate(schedule_a):
        assert 0 < int(t) < 240
        if idx > 0:
            delta = int(schedule_a[idx]) - int(schedule_a[idx - 1])
            assert 45 <= delta <= 75


def test_baseline_connected_keeps_post_target_hold_enabled(monkeypatch, tmp_path: Path) -> None:
    ctx = replace(
        _ctx(tmp_path),
        dynamic_run_id="r-connected",
        package_name="com.facebook.orca",
        run_profile="baseline_connected",
        messaging_activity="connected_idle",
    )
    calls: list[dict[str, object]] = []

    def _fake_loop(*args, **kwargs):
        calls.append(dict(kwargs))
        return datetime.now(UTC)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_baseline_interactive_loop",
        _fake_loop,
    )

    _run_messaging_connected_baseline(
        run_ctx=ctx,
        target_duration_s=240,
        protocol={},
        on_protocol_event=None,
    )

    assert calls
    assert calls[0]["continue_after_target"] is True


def test_extra_hold_timer_message_uses_explicit_extra_hold_wording() -> None:
    message = _extra_hold_timer_message(
        target_duration_s=240,
        elapsed_s=330,
        timer_detail="connected baseline",
        suffix=" *",
    )

    assert message == (
        "Target reached: 4 Mins 0 Secs | extra hold: +1 Min 30 Secs | "
        "press Enter to finalize | connected baseline *"
    )


def test_voice_call_activity_hard_switches_to_call_template(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r3",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        messaging_activity="voice_call",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "whatsapp_voice_v1"


def test_video_call_activity_hard_switches_to_call_template(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r4",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        messaging_activity="video_call",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "whatsapp_video_v1"


def test_mixed_call_activity_hard_switches_to_call_template(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r5",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        messaging_activity="mixed",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "messaging_call_basic_v1"


def test_snapchat_uses_snapchat_template_override(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r6",
        package_name="com.snapchat.android",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "snapchat_basic_v1"


def test_twitter_uses_x_template_override(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r7",
        package_name="com.twitter.android",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "x_twitter_full_session_v1"


def test_whatsapp_uses_whatsapp_template_override(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r8",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        messaging_activity="none",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "whatsapp_idle_v1"


def test_facebook_uses_facebook_template_override(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r9",
        package_name="com.facebook.katana",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        device_serial="SERIAL",
    )
    template_id, _steps = _resolve_script_template(ctx)
    assert template_id == "facebook_behavior_v3"
    assert template_steps_for_id("facebook_basic_v2") is not None


def test_facebook_behavior_v3_template_hash_is_deterministic(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="r9",
        package_name="com.facebook.katana",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        device_serial="SERIAL",
    )
    template_id, steps = _resolve_script_template(ctx)

    assert template_id == "facebook_behavior_v3"
    assert _build_template_hash(template_id, steps) == _build_template_hash(template_id, steps)
    assert _build_template_hash(
        "facebook_basic_v2", template_steps_for_id("facebook_basic_v2") or ()
    ) != _build_template_hash(template_id, steps)


def test_news_reader_uses_subscription_aware_template(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="news",
        package_name="bbc.mobile.news.ww",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        device_serial="SERIAL",
    )
    template_id, steps = _resolve_script_template(ctx)

    assert template_id == "news_reader_behavior_v2"
    assert template_steps_for_id("news_reader_basic_v1") is not None
    assert _build_template_hash(template_id, steps) == _build_template_hash(template_id, steps)
    assert _build_template_hash(
        "news_reader_basic_v1", template_steps_for_id("news_reader_basic_v1") or ()
    ) != _build_template_hash(template_id, steps)


def test_timing_action_parses_skip_aliases() -> None:
    assert _parse_timing_action("n\n") == "skip"
    assert _parse_timing_action("skip\n") == "skip"


def test_timing_action_parses_limited_aliases() -> None:
    assert _parse_timing_action("l\n") == "limited"
    assert _parse_timing_action("limited\n") == "limited"


def test_timing_action_accepts_d_done_but_not_c_alias() -> None:
    assert _parse_timing_action("d\n") == "enter"
    assert _parse_timing_action("done\n") == "enter"
    assert _parse_timing_action("c\n") == "other"


def test_timing_action_supports_return_home_marker() -> None:
    assert _parse_timing_action("h\n") == "return_home"
    assert _parse_timing_action("return_home\n") == "return_home"


def test_read_device_foreground_package_parses_current_focus() -> None:
    import scytaledroid.DeviceAnalysis.adb.client as adb_client
    from scytaledroid.DynamicAnalysis.scenarios.manual import _read_device_foreground_package

    stdout = (
        "  mCurrentFocus=Window{abc u0 com.twitter.android/com.twitter.app.main.MainActivity}\n"
    )
    completed = SimpleNamespace(stdout=stdout)

    class _FakeClient:
        @staticmethod
        def is_available() -> bool:
            return True

        @staticmethod
        def run_shell_command(_serial, _command, timeout=10):
            return completed

    original = adb_client.is_available
    original_run = adb_client.run_shell_command
    try:
        adb_client.is_available = _FakeClient.is_available
        adb_client.run_shell_command = _FakeClient.run_shell_command
        assert _read_device_foreground_package("SERIAL") == "com.twitter.android"
    finally:
        adb_client.is_available = original
        adb_client.run_shell_command = original_run


def test_baseline_idle_checkpoint_messages_include_package() -> None:
    from scytaledroid.DynamicAnalysis.scenarios.manual import _baseline_idle_checkpoint_messages

    messages = _baseline_idle_checkpoint_messages("com.twitter.android")
    assert 60 in messages and 120 in messages
    assert "com.twitter.android" in messages[60]


def test_baseline_idle_checkpoint_messages_are_news_reader_specific() -> None:
    from scytaledroid.DynamicAnalysis.scenarios.manual import _baseline_idle_checkpoint_messages

    messages = _baseline_idle_checkpoint_messages("com.guardian")
    assert "calm article or section" in messages[60]
    assert "autoplay video" in messages[120]
