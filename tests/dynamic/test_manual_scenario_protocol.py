from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.manual import (
    ManualScenarioRunner,
    ScenarioAbortRequested,
    SCRIPT_LIMITATION_REASON_LABELS,
    _StopScriptEarly,
    _build_baseline_connected_schedule,
    _build_template_hash,
    _confirm_script_exit,
    _parse_timing_action,
    _resolve_script_template,
    _wait_for_step_completion_with_stopwatch,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import template_steps_for_id


def _ctx(tmp_path: Path) -> RunContext:
    run_dir = tmp_path / "run"
    return RunContext(
        dynamic_run_id="r1",
        package_name="com.facebook.katana",
        duration_seconds=1,
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


def test_scripted_protocol_emits_markers_and_metadata(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)
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

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )
    protocol = result.protocol or {}
    assert protocol.get("script_hash")
    assert int(protocol.get("step_count_planned") or 0) > 0
    assert protocol.get("script_end_marker") is True
    assert protocol.get("script_exit_code") == 0
    event_types = [event_type for event_type, _details in events]
    assert "SCRIPT_START" in event_types
    assert "SCRIPT_END" in event_types
    assert event_types.count("STEP_START") == int(protocol.get("step_count_planned"))
    assert event_types.count("STEP_END") == int(protocol.get("step_count_planned"))
    assert protocol.get("account_context") == "control_test_account"
    assert protocol.get("control_account_mode") == "control_account_active"
    text_submit = next(
        details
        for event_type, details in events
        if event_type == "STEP_END" and details.get("step_id") == "text_post_submit_1"
    )
    assert text_submit["mutation_performed"] is True
    assert text_submit["repeat_group"] == "text_post_submit"
    assert text_submit["repeat_index"] == 1
    assert text_submit["repeat_total"] == 3


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
        details for event_type, details in events if event_type == "STEP_END" and details.get("step_id") == "home_feed"
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
    for left, right in zip(step_ids, step_ids[1:]):
        assert not (left.endswith("_open") and right.endswith("_hold"))


def test_scripted_protocol_step_prompt_wording_is_compact(monkeypatch, tmp_path: Path, capsys) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)

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

    runner.run(ctx, on_protocol_event=lambda *_args, **_kwargs: None)

    out = capsys.readouterr().out
    assert "Scripted interactive run" in out
    assert "Template: facebook_behavior_v3" in out
    assert "Plan: 44 steps" in out
    assert "Controls: D=done | L=limited | N=skip | H=return home/reset | S=stop/finalize | A=abort" in out
    assert "Tip: use D+Enter, L+Enter, or N+Enter. Avoid Ctrl+C." in out
    assert "Action: D=done | L=limited | N=skip | H=return home/reset" in out
    assert "Use D+Enter to complete this step. Enter alone still works." not in out
    assert "If Enter feels flaky" not in out


def test_facebook_behavior_no_repeat_plan_skips_optional_repeats(monkeypatch, tmp_path: Path) -> None:
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

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )

    protocol = result.protocol or {}
    skipped = [
        details
        for event_type, details in events
        if event_type == "STEP_END" and details.get("step_outcome") == "skipped_optional_repeat"
    ]
    assert protocol["repeat_plan"] == {
        "text_post_submit": 1,
        "photo_post_submit": 1,
        "friend_request_accept": 2,
    }
    assert any(row["step_id"] == "text_post_submit_2" for row in skipped)
    assert any(row["step_id"] == "photo_post_submit_3" for row in skipped)
    assert all(row["repeat_enabled"] is False for row in skipped)


def test_confirm_script_exit_requires_explicit_finalize(monkeypatch) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_text",
        lambda message, required=False: prompts.append(message) or "",
    )

    assert _confirm_script_exit("stop") is False
    assert prompts == [
        "Finalize early? This may make the run invalid. Type FINALIZE to continue, or Enter to cancel."
    ]


def test_confirm_script_exit_requires_explicit_abort(monkeypatch) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_text",
        lambda message, required=False: prompts.append(message) or "",
    )

    assert _confirm_script_exit("abort") is False
    assert prompts == [
        "Abort and discard this run? Type ABORT to continue, or Enter to cancel."
    ]


def test_scripted_step_blank_input_is_ignored_then_done(monkeypatch) -> None:
    class _FakeIn:
        def __init__(self, lines):
            self._lines = iter(lines)

        def isatty(self):
            return True

        def readline(self):
            return next(self._lines)

    class _FakeOut:
        def __init__(self):
            self.buf = []

        def isatty(self):
            return True

        def write(self, text):
            self.buf.append(text)
            return len(text)

        def flush(self):
            return None

    fake_in = _FakeIn(["\n", "d\n"])
    fake_out = _FakeOut()
    select_results = iter([([fake_in], [], []), ([fake_in], [], [])])
    def _fake_select(*_args, **_kwargs):
        try:
            return next(select_results)
        except StopIteration:
            return ([], [], [])

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin", fake_in)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdout", fake_out)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking", lambda **_kwargs: None)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.select.select",
        _fake_select,
    )

    result = _wait_for_step_completion_with_stopwatch(
        step_index=1,
        step_count=6,
        step_id="open_home",
        script_started_monotonic=0.0,
        step_started_monotonic=0.0,
        target_duration_s=240,
    )

    assert result == ("completed", None, None)


def test_scripted_step_stop_requires_confirmation_and_can_cancel(monkeypatch) -> None:
    class _FakeIn:
        def __init__(self, lines):
            self._lines = iter(lines)

        def isatty(self):
            return True

        def readline(self):
            return next(self._lines)

    class _FakeOut:
        def write(self, _text):
            return 0

        def flush(self):
            return None

        def isatty(self):
            return True

    fake_in = _FakeIn(["s\n", "d\n"])
    fake_out = _FakeOut()
    select_results = iter([([fake_in], [], []), ([fake_in], [], [])])
    prompts: list[str] = []
    def _fake_select(*_args, **_kwargs):
        try:
            return next(select_results)
        except StopIteration:
            return ([], [], [])

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin", fake_in)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdout", fake_out)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking", lambda **_kwargs: None)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.select.select",
        _fake_select,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_text",
        lambda message, required=False: prompts.append(message) or "",
    )

    result = _wait_for_step_completion_with_stopwatch(
        step_index=1,
        step_count=6,
        step_id="open_home",
        script_started_monotonic=0.0,
        step_started_monotonic=0.0,
        target_duration_s=240,
    )

    assert result == ("completed", None, None)
    assert prompts == [
        "Finalize early? This may make the run invalid. Type FINALIZE to continue, or Enter to cancel."
    ]


def test_scripted_step_stop_requires_finalize_confirmation(monkeypatch) -> None:
    class _FakeIn:
        def __init__(self, lines):
            self._lines = iter(lines)

        def isatty(self):
            return True

        def readline(self):
            return next(self._lines)

    class _FakeOut:
        def write(self, _text):
            return 0

        def flush(self):
            return None

        def isatty(self):
            return True

    fake_in = _FakeIn(["s\n"])
    fake_out = _FakeOut()
    select_results = iter([([fake_in], [], [])])
    def _fake_select(*_args, **_kwargs):
        try:
            return next(select_results)
        except StopIteration:
            return ([], [], [])

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin", fake_in)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdout", fake_out)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking", lambda **_kwargs: None)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.select.select",
        _fake_select,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_text",
        lambda message, required=False: "FINALIZE",
    )

    try:
        _wait_for_step_completion_with_stopwatch(
            step_index=1,
            step_count=6,
            step_id="open_home",
            script_started_monotonic=0.0,
            step_started_monotonic=0.0,
            target_duration_s=240,
        )
        assert False, "expected _StopScriptEarly"
    except _StopScriptEarly:
        pass


def test_scripted_step_abort_requires_abort_confirmation(monkeypatch) -> None:
    class _FakeIn:
        def __init__(self, lines):
            self._lines = iter(lines)

        def isatty(self):
            return True

        def readline(self):
            return next(self._lines)

    class _FakeOut:
        def write(self, _text):
            return 0

        def flush(self):
            return None

        def isatty(self):
            return True

    fake_in = _FakeIn(["a\n"])
    fake_out = _FakeOut()
    select_results = iter([([fake_in], [], [])])
    def _fake_select(*_args, **_kwargs):
        try:
            return next(select_results)
        except StopIteration:
            return ([], [], [])

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin", fake_in)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdout", fake_out)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking", lambda **_kwargs: None)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.select.select",
        _fake_select,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.prompt_text",
        lambda message, required=False: "ABORT",
    )

    try:
        _wait_for_step_completion_with_stopwatch(
            step_index=1,
            step_count=6,
            step_id="open_home",
            script_started_monotonic=0.0,
            step_started_monotonic=0.0,
            target_duration_s=240,
        )
        assert False, "expected ScenarioAbortRequested"
    except ScenarioAbortRequested:
        pass


def test_limitation_reason_choices_do_not_duplicate_paywall() -> None:
    keys = [key for key, _label in SCRIPT_LIMITATION_REASON_LABELS]
    labels = [label for _key, label in SCRIPT_LIMITATION_REASON_LABELS]

    assert "paywall" not in keys
    assert keys.count("subscription_required") == 1
    assert labels.count("subscription required / paywall shown") == 1


def test_news_subscription_branch_skips_article_scroll_and_records_markers(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)
    events: list[tuple[str, dict[str, object]]] = []
    wait_calls = {"count": 0}
    choices = iter(["2"])

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._resolve_script_template",
        lambda _run_ctx: (
            "news_reader_behavior_v2",
            (
                ("open_article", "Open one article.", 30),
                ("article_scroll", "Scroll article content.", 45),
                ("subscription_wall_observe", "Observe subscription wall.", 30),
                ("subscription_options_observe", "Open subscription options.", 30),
                ("subscription_return_home", "Return home.", 15),
            ),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.get_choice",
        lambda *args, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )

    def _fake_wait(**_kwargs):
        wait_calls["count"] += 1
        if wait_calls["count"] == 1:
            return ("limited", "subscription_required", "hit subscription wall")
        return ("completed", None, None)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._wait_for_step_completion_with_stopwatch",
        _fake_wait,
    )

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )

    protocol = result.protocol or {}
    step_end_events = [details for event_type, details in events if event_type == "STEP_END"]

    assert wait_calls["count"] == 4
    assert protocol["article_branch"] == "subscription_required"
    assert protocol["subscription_branch_choice"] == "subscription_options_observed"
    assert protocol["protocol_fit"] == "limited_but_compliant"
    assert step_end_events[0]["step_id"] == "open_article"
    assert step_end_events[0]["limitation_reason"] == "subscription_required"
    assert step_end_events[0]["branch_taken"] == "subscription_required"
    assert step_end_events[1]["step_id"] == "article_scroll"
    assert step_end_events[1]["step_outcome"] == "skipped_branch_not_taken"
    assert step_end_events[2]["step_id"] == "subscription_wall_observe"
    assert step_end_events[2]["subscription_wall_observed"] is True
    assert step_end_events[3]["step_id"] == "subscription_options_observe"
    assert step_end_events[3]["subscription_options_opened"] is True
    assert step_end_events[4]["step_id"] == "subscription_return_home"
    assert step_end_events[4]["return_home_performed"] is True


def test_scripted_early_finalize_keeps_zero_exit_code(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._resolve_script_template",
        lambda _run_ctx: (
            "news_reader_behavior_v2",
            (
                ("open_home", "Open home.", 30),
                ("scroll_headlines", "Scroll headlines.", 45),
                ("open_article", "Open article.", 30),
            ),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )

    def _raise_stop(**_kwargs):
        raise _StopScriptEarly("STOP_FINALIZE")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._wait_for_step_completion_with_stopwatch",
        _raise_stop,
    )

    result = runner.run(ctx)
    protocol = result.protocol or {}

    assert protocol.get("stopped_early") is True
    assert protocol.get("script_exit_code") == 0
    assert int(protocol.get("step_count_completed") or 0) < int(protocol.get("step_count_planned") or 0)
    assert "STOPPED_EARLY" in list(protocol.get("deviation_codes") or [])


def test_news_article_opened_path_runs_article_scroll(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._resolve_script_template",
        lambda _run_ctx: (
            "news_reader_behavior_v2",
            (
                ("open_article", "Open one article.", 30),
                ("article_scroll", "Scroll article content.", 45),
                ("subscription_wall_observe", "Observe subscription wall.", 30),
            ),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._wait_for_step_completion_with_stopwatch",
        lambda **_kwargs: ("completed", None, None),
    )

    runner.run(ctx, on_protocol_event=lambda event_type, details: events.append((event_type, details)))

    step_end_events = [details for event_type, details in events if event_type == "STEP_END"]
    assert step_end_events[0]["branch_taken"] == "article_opened"
    assert step_end_events[1]["step_id"] == "article_scroll"
    assert step_end_events[1]["step_outcome"] == "completed"
    assert step_end_events[2]["step_id"] == "subscription_wall_observe"
    assert step_end_events[2]["step_outcome"] == "skipped_branch_not_taken"


def test_news_login_required_branch_does_not_ask_for_article_scroll(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)
    events: list[tuple[str, dict[str, object]]] = []
    wait_calls = {"count": 0}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._resolve_script_template",
        lambda _run_ctx: (
            "news_reader_behavior_v2",
            (
                ("open_article", "Open one article.", 30),
                ("article_scroll", "Scroll article content.", 45),
            ),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )

    def _fake_wait(**_kwargs):
        wait_calls["count"] += 1
        return ("limited", "login_required", "login wall")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._wait_for_step_completion_with_stopwatch",
        _fake_wait,
    )

    result = runner.run(ctx, on_protocol_event=lambda event_type, details: events.append((event_type, details)))

    step_end_events = [details for event_type, details in events if event_type == "STEP_END"]
    assert wait_calls["count"] == 1
    assert (result.protocol or {})["protocol_fit"] == "limited_but_compliant"
    assert step_end_events[1]["step_id"] == "article_scroll"
    assert step_end_events[1]["step_outcome"] == "skipped_branch_not_taken"
    assert step_end_events[1]["branch_taken"] == "login_required"


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
    assert isinstance(protocol.get("baseline_protocol_hash"), str) and len(str(protocol.get("baseline_protocol_hash"))) == 64


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
    assert _build_template_hash("facebook_basic_v2", template_steps_for_id("facebook_basic_v2") or ()) != _build_template_hash(template_id, steps)


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
    assert _build_template_hash("news_reader_basic_v1", template_steps_for_id("news_reader_basic_v1") or ()) != _build_template_hash(template_id, steps)


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


def test_scripted_step_return_home_completes_step(monkeypatch) -> None:
    class _FakeIn:
        def __init__(self, lines):
            self._lines = iter(lines)

        def isatty(self):
            return True

        def readline(self):
            return next(self._lines)

    class _FakeOut:
        def write(self, _text):
            return 0

        def flush(self):
            return None

        def isatty(self):
            return True

    markers: list[dict[str, object]] = []
    fake_in = _FakeIn(["h\n"])
    fake_out = _FakeOut()
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin", fake_in)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdout", fake_out)
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking", lambda **_kwargs: None)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.select.select",
        lambda *_args, **_kwargs: ([fake_in], [], []),
    )

    result = _wait_for_step_completion_with_stopwatch(
        step_index=7,
        step_count=10,
        step_id="subscription_options_observe",
        script_started_monotonic=0.0,
        step_started_monotonic=0.0,
        target_duration_s=240,
        on_phase_marker=lambda marker: markers.append(marker),
    )

    assert result == ("completed", None, None)
    assert markers == [
        {
            "phase_id": "return_home_manual",
            "phase_label": "Return Home Manual",
            "operator_result": "done",
            "mutation_performed": False,
        }
    ]


def test_read_device_foreground_package_parses_current_focus() -> None:
    from scytaledroid.DynamicAnalysis.scenarios.manual import _read_device_foreground_package
    import scytaledroid.DeviceAnalysis.adb.client as adb_client

    stdout = "  mCurrentFocus=Window{abc u0 com.twitter.android/com.twitter.app.main.MainActivity}\n"
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


def test_terminal_hold_early_stop_completes_protocol(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._resolve_script_template",
        lambda _run_ctx: (
            "news_reader_behavior_v2",
            (
                ("open_home", "Open home.", 30),
                ("final_hold", "Remain on feed.", 0),
            ),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )

    call_count = {"n": 0}

    def _stop_on_final_hold(**kwargs) -> tuple[str, None, None]:
        call_count["n"] += 1
        if str(kwargs.get("step_id") or "") == "final_hold":
            raise _StopScriptEarly("STOP_FINALIZE")
        return ("completed", None, None)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._wait_for_step_completion_with_stopwatch",
        _stop_on_final_hold,
    )

    result = runner.run(ctx)
    protocol = result.protocol or {}

    assert call_count["n"] == 2
    assert protocol.get("script_exit_code") == 0
    assert protocol.get("terminal_hold_finalize") is True
    assert protocol.get("stopped_early") is False
    assert int(protocol.get("step_count_completed") or 0) == int(protocol.get("step_count_planned") or 0)
    assert "TERMINAL_HOLD_FINALIZE" in list(protocol.get("deviation_codes") or [])


def test_apply_script_early_stop_never_sets_exit_code_130() -> None:
    from scytaledroid.DynamicAnalysis.scenarios.manual import _apply_script_early_stop

    protocol: dict[str, object] = {
        "step_count_planned": 6,
        "step_count_completed": 3,
        "script_exit_code": 0,
        "deviation_codes": [],
    }
    _apply_script_early_stop(protocol, active_step_id="open_article")
    assert protocol.get("script_exit_code") == 0
    assert protocol.get("stopped_early") is True
    assert int(protocol.get("step_count_completed") or 0) == 3
