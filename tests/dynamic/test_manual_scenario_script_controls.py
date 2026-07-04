from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.scenarios.manual import (
    SCRIPT_LIMITATION_REASON_LABELS,
    ManualScenarioRunner,
    ScenarioAbortRequested,
    _confirm_script_exit,
    _StopScriptEarly,
    _wait_for_step_completion_with_stopwatch,
)
from tests.dynamic._manual_protocol_support import _ctx


def test_scripted_protocol_step_prompt_wording_is_compact(
    monkeypatch, tmp_path: Path, capsys
) -> None:
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
    assert (
        "Controls: D=done | L=limited | N=skip | H=return home/reset | S=stop/finalize | A=abort"
        in out
    )
    assert "Tip: use D+Enter, L+Enter, or N+Enter. Avoid Ctrl+C." in out
    assert "Action: D=done | L=limited | N=skip | H=return home/reset" in out
    assert "Use D+Enter to complete this step. Enter alone still works." not in out
    assert "If Enter feels flaky" not in out


def test_facebook_behavior_no_repeat_plan_skips_optional_repeats(
    monkeypatch, tmp_path: Path
) -> None:
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
    assert prompts == ["Abort and discard this run? Type ABORT to continue, or Enter to cancel."]


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
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking",
        lambda **_kwargs: None,
    )
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
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking",
        lambda **_kwargs: None,
    )
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
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking",
        lambda **_kwargs: None,
    )
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
        raise AssertionError("expected _StopScriptEarly")
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
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking",
        lambda **_kwargs: None,
    )
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
        raise AssertionError("expected ScenarioAbortRequested")
    except ScenarioAbortRequested:
        pass


def test_limitation_reason_choices_do_not_duplicate_paywall() -> None:
    keys = [key for key, _label in SCRIPT_LIMITATION_REASON_LABELS]
    labels = [label for _key, label in SCRIPT_LIMITATION_REASON_LABELS]

    assert "paywall" not in keys
    assert keys.count("subscription_required") == 1
    assert labels.count("subscription required / paywall shown") == 1


def test_news_subscription_branch_skips_article_scroll_and_records_markers(
    monkeypatch, tmp_path: Path
) -> None:
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
    assert int(protocol.get("step_count_completed") or 0) < int(
        protocol.get("step_count_planned") or 0
    )
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

    runner.run(
        ctx, on_protocol_event=lambda event_type, details: events.append((event_type, details))
    )

    step_end_events = [details for event_type, details in events if event_type == "STEP_END"]
    assert step_end_events[0]["branch_taken"] == "article_opened"
    assert step_end_events[1]["step_id"] == "article_scroll"
    assert step_end_events[1]["step_outcome"] == "completed"
    assert step_end_events[2]["step_id"] == "subscription_wall_observe"
    assert step_end_events[2]["step_outcome"] == "skipped_branch_not_taken"


def test_news_login_required_branch_does_not_ask_for_article_scroll(
    monkeypatch, tmp_path: Path
) -> None:
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

    result = runner.run(
        ctx, on_protocol_event=lambda event_type, details: events.append((event_type, details))
    )

    step_end_events = [details for event_type, details in events if event_type == "STEP_END"]
    assert wait_calls["count"] == 1
    assert (result.protocol or {})["protocol_fit"] == "limited_but_compliant"
    assert step_end_events[1]["step_id"] == "article_scroll"
    assert step_end_events[1]["step_outcome"] == "skipped_branch_not_taken"
    assert step_end_events[1]["branch_taken"] == "login_required"


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
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._drain_stdin_nonblocking",
        lambda **_kwargs: None,
    )
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
    assert int(protocol.get("step_count_completed") or 0) == int(
        protocol.get("step_count_planned") or 0
    )
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
