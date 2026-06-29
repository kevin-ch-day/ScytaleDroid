from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.manual import (
    ManualScenarioRunner,
    ScenarioAbortRequested,
    _StopScriptEarly,
    _build_baseline_connected_schedule,
    _confirm_script_exit,
    _parse_timing_action,
    _resolve_script_template,
    _wait_for_step_completion_with_stopwatch,
)


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
    events: list[str] = []

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, _details: events.append(event_type),
    )
    protocol = result.protocol or {}
    assert protocol.get("script_hash")
    assert int(protocol.get("step_count_planned") or 0) > 0
    assert protocol.get("script_end_marker") is True
    assert protocol.get("script_exit_code") == 0
    assert "SCRIPT_START" in events
    assert "SCRIPT_END" in events
    assert events.count("STEP_START") == int(protocol.get("step_count_planned"))
    assert events.count("STEP_END") == int(protocol.get("step_count_planned"))


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

    runner.run(ctx, on_protocol_event=lambda *_args, **_kwargs: None)

    out = capsys.readouterr().out
    assert "Scripted interactive run" in out
    assert "Template: facebook_basic_v2" in out
    assert "Controls: D=done | L=limited | N=skip | S=stop/finalize | A=abort" in out
    assert "Tip: use D+Enter, L+Enter, or N+Enter. Avoid Ctrl+C." in out
    assert "Action: D=done | L=limited | N=skip" in out
    assert "Use D+Enter to complete this step. Enter alone still works." not in out
    assert "If Enter feels flaky" not in out


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


def test_scripted_article_limitation_carries_forward_to_scroll(monkeypatch, tmp_path: Path, capsys) -> None:
    runner = ManualScenarioRunner()
    ctx = _ctx(tmp_path)
    events: list[tuple[str, dict[str, object]]] = []
    wait_calls = {"count": 0}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._resolve_script_template",
        lambda _run_ctx: (
            "news_reader_basic_v1",
            (
                ("open_article", "Open one free article.", 45),
                ("scroll_article", "Scroll article content.", 45),
            ),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.get_choice",
        lambda *args, **kwargs: "L",
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
            return ("limited", "paywall", "hit subscription wall")
        raise AssertionError("scroll_article should not re-enter the stopwatch when carry-forward applies")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._wait_for_step_completion_with_stopwatch",
        _fake_wait,
    )

    result = runner.run(
        ctx,
        on_protocol_event=lambda event_type, details: events.append((event_type, details)),
    )

    out = capsys.readouterr().out
    protocol = result.protocol or {}
    step_end_events = [details for event_type, details in events if event_type == "STEP_END"]

    assert wait_calls["count"] == 1
    assert "Article unavailable from prior limited open_article step (paywall / subscription wall)." in out
    assert "Action: L=limited | N=skip | D=done" in out
    assert int(protocol.get("step_limited_count") or 0) == 2
    assert len(step_end_events) == 2
    assert step_end_events[0]["step_id"] == "open_article"
    assert step_end_events[0]["limitation_reason"] == "paywall"
    assert step_end_events[1]["step_id"] == "scroll_article"
    assert step_end_events[1]["limitation_reason"] == "paywall"
    assert step_end_events[1]["operator_note"] == "hit subscription wall"


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
    assert template_id == "facebook_basic_v2"


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
