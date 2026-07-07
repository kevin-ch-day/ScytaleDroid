from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.scenarios.manual import ManualScenarioRunner
from tests.dynamic._manual_protocol_support import _ctx


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


def test_x_manual_interactive_run_shows_surface_guidance(monkeypatch, tmp_path: Path, capsys) -> None:
    runner = ManualScenarioRunner()
    ctx = replace(
        _ctx(tmp_path),
        package_name="com.twitter.android",
        run_profile="interaction_manual",
        interaction_level="normal",
    )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._ensure_target_foreground_before_capture",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        lambda _seconds, **_kwargs: datetime.now(UTC),
    )

    runner.run(ctx)

    out = capsys.readouterr().out
    assert "Interaction: normal" in out
    assert "Keep X in the foreground and generate real navigation" in out
    assert "Open one post detail or replies view briefly, then return" in out
    assert "Visit Search and Explore; prefer Trending or News" in out
    assert "Optionally open Notifications or Chat" in out
    assert "Avoid compose/posting, likes, follows, DMs" in out


def test_x_manual_interactive_run_wires_checkpoint_messages(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = replace(
        _ctx(tmp_path),
        package_name="com.twitter.android",
        run_profile="interaction_manual",
        interaction_level="normal",
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.press_enter_to_continue",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._ensure_target_foreground_before_capture",
        lambda *_args, **_kwargs: None,
    )

    def _fake_run_countdown(_seconds, **kwargs):
        seen.update(kwargs)
        return datetime.now(UTC)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._run_countdown",
        _fake_run_countdown,
    )

    runner.run(ctx)

    assert seen["checkpoint_messages"] == {
        60: "60s checkpoint: if you are still only on the X home feed, open one post or profile briefly, then return.",
        120: "120s checkpoint: visit Search and Explore or another distinct X surface such as Trending, News, Notifications, or Chat if available.",
        180: "180s checkpoint: aim to finish with 2-4 distinct in-app X surfaces captured; avoid compose/posting, DMs, follows, and external links.",
    }
