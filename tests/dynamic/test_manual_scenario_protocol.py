from __future__ import annotations

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
