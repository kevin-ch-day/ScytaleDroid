from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.manual import ManualScenarioRunner


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
        lambda _seconds: datetime.now(UTC),
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
