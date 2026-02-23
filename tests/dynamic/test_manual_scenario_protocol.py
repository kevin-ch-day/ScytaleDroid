from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.manual import (
    ManualScenarioRunner,
    _build_baseline_connected_schedule,
    _parse_timing_action,
    _resolve_script_template,
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
