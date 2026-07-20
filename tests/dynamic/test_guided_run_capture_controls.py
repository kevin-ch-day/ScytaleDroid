from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios import manual
from scytaledroid.DynamicAnalysis.scenarios.manual import (
    ManualScenarioRunner,
    ScenarioAbortRequested,
)
from tests.dynamic._manual_protocol_support import _ctx


class _FakeIn:
    def __init__(self, lines: list[str]) -> None:
        self._lines = iter(lines)

    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        return next(self._lines)

    def read(self, _count: int = 1) -> str:
        value = self.readline()
        return value[:1] if value else ""

    def fileno(self) -> int:
        return 0


class _FakeOut:
    def __init__(self) -> None:
        self.buf: list[str] = []

    def isatty(self) -> bool:
        return True

    def write(self, text: str) -> int:
        self.buf.append(text)
        return len(text)

    def flush(self) -> None:
        return None


def _tick_factory(step: float = 1.0):
    state = {"value": -step}

    def _tick() -> float:
        state["value"] += step
        return float(state["value"])

    return _tick


def _patch_terminal_mode(monkeypatch) -> None:
    @contextmanager
    def _activate(_self):
        yield True

    @contextmanager
    def _suspend(_self):
        yield

    monkeypatch.setattr(manual.CbreakTerminal, "activate", _activate)
    monkeypatch.setattr(manual.CbreakTerminal, "suspend", _suspend)


def test_active_capture_bare_enter_triggers_stop_finalize(monkeypatch) -> None:
    fake_in = _FakeIn(["", "\n"])
    fake_out = _FakeOut()
    _patch_terminal_mode(monkeypatch)

    monkeypatch.setattr(manual.sys, "stdin", fake_in)
    monkeypatch.setattr(manual.sys, "stdout", fake_out)
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual, "_should_continue_collecting", lambda **_kwargs: False)

    ended_at = manual._run_baseline_interactive_loop(240, continue_after_target=True)

    assert isinstance(ended_at, datetime)
    assert "Opening live capture console. The transcript will resume after capture ends." in "".join(fake_out.buf)
    assert "Live capture console closed; returning to run transcript." in "".join(fake_out.buf)


def test_active_capture_a_enter_aborts_and_discards(monkeypatch) -> None:
    fake_in = _FakeIn(["a\n"])
    fake_out = _FakeOut()
    _patch_terminal_mode(monkeypatch)

    monkeypatch.setattr(manual.sys, "stdin", fake_in)
    monkeypatch.setattr(manual.sys, "stdout", fake_out)
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual, "_confirm_script_exit", lambda action: action == "abort")

    with pytest.raises(ScenarioAbortRequested):
        manual._run_baseline_interactive_loop(240, continue_after_target=True)
    assert "Opening live capture console. The transcript will resume after capture ends." in "".join(fake_out.buf)
    assert "Live capture console aborted; run marked discarded/not countable; returning to run transcript." in "".join(fake_out.buf)


def test_active_capture_ctrl_c_is_graceful_abort(monkeypatch) -> None:
    fake_in = _FakeIn([])
    fake_out = _FakeOut()
    _patch_terminal_mode(monkeypatch)

    monkeypatch.setattr(manual.sys, "stdin", fake_in)
    monkeypatch.setattr(manual.sys, "stdout", fake_out)
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.SelectInputReader.poll",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(ScenarioAbortRequested):
        manual._run_baseline_interactive_loop(240, continue_after_target=True)


def test_target_foreground_is_restored_before_capture_starts(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    ctx = RunContext(
        dynamic_run_id="r-whatsapp",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_connected",
        interaction_level="minimal",
        messaging_activity="connected_idle",
        device_serial="SERIAL",
        static_plan={"display_label": "WhatsApp"},
    )
    foregrounds = iter(
        [
            ("com.emanuelef.remote_capture", "com.emanuelef.remote_capture.activities.MainActivity"),
            ("com.emanuelef.remote_capture", "com.emanuelef.remote_capture.activities.MainActivity"),
            ("com.whatsapp", "com.whatsapp.Main"),
        ]
    )
    launches: list[tuple[str | None, str | None]] = []

    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(
        manual,
        "_launch_package_to_foreground",
        lambda serial, package: launches.append((serial, package)),
    )
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)

    manual._ensure_target_foreground_before_capture(ctx)

    out = capsys.readouterr().out
    assert launches == [("SERIAL", "com.whatsapp")]
    assert "Returning WhatsApp to foreground..." in out


def test_messaging_connected_baseline_starts_immediately_after_foreground_ready_when_prestart_enter_was_already_used(
    monkeypatch, tmp_path: Path
) -> None:
    runner = ManualScenarioRunner()
    ctx = replace(
        _ctx(tmp_path),
        package_name="com.whatsapp",
        run_profile="baseline_connected",
        interaction_level="minimal",
        messaging_activity="connected_idle",
        static_plan={"display_label": "WhatsApp"},
    )
    order: list[str] = []

    monkeypatch.setattr(
        manual,
        "_maybe_show_raw_high_value_permissions",
        lambda _run_ctx: True,
    )
    monkeypatch.setattr(
        manual,
        "_ensure_target_foreground_before_capture",
        lambda *_args, **_kwargs: order.append("foreground_ready"),
    )
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda *_args, **_kwargs: order.append("begin_prompt"),
    )
    monkeypatch.setattr(
        manual,
        "_run_messaging_connected_baseline",
        lambda **_kwargs: datetime.now(UTC),
    )

    runner.run(ctx, on_start=lambda: order.append("on_start"))

    assert order == ["on_start", "foreground_ready"]


def test_messaging_connected_baseline_shows_explicit_begin_prompt_when_prestart_permissions_view_pauses_start(
    monkeypatch, tmp_path: Path
) -> None:
    runner = ManualScenarioRunner()
    ctx = replace(
        _ctx(tmp_path),
        package_name="com.whatsapp",
        run_profile="baseline_connected",
        interaction_level="minimal",
        messaging_activity="connected_idle",
        static_plan={"display_label": "WhatsApp"},
    )
    order: list[str] = []

    monkeypatch.setattr(
        manual,
        "_maybe_show_raw_high_value_permissions",
        lambda _run_ctx: False,
    )
    monkeypatch.setattr(
        manual,
        "_ensure_target_foreground_before_capture",
        lambda *_args, **_kwargs: order.append("foreground_ready"),
    )
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda *_args, **_kwargs: order.append("begin_prompt"),
    )
    monkeypatch.setattr(
        manual,
        "_run_messaging_connected_baseline",
        lambda **_kwargs: datetime.now(UTC),
    )

    runner.run(ctx, on_start=lambda: order.append("on_start"))

    assert order == ["on_start", "foreground_ready", "begin_prompt"]


def test_foreground_drift_pauses_timer_and_reports_resume(monkeypatch) -> None:
    fake_in = _FakeIn(["", "", "", "\n"])
    fake_out = _FakeOut()
    _patch_terminal_mode(monkeypatch)
    foregrounds = iter(
        [
            ("com.whatsapp", "com.whatsapp.HomeActivity"),
            ("com.emanuelef.remote_capture", "com.emanuelef.remote_capture.activities.MainActivity"),
            ("com.whatsapp", "com.whatsapp.HomeActivity"),
        ]
    )

    monkeypatch.setattr(manual.sys, "stdin", fake_in)
    monkeypatch.setattr(manual.sys, "stdout", fake_out)
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(manual, "_should_continue_collecting", lambda **_kwargs: False)

    manual._run_baseline_interactive_loop(
        240,
        continue_after_target=True,
        device_serial="SERIAL",
        foreground_package="com.whatsapp",
    )

    output = "".join(fake_out.buf)
    assert "Foreground drift active; valid timing paused." in output
    assert "Target app restored to foreground; valid timing resumed." in output


def test_active_capture_does_not_print_generic_target_reached_status(monkeypatch) -> None:
    fake_in = _FakeIn(["", "", "\n"])
    fake_out = _FakeOut()
    _patch_terminal_mode(monkeypatch)

    monkeypatch.setattr(manual.sys, "stdin", fake_in)
    monkeypatch.setattr(manual.sys, "stdout", fake_out)
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory(120.0))
    monkeypatch.setattr(manual, "_should_continue_collecting", lambda **_kwargs: False)

    manual._run_baseline_interactive_loop(240, continue_after_target=True)

    output = "".join(fake_out.buf)
    assert "Target reached. Keep collecting if needed; press Enter when finished." not in output


def test_guardian_baseline_run_wires_runtime_surface_probe(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = RunContext(
        dynamic_run_id="r-guardian",
        package_name="com.guardian",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_idle",
        interaction_level="minimal",
        device_serial="SERIAL",
        static_plan={"display_label": "Guardian"},
    )
    seen: dict[str, object] = {}

    class _FakeRuntime:
        def __init__(self, **_kwargs) -> None:
            return None

        def run_baseline_interactive_loop(self, config, **_kwargs):
            seen["surface_probe"] = config.surface_probe
            return datetime.now(UTC)

    monkeypatch.setattr(manual, "_ActiveCaptureRuntime", _FakeRuntime)
    monkeypatch.setattr(manual, "_maybe_show_raw_high_value_permissions", lambda _run_ctx: True)
    monkeypatch.setattr(manual, "_ensure_target_foreground_before_capture", lambda *_args, **_kwargs: None)

    runner.run(ctx, on_start=lambda: None)

    assert callable(seen.get("surface_probe"))


def test_x_manual_run_wires_runtime_surface_probe(monkeypatch, tmp_path: Path) -> None:
    runner = ManualScenarioRunner()
    ctx = RunContext(
        dynamic_run_id="r-x",
        package_name="com.twitter.android",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="interaction_manual",
        interaction_level="normal",
        device_serial="SERIAL",
        static_plan={"display_label": "X"},
    )
    seen: dict[str, object] = {}

    class _FakeRuntime:
        def __init__(self, **_kwargs) -> None:
            return None

        def run_baseline_interactive_loop(self, config, **_kwargs):
            seen["surface_probe"] = config.surface_probe
            return datetime.now(UTC)

    monkeypatch.setattr(manual, "_ActiveCaptureRuntime", _FakeRuntime)
    monkeypatch.setattr(manual, "_maybe_show_raw_high_value_permissions", lambda _run_ctx: True)
    monkeypatch.setattr(manual, "_ensure_target_foreground_before_capture", lambda *_args, **_kwargs: None)

    runner.run(ctx, on_start=lambda: None)

    assert callable(seen.get("surface_probe"))


def test_facebook_baseline_gate_allows_known_loginactivity_false_positive(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    ctx = RunContext(
        dynamic_run_id="r-facebook",
        package_name="com.facebook.katana",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_idle",
        interaction_level="minimal",
        device_serial="SERIAL",
        static_plan={"display_label": "Facebook"},
    )
    foregrounds = iter(
        [
            ("com.facebook.katana", "com.facebook.katana.LoginActivity"),
        ]
    )
    prompts: list[str] = []

    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda msg="": prompts.append(msg),
    )

    manual._ensure_target_foreground_before_capture(ctx)

    out = capsys.readouterr().out
    assert "stable in-app screen" not in out
    assert prompts == []


def test_baseline_gate_still_blocks_generic_login_surface_before_capture_starts(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    ctx = RunContext(
        dynamic_run_id="r-example-login",
        package_name="com.example.social",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_idle",
        interaction_level="minimal",
        device_serial="SERIAL",
        static_plan={"display_label": "Example Social"},
    )
    foregrounds = iter(
        [
            ("com.example.social", "com.example.social.LoginActivity"),
            ("com.example.social", "com.example.social.ProfileActivity"),
        ]
    )
    prompts: list[str] = []

    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda msg="": prompts.append(msg),
    )

    manual._ensure_target_foreground_before_capture(ctx)

    out = capsys.readouterr().out
    assert "LoginActivity" in out
    assert "stable in-app screen" in out
    assert prompts == ["Move Example Social off com.example.social.LoginActivity, then press Enter to re-check"]


def test_facebook_baseline_gate_blocks_story_viewer_surface_before_capture_starts(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    ctx = RunContext(
        dynamic_run_id="r-facebook-story",
        package_name="com.facebook.katana",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_idle",
        interaction_level="minimal",
        device_serial="SERIAL",
        static_plan={"display_label": "Facebook"},
    )
    foregrounds = iter(
        [
            ("com.facebook.katana", "com.facebook.stories.viewer.activity.StoryViewerActivity"),
            ("com.facebook.katana", "com.facebook.katana.activity.FbMainTabActivity"),
        ]
    )
    prompts: list[str] = []

    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda msg="": prompts.append(msg),
    )

    manual._ensure_target_foreground_before_capture(ctx)

    out = capsys.readouterr().out
    assert "media/story surface" in out
    assert prompts == [
        "Move Facebook off com.facebook.stories.viewer.activity.StoryViewerActivity, then press Enter to re-check"
    ]


def test_interactive_gate_allows_login_surface(monkeypatch, tmp_path: Path) -> None:
    ctx = RunContext(
        dynamic_run_id="r-facebook-int",
        package_name="com.facebook.katana",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="interaction_manual",
        interaction_level="normal",
        device_serial="SERIAL",
        static_plan={"display_label": "Facebook"},
    )
    foregrounds = iter(
        [
            ("com.facebook.katana", "com.facebook.katana.LoginActivity"),
        ]
    )
    prompts: list[str] = []

    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda msg="": prompts.append(msg),
    )

    manual._ensure_target_foreground_before_capture(ctx)

    assert prompts == []


def test_connected_baseline_gate_blocks_whatsapp_call_surface(monkeypatch, tmp_path: Path, capsys) -> None:
    ctx = RunContext(
        dynamic_run_id="r-whatsapp-call",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=tmp_path / "run",
        artifacts_dir=tmp_path / "run/artifacts",
        analysis_dir=tmp_path / "run/analysis",
        notes_dir=tmp_path / "run/notes",
        interactive=True,
        run_profile="baseline_connected",
        interaction_level="minimal",
        messaging_activity="connected_idle",
        device_serial="SERIAL",
        static_plan={"display_label": "WhatsApp"},
    )
    foregrounds = iter(
        [
            ("com.whatsapp", "com.whatsapp.calling.ui.VoipActivityV2"),
            ("com.whatsapp", "com.whatsapp.Conversation"),
        ]
    )
    prompts: list[str] = []

    monkeypatch.setattr(manual, "_read_device_foreground_target", lambda _serial: next(foregrounds))
    monkeypatch.setattr(manual.time, "monotonic", _tick_factory())
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manual.prompt_utils,
        "press_enter_to_continue",
        lambda msg="": prompts.append(msg),
    )

    manual._ensure_target_foreground_before_capture(ctx)

    out = capsys.readouterr().out
    assert "VoipActivityV2" in out
    assert "stable in-app screen" in out
    assert prompts == [
        "Move WhatsApp off com.whatsapp.calling.ui.VoipActivityV2, then press Enter to re-check"
    ]
