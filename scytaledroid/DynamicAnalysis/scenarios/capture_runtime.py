"""Live capture runtime helpers for dynamic manual scenarios.

This module owns the active-capture foreground/timer console orchestration so
``manual.py`` can stay focused on scenario selection and protocol assembly.
"""

from __future__ import annotations

import select
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.capture.state import CaptureAction, ObserverStatus
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    ensure_target_foreground_before_capture as _guided_ensure_target_foreground_before_capture,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    format_duration as _format_duration,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    format_duration_precise as _format_duration_precise,
)


@dataclass(frozen=True)
class ActiveCaptureConfig:
    target_duration_s: int
    continue_after_target: bool = True
    timer_detail: str = ""
    app_name: str | None = None
    run_profile: str | None = None
    version_code: str | None = None
    phase: str | None = None
    minimum_duration_s: int = 180
    device_serial: str | None = None
    foreground_package: str | None = None
    checkpoint_messages: dict[int, str] | None = None
    surface_probe: Callable[[object], tuple[str | None, str | None]] | None = None


def capture_controls_status_message() -> str:
    return (
        "Enter = stop & finalize | A = discard run (not countable) | "
        "R = relaunch target | Ctrl+C = emergency abort"
    )


def capture_console_launch_message() -> str:
    return "Opening live capture console. The transcript will resume after capture ends."


def capture_console_exit_message(action: CaptureAction) -> str:
    if action == CaptureAction.ABORT:
        return "Live capture console aborted; run marked discarded/not countable; returning to run transcript."
    return "Live capture console closed; returning to run transcript."


def ensure_target_foreground_before_capture(
    run_ctx: RunContext,
    *,
    target_label: str,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None,
    prompt_continue_fn: Callable[[str], object],
    status_printer: Callable[[str, str], None],
    read_foreground_fn: Callable[[str | None], tuple[str | None, str | None]],
    launch_callback: Callable[[str | None, str | None], None],
) -> None:
    _guided_ensure_target_foreground_before_capture(
        device_serial=str(getattr(run_ctx, "device_serial", "") or ""),
        package_name=str(getattr(run_ctx, "package_name", "") or ""),
        app_name=target_label,
        static_plan=run_ctx.static_plan if isinstance(run_ctx.static_plan, dict) else None,
        run_profile=str(getattr(run_ctx, "run_profile", "") or ""),
        on_protocol_event=on_protocol_event,
        prompt_continue_fn=prompt_continue_fn,
        status_printer=status_printer,
        read_foreground_fn=read_foreground_fn,
        launch_callback=launch_callback,
    )


def extra_hold_timer_message(
    *,
    target_duration_s: int,
    elapsed_s: int,
    timer_detail: str = "",
    suffix: str = "",
) -> str:
    target = _format_duration(int(target_duration_s))
    hold_elapsed = _format_duration(max(int(elapsed_s) - int(target_duration_s), 0))
    detail = f" | {timer_detail}" if str(timer_detail or "").strip() else ""
    return (
        f"Target reached: {target} | optional extra hold: +{hold_elapsed} | "
        f"press Enter to finalize{detail}{suffix}"
    )


def capture_phase_label(*, run_profile: str | None, timer_detail: str = "") -> str:
    profile = str(run_profile or "").strip().lower()
    detail = str(timer_detail or "").strip().lower()
    if profile == "baseline_connected":
        return "Baseline connected-idle"
    if profile.startswith("baseline"):
        return "Baseline idle"
    if profile == "interaction_scripted":
        return "Scripted interactive"
    if detail == "connected baseline":
        return "Baseline connected-idle"
    if detail == "baseline idle":
        return "Baseline idle"
    return "Manual interactive"


def resolve_capture_version_code(run_ctx: RunContext) -> str | None:
    plan = run_ctx.static_plan if isinstance(run_ctx.static_plan, dict) else {}
    identity = plan.get("identity") if isinstance(plan.get("identity"), dict) else {}
    for source in (identity, plan):
        version_code = str(source.get("version_code") or source.get("expected_version_code") or "").strip()
        if version_code:
            return version_code
    return None


def run_countdown_fallback(
    duration_seconds: int,
    *,
    continue_after_target: bool = False,
    allow_early_stop: bool = True,
    ignore_stop_inputs: bool = False,
    stdin: object,
    stdout: object,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    format_duration: Callable[[int], str],
    pulse_marker: Callable[[int], str],
    extra_hold_timer_message_fn: Callable[..., str],
    clear_status_line_fn: Callable[[int], None],
    parse_timing_action_fn: Callable[[str | None], str],
    should_continue_collecting_fn: Callable[..., bool],
    abort_exception_factory: Callable[[str], Exception],
    stop_exception_factory: Callable[[str], Exception],
) -> datetime:
    if not stdin.isatty() or not stdout.isatty():
        sleep(max(duration_seconds, 0))
        return datetime.now(UTC)
    line_width = 56
    start = clock()
    last_rendered = None
    target_reached_announced = False
    try:
        while True:
            elapsed = clock() - start
            remaining = max(duration_seconds - int(elapsed), 0)
            elapsed_i = int(elapsed)
            elapsed_fmt = format_duration(elapsed_i)
            total = format_duration(duration_seconds)
            suffix = pulse_marker(int(elapsed))
            if remaining > 0:
                message = f"\rElapsed time: {elapsed_fmt} (target {total}){suffix}".ljust(line_width)
            else:
                message = (
                    "\r"
                    + extra_hold_timer_message_fn(
                        target_duration_s=int(duration_seconds),
                        elapsed_s=elapsed_i,
                        suffix=suffix,
                    )
                ).ljust(line_width)
            if message != last_rendered:
                stdout.write(message)
                stdout.flush()
                last_rendered = message
            if remaining <= 0 and not target_reached_announced:
                clear_status_line_fn(line_width)
                target_reached_announced = True
                if not continue_after_target:
                    print()
                    break
            if allow_early_stop:
                readable, _, _ = select.select([stdin], [], [], 1.0)
                if readable:
                    action = parse_timing_action_fn(stdin.readline())
                    if action == "abort":
                        clear_status_line_fn(line_width)
                        print()
                        raise abort_exception_factory("ABORT_DISCARD")
                    if action in {"enter", "stop"}:
                        if should_continue_collecting_fn(elapsed_s=elapsed_i, target_s=duration_seconds):
                            continue
                        clear_status_line_fn(line_width)
                        print()
                        break
            else:
                readable, _, _ = select.select([stdin], [], [], 1.0)
                if readable:
                    action = parse_timing_action_fn(stdin.readline())
                    if action == "abort":
                        clear_status_line_fn(line_width)
                        print()
                        raise abort_exception_factory("ABORT_DISCARD")
                    if action in {"enter", "stop"} and not ignore_stop_inputs:
                        clear_status_line_fn(line_width)
                        print()
                        raise stop_exception_factory("STOP_FINALIZE")
    except KeyboardInterrupt:
        clear_status_line_fn(line_width)
        print()
        if allow_early_stop or ignore_stop_inputs:
            raise abort_exception_factory("ABORT_DISCARD") from None
        raise stop_exception_factory("STOP_FINALIZE") from None
    return datetime.now(UTC)


def run_stopwatch_fallback(
    *,
    stdin: object,
    stdout: object,
    clock: Callable[[], float],
    format_duration: Callable[[int], str],
    controls_message: str,
    parse_timing_action_fn: Callable[[str | None], str],
    should_continue_collecting_fn: Callable[..., bool],
    abort_exception_factory: Callable[[str], Exception],
    prompt_continue_fn: Callable[[str], object],
) -> datetime:
    if not stdin.isatty() or not stdout.isatty():
        prompt_continue_fn("Press Enter when finished (timer stops)...")
        return datetime.now(UTC)
    line_width = 56
    start = clock()
    last_rendered = None
    print(controls_message)
    while True:
        elapsed = int(clock() - start)
        formatted = format_duration(elapsed)
        message = f"\rElapsed time: {formatted} (Enter to stop)".ljust(line_width)
        if message != last_rendered:
            stdout.write(message)
            stdout.flush()
            last_rendered = message
        readable, _, _ = select.select([stdin], [], [], 1.0)
        if readable:
            action = parse_timing_action_fn(stdin.readline())
            if action == "abort":
                print()
                raise abort_exception_factory("ABORT_DISCARD")
            if action in {"enter", "stop"}:
                if should_continue_collecting_fn(elapsed_s=elapsed, target_s=None):
                    continue
                print()
                break
    return datetime.now(UTC)


class ActiveCaptureRuntime:
    def __init__(
        self,
        *,
        build_capture_state: Callable[..., object],
        observer_status_provider_factory: Callable[..., object],
        read_foreground_target: Callable[[str | None], tuple[str | None, str | None]],
        foreground_surface_validator_factory: Callable[..., object] | None,
        launch_package_to_foreground: Callable[[str | None, str | None], None],
        should_continue_collecting: Callable[..., bool],
        console_class: type,
        input_reader_factory: Callable[[object], object],
        terminal_factory: Callable[..., object],
        clock: Callable[[], float],
        stdin: object,
        stdout: object,
        status_printer: Callable[[str, str], None],
    ) -> None:
        self._build_capture_state = build_capture_state
        self._observer_status_provider_factory = observer_status_provider_factory
        self._read_foreground_target = read_foreground_target
        self._foreground_surface_validator_factory = foreground_surface_validator_factory
        self._launch_package_to_foreground = launch_package_to_foreground
        self._should_continue_collecting = should_continue_collecting
        self._console_class = console_class
        self._input_reader_factory = input_reader_factory
        self._terminal_factory = terminal_factory
        self._clock = clock
        self._stdin = stdin
        self._stdout = stdout
        self._status_printer = status_printer

    def run_baseline_interactive_loop(
        self,
        config: ActiveCaptureConfig,
        *,
        on_elapsed: Callable[[int, Callable[[str, str], None]], None] | None = None,
        on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
        pcap_bytes_provider: Callable[[], int | None] | None = None,
    ) -> datetime:
        if not self._stdin.isatty() or not self._stdout.isatty():
            time.sleep(max(int(config.target_duration_s), 0))
            return datetime.now(UTC)
        target_package = str(config.foreground_package or "").strip()
        state = self._build_capture_state(
            app_name=str(config.app_name or target_package or "target app").strip() or "target app",
            package_name=target_package,
            expected_package=target_package,
            version_code=config.version_code,
            phase=str(config.phase or "Manual capture").strip() or "Manual capture",
            target_duration_s=int(config.target_duration_s),
            minimum_duration_s=int(config.minimum_duration_s),
            observer_status=ObserverStatus(),
        )
        target_reached_announced = {"value": False}
        checkpoint_emitted: set[int] = set()
        last_status: dict[str, object] = {"value": None}
        last_surface: dict[str, tuple[str | None, str | None] | None] = {"value": None}
        foreground_surface_validator = (
            self._foreground_surface_validator_factory(
                package_name=target_package,
                run_profile=str(config.run_profile or ""),
            )
            if self._foreground_surface_validator_factory is not None
            else None
        )

        console = self._console_class(
            foreground_provider=lambda: self._read_foreground_target(config.device_serial),
            foreground_surface_validator=foreground_surface_validator,
            clock=self._clock,
            input_reader=self._input_reader_factory(self._stdin),
            observer_status_provider=self._observer_status_provider_factory(
                pcap_bytes_provider=pcap_bytes_provider,
            ),
            relaunch_callback=lambda _state: (
                self._launch_package_to_foreground(config.device_serial, target_package)
                or f"Returning {state.app_name} to foreground..."
            ),
            finalize_callback=lambda live_state: self._finalize_request(
                console,
                live_state,
                target_duration_s=int(config.target_duration_s),
            ),
            abort_callback=lambda _live_state: self._abort_request(console),
            cleanup_callback=lambda _live_state, _reason: None,
            tick_callback=lambda live_state, emit_status: self._tick_console(
                live_state,
                emit_status,
                checkpoint_messages=config.checkpoint_messages,
                checkpoint_emitted=checkpoint_emitted,
                continue_after_target=bool(config.continue_after_target),
                target_duration_s=int(config.target_duration_s),
                target_reached_announced_ref=target_reached_announced,
                last_status_ref=last_status,
                last_surface_ref=last_surface,
                surface_probe=config.surface_probe,
                on_elapsed=on_elapsed,
                on_protocol_event=on_protocol_event,
            ),
            stdout=self._stdout,
            terminal=self._terminal_factory(stream=self._stdin),
        )
        self._status_printer(capture_console_launch_message(), "info")
        try:
            result = console.run(state)
        except KeyboardInterrupt:
            raise RuntimeError("ABORT_DISCARD") from None
        print(file=self._stdout)
        self._status_printer(capture_console_exit_message(result.action), "info")
        if result.action == CaptureAction.ABORT:
            raise RuntimeError("ABORT_DISCARD")
        return datetime.now(UTC)

    def _finalize_request(self, console: object, state: object, *, target_duration_s: int) -> bool:
        with console.suspend_terminal_mode():
            return not self._should_continue_collecting(
                elapsed_s=int(getattr(state, "valid_elapsed_s", 0)),
                target_s=int(target_duration_s),
            )

    def _abort_request(self, console: object) -> bool:
        with console.suspend_terminal_mode():
            return True

    def _tick_console(
        self,
        state: object,
        emit_status: Callable[[str, str], None],
        *,
        checkpoint_messages: dict[int, str] | None,
        checkpoint_emitted: set[int],
        continue_after_target: bool,
        target_duration_s: int,
        target_reached_announced_ref: dict[str, bool],
        last_status_ref: dict[str, object],
        last_surface_ref: dict[str, tuple[str | None, str | None] | None],
        surface_probe: Callable[[object], tuple[str | None, str | None]] | None,
        on_elapsed: Callable[[int, Callable[[str, str], None]], None] | None,
        on_protocol_event: Callable[[str, dict[str, object]], None] | None,
    ) -> None:
        elapsed_i = int(getattr(state, "valid_elapsed_s", 0))
        if on_elapsed is not None:
            on_elapsed(elapsed_i, lambda message, level="info": emit_status(message, level))
        previous_status = last_status_ref.get("value")
        if previous_status != getattr(state, "status", None):
            if getattr(getattr(state, "status", None), "name", "") == "PAUSED_FOREGROUND_DRIFT" and on_protocol_event:
                on_protocol_event(
                    "BASELINE_FOREGROUND_DRIFT_ACTIVE",
                    {
                        "expected_package": getattr(state, "expected_package", None),
                        "actual_package": getattr(state, "foreground_package", None),
                    },
                )
            elif (
                previous_status is not None
                and getattr(previous_status, "name", "") == "PAUSED_FOREGROUND_DRIFT"
                and getattr(getattr(state, "status", None), "name", "") == "RUNNING_VALID"
                and on_protocol_event
            ):
                on_protocol_event(
                    "BASELINE_FOREGROUND_DRIFT_CLEAR",
                    {"expected_package": getattr(state, "expected_package", None)},
                )
            last_status_ref["value"] = getattr(state, "status", None)
        if surface_probe is not None:
            try:
                surface_label, surface_detail = surface_probe(state)
            except Exception:
                surface_label, surface_detail = (None, None)
            setattr(state, "foreground_surface_label", surface_label)
            setattr(state, "foreground_surface_detail", surface_detail)
            current_surface = (surface_label, surface_detail)
            if current_surface != last_surface_ref.get("value"):
                last_surface_ref["value"] = current_surface
                if surface_label and on_protocol_event:
                    on_protocol_event(
                        "FOREGROUND_SURFACE_CHANGE",
                        {
                            "elapsed_s": int(elapsed_i),
                            "foreground_package": getattr(state, "foreground_package", None),
                            "foreground_component": getattr(state, "foreground_component", None),
                            "surface_label": surface_label,
                            "surface_detail": surface_detail,
                        },
                    )
        for checkpoint_s, checkpoint_msg in sorted((checkpoint_messages or {}).items()):
            if checkpoint_s in checkpoint_emitted or elapsed_i < int(checkpoint_s):
                continue
            checkpoint_emitted.add(int(checkpoint_s))
            emit_status(checkpoint_msg, "info")
            if on_protocol_event:
                on_protocol_event(
                    f"BASELINE_IDLE_CHECKPOINT_{int(checkpoint_s)}",
                    {"elapsed_s": int(elapsed_i), "checkpoint_s": int(checkpoint_s)},
                )
        if elapsed_i >= int(target_duration_s) and not target_reached_announced_ref.get("value", False):
            target_reached_announced_ref["value"] = True
            if not continue_after_target:
                emit_status("Target reached; finalizing capture.", "info")
                setattr(state, "finalize_requested", True)


__all__ = [
    "ActiveCaptureConfig",
    "ActiveCaptureRuntime",
    "capture_controls_status_message",
    "capture_console_launch_message",
    "capture_console_exit_message",
    "ensure_target_foreground_before_capture",
    "extra_hold_timer_message",
    "capture_phase_label",
    "resolve_capture_version_code",
    "run_countdown_fallback",
    "run_stopwatch_fallback",
]
