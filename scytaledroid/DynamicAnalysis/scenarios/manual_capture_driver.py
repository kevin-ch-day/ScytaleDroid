"""Manual live-capture helpers extracted from ``manual.py``.

This module keeps the manual scenario runner focused on protocol and operator
flow while consolidating the active-capture console and timing-loop glue in one
place.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from datetime import datetime

from scytaledroid.DynamicAnalysis.capture.console import (
    CbreakTerminal,
    LiveCaptureConsole,
    SelectInputReader,
)
from scytaledroid.DynamicAnalysis.capture.state import CaptureAction, CaptureState
from scytaledroid.DynamicAnalysis.capture.surface_probe import (
    infer_runtime_surface as _infer_runtime_surface,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    build_capture_state as _build_capture_state,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    make_runtime_foreground_surface_validator as _guided_make_runtime_foreground_surface_validator,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    make_runtime_observer_status_provider as _guided_make_runtime_observer_status_provider,
)
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    ActiveCaptureConfig as _ActiveCaptureConfig,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    ActiveCaptureRuntime as _ActiveCaptureRuntime,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    capture_console_exit_message as _runtime_capture_console_exit_message,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    capture_console_launch_message as _runtime_capture_console_launch_message,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    run_countdown_fallback as _runtime_run_countdown_fallback,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    run_stopwatch_fallback as _runtime_run_stopwatch_fallback,
)
from scytaledroid.Utils.DisplayUtils import status_messages


def make_runtime_surface_probe(
    run_ctx: RunContext,
    *,
    clock: Callable[[], float] = time.monotonic,
    refresh_interval_s: float = 8.0,
    infer_runtime_surface_fn: Callable[..., tuple[str | None, str | None]] = _infer_runtime_surface,
) -> Callable[[CaptureState], tuple[str | None, str | None]] | None:
    device_serial = str(getattr(run_ctx, "device_serial", "") or "").strip()
    expected_package = str(getattr(run_ctx, "package_name", "") or "").strip()
    if not device_serial or not expected_package:
        return None

    cache: dict[str, object] = {
        "sampled_at": -999.0,
        "foreground_package": None,
        "foreground_component": None,
        "result": (None, None),
    }

    def _probe(state: CaptureState) -> tuple[str | None, str | None]:
        foreground_package = str(getattr(state, "foreground_package", "") or "").strip()
        foreground_component = str(getattr(state, "foreground_component", "") or "").strip()
        now = clock()
        cached_result = cache.get("result")
        if (
            foreground_package == cache.get("foreground_package")
            and foreground_component == cache.get("foreground_component")
            and (now - float(cache.get("sampled_at") or 0.0)) < float(refresh_interval_s)
            and isinstance(cached_result, tuple)
            and len(cached_result) == 2
        ):
            return cached_result  # type: ignore[return-value]

        result = infer_runtime_surface_fn(
            expected_package=expected_package,
            foreground_package=foreground_package,
            foreground_component=foreground_component,
            device_serial=device_serial,
        )
        cache["sampled_at"] = now
        cache["foreground_package"] = foreground_package
        cache["foreground_component"] = foreground_component
        cache["result"] = result
        return result

    return _probe


def run_baseline_interactive_loop(
    target_duration_s: int,
    *,
    continue_after_target: bool = True,
    run_profile: str | None = None,
    timer_detail: str = "",
    app_name: str | None = None,
    version_code: str | None = None,
    phase: str | None = None,
    minimum_duration_s: int | None = None,
    minimum_duration_default_s: int = 180,
    device_serial: str | None = None,
    foreground_package: str | None = None,
    checkpoint_messages: dict[int, str] | None = None,
    surface_probe: Callable[[CaptureState], tuple[str | None, str | None]] | None = None,
    on_elapsed: Callable[[int, Callable[[str, str], None]], None] | None = None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
    pcap_bytes_provider: Callable[[], int | None] | None = None,
    read_foreground_target: Callable[[str | None], tuple[str | None, str | None]] | None = None,
    launch_package_to_foreground: Callable[[str | None, str | None], None] | None = None,
    should_continue_collecting_fn: Callable[..., bool] | None = None,
    clock: Callable[[], float] = time.monotonic,
    stdin: object = sys.stdin,
    stdout: object = sys.stdout,
    abort_exception_factory: Callable[[str], Exception] | None = None,
    runtime_class: type = _ActiveCaptureRuntime,
    capture_config_class: type = _ActiveCaptureConfig,
    console_class: type = LiveCaptureConsole,
    input_reader_factory: Callable[[object], object] = SelectInputReader,
    terminal_factory: Callable[..., object] = CbreakTerminal,
) -> datetime:
    runtime = runtime_class(
        build_capture_state=_build_capture_state,
        observer_status_provider_factory=_guided_make_runtime_observer_status_provider,
        read_foreground_target=read_foreground_target or (lambda _serial: (None, None)),
        foreground_surface_validator_factory=_guided_make_runtime_foreground_surface_validator,
        launch_package_to_foreground=launch_package_to_foreground or (lambda _serial, _package: None),
        should_continue_collecting=should_continue_collecting_fn or (lambda **_kwargs: False),
        console_class=console_class,
        input_reader_factory=input_reader_factory,
        terminal_factory=terminal_factory,
        clock=clock,
        stdin=stdin,
        stdout=stdout,
        status_printer=lambda message, level="info": print(status_messages.status(message, level=level)),
    )
    config = capture_config_class(
        target_duration_s=int(target_duration_s),
        continue_after_target=bool(continue_after_target),
        timer_detail=str(timer_detail or ""),
        app_name=app_name,
        run_profile=run_profile,
        version_code=version_code,
        phase=phase,
        minimum_duration_s=int(minimum_duration_s or minimum_duration_default_s),
        device_serial=device_serial,
        foreground_package=foreground_package,
        checkpoint_messages=checkpoint_messages,
        surface_probe=surface_probe,
    )
    try:
        return runtime.run_baseline_interactive_loop(
            config,
            on_elapsed=on_elapsed,
            on_protocol_event=on_protocol_event,
            pcap_bytes_provider=pcap_bytes_provider,
        )
    except RuntimeError as exc:
        if str(exc) == "ABORT_DISCARD" and abort_exception_factory is not None:
            raise abort_exception_factory("ABORT_DISCARD") from None
        raise


def run_countdown(
    duration_seconds: int,
    *,
    continue_after_target: bool = False,
    allow_early_stop: bool = True,
    ignore_stop_inputs: bool = False,
    run_profile: str | None = None,
    app_name: str | None = None,
    version_code: str | None = None,
    phase: str | None = None,
    minimum_duration_s: int | None = None,
    minimum_duration_default_s: int = 180,
    timer_detail: str = "",
    device_serial: str | None = None,
    foreground_package: str | None = None,
    checkpoint_messages: dict[int, str] | None = None,
    surface_probe: Callable[[CaptureState], tuple[str | None, str | None]] | None = None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
    should_continue_collecting_fn: Callable[..., bool] | None = None,
    abort_exception_factory: Callable[[str], Exception] | None = None,
    stop_exception_factory: Callable[[str], Exception] | None = None,
    format_duration_fn: Callable[[int], str] | None = None,
    pulse_marker_fn: Callable[[int], str] | None = None,
    extra_hold_timer_message_fn: Callable[..., str] | None = None,
    clear_status_line_fn: Callable[[int], None] | None = None,
    parse_timing_action_fn: Callable[[str | None], str] | None = None,
    read_foreground_target: Callable[[str | None], tuple[str | None, str | None]] | None = None,
    launch_package_to_foreground: Callable[[str | None, str | None], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    stdin: object = sys.stdin,
    stdout: object = sys.stdout,
) -> datetime:
    if allow_early_stop and not ignore_stop_inputs:
        return run_baseline_interactive_loop(
            int(duration_seconds),
            continue_after_target=continue_after_target,
            run_profile=run_profile,
            app_name=app_name,
            version_code=version_code,
            phase=phase,
            minimum_duration_s=minimum_duration_s,
            minimum_duration_default_s=minimum_duration_default_s,
            timer_detail=timer_detail,
            device_serial=device_serial,
            foreground_package=foreground_package,
            checkpoint_messages=checkpoint_messages,
            surface_probe=surface_probe,
            on_protocol_event=on_protocol_event,
            read_foreground_target=read_foreground_target,
            launch_package_to_foreground=launch_package_to_foreground,
            should_continue_collecting_fn=should_continue_collecting_fn,
            clock=clock,
            stdin=stdin,
            stdout=stdout,
            abort_exception_factory=abort_exception_factory,
        )
    return _runtime_run_countdown_fallback(
        int(duration_seconds),
        continue_after_target=continue_after_target,
        allow_early_stop=allow_early_stop,
        ignore_stop_inputs=ignore_stop_inputs,
        stdin=stdin,
        stdout=stdout,
        clock=clock,
        sleep=sleep,
        format_duration=format_duration_fn or (lambda seconds: str(seconds)),
        pulse_marker=pulse_marker_fn or (lambda _seconds: ""),
        extra_hold_timer_message_fn=extra_hold_timer_message_fn or (lambda **_kwargs: ""),
        clear_status_line_fn=clear_status_line_fn or (lambda _width: None),
        parse_timing_action_fn=parse_timing_action_fn or (lambda _line: "enter"),
        should_continue_collecting_fn=should_continue_collecting_fn or (lambda **_kwargs: False),
        abort_exception_factory=abort_exception_factory or RuntimeError,
        stop_exception_factory=stop_exception_factory or RuntimeError,
    )


def run_stopwatch(
    *,
    format_duration_fn: Callable[[int], str],
    controls_message: str,
    parse_timing_action_fn: Callable[[str | None], str],
    should_continue_collecting_fn: Callable[..., bool],
    abort_exception_factory: Callable[[str], Exception],
    prompt_continue_fn: Callable[[str], object],
    clock: Callable[[], float] = time.monotonic,
    stdin: object = sys.stdin,
    stdout: object = sys.stdout,
) -> datetime:
    return _runtime_run_stopwatch_fallback(
        stdin=stdin,
        stdout=stdout,
        clock=clock,
        format_duration=format_duration_fn,
        controls_message=controls_message,
        parse_timing_action_fn=parse_timing_action_fn,
        should_continue_collecting_fn=should_continue_collecting_fn,
        abort_exception_factory=abort_exception_factory,
        prompt_continue_fn=prompt_continue_fn,
    )


def capture_console_launch_message() -> str:
    return _runtime_capture_console_launch_message()


def capture_console_exit_message(action: CaptureAction) -> str:
    return _runtime_capture_console_exit_message(action)
