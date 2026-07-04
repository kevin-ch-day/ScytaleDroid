"""Terminal-mode live capture console for dynamic runs."""

from __future__ import annotations

import select
import sys
import termios
import tty
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable

from scytaledroid.DynamicAnalysis.capture.renderer import render_capture_dashboard
from scytaledroid.DynamicAnalysis.capture.state import (
    CaptureAction,
    CaptureConsoleResult,
    CaptureState,
    CaptureStatus,
    ObserverStatus,
)

_CLEAR_AND_HOME = "\033[2J\033[H"
_HOME_ONLY = "\033[H"


class SelectInputReader:
    """Non-blocking single-character reader for Linux terminals."""

    def __init__(self, stream=None) -> None:
        self._stream = stream or sys.__stdin__

    def poll(self, timeout_s: float) -> str | None:
        readable, _, _ = select.select([self._stream], [], [], max(float(timeout_s), 0.0))
        if not readable:
            return None
        if hasattr(self._stream, "read"):
            return self._stream.read(1)
        if hasattr(self._stream, "readline"):
            line = self._stream.readline()
            return str(line or "")[:1] or None
        return None


class CbreakTerminal:
    """Context manager that enables cbreak mode and restores attrs safely."""

    def __init__(self, *, stream=None) -> None:
        self._stream = stream or sys.__stdin__
        self._fd: int | None = None
        self._attrs = None
        self._active = False

    def available(self) -> bool:
        return bool(getattr(self._stream, "isatty", lambda: False)())

    @contextmanager
    def activate(self):
        if not self.available():
            yield False
            return
        self._fd = self._stream.fileno()
        self._attrs = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        self._active = True
        try:
            yield True
        finally:
            self.restore()

    @contextmanager
    def suspend(self):
        if not self._active or self._fd is None or self._attrs is None:
            yield
            return
        termios.tcsetattr(self._fd, termios.TCSADRAIN, self._attrs)
        self._active = False
        try:
            yield
        finally:
            tty.setcbreak(self._fd)
            self._active = True

    def restore(self) -> None:
        if self._fd is None or self._attrs is None:
            return
        termios.tcsetattr(self._fd, termios.TCSADRAIN, self._attrs)
        self._active = False


@dataclass
class LiveCaptureConsole:
    foreground_provider: Callable[[], str | None]
    clock: Callable[[], float]
    input_reader: SelectInputReader | Callable[[float], str | None]
    renderer: Callable[[CaptureState], str] = render_capture_dashboard
    observer_status_provider: Callable[[CaptureState], ObserverStatus | None] | None = None
    relaunch_callback: Callable[[CaptureState], str | None] | None = None
    finalize_callback: Callable[[CaptureState], bool] | None = None
    abort_callback: Callable[[CaptureState], bool] | None = None
    cleanup_callback: Callable[[CaptureState, str], None] | None = None
    tick_callback: Callable[[CaptureState, Callable[[str, str], None]], None] | None = None
    stdout: object | None = None
    terminal: CbreakTerminal | None = None
    tick_seconds: float = 0.25

    def __post_init__(self) -> None:
        if self.stdout is None:
            self.stdout = sys.stdout
        if self.terminal is None:
            self.terminal = CbreakTerminal()
        if not hasattr(self.input_reader, "poll"):
            poller = self.input_reader

            class _Adapter:
                def poll(self, timeout_s: float):
                    return poller(timeout_s)

            self.input_reader = _Adapter()

    @contextmanager
    def suspend_terminal_mode(self):
        assert self.terminal is not None
        with self.terminal.suspend():
            yield

    def _emit_status(self, state: CaptureState, message: str, level: str = "info") -> None:
        text = str(message or "").strip()
        if not text:
            return
        if level == "warn":
            state.latest_warning = text
        else:
            state.latest_event = text
            if level == "info":
                state.latest_warning = ""

    def _refresh_observer_status(self, state: CaptureState) -> None:
        if self.observer_status_provider is None:
            return
        status = self.observer_status_provider(state)
        if isinstance(status, ObserverStatus):
            state.observer_status = status

    def _update_foreground_timing(self, state: CaptureState, now: float) -> None:
        last_tick = state.last_tick_at if state.last_tick_at is not None else state.wall_started_at
        delta = max(float(now) - float(last_tick), 0.0)
        state.last_tick_at = float(now)
        state.wall_elapsed_s = max(float(now) - float(state.wall_started_at), 0.0)
        state.foreground_package = self.foreground_provider()
        expected = str(state.expected_package or "").strip()
        actual = str(state.foreground_package or "").strip()
        if expected and actual == expected:
            if state.status == CaptureStatus.PAUSED_FOREGROUND_DRIFT:
                self._emit_status(state, "Target app restored to foreground; valid timing resumed.", "info")
            elif not state.valid_timing_started:
                self._emit_status(state, "Target app is in foreground; valid timing active.", "info")
            state.status = CaptureStatus.RUNNING_VALID
            state.valid_timing_started = True
            state.valid_elapsed_s += delta
            return
        if state.valid_timing_started:
            if state.status != CaptureStatus.PAUSED_FOREGROUND_DRIFT:
                state.drift_seen = True
                state.drift_count += 1
                self._emit_status(
                    state,
                    (
                        "Foreground drift active; valid timing paused. "
                        f"Expected {expected or 'unknown'}, saw {actual or 'unknown'}."
                    ),
                    "warn",
                )
            state.status = CaptureStatus.PAUSED_FOREGROUND_DRIFT
            return
        state.status = CaptureStatus.WAIT_TARGET_FOREGROUND
        self._emit_status(
            state,
            (
                f"Waiting for {state.app_name} foreground before valid timing starts."
                if state.app_name
                else "Waiting for target app foreground before valid timing starts."
            ),
            "info",
        )

    def _draw(self, state: CaptureState, *, first_frame: bool) -> None:
        stream = self.stdout
        if stream is None:
            return
        rendered = self.renderer(state)
        prefix = _CLEAR_AND_HOME if first_frame else _HOME_ONLY
        stream.write(prefix + rendered)
        if not rendered.endswith("\n"):
            stream.write("\n")
        stream.flush()

    def _handle_key(self, key: str | None, state: CaptureState) -> CaptureAction | None:
        if key is None:
            return None
        if key in {"\n", "\r"}:
            state.finalize_requested = True
            if self.finalize_callback is None or self.finalize_callback(state):
                state.status = CaptureStatus.STOPPING_FINALIZE
                return CaptureAction.FINALIZE
            state.finalize_requested = False
            return None
        if key.lower() == "a":
            state.abort_requested = True
            if self.abort_callback is None or self.abort_callback(state):
                state.status = CaptureStatus.ABORTING_DISCARD
                return CaptureAction.ABORT
            state.abort_requested = False
            return None
        if key.lower() == "r":
            state.relaunch_requested = True
            if self.relaunch_callback is not None:
                result = self.relaunch_callback(state)
                if result:
                    self._emit_status(state, result, "info")
            state.relaunch_requested = False
        return None

    def run(self, state: CaptureState) -> CaptureConsoleResult:
        assert self.terminal is not None
        state.wall_started_at = float(self.clock())
        state.last_tick_at = state.wall_started_at
        state.wall_elapsed_s = 0.0
        first_frame = True
        action = CaptureAction.FINALIZE
        try:
            with self.terminal.activate():
                while True:
                    now = float(self.clock())
                    self._update_foreground_timing(state, now)
                    self._refresh_observer_status(state)
                    if self.tick_callback is not None:
                        self.tick_callback(state, lambda message, level="info": self._emit_status(state, message, level))
                    if state.abort_requested:
                        state.status = CaptureStatus.ABORTING_DISCARD
                        action = CaptureAction.ABORT
                        break
                    if state.finalize_requested:
                        state.status = CaptureStatus.STOPPING_FINALIZE
                        action = CaptureAction.FINALIZE
                        break
                    self._draw(state, first_frame=first_frame)
                    first_frame = False
                    key = self.input_reader.poll(self.tick_seconds)
                    action_value = self._handle_key(key, state)
                    if action_value is not None:
                        action = action_value
                        break
        except KeyboardInterrupt:
            state.abort_requested = True
            state.status = CaptureStatus.ABORTING_DISCARD
            self._emit_status(state, "Emergency abort requested by operator.", "warn")
            action = CaptureAction.ABORT
        finally:
            reason = "finalize" if action == CaptureAction.FINALIZE else "abort"
            if self.cleanup_callback is not None:
                self.cleanup_callback(state, reason)
        if action == CaptureAction.FINALIZE:
            state.status = CaptureStatus.FINALIZED
        ended_at = float(self.clock())
        state.wall_elapsed_s = max(ended_at - float(state.wall_started_at), 0.0)
        return CaptureConsoleResult(action=action, ended_at_monotonic=ended_at, state=state)


__all__ = [
    "CbreakTerminal",
    "LiveCaptureConsole",
    "SelectInputReader",
]
