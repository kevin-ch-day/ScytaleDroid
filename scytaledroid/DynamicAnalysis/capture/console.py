"""Terminal-mode live capture console for dynamic runs."""

from __future__ import annotations

import select
import re
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

_ESC = chr(27)
_CLEAR_AND_HOME = f"{_ESC}[2J{_ESC}[H"
_HOME_AND_CLEAR_REST = f"{_ESC}[H{_ESC}[J"
_ALT_SCREEN_ENTER = f"{_ESC}[?1049h{_ESC}[H{_ESC}[?25l"
_ALT_SCREEN_EXIT = f"{_ESC}[?25h{_ESC}[?1049l"
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _normalize_foreground_reading(reading: object) -> tuple[str | None, str | None]:
    if isinstance(reading, tuple):
        pkg = str(reading[0] or "").strip() if len(reading) >= 1 else ""
        component = str(reading[1] or "").strip() if len(reading) >= 2 else ""
        return (pkg or None, component or None)
    pkg = str(reading or "").strip()
    return (pkg or None, None)


def _safe_flush(stream: object | None) -> None:
    if stream is None:
        return
    try:
        flush = getattr(stream, "flush", None)
        if callable(flush):
            flush()
    except Exception:
        return


class SelectInputReader:
    """Non-blocking single-character reader for Linux terminals."""

    def __init__(self, stream=None) -> None:
        self._stream = stream or sys.__stdin__

    def _read_once(self) -> str | None:
        if hasattr(self._stream, "read"):
            try:
                value = self._stream.read(1)
            except StopIteration:
                return None
            return value or None
        if hasattr(self._stream, "readline"):
            try:
                line = self._stream.readline()
            except StopIteration:
                return None
            return str(line or "")[:1] or None
        return None

    def poll(self, timeout_s: float) -> str | None:
        if self._stream is not sys.__stdin__ and self._stream is not sys.stdin:
            return self._read_once()
        readable, _, _ = select.select([self._stream], [], [], max(float(timeout_s), 0.0))
        if not readable:
            return None
        return self._read_once()

    def drain_startup_input(self, *, max_reads: int = 8) -> str | None:
        """Drop stale buffered newlines while preserving the first real hotkey."""

        reads = 0
        while reads < max(int(max_reads), 0):
            key = self.poll(0.0)
            if key is None:
                return None
            reads += 1
            if key in {"\n", "\r"}:
                continue
            return key
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


class _StatusStreamProxy:
    """Route stray runtime prints into the live console status area."""

    def __init__(
        self,
        *,
        fallback_stream,
        state: CaptureState,
        emit_status: Callable[[CaptureState, str, str], None],
    ) -> None:
        self._fallback_stream = fallback_stream
        self._state = state
        self._emit_status = emit_status
        self._buffer = ""
        self._passthrough = False

    def set_passthrough(self, enabled: bool) -> None:
        self._passthrough = bool(enabled)

    def _consume_line(self, line: str) -> None:
        clean = _ANSI_ESCAPE_RE.sub("", str(line or "")).replace("\r", "").strip()
        if not clean:
            return
        level = "warn" if any(token in clean for token in ("[WARN]", "[ERROR]", "WARN", "ERROR")) else "info"
        self._emit_status(self._state, clean, level)

    def write(self, text: str) -> int:
        rendered = str(text or "")
        if self._passthrough:
            return self._fallback_stream.write(rendered)
        for ch in rendered:
            if ch == "\r":
                # Progress-style carriage returns rewrite the active line; keep only the
                # most recent segment so timers/prompts do not concatenate into nonsense.
                self._buffer = ""
                continue
            if ch == "\n":
                self._consume_line(self._buffer)
                self._buffer = ""
                continue
            self._buffer += ch
        return len(rendered)

    def flush(self) -> None:
        if self._passthrough:
            self._fallback_stream.flush()
            return
        if self._buffer.strip():
            self._consume_line(self._buffer)
        self._buffer = ""

    def isatty(self) -> bool:
        return bool(getattr(self._fallback_stream, "isatty", lambda: False)())

    def fileno(self) -> int:
        if hasattr(self._fallback_stream, "fileno"):
            return self._fallback_stream.fileno()
        raise OSError("fallback stream does not expose fileno()")

    @property
    def encoding(self) -> str | None:
        return getattr(self._fallback_stream, "encoding", None)

    def writable(self) -> bool:
        return bool(getattr(self._fallback_stream, "writable", lambda: True)())

    def __getattr__(self, name: str):
        return getattr(self._fallback_stream, name)


class _StdStreamInterception:
    """Temporarily intercept stdout/stderr while the live dashboard is active."""

    def __init__(
        self,
        *,
        state: CaptureState,
        emit_status: Callable[[CaptureState, str, str], None],
        fallback_stdout,
        fallback_stderr,
    ) -> None:
        self._state = state
        self._emit_status = emit_status
        self._fallback_stdout = fallback_stdout
        self._fallback_stderr = fallback_stderr
        self._stdout_proxy = _StatusStreamProxy(
            fallback_stream=fallback_stdout,
            state=state,
            emit_status=emit_status,
        )
        self._stderr_proxy = _StatusStreamProxy(
            fallback_stream=fallback_stderr,
            state=state,
            emit_status=emit_status,
        )
        self._prev_stdout = None
        self._prev_stderr = None

    @contextmanager
    def activate(self):
        self._prev_stdout = sys.stdout
        self._prev_stderr = sys.stderr
        sys.stdout = self._stdout_proxy
        sys.stderr = self._stderr_proxy
        try:
            yield self
        finally:
            self._stdout_proxy.flush()
            self._stderr_proxy.flush()
            sys.stdout = self._prev_stdout
            sys.stderr = self._prev_stderr

    @contextmanager
    def pause(self):
        self._stdout_proxy.set_passthrough(True)
        self._stderr_proxy.set_passthrough(True)
        sys.stdout = self._fallback_stdout
        sys.stderr = self._fallback_stderr
        try:
            yield
        finally:
            sys.stdout = self._stdout_proxy
            sys.stderr = self._stderr_proxy
            self._stdout_proxy.set_passthrough(False)
            self._stderr_proxy.set_passthrough(False)


@dataclass
class LiveCaptureConsole:
    foreground_provider: Callable[[], str | None]
    clock: Callable[[], float]
    input_reader: SelectInputReader | Callable[[float], str | None]
    renderer: Callable[[CaptureState], str] = render_capture_dashboard
    foreground_surface_validator: Callable[[CaptureState], tuple[bool, str | None]] | None = None
    observer_status_provider: Callable[[CaptureState], ObserverStatus | None] | None = None
    relaunch_callback: Callable[[CaptureState], str | None] | None = None
    finalize_callback: Callable[[CaptureState], bool] | None = None
    abort_callback: Callable[[CaptureState], bool] | None = None
    cleanup_callback: Callable[[CaptureState, str], None] | None = None
    tick_callback: Callable[[CaptureState, Callable[[str, str], None]], None] | None = None
    stdout: object | None = None
    terminal: CbreakTerminal | None = None
    tick_seconds: float = 0.25
    _stdio_interception: _StdStreamInterception | None = None

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
        if self._stdio_interception is None:
            with self.terminal.suspend():
                yield
            return
        with self.terminal.suspend():
            with self._stdio_interception.pause():
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
        state.foreground_package, state.foreground_component = _normalize_foreground_reading(
            self.foreground_provider()
        )
        expected = str(state.expected_package or "").strip()
        actual = str(state.foreground_package or "").strip()
        if expected and actual == expected:
            surface_ok = True
            surface_reason: str | None = None
            if self.foreground_surface_validator is not None:
                surface_ok, surface_reason = self.foreground_surface_validator(state)
            if not surface_ok:
                reason_text = str(surface_reason or "surface mismatch").strip()
                if state.valid_timing_started:
                    if state.status != CaptureStatus.PAUSED_FOREGROUND_DRIFT:
                        state.drift_seen = True
                        state.drift_count += 1
                        self._emit_status(
                            state,
                            (
                                "Foreground drift active; valid timing paused. "
                                f"Expected stable {expected or 'unknown'} surface, saw {actual or 'unknown'} "
                                f"({reason_text})."
                            ),
                            "warn",
                        )
                    state.status = CaptureStatus.PAUSED_FOREGROUND_DRIFT
                    return
                state.status = CaptureStatus.WAIT_TARGET_FOREGROUND
                self._emit_status(
                    state,
                    (
                        f"Waiting for a stable {state.app_name} surface before valid timing starts "
                        f"({reason_text})."
                    ),
                    "info",
                )
                return
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
        prefix = _CLEAR_AND_HOME if first_frame else _HOME_AND_CLEAR_REST
        stream.write(prefix + rendered)
        if not rendered.endswith("\n"):
            stream.write("\n")
        stream.flush()

    def _enter_live_screen(self) -> None:
        stream = self.stdout
        if stream is None:
            return
        _safe_flush(stream)
        _safe_flush(sys.stderr)
        stream.write(_ALT_SCREEN_ENTER)
        stream.flush()

    def _exit_live_screen(self) -> None:
        stream = self.stdout
        if stream is None:
            return
        _safe_flush(stream)
        _safe_flush(sys.stderr)
        stream.write(_ALT_SCREEN_EXIT)
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

    def _drain_startup_input(self) -> str | None:
        """Drop stale begin-prompt newlines while preserving real buffered hotkeys."""

        drain = getattr(self.input_reader, "drain_startup_input", None)
        if callable(drain):
            return drain(max_reads=8)
        return None

    def run(self, state: CaptureState) -> CaptureConsoleResult:
        assert self.terminal is not None
        state.wall_started_at = float(self.clock())
        state.last_tick_at = state.wall_started_at
        state.wall_elapsed_s = 0.0
        first_frame = True
        action = CaptureAction.FINALIZE
        pending_key: str | None = None
        interception = _StdStreamInterception(
            state=state,
            emit_status=self._emit_status,
            fallback_stdout=self.stdout,
            fallback_stderr=sys.stderr,
        )
        self._stdio_interception = interception
        try:
            _safe_flush(self.stdout)
            _safe_flush(sys.stderr)
            with self.terminal.activate():
                with interception.activate():
                    pending_key = self._drain_startup_input()
                    self._enter_live_screen()
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
                        if pending_key is not None:
                            key = pending_key
                            pending_key = None
                        else:
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
            self._exit_live_screen()
            self._stdio_interception = None
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
