from __future__ import annotations

import sys
from contextlib import contextmanager

import pytest
from scytaledroid.DynamicAnalysis.capture.console import CbreakTerminal, LiveCaptureConsole
from scytaledroid.DynamicAnalysis.capture.state import CaptureAction, CaptureState


class _FakeClock:
    def __init__(self, *, step: float = 1.0) -> None:
        self.value = -step
        self.step = step

    def __call__(self) -> float:
        self.value += self.step
        return float(self.value)


class _FakeInputReader:
    def __init__(self, values: list[str | BaseException | None]) -> None:
        self._values = list(values)
        self._index = 0
        self.poll_calls = 0

    def poll(self, _timeout_s: float) -> str | None:
        self.poll_calls += 1
        if self._index >= len(self._values):
            raise StopIteration
        value = self._values[self._index]
        self._index += 1
        if isinstance(value, BaseException):
            raise value
        return value

    def drain_startup_input(self, *, max_reads: int = 8) -> str | None:
        reads = 0
        while reads < max_reads and self._index < len(self._values):
            value = self._values[self._index]
            if isinstance(value, BaseException):
                self._index += 1
                raise value
            if value is None:
                return None
            self._index += 1
            reads += 1
            if value in {"\n", "\r"}:
                continue
            return value
        return None


class _FakeOut:
    def __init__(self) -> None:
        self.buf: list[str] = []
        self.encoding = "utf-8"
        self.flush_count = 0

    def write(self, text: str) -> int:
        self.buf.append(text)
        return len(text)

    def flush(self) -> None:
        self.flush_count += 1
        return None

    def writable(self) -> bool:
        return True

    def fileno(self) -> int:
        return 1


class _FakeTerminal:
    def __init__(self) -> None:
        self.activations = 0
        self.suspends = 0

    @contextmanager
    def activate(self):
        self.activations += 1
        yield True

    @contextmanager
    def suspend(self):
        self.suspends += 1
        yield


def _state() -> CaptureState:
    return CaptureState(
        app_name="WhatsApp",
        package_name="com.whatsapp",
        expected_package="com.whatsapp",
        version_code="262508000",
        phase="Baseline connected-idle",
        target_duration_s=240,
        minimum_duration_s=180,
    )


def test_console_enter_requests_finalize() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
    )

    result = console.run(state)

    assert result.action == CaptureAction.FINALIZE
    assert state.status.value == "FINALIZED"


def test_console_drains_stale_startup_newline_before_processing_finalize_enter() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader(["\n", None, "\n"])
    state = _state()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
    )

    result = console.run(state)

    assert result.action == CaptureAction.FINALIZE
    assert state.status.value == "FINALIZED"
    assert state.valid_elapsed_s >= 1.0
    assert state.wall_elapsed_s >= 1.0


def test_console_a_requests_abort() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader(["a"])
    state = _state()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
        abort_callback=lambda _state: True,
    )

    result = console.run(state)

    assert result.action == CaptureAction.ABORT


def test_console_preserves_buffered_abort_hotkey_after_startup_drain() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader(["\n", "a"])
    state = _state()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
        abort_callback=lambda _state: True,
    )

    result = console.run(state)

    assert result.action == CaptureAction.ABORT


def test_console_r_requests_relaunch() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader(["r", "\n"])
    state = _state()
    relaunched: list[str] = []

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.emanuelef.remote_capture",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
        relaunch_callback=lambda _state: relaunched.append("yes") or "Returning WhatsApp to foreground...",
    )

    result = console.run(state)

    assert result.action == CaptureAction.FINALIZE
    assert relaunched == ["yes"]


def test_console_ctrl_c_aborts_and_cleans_up() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([KeyboardInterrupt()])
    state = _state()
    cleanup_calls: list[str] = []

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
        cleanup_callback=lambda _state, reason: cleanup_calls.append(reason),
    )

    result = console.run(state)

    assert result.action == CaptureAction.ABORT
    assert cleanup_calls == ["abort"]


def test_console_intercepts_stray_stdout_and_updates_latest_event() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()
    out = _FakeOut()

    def _tick(_state, _emit_status) -> None:
        print("Background check finished.")

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
        tick_callback=_tick,
    )

    console.run(state)

    rendered = "".join(out.buf)
    assert "Latest     : Background check finished." in rendered
    assert "\nBackground check finished.\n" not in rendered
    assert state.latest_event == "Background check finished."


def test_console_progress_carriage_returns_do_not_concatenate_status_text() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()
    out = _FakeOut()

    def _tick(_state, _emit_status) -> None:
        sys.stdout.write("\rElapsed 00:10")
        sys.stdout.write("\rElapsed 00:11")
        sys.stdout.write("\rBackground check finished.\n")

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
        tick_callback=_tick,
    )

    console.run(state)

    rendered = "".join(out.buf)
    assert "Latest     : Background check finished." in rendered
    assert "Elapsed 00:10Background" not in rendered
    assert "Elapsed 00:11Background" not in rendered
    assert state.latest_event == "Background check finished."


def test_console_suspend_restores_real_stdout_for_prompt_output() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()
    out = _FakeOut()

    def _finalize(_state) -> bool:
        with console.suspend_terminal_mode():
            print("Confirm finalize prompt")
        return True

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
        finalize_callback=_finalize,
    )

    console.run(state)

    assert "Confirm finalize prompt" in "".join(out.buf)


def test_console_uses_alternate_screen_sequences() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()
    out = _FakeOut()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
    )

    console.run(state)

    rendered = "".join(out.buf)
    assert "\033[?1049h" in rendered
    assert "\033[?1049l" in rendered


def test_console_flushes_stream_before_entering_live_screen() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()
    out = _FakeOut()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
    )

    console.run(state)

    assert out.flush_count >= 3


def test_console_stream_proxy_exposes_basic_stream_attrs() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()
    out = _FakeOut()
    seen: list[tuple[object, object, object]] = []

    def _tick(_state, _emit_status) -> None:
        seen.append((sys.stdout.isatty(), sys.stdout.writable(), sys.stdout.fileno()))

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
        tick_callback=_tick,
    )

    console.run(state)

    assert seen
    assert all(item == (False, True, 1) for item in seen)


def test_valid_time_does_not_advance_during_pcapdroid_foreground() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, None, "\n"])
    state = _state()
    fg = iter(
        [
            "com.emanuelef.remote_capture",
            "com.emanuelef.remote_capture",
            "com.whatsapp",
        ]
    )

    console = LiveCaptureConsole(
        foreground_provider=lambda: next(fg),
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
    )

    console.run(state)

    assert int(state.valid_elapsed_s) == 1
    assert state.drift_seen is False


def test_foreground_recovery_resumes_valid_time() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, None, None, "\n"])
    state = _state()
    fg = iter(
        [
            "com.whatsapp",
            "com.emanuelef.remote_capture",
            "com.whatsapp",
            "com.whatsapp",
        ]
    )

    console = LiveCaptureConsole(
        foreground_provider=lambda: next(fg),
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
    )

    console.run(state)

    assert int(state.valid_elapsed_s) >= 2
    assert state.drift_seen is True
    assert state.drift_count == 1


def test_valid_time_does_not_advance_on_same_package_call_surface() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, None, "\n"])
    state = _state()
    out = _FakeOut()
    fg = iter(
        [
            ("com.whatsapp", "com.whatsapp.calling.ui.VoipActivityV2"),
            ("com.whatsapp", "com.whatsapp.calling.ui.VoipActivityV2"),
            ("com.whatsapp", "com.whatsapp.Conversation"),
        ]
    )

    console = LiveCaptureConsole(
        foreground_provider=lambda: next(fg),
        foreground_surface_validator=lambda live_state: (
            "calling.ui.VoipActivityV2" not in str(live_state.foreground_component or ""),
            "call surface",
        ),
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=out,
    )

    console.run(state)

    assert int(state.valid_elapsed_s) == 1
    assert state.drift_seen is False
    assert "stable WhatsApp surface" in "".join(out.buf)


def test_terminal_attrs_restored_on_finalize(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    class _Stream:
        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return 99

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.termios.tcgetattr",
        lambda _fd: ["old"],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.tty.setcbreak",
        lambda fd: calls.append(("cbreak", fd)),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.termios.tcsetattr",
        lambda fd, when, attrs: calls.append(("restore", fd, when, tuple(attrs))),
    )

    terminal = CbreakTerminal(stream=_Stream())
    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=_FakeClock(),
        input_reader=_FakeInputReader([None, "\n"]),
        terminal=terminal,
        stdout=_FakeOut(),
    )
    console.run(_state())

    assert ("cbreak", 99) in calls
    assert any(call[0] == "restore" for call in calls)


def test_terminal_attrs_restored_on_exception(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    class _Stream:
        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return 88

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.termios.tcgetattr",
        lambda _fd: ["old"],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.tty.setcbreak",
        lambda fd: calls.append(("cbreak", fd)),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.termios.tcsetattr",
        lambda fd, when, attrs: calls.append(("restore", fd, when, tuple(attrs))),
    )

    terminal = CbreakTerminal(stream=_Stream())
    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=_FakeClock(),
        input_reader=_FakeInputReader(["\n"]),
        terminal=terminal,
        stdout=_FakeOut(),
        renderer=lambda _state: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError):
        console.run(_state())

    assert ("cbreak", 88) in calls
    assert any(call[0] == "restore" for call in calls)


def test_terminal_attrs_restored_on_abort(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    class _Stream:
        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return 77

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.termios.tcgetattr",
        lambda _fd: ["old"],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.tty.setcbreak",
        lambda fd: calls.append(("cbreak", fd)),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.capture.console.termios.tcsetattr",
        lambda fd, when, attrs: calls.append(("restore", fd, when, tuple(attrs))),
    )

    terminal = CbreakTerminal(stream=_Stream())
    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=_FakeClock(),
        input_reader=_FakeInputReader(["a"]),
        terminal=terminal,
        stdout=_FakeOut(),
        abort_callback=lambda _state: True,
    )
    console.run(_state())

    assert ("cbreak", 77) in calls
    assert any(call[0] == "restore" for call in calls)


def test_console_loop_uses_polling_reader_not_blocking_input() -> None:
    clock = _FakeClock()
    terminal = _FakeTerminal()
    reader = _FakeInputReader([None, "\n"])
    state = _state()

    console = LiveCaptureConsole(
        foreground_provider=lambda: "com.whatsapp",
        clock=clock,
        input_reader=reader,
        terminal=terminal,
        stdout=_FakeOut(),
    )
    console.run(state)

    assert reader.poll_calls >= 2
