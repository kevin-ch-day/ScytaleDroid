from __future__ import annotations

from contextlib import contextmanager

import pytest

from scytaledroid.DynamicAnalysis.capture.console import CbreakTerminal, LiveCaptureConsole
from scytaledroid.DynamicAnalysis.capture.state import CaptureAction, CaptureState, ObserverStatus


class _FakeClock:
    def __init__(self, *, step: float = 1.0) -> None:
        self.value = -step
        self.step = step

    def __call__(self) -> float:
        self.value += self.step
        return float(self.value)


class _FakeInputReader:
    def __init__(self, values: list[str | BaseException | None]) -> None:
        self._values = iter(values)
        self.poll_calls = 0

    def poll(self, _timeout_s: float) -> str | None:
        self.poll_calls += 1
        value = next(self._values)
        if isinstance(value, BaseException):
            raise value
        return value


class _FakeOut:
    def __init__(self) -> None:
        self.buf: list[str] = []

    def write(self, text: str) -> int:
        self.buf.append(text)
        return len(text)

    def flush(self) -> None:
        return None


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
    reader = _FakeInputReader(["\n"])
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
        input_reader=_FakeInputReader(["\n"]),
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
