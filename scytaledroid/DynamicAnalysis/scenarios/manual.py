"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import select
import sys
import time
from typing import Callable

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from scytaledroid.DynamicAnalysis.core.run_context import RunContext


@dataclass(frozen=True)
class ScenarioResult:
    started_at: datetime
    ended_at: datetime
    notes: str | None = None


class ManualScenarioRunner:
    def run(
        self,
        run_ctx: RunContext,
        *,
        on_start: Callable[[], None] | None = None,
        on_end: Callable[[], None] | None = None,
    ) -> ScenarioResult:
        if run_ctx.interactive:
            duration = f"{run_ctx.duration_seconds}s" if run_ctx.duration_seconds else "unspecified"
            print(
                status_messages.status(
                    f"Scenario: {run_ctx.scenario_id} (duration {duration}). Use the app normally.",
                    level="info",
                )
            )
            print(status_messages.status("Tip: keep the app in the foreground during the session.", level="info"))
            if run_ctx.scenario_hint:
                print(status_messages.status(run_ctx.scenario_hint, level="info"))
            prompt_utils.press_enter_to_continue("Press Enter to begin (timer starts)...")
            started_at = datetime.now(timezone.utc)
            if on_start:
                on_start()
            duration_seconds = max(int(run_ctx.duration_seconds or 0), 0)
            if duration_seconds:
                print(status_messages.status("Press Enter to stop early (optional).", level="info"))
                ended_at = _run_countdown(duration_seconds)
            else:
                ended_at = _run_stopwatch()
            if on_end:
                on_end()
            elapsed = int((ended_at - started_at).total_seconds())
            print(status_messages.status(f"Scenario elapsed time: {_format_duration(elapsed)}.", level="info"))
        else:
            started_at = datetime.now(timezone.utc)
            if on_start:
                on_start()
            time.sleep(max(run_ctx.duration_seconds, 0))
            ended_at = datetime.now(timezone.utc)
            if on_end:
                on_end()
        return ScenarioResult(started_at=started_at, ended_at=ended_at)


def _run_countdown(duration_seconds: int) -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        time.sleep(max(duration_seconds, 0))
        return datetime.now(timezone.utc)
    start = time.monotonic()
    line_width = 32
    last_rendered = None
    while True:
        elapsed = time.monotonic() - start
        remaining = max(duration_seconds - int(elapsed), 0)
        formatted = _format_duration(remaining)
        total = _format_duration(duration_seconds)
        elapsed_fmt = _format_duration(int(elapsed))
        suffix = _pulse_marker(int(elapsed))
        message = f"\rTime remaining: {formatted} | {elapsed_fmt}/{total}{suffix}".ljust(line_width)
        if message != last_rendered:
            sys.stdout.write(message)
            sys.stdout.flush()
            last_rendered = message
        if remaining <= 0:
            print()
            break
        readable, _, _ = select.select([sys.stdin], [], [], 1.0)
        if readable:
            _ = sys.stdin.readline()
            print()
            break
    return datetime.now(timezone.utc)


def _run_stopwatch() -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when finished (timer stops)...")
        return datetime.now(timezone.utc)
    if os.environ.get("SCYTALEDROID_RUN_MONITOR") == "1":
        print(status_messages.status("Press Enter when finished (timer stops).", level="info"))
        start = time.monotonic()
        last_tick = 0
        while True:
            elapsed = int(time.monotonic() - start)
            if elapsed - last_tick >= 5:
                print(f"Elapsed time: {_format_duration(elapsed)}")
                last_tick = elapsed
            readable, _, _ = select.select([sys.stdin], [], [], 1.0)
            if readable:
                _ = sys.stdin.readline()
                print()
                break
        return datetime.now(timezone.utc)
    start = time.monotonic()
    line_width = 32
    print(status_messages.status("Press Enter when finished (timer stops).", level="info"))
    last_rendered = None
    while True:
        elapsed = int(time.monotonic() - start)
        formatted = _format_duration(elapsed)
        message = f"\rElapsed time: {formatted} (Enter to stop)".ljust(line_width)
        if message != last_rendered:
            sys.stdout.write(message)
            sys.stdout.flush()
            last_rendered = message
        readable, _, _ = select.select([sys.stdin], [], [], 1.0)
        if readable:
            _ = sys.stdin.readline()
            print()
            break
    return datetime.now(timezone.utc)


def _format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    min_label = "Min" if minutes == 1 else "Mins"
    sec_label = "Sec" if secs == 1 else "Secs"
    return f"{minutes} {min_label} {secs} {sec_label}"


def _pulse_marker(elapsed_seconds: int) -> str:
    if elapsed_seconds > 0 and elapsed_seconds % 10 == 0:
        return " •"
    return ""


__all__ = ["ManualScenarioRunner", "ScenarioResult"]
