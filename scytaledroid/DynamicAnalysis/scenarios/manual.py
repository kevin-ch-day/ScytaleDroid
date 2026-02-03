"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
            print(status_messages.status(f"Scenario elapsed time: {elapsed}s.", level="info"))
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
    if not sys.stdin.isatty():
        time.sleep(max(duration_seconds, 0))
        return datetime.now(timezone.utc)
    start = time.monotonic()
    while True:
        elapsed = time.monotonic() - start
        remaining = max(duration_seconds - int(elapsed), 0)
        message = f"\rTime remaining: {remaining:>4}s"
        print(message, end="", flush=True)
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
    if not sys.stdin.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when finished (timer stops)...")
        return datetime.now(timezone.utc)
    start = time.monotonic()
    print(status_messages.status("Press Enter when finished (timer stops).", level="info"))
    while True:
        elapsed = int(time.monotonic() - start)
        message = f"\rElapsed time: {elapsed:>4}s"
        print(message, end="", flush=True)
        readable, _, _ = select.select([sys.stdin], [], [], 1.0)
        if readable:
            _ = sys.stdin.readline()
            print()
            break
    return datetime.now(timezone.utc)


__all__ = ["ManualScenarioRunner", "ScenarioResult"]
