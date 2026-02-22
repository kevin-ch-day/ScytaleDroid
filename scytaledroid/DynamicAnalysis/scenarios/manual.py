"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

import select
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


@dataclass(frozen=True)
class ScenarioResult:
    started_at: datetime
    ended_at: datetime
    notes: str | None = None
    interaction_level: str | None = None
    protocol: dict[str, object] | None = None


SCRIPT_PROTOCOL_VERSION = 1
SCRIPT_STEPS_BASIC_USAGE: tuple[tuple[str, str, int], ...] = (
    ("launch_feed", "Scroll the main feed for new content.", 25),
    ("open_comments", "Open comments on one post and return.", 20),
    ("open_profile", "Open a profile page and return to feed.", 20),
    ("search_nav", "Use search/navigation briefly and return.", 20),
)


class ManualScenarioRunner:
    def run(
        self,
        run_ctx: RunContext,
        *,
        on_start: Callable[[], None] | None = None,
        on_end: Callable[[], None] | None = None,
        on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
    ) -> ScenarioResult:
        interaction_level = getattr(run_ctx, "interaction_level", None)
        protocol: dict[str, object] | None = None
        if run_ctx.interactive:
            duration_seconds = max(int(run_ctx.duration_seconds or 0), 0)
            profile = getattr(run_ctx, "run_profile", None)
            # Operator protocol metadata: pick interaction level *before* the run starts so the
            # evidence pack is tagged deterministically without post-run prompts.
            if not interaction_level:
                interaction_level = _prompt_interaction_level(profile)

            # Render a concise multi-line protocol block (operator-friendly).
            min_s = int(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120))
            target_s = int(getattr(app_config, "DYNAMIC_TARGET_DURATION_S", 180))

            block: list[str] = []
            block.append(f"Scenario: {run_ctx.scenario_id}")
            if interaction_level:
                block.append(f"Interaction: {interaction_level}")
            if duration_seconds:
                block.append(f"Duration: {duration_seconds}s")
            else:
                # Manual runs are stopwatch-based; still show the dataset target/minimum.
                block.append(f"Target duration: {target_s}s (min {min_s}s)")
            if profile:
                block.append(f"Profile: {profile}")
            # Do not surface run sequencing/slot labels. Operators may run in any order.

            block.append("")
            block.append("User behavior:")
            if profile == "baseline_idle":
                block.append("  - Keep the app in the foreground")
                block.append("  - Minimize interactions (baseline capture)")
            else:
                block.append("  - Keep the app in the foreground")
                block.append("  - Use the app normally")
            print(status_messages.status("\n".join(block).rstrip(), level="info"))
            if run_ctx.scenario_hint:
                print(status_messages.status(run_ctx.scenario_hint, level="info"))
            prompt_utils.press_enter_to_continue("Press Enter to begin (timer starts)...")
            started_at = datetime.now(UTC)
            if on_start:
                on_start()
            if profile == "interaction_scripted":
                target_s = duration_seconds or target_s
                protocol = _run_scripted_protocol(
                    run_ctx=run_ctx,
                    target_duration_s=int(target_s),
                    on_protocol_event=on_protocol_event,
                )
                ended_at = datetime.now(UTC)
            elif duration_seconds:
                print(status_messages.status("Press Enter to stop early (optional).", level="info"))
                ended_at = _run_countdown(duration_seconds)
            else:
                ended_at = _run_stopwatch()
            if on_end:
                on_end()
            elapsed = int((ended_at - started_at).total_seconds())
            print(status_messages.status(f"Scenario elapsed time: {_format_duration(elapsed)}.", level="info"))
        else:
            started_at = datetime.now(UTC)
            if on_start:
                on_start()
            time.sleep(max(run_ctx.duration_seconds, 0))
            ended_at = datetime.now(UTC)
            if on_end:
                on_end()
        return ScenarioResult(
            started_at=started_at,
            ended_at=ended_at,
            interaction_level=interaction_level,
            protocol=protocol,
        )


def _prompt_interaction_level(profile: str | None) -> str:
    # This is operator protocol metadata. It is used for QA and stratified analysis,
    # not as a behavioral feature.
    options = [
        ("1", "minimal", "Baseline / low interaction"),
        ("2", "normal", "Typical interaction"),
        ("3", "heavy", "High interaction"),
    ]
    default_key = "1" if profile == "baseline_idle" else "2"
    print(status_messages.status("Operator note: tag interaction level for this run.", level="info"))
    from scytaledroid.Utils.DisplayUtils import menu_utils

    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=[
                menu_utils.MenuOption(key, label, description=desc)
                for key, label, desc in options
            ],
            default=default_key,
            exit_label=None,
            show_exit=False,
            show_descriptions=True,
            compact=True,
        )
    )
    selection = prompt_utils.get_choice([key for key, _, _ in options], default=default_key)
    mapping = {key: label for key, label, _ in options}
    return mapping.get(selection, mapping[default_key])


def _run_countdown(duration_seconds: int) -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        time.sleep(max(duration_seconds, 0))
        return datetime.now(UTC)
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
    return datetime.now(UTC)


def _run_stopwatch() -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when finished (timer stops)...")
        return datetime.now(UTC)
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
    return datetime.now(UTC)


def _run_scripted_protocol(
    *,
    run_ctx: RunContext,
    target_duration_s: int,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None,
) -> dict[str, object]:
    steps = SCRIPT_STEPS_BASIC_USAGE
    hash_payload = "|".join(step_id for step_id, _desc, _expected in steps)
    script_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
    protocol: dict[str, object] = {
        "interaction_protocol_version": SCRIPT_PROTOCOL_VERSION,
        "script_name": f"{run_ctx.scenario_id}_scripted_v1",
        "script_hash": script_hash,
        "step_count_planned": len(steps),
        "step_count_completed": 0,
        "target_duration_s": int(target_duration_s),
        "script_exit_code": 0,
        "script_end_marker": False,
        "timing_within_tolerance": True,
        "deviation_codes": [],
    }
    started_monotonic = time.monotonic()
    if on_protocol_event:
        on_protocol_event(
            "SCRIPT_START",
            {
                "script_name": protocol["script_name"],
                "script_hash": script_hash,
                "step_count_planned": len(steps),
                "interaction_protocol_version": SCRIPT_PROTOCOL_VERSION,
            },
        )
    for idx, (step_id, step_desc, expected_s) in enumerate(steps, start=1):
        print()
        print(status_messages.status(f"Step {idx}/{len(steps)}: {step_id}", level="info"))
        print(status_messages.status(f"  {step_desc}", level="info"))
        print(status_messages.status(f"  Expected duration: {expected_s}s", level="info"))
        if on_protocol_event:
            on_protocol_event(
                "STEP_START",
                {"step_id": step_id, "step_index": idx, "expected_duration_s": expected_s},
            )
        step_start = time.monotonic()
        prompt_utils.press_enter_to_continue("Press Enter when step is complete...")
        step_elapsed = max(0.0, time.monotonic() - step_start)
        tolerance = min(max(0.25 * float(expected_s), 5.0), 30.0)
        within = step_elapsed <= (float(expected_s) + tolerance)
        if not within:
            protocol["timing_within_tolerance"] = False
            deviations = protocol.get("deviation_codes")
            if isinstance(deviations, list):
                deviations.append("SCRIPT_TIMEOUT")
        if on_protocol_event:
            on_protocol_event(
                "STEP_END",
                {
                    "step_id": step_id,
                    "step_index": idx,
                    "elapsed_s": round(step_elapsed, 3),
                    "expected_duration_s": expected_s,
                    "tolerance_s": round(tolerance, 3),
                    "within_tolerance": bool(within),
                },
            )
        protocol["step_count_completed"] = idx
    elapsed_total = int(time.monotonic() - started_monotonic)
    remaining = max(int(target_duration_s) - elapsed_total, 0)
    if remaining > 0:
        print(status_messages.status(f"Protocol completed; hold foreground for {remaining}s.", level="info"))
        _run_countdown(remaining)
    protocol["script_end_marker"] = True
    protocol["actual_duration_s"] = int(time.monotonic() - started_monotonic)
    if on_protocol_event:
        on_protocol_event(
            "SCRIPT_END",
            {
                "script_name": protocol["script_name"],
                "script_hash": script_hash,
                "step_count_completed": protocol["step_count_completed"],
                "step_count_planned": protocol["step_count_planned"],
                "script_exit_code": protocol["script_exit_code"],
                "timing_within_tolerance": protocol["timing_within_tolerance"],
            },
        )
    return protocol


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


__all__ = ["ManualScenarioRunner", "ScenarioResult", "SCRIPT_PROTOCOL_VERSION"]
