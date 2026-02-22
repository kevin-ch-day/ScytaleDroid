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
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config
from scytaledroid.DynamicAnalysis.templates.category_map import (
    mapping_sha256,
    mapping_version,
    template_for_package,
)
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


@dataclass(frozen=True)
class ScenarioResult:
    started_at: datetime
    ended_at: datetime
    notes: str | None = None
    interaction_level: str | None = None
    protocol: dict[str, object] | None = None


SCRIPT_PROTOCOL_VERSION = 2
SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2: tuple[tuple[str, str, int], ...] = (
    ("launch_feed", "Scroll the main feed for new content.", 25),
    ("open_reply_or_comments", "Open a reply/comments thread on one post and return.", 20),
    (
        "compose_post",
        "Open composer/create-post, type a short draft, then discard/cancel and return.",
        25,
    ),
    ("search_nav", "Use search/navigation briefly and return.", 20),
)
SCRIPT_STEPS_MESSAGING_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread and return.", 25),
    ("type_draft", "Type a short draft message (do not send).", 20),
    ("open_info_or_media", "Open conversation info OR shared media and return.", 20),
    ("search_or_new_chat", "Open search or new chat briefly and return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)


def _effective_min_sampling_seconds() -> int:
    configured = int(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120))
    paper_floor = int(getattr(paper2_config, "MIN_SAMPLING_SECONDS", 180))
    return max(configured, paper_floor)


def _effective_recommended_sampling_seconds() -> int:
    configured = int(getattr(app_config, "DYNAMIC_TARGET_DURATION_S", 180))
    paper_target = int(getattr(paper2_config, "RECOMMENDED_SAMPLING_SECONDS", 240))
    return max(configured, paper_target)


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
            min_s = _effective_min_sampling_seconds()
            rec_s = _effective_recommended_sampling_seconds()

            block: list[str] = []
            block.append(f"Scenario: {run_ctx.scenario_id}")
            if interaction_level:
                block.append(f"Interaction: {interaction_level}")
            if duration_seconds:
                block.append(f"Target duration: {_format_duration_precise(duration_seconds)}")
            else:
                # Manual runs are stopwatch-based; still show the paper contract floors.
                block.append(f"Target duration: {_format_duration_precise(rec_s)}")
            block.append(
                "Sampling contract: "
                f"min {_format_duration_precise(min_s)} | "
                f"recommended {_format_duration_precise(rec_s)}"
            )
            if profile:
                block.append(f"Profile: {profile}")
            if profile == "interaction_scripted":
                try:
                    template_id, steps = _resolve_script_template(run_ctx)
                    template_hash = _build_template_hash(template_id, steps)
                    block.append(f"Template: {template_id}")
                    block.append(f"Protocol version: {SCRIPT_PROTOCOL_VERSION}")
                    block.append(f"Template hash: {template_hash[:12]}...")
                except Exception as exc:
                    block.append(f"Template: unavailable ({exc})")
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
            _maybe_show_raw_high_value_permissions(run_ctx)
            prompt_utils.press_enter_to_continue("Press Enter to begin (timer starts)...")
            started_at = datetime.now(UTC)
            if on_start:
                on_start()
            if profile == "interaction_scripted":
                target_s = duration_seconds or rec_s
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
            if profile == "interaction_scripted":
                target_s = int((protocol or {}).get("target_duration_s") or duration_seconds or rec_s)
                overrun_s = int((protocol or {}).get("target_overrun_s") or 0)
                print(
                    status_messages.status(
                        (
                            f"Protocol timer elapsed: {_format_duration(elapsed)} "
                            f"(target {_format_duration(target_s)}"
                            + (f", overrun {overrun_s}s" if overrun_s > 0 else ", on-target")
                            + ")."
                        ),
                        level=("warn" if overrun_s > 0 else "info"),
                    )
                )
            else:
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
    template_id, steps = _resolve_script_template(run_ctx)
    template_hash = _build_template_hash(template_id, steps)
    protocol: dict[str, object] = {
        "interaction_protocol_version": SCRIPT_PROTOCOL_VERSION,
        "template_id": template_id,
        "template_map_version": mapping_version(),
        "template_map_hash": mapping_sha256(),
        "template_hash": template_hash,
        "script_name": template_id,
        "scenario_template": template_id,
        "script_hash": template_hash,
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
                "scenario_template": template_id,
                "template_id": template_id,
                "template_hash": template_hash,
                "template_map_version": mapping_version(),
                "template_map_hash": mapping_sha256(),
                "script_name": protocol["script_name"],
                "script_hash": template_hash,
                "step_count_planned": len(steps),
                "interaction_protocol_version": SCRIPT_PROTOCOL_VERSION,
            },
        )
    print(status_messages.status(f"Script template: {template_id} (protocol v{SCRIPT_PROTOCOL_VERSION})", level="info"))
    for idx, (step_id, step_desc, expected_s) in enumerate(steps, start=1):
        print()
        print(status_messages.status(f"Step {idx}/{len(steps)}: {step_id}", level="info"))
        print(status_messages.status(f"  {step_desc}", level="info"))
        print(status_messages.status(f"  Expected duration: {expected_s}s", level="info"))
        step_variant = None
        if step_id == "open_info_or_media":
            step_variant = _prompt_step3_variant()
            print(status_messages.status(f"  Variant: {step_variant}", level="info"))
        if on_protocol_event:
            on_protocol_event(
                "STEP_START",
                {
                    "step_id": step_id,
                    "step_index": idx,
                    "expected_duration_s": expected_s,
                    "step_variant": step_variant,
                },
            )
        step_elapsed = 0.0
        if step_id == "hold_foreground":
            elapsed_total = int(time.monotonic() - started_monotonic)
            remaining = max(int(target_duration_s) - elapsed_total, 0)
            step_elapsed = float(max(remaining, 0))
            if remaining > 0:
                print(status_messages.status(f"Protocol completed; hold foreground for {remaining}s.", level="info"))
                _run_countdown(remaining)
        else:
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
                    "step_variant": step_variant,
                },
            )
        protocol["step_count_completed"] = idx
    elapsed_total = int(time.monotonic() - started_monotonic)
    remaining = max(int(target_duration_s) - elapsed_total, 0)
    protocol["script_end_marker"] = True
    actual_duration_s = int(time.monotonic() - started_monotonic)
    protocol["actual_duration_s"] = actual_duration_s
    overrun_s = max(0, int(actual_duration_s) - int(target_duration_s))
    protocol["target_overrun_s"] = int(overrun_s)
    protocol["target_controlled"] = bool(overrun_s == 0)
    if overrun_s > 0:
        deviations = protocol.get("deviation_codes")
        if isinstance(deviations, list):
            deviations.append("SCRIPT_TARGET_OVERRUN")
    if on_protocol_event:
        on_protocol_event(
            "SCRIPT_END",
            {
                "script_name": protocol["script_name"],
                "script_hash": template_hash,
                "template_id": template_id,
                "template_hash": template_hash,
                "template_map_version": mapping_version(),
                "template_map_hash": mapping_sha256(),
                "step_count_completed": protocol["step_count_completed"],
                "step_count_planned": protocol["step_count_planned"],
                "script_exit_code": protocol["script_exit_code"],
                "timing_within_tolerance": protocol["timing_within_tolerance"],
                "target_overrun_s": protocol["target_overrun_s"],
                "target_controlled": protocol["target_controlled"],
            },
        )
    return protocol


def _resolve_script_template(run_ctx: RunContext) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    pkg = str(getattr(run_ctx, "package_name", "") or "").strip().lower()
    template_id = template_for_package(pkg)
    if not template_id:
        raise RuntimeError(f"BLOCKED_UNKNOWN_CATEGORY:{pkg}")
    if template_id == "messaging_basic_v1":
        return ("messaging_basic_v1", SCRIPT_STEPS_MESSAGING_BASIC_V1)
    if template_id == "social_feed_basic_v2":
        return ("social_feed_basic_v2", SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2)
    raise RuntimeError(f"BLOCKED_UNKNOWN_CATEGORY:{pkg}")


def _build_template_hash(template_id: str, steps: tuple[tuple[str, str, int], ...]) -> str:
    # Template hash is the reproducibility contract for scripted behavior.
    # Any step/order/text/duration/protocol change should produce a new hash.
    payload = {
        "template_id": template_id,
        "protocol_version": int(SCRIPT_PROTOCOL_VERSION),
        "category_map_version": mapping_version(),
        "timing_tolerance": {"percent": 25, "min_s": 5, "max_s": 30},
        "step3_variant_rule": (
            "open_info_or_media: allowed variants are info|media; variant must be recorded"
        ),
        "steps": [
            {"id": sid, "text": sdesc, "expected_s": int(sexp)}
            for sid, sdesc, sexp in steps
        ],
    }
    material = json_dumps_sorted(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _prompt_step3_variant() -> str:
    print(status_messages.status("Step variant (allowed):", level="info"))
    print("  1) info")
    print("  2) media")
    choice = prompt_utils.get_choice(["1", "2"], default="1", invalid_message="Choose 1 or 2.")
    return "media" if choice == "2" else "info"


def json_dumps_sorted(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _maybe_show_raw_high_value_permissions(run_ctx: RunContext) -> None:
    plan = run_ctx.static_plan if isinstance(run_ctx.static_plan, dict) else {}
    perms = plan.get("permissions") if isinstance(plan.get("permissions"), dict) else {}
    high_value = perms.get("high_value") if isinstance(perms.get("high_value"), list) else []
    raw = [str(p).strip() for p in high_value if str(p).strip()]
    if not raw:
        return
    choice = prompt_utils.prompt_text(
        "Press P to view raw high-value permissions, or Enter to continue",
        required=False,
    ).strip().lower()
    if choice != "p":
        return
    sample = ", ".join(sorted(raw)[:10])
    print(status_messages.status(f"High-value permissions (sample): {sample}", level="info"))


def _format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    min_label = "Min" if minutes == 1 else "Mins"
    sec_label = "Sec" if secs == 1 else "Secs"
    return f"{minutes} {min_label} {secs} {sec_label}"


def _format_duration_precise(seconds: int) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 60:
        return f"{seconds} sec"
    minutes, secs = divmod(seconds, 60)
    min_label = "min" if minutes == 1 else "mins"
    sec_label = "sec" if secs == 1 else "sec"
    return f"{minutes} {min_label} {secs} {sec_label} ({seconds}s)"


def _pulse_marker(elapsed_seconds: int) -> str:
    if elapsed_seconds > 0 and elapsed_seconds % 10 == 0:
        return " •"
    return ""


__all__ = ["ManualScenarioRunner", "ScenarioResult", "SCRIPT_PROTOCOL_VERSION"]
