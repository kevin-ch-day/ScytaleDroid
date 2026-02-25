"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

import hashlib
import random
import select
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import (
    SNAPCHAT_TEMPLATE_HINTS,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import (
    requested_script_template as _requested_script_template_for_package,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import (
    resolve_script_template as _resolve_script_template_for_package,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    clear_status_line as _timing_clear_status_line,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    format_duration as _timing_format_duration,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    format_duration_precise as _timing_format_duration_precise,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    parse_timing_action as _timing_parse_timing_action,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    pulse_marker as _timing_pulse_marker,
)
from scytaledroid.DynamicAnalysis.templates.category_map import (
    category_for_package,
    mapping_sha256,
    mapping_version,
)
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


@dataclass(frozen=True)
class ScenarioResult:
    started_at: datetime
    ended_at: datetime
    notes: str | None = None
    interaction_level: str | None = None
    protocol: dict[str, object] | None = None


class ScenarioAbortRequested(RuntimeError):
    """Operator requested abort/discard during interactive timing loop."""


class _StopScriptEarly(RuntimeError):
    """Operator requested stop/finalize during scripted step execution."""


SCRIPT_PROTOCOL_VERSION = 2
BASELINE_PROTOCOL_VERSION = 2
BASELINE_PROTOCOL_ID_CONNECTED = "baseline_connected_v2"
BASELINE_PROTOCOL_ID_IDLE = "baseline_idle_v1"
CALL_CONNECT_TIMEOUT_S = 30
CALL_MIN_CONNECTED_DURATION_S = 90


def _effective_min_sampling_seconds() -> int:
    configured = int(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120))
    profile_floor = int(getattr(profile_config, "MIN_SAMPLING_SECONDS", 180))
    return max(configured, profile_floor)


def _effective_recommended_sampling_seconds() -> int:
    configured = int(getattr(app_config, "DYNAMIC_TARGET_DURATION_S", 180))
    profile_target = int(getattr(profile_config, "RECOMMENDED_SAMPLING_SECONDS", 240))
    return max(configured, profile_target)


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
            if str(profile or "").strip().lower().startswith("baseline"):
                category = str(category_for_package(getattr(run_ctx, "package_name", "") or "") or "").strip().lower()
                msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
                if category == "messaging" and msg_activity in {"", "connected_idle", "none"}:
                    block.append("  - Keep the app in the foreground")
                    block.append("  - Open an existing conversation thread and keep it visible")
                    block.append("  - Every 45-75s, do one non-mutating check action (small scroll OR chat-list/thread switch)")
                    block.append("  - Perform exactly one refresh/check action around minute 2")
                    block.append("  - Do not type, send, call, upload media, search, or open external links")
                else:
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
            elif str(profile or "").strip().lower().startswith("baseline"):
                target_s = duration_seconds or rec_s
                protocol = _build_baseline_protocol(run_ctx=run_ctx, target_duration_s=int(target_s))
                if _is_messaging_connected_baseline_context(run_ctx):
                    ended_at = _run_messaging_connected_baseline(
                        run_ctx=run_ctx,
                        target_duration_s=int(target_s),
                        protocol=protocol,
                        on_protocol_event=on_protocol_event,
                    )
                elif duration_seconds:
                    print(
                        status_messages.status(
                            "Press Enter to stop early (optional). S+Enter=Stop&Finalize, A+Enter=Abort&Discard.",
                            level="info",
                        )
                    )
                    ended_at = _run_countdown(duration_seconds, continue_after_target=True)
                else:
                    ended_at = _run_stopwatch()
            elif duration_seconds:
                print(
                    status_messages.status(
                        "Press Enter to stop early (optional). S+Enter=Stop&Finalize, A+Enter=Abort&Discard.",
                        level="info",
                    )
                )
                ended_at = _run_countdown(duration_seconds, continue_after_target=True)
            else:
                ended_at = _run_stopwatch()
            if on_end:
                on_end()
            elapsed = int((ended_at - started_at).total_seconds())
            if profile == "interaction_scripted":
                target_s = int((protocol or {}).get("target_duration_s") or duration_seconds or rec_s)
                overrun_s = int((protocol or {}).get("target_overrun_s") or 0)
                underrun_s = int((protocol or {}).get("target_underrun_s") or 0)
                status_detail = ", on-target"
                level = "info"
                if overrun_s > 0:
                    status_detail = f", overrun {overrun_s}s"
                    level = "warn"
                elif underrun_s > 0:
                    status_detail = f", underrun {underrun_s}s"
                    level = "warn"
                print(
                    status_messages.status(
                        f"Protocol timer elapsed: {_format_duration(elapsed)} "
                        f"(target {_format_duration(target_s)}{status_detail}).",
                        level=level,
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
    default_key = "1" if str(profile or "").strip().lower().startswith("baseline") else "2"
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


def _run_countdown(
    duration_seconds: int,
    *,
    continue_after_target: bool = False,
    allow_early_stop: bool = True,
) -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        time.sleep(max(duration_seconds, 0))
        return datetime.now(UTC)
    start = time.monotonic()
    line_width = 56
    last_rendered = None
    target_reached_announced = False
    try:
        while True:
            elapsed = time.monotonic() - start
            remaining = max(duration_seconds - int(elapsed), 0)
            elapsed_i = int(elapsed)
            elapsed_fmt = _format_duration(elapsed_i)
            total = _format_duration(duration_seconds)
            suffix = _pulse_marker(int(elapsed))
            if remaining > 0:
                message = f"\rElapsed time: {elapsed_fmt} (target {total}){suffix}".ljust(line_width)
            else:
                message = f"\rElapsed time: {elapsed_fmt} (target reached){suffix}".ljust(line_width)
            if message != last_rendered:
                sys.stdout.write(message)
                sys.stdout.flush()
                last_rendered = message
            if remaining <= 0 and not target_reached_announced:
                _clear_status_line(line_width)
                if continue_after_target:
                    print(
                        status_messages.status(
                            "Target reached. Keep collecting if needed; press Enter when finished.",
                            level="info",
                        )
                    )
                target_reached_announced = True
                if not continue_after_target:
                    print()
                    break
            if allow_early_stop:
                readable, _, _ = select.select([sys.stdin], [], [], 1.0)
                if readable:
                    action = _parse_timing_action(sys.stdin.readline())
                    if action == "abort":
                        _clear_status_line(line_width)
                        print()
                        raise ScenarioAbortRequested("ABORT_DISCARD")
                    if action in {"enter", "stop"}:
                        if _should_continue_collecting(elapsed_s=elapsed_i, target_s=duration_seconds):
                            continue
                        _clear_status_line(line_width)
                        print()
                        break
            else:
                # Locked countdown (scripted hold): allow explicit operator escape
                # keys without requiring Ctrl+C.
                readable, _, _ = select.select([sys.stdin], [], [], 1.0)
                if readable:
                    action = _parse_timing_action(sys.stdin.readline())
                    if action == "abort":
                        _clear_status_line(line_width)
                        print()
                        raise ScenarioAbortRequested("ABORT_DISCARD")
                    if action in {"enter", "stop"}:
                        _clear_status_line(line_width)
                        print()
                        raise _StopScriptEarly("STOP_FINALIZE")
                    # Ignore bare Enter in locked mode to avoid accidental early exits.
    except KeyboardInterrupt:
        _clear_status_line(line_width)
        print()
        if allow_early_stop:
            raise ScenarioAbortRequested("ABORT_DISCARD") from None
        raise _StopScriptEarly("STOP_FINALIZE") from None
    return datetime.now(UTC)


def _run_stopwatch() -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when finished (timer stops)...")
        return datetime.now(UTC)
    start = time.monotonic()
    line_width = 32
    print(status_messages.status("Press Enter when finished. S+Enter=Stop&Finalize, A+Enter=Abort&Discard.", level="info"))
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
            action = _parse_timing_action(sys.stdin.readline())
            if action == "abort":
                print()
                raise ScenarioAbortRequested("ABORT_DISCARD")
            if action in {"enter", "stop"}:
                if _should_continue_collecting(elapsed_s=elapsed, target_s=None):
                    continue
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
    requested_template_id = _requested_script_template(run_ctx)
    template_hash = _build_template_hash(template_id, steps)
    protocol: dict[str, object] = {
        "interaction_protocol_version": SCRIPT_PROTOCOL_VERSION,
        "template_id": template_id,
        "template_id_requested": requested_template_id,
        "template_id_actual": template_id,
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
        "call_type": None,
        "call_attempted": False,
        "call_connected": None,
        "call_connect_latency_s": None,
        "call_connected_duration_s": None,
        "call_end_reason": None,
        "call_outcome_reason": None,
        "script_call_in_non_call_template": False,
        "ai_used": False,
        "ai_provider": None,
        "ai_prompt_id": None,
    }
    started_monotonic = time.monotonic()
    if on_protocol_event:
        on_protocol_event(
            "SCRIPT_START",
            {
                "scenario_template": template_id,
                "template_id": template_id,
                "template_id_requested": requested_template_id,
                "template_id_actual": template_id,
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
    print(
        status_messages.status(
            "Controls: Enter/D/C=step complete, N=Skip(not found), S=Stop&Finalize, A=Abort&Discard (then press Enter).",
            level="info",
        )
    )
    msg_activity_raw = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
    if msg_activity_raw:
        print(status_messages.status(f"Messaging activity: {msg_activity_raw}", level="info"))
    call_templates = {
        "messaging_call_basic_v1",
        "messaging_voice_v1",
        "messaging_video_v1",
        "whatsapp_voice_v1",
        "whatsapp_video_v1",
    }
    if template_id in call_templates:
        msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
        protocol["call_type"] = (
            "video"
            if msg_activity == "video_call"
            else ("mixed" if msg_activity == "mixed" else "voice")
        )
    pkg_lc = str(getattr(run_ctx, "package_name", "") or "").strip().lower()
    show_snapchat_hints = bool(pkg_lc == "com.snapchat.android" and template_id == "social_feed_basic_v2")
    go_live_start_skipped = False
    try:
        for idx, (step_id, step_desc, expected_s) in enumerate(steps, start=1):
            step_outcome = "completed"
            print()
            print(status_messages.status(f"Step {idx}/{len(steps)}: {step_id}", level="info"))
            print(status_messages.status(f"  {step_desc}", level="info"))
            print(status_messages.status(f"  Expected duration: {expected_s}s", level="info"))
            print(
                status_messages.status(
                    "  Press Enter when step is complete (in this terminal). "
                    "If Enter feels flaky, type D+Enter. (N+Enter to skip if not found)",
                    level="info",
                )
            )
            if show_snapchat_hints:
                hint = SNAPCHAT_TEMPLATE_HINTS.get(str(step_id))
                if hint:
                    print(status_messages.status(f"  {hint}", level="info"))
            step_variant = None
            if step_id == "open_info_or_media":
                step_variant = _prompt_step3_variant()
                if step_variant == "skip":
                    # Treat as a deterministic per-step skip rather than forcing the operator
                    # to enter the stopwatch loop and then skip again.
                    step_outcome = "skipped_not_found"
                    step_variant = "skipped_not_found"
                    print(status_messages.status("  Variant: skipped_not_found", level="warn"))
                else:
                    print(status_messages.status(f"  Variant: {step_variant}", level="info"))
            if step_id == "open_map":
                has_map = prompt_utils.prompt_yes_no("Is Snap Map available/enabled on this account?", default=True)
                step_variant = "available" if has_map else "not_available"
                print(status_messages.status(f"  Variant: {step_variant}", level="info"))
            if step_id in {"my_ai_open", "my_ai_chat"}:
                has_my_ai = prompt_utils.prompt_yes_no("Is My AI visible/available in this account?", default=True)
                step_variant = "available" if has_my_ai else "not_available"
                print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                if has_my_ai:
                    protocol["ai_used"] = True
                    protocol["ai_provider"] = "snap_my_ai"
                    protocol["ai_prompt_id"] = (
                        "snap_my_ai_chat_prompt_01" if step_id == "my_ai_chat" else "snap_my_ai_view_only_v1"
                    )
            if step_id == "team_snapchat_chat":
                has_team_snapchat = prompt_utils.prompt_yes_no(
                    "Is 'Team Snapchat' chat visible/available in this account?",
                    default=True,
                )
                step_variant = "available" if has_team_snapchat else "not_available"
                print(status_messages.status(f"  Variant: {step_variant}", level="info"))
            if step_id == "ask_meta_ai":
                has_meta_ai = prompt_utils.prompt_yes_no("Is Ask Meta AI visible/available on this account?", default=True)
                step_variant = "available" if has_meta_ai else "not_available"
                print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                if has_meta_ai:
                    protocol["ai_used"] = True
                    protocol["ai_provider"] = "meta_ai"
                    protocol["ai_prompt_id"] = "meta_ai_prompt_01"
            if step_id == "grok_ai_prompt":
                has_grok = prompt_utils.prompt_yes_no("Is Grok available/enabled on this account?", default=True)
                step_variant = "available" if has_grok else "not_available"
                print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                if has_grok:
                    protocol["ai_used"] = True
                    protocol["ai_provider"] = "grok"
                    protocol["ai_prompt_id"] = "grok_prompt_01"
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
            if step_outcome == "skipped_not_found":
                # Skip without entering the stopwatch loop.
                if on_protocol_event:
                    on_protocol_event(
                        "STEP_END",
                        {
                            "step_id": step_id,
                            "step_index": idx,
                            "elapsed_s": 0.0,
                            "expected_duration_s": expected_s,
                            "tolerance_s": 0.0,
                            "within_tolerance": True,
                            "step_variant": step_variant,
                            "step_outcome": step_outcome,
                        },
                    )
                protocol["step_skipped_not_found_count"] = int(protocol.get("step_skipped_not_found_count") or 0) + 1
                print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                protocol["step_count_completed"] = idx
                continue
            if step_id == "call_active":
                if protocol.get("call_connected") is True:
                    call_hold_s = int(expected_s)
                    _run_countdown(
                        call_hold_s,
                        continue_after_target=False,
                        allow_early_stop=False,
                    )
                    step_elapsed = float(call_hold_s)
                    protocol["call_connected_duration_s"] = float(call_hold_s)
                    protocol["call_end_reason"] = protocol.get("call_end_reason") or "user_end"
                else:
                    print(status_messages.status("Call not connected; skipping active-hold window.", level="warn"))
                    step_elapsed = 0.0
                    protocol["call_connected_duration_s"] = 0.0
                    protocol["call_end_reason"] = protocol.get("call_end_reason") or "timeout"
            elif step_id == "go_live_hold_5s":
                if go_live_start_skipped:
                    step_outcome = "skipped_not_found"
                    # Skip hold if the live entry step was skipped/not found.
                    if on_protocol_event:
                        on_protocol_event(
                            "STEP_END",
                            {
                                "step_id": step_id,
                                "step_index": idx,
                                "elapsed_s": 0.0,
                                "expected_duration_s": expected_s,
                                "tolerance_s": 0.0,
                                "within_tolerance": True,
                                "step_variant": step_variant,
                                "step_outcome": step_outcome,
                            },
                        )
                    protocol["step_skipped_not_found_count"] = int(protocol.get("step_skipped_not_found_count") or 0) + 1
                    print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                    protocol["step_count_completed"] = idx
                    continue
                live_hold_s = max(int(expected_s), 1)
                _run_countdown(
                    live_hold_s,
                    continue_after_target=False,
                    allow_early_stop=False,
                )
                step_elapsed = float(live_hold_s)
            elif step_id in {"hold_foreground", "user_activity"}:
                elapsed_total = int(time.monotonic() - started_monotonic)
                remaining = max(int(target_duration_s) - elapsed_total, 0)
                step_elapsed = float(max(remaining, 0))
                if remaining > 0:
                    print(status_messages.status(f"Protocol completed; hold foreground for {remaining}s.", level="info"))
                    print(
                        status_messages.status(
                            "Press Enter to stop early (optional). S+Enter=Stop&Finalize, A+Enter=Abort&Discard.",
                            level="info",
                        )
                    )
                    _run_countdown(
                        remaining,
                        # Operators frequently want to continue capturing after the nominal
                        # target (e.g., to stabilize traffic). Do not auto-stop at target.
                        continue_after_target=True,
                        allow_early_stop=True,
                    )
            else:
                step_start = time.monotonic()
                step_outcome = _wait_for_step_completion_with_stopwatch(
                    step_index=idx,
                    step_count=len(steps),
                    step_id=step_id,
                    script_started_monotonic=started_monotonic,
                    step_started_monotonic=step_start,
                    target_duration_s=int(target_duration_s),
                )
                step_elapsed = max(0.0, time.monotonic() - step_start)
                if step_outcome == "skipped_not_found":
                    protocol["step_skipped_not_found_count"] = int(protocol.get("step_skipped_not_found_count") or 0) + 1
                    print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                    if step_id == "go_live_start":
                        go_live_start_skipped = True
                if step_id == "start_call":
                    protocol["call_attempted"] = True
                    connected = prompt_utils.prompt_yes_no("Did the call connect?", default=True)
                    protocol["call_connected"] = bool(connected)
                    protocol["call_connect_latency_s"] = float(round(step_elapsed, 3))
                    protocol["call_connect_timeout_s"] = int(CALL_CONNECT_TIMEOUT_S)
                    if not connected:
                        protocol["call_end_reason"] = "timeout"
                        protocol["call_outcome_reason"] = "CALL_NOT_CONNECTED"
                    elif not protocol.get("call_end_reason"):
                        protocol["call_end_reason"] = "user_end"
                if step_id == "end_call" and protocol.get("call_attempted") is True:
                    protocol["call_end_reason"] = protocol.get("call_end_reason") or "user_end"
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
                        "step_outcome": step_outcome,
                    },
                )
            protocol["step_count_completed"] = idx
    except _StopScriptEarly:
        protocol["script_exit_code"] = int(protocol.get("script_exit_code") or 0) or 130
        deviations = protocol.get("deviation_codes")
        if isinstance(deviations, list):
            deviations.append("STOPPED_EARLY")
        print(status_messages.status("Stop requested; finalizing run early.", level="warn"))
    elapsed_total = int(time.monotonic() - started_monotonic)
    remaining = max(int(target_duration_s) - elapsed_total, 0)
    if remaining > 0 and int(protocol.get("script_exit_code") or 0) == 0:
        # Safety: ensure scripted runs honor target duration even if the template
        # omitted an explicit hold step.
        print(status_messages.status(f"Protocol completed; hold foreground for {remaining}s.", level="info"))
        _run_countdown(
            remaining,
            continue_after_target=True,
            allow_early_stop=True,
        )
    protocol["script_end_marker"] = True
    actual_duration_s = int(time.monotonic() - started_monotonic)
    protocol["actual_duration_s"] = actual_duration_s
    overrun_s = max(0, int(actual_duration_s) - int(target_duration_s))
    underrun_s = max(0, int(target_duration_s) - int(actual_duration_s))
    protocol["target_overrun_s"] = int(overrun_s)
    protocol["target_underrun_s"] = int(underrun_s)
    protocol["target_controlled"] = bool(overrun_s == 0 and underrun_s == 0)
    if overrun_s > 0:
        deviations = protocol.get("deviation_codes")
        if isinstance(deviations, list):
            deviations.append("SCRIPT_TARGET_OVERRUN")
    if underrun_s > 0:
        deviations = protocol.get("deviation_codes")
        if isinstance(deviations, list):
            deviations.append("SCRIPT_TARGET_UNDERRUN")
    if on_protocol_event:
        on_protocol_event(
            "SCRIPT_END",
            {
                "script_name": protocol["script_name"],
                "script_hash": template_hash,
                "template_id": template_id,
                "template_id_requested": requested_template_id,
                "template_id_actual": template_id,
                "template_hash": template_hash,
                "template_map_version": mapping_version(),
                "template_map_hash": mapping_sha256(),
                "step_count_completed": protocol["step_count_completed"],
                "step_count_planned": protocol["step_count_planned"],
                "script_exit_code": protocol["script_exit_code"],
                "timing_within_tolerance": protocol["timing_within_tolerance"],
                "target_overrun_s": protocol["target_overrun_s"],
                "target_underrun_s": protocol["target_underrun_s"],
                "target_controlled": protocol["target_controlled"],
                "call_type": protocol.get("call_type"),
                "call_attempted": protocol.get("call_attempted"),
                "call_connected": protocol.get("call_connected"),
                "call_connect_latency_s": protocol.get("call_connect_latency_s"),
                "call_connected_duration_s": protocol.get("call_connected_duration_s"),
                "call_end_reason": protocol.get("call_end_reason"),
                "call_outcome_reason": protocol.get("call_outcome_reason"),
                "call_outcome_flag": protocol.get("call_outcome_flag"),
                "script_call_in_non_call_template": protocol.get("script_call_in_non_call_template"),
                "ai_used": protocol.get("ai_used"),
                "ai_provider": protocol.get("ai_provider"),
                "ai_prompt_id": protocol.get("ai_prompt_id"),
            },
        )
    if (
        template_id in call_templates
        and protocol.get("call_connected") is True
        and float(protocol.get("call_connected_duration_s") or 0.0) < float(CALL_MIN_CONNECTED_DURATION_S)
    ):
        protocol["call_outcome_flag"] = "CALL_CONNECTED_SHORT"
        protocol["call_outcome_reason"] = "CALL_CONNECTED_SHORT"
    if template_id in call_templates and protocol.get("call_outcome_reason") is None:
        if protocol.get("call_connected") is True:
            protocol["call_outcome_reason"] = "CALL_CONNECTED_OK"
        elif protocol.get("call_connected") is False:
            protocol["call_outcome_reason"] = "CALL_NOT_CONNECTED"
    non_call_messaging_templates = {
        "messaging_idle_v1",
        "messaging_text_v1",
        "whatsapp_idle_v1",
        "whatsapp_text_v1",
    }
    if (
        template_id in non_call_messaging_templates
        and int(protocol.get("script_exit_code") or 0) == 0
        and int(protocol.get("step_count_completed") or 0) == int(protocol.get("step_count_planned") or 0)
    ):
        call_in_non_call = prompt_utils.prompt_yes_no(
            f"Did any voice/video call occur during this run? (protocol violation for {template_id})",
            default=False,
        )
        protocol["script_call_in_non_call_template"] = bool(call_in_non_call)
        if call_in_non_call:
            deviations = protocol.get("deviation_codes")
            if isinstance(deviations, list):
                deviations.append("SCRIPT_CALL_ACTION_NON_CALL_TEMPLATE")
    return protocol


def _is_messaging_connected_baseline_context(run_ctx: RunContext) -> bool:
    profile = str(getattr(run_ctx, "run_profile", "") or "").strip().lower()
    if profile != "baseline_connected":
        return False
    msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
    if msg_activity not in {"", "connected_idle"}:
        return False
    category = str(category_for_package(getattr(run_ctx, "package_name", "") or "") or "").strip().lower()
    return category == "messaging"


def _run_messaging_connected_baseline(
    *,
    run_ctx: RunContext,
    target_duration_s: int,
    protocol: dict[str, object],
    on_protocol_event: Callable[[str, dict[str, object]], None] | None,
) -> datetime:
    print(
        status_messages.status(
            "Press Enter to stop early (optional). S+Enter=Stop&Finalize, A+Enter=Abort&Discard.",
            level="info",
        )
    )
    action_schedule_s, refresh_check_s = _build_baseline_connected_schedule(
        run_id=str(getattr(run_ctx, "dynamic_run_id", "") or ""),
        target_duration_s=int(target_duration_s),
    )
    protocol["cadence_rule_s"] = {"min": 45, "max": 75}
    protocol["refresh_check_window_s"] = {"min": 90, "max": 150}
    protocol["action_schedule_s"] = list(action_schedule_s)
    protocol["refresh_check_s"] = int(refresh_check_s)

    if on_protocol_event:
        on_protocol_event(
            "BASELINE_CONNECTED_START",
            {
                "baseline_protocol_id": protocol.get("baseline_protocol_id"),
                "baseline_protocol_version": protocol.get("baseline_protocol_version"),
                "baseline_protocol_hash": protocol.get("baseline_protocol_hash"),
                "target_duration_s": int(target_duration_s),
                "cadence_rule_s": {"min": 45, "max": 75},
                "refresh_check_window_s": {"min": 90, "max": 150},
                "action_schedule_s": list(action_schedule_s),
                "refresh_check_s": int(refresh_check_s),
            },
        )

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        time.sleep(max(int(target_duration_s), 0))
        if on_protocol_event:
            on_protocol_event(
                "BASELINE_CONNECTED_END",
                {"target_duration_s": int(target_duration_s), "advisory_prompts_emitted": 0},
            )
        return datetime.now(UTC)

    start = time.monotonic()
    line_width = 56
    last_rendered = None
    action_idx = 0
    refresh_emitted = False
    checkpoint_emitted = False
    advisory_prompts_emitted = 0
    target_reached_announced = False
    while True:
        elapsed_i = int(time.monotonic() - start)
        remaining = max(int(target_duration_s) - elapsed_i, 0)

        while action_idx < len(action_schedule_s) and elapsed_i >= int(action_schedule_s[action_idx]):
            _clear_status_line(line_width)
            advisory_prompts_emitted += 1
            prompt_msg = (
                "Baseline-connected prompt: perform one allowed non-mutating check "
                "(small thread scroll OR chat-list/thread switch), then continue holding foreground."
            )
            print(status_messages.status(prompt_msg, level="info"))
            if on_protocol_event:
                on_protocol_event(
                    "BASELINE_CONNECTED_ACTION_PROMPT",
                    {
                        "prompt_index": int(action_idx + 1),
                        "scheduled_s": int(action_schedule_s[action_idx]),
                        "elapsed_s": int(elapsed_i),
                    },
                )
            action_idx += 1

        if (not refresh_emitted) and elapsed_i >= int(refresh_check_s):
            _clear_status_line(line_width)
            advisory_prompts_emitted += 1
            print(
                status_messages.status(
                    "Baseline-connected prompt: perform the single refresh/check action now, then return to thread and hold.",
                    level="info",
                )
            )
            if on_protocol_event:
                on_protocol_event(
                    "BASELINE_CONNECTED_REFRESH_PROMPT",
                    {
                        "scheduled_s": int(refresh_check_s),
                        "elapsed_s": int(elapsed_i),
                    },
                )
            refresh_emitted = True

        if (not checkpoint_emitted) and elapsed_i >= 120:
            _clear_status_line(line_width)
            print(
                status_messages.status(
                    "120s checkpoint: if packet span appears low, do one allowed non-mutating check action now.",
                    level="warn",
                )
            )
            if on_protocol_event:
                on_protocol_event(
                    "BASELINE_CONNECTED_CHECKPOINT_120",
                    {"elapsed_s": int(elapsed_i)},
                )
            checkpoint_emitted = True

        total = _format_duration(int(target_duration_s))
        elapsed_fmt = _format_duration(elapsed_i)
        suffix = _pulse_marker(elapsed_i)
        if remaining > 0:
            message = f"\rElapsed time: {elapsed_fmt} (target {total}){suffix}".ljust(line_width)
        else:
            message = f"\rElapsed time: {elapsed_fmt} (target reached){suffix}".ljust(line_width)
        if message != last_rendered:
            sys.stdout.write(message)
            sys.stdout.flush()
            last_rendered = message
        if remaining <= 0 and not target_reached_announced:
            _clear_status_line(line_width)
            print(
                status_messages.status(
                    "Target reached. Keep collecting if needed; press Enter when finished.",
                    level="info",
                )
            )
            target_reached_announced = True
        readable, _, _ = select.select([sys.stdin], [], [], 1.0)
        if readable:
            action = _parse_timing_action(sys.stdin.readline())
            if action == "abort":
                _clear_status_line(line_width)
                print()
                raise ScenarioAbortRequested("ABORT_DISCARD")
            if action in {"enter", "stop"}:
                if _should_continue_collecting(elapsed_s=elapsed_i, target_s=int(target_duration_s)):
                    continue
                _clear_status_line(line_width)
                print()
                break
    if on_protocol_event:
        on_protocol_event(
            "BASELINE_CONNECTED_END",
            {
                "target_duration_s": int(target_duration_s),
                "advisory_prompts_emitted": int(advisory_prompts_emitted),
                "refresh_prompt_emitted": bool(refresh_emitted),
                "checkpoint_120_emitted": bool(checkpoint_emitted),
            },
        )
    protocol["advisory_prompts_emitted"] = int(advisory_prompts_emitted)
    protocol["refresh_prompt_emitted"] = bool(refresh_emitted)
    protocol["checkpoint_120_emitted"] = bool(checkpoint_emitted)
    return datetime.now(UTC)


def _build_baseline_connected_schedule(*, run_id: str, target_duration_s: int) -> tuple[list[int], int]:
    # Deterministic bounded variation: schedule differs per run_id but stays within
    # PM-locked cadence constraints (45-75s).
    seed = int(hashlib.sha256(str(run_id or "baseline").encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(seed)
    max_t = max(int(target_duration_s), 1)
    times: list[int] = []
    t = rng.randint(45, 75)
    while t < max_t:
        times.append(int(t))
        t += rng.randint(45, 75)
    refresh_lo = 90
    refresh_hi = min(150, max_t)
    if refresh_hi < refresh_lo:
        refresh_check_s = int(max(1, min(max_t, 90)))
    else:
        refresh_check_s = int(rng.randint(refresh_lo, refresh_hi))
    return times, refresh_check_s


def _build_baseline_protocol(*, run_ctx: RunContext, target_duration_s: int) -> dict[str, object]:
    category = str(category_for_package(getattr(run_ctx, "package_name", "") or "") or "").strip().lower()
    msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
    is_messaging_connected = category == "messaging" and msg_activity == "connected_idle"
    protocol_id = BASELINE_PROTOCOL_ID_CONNECTED if is_messaging_connected else BASELINE_PROTOCOL_ID_IDLE
    payload = {
        "protocol_id": protocol_id,
        "protocol_version": int(BASELINE_PROTOCOL_VERSION),
        "category": category or "unknown",
        "messaging_activity": msg_activity or None,
        "cadence_rule_s": {"min": 45, "max": 75} if is_messaging_connected else None,
        "refresh_check_window_s": {"min": 90, "max": 150} if is_messaging_connected else None,
        "constraints": {
            "no_typing": True,
            "no_send": True,
            "no_call": True,
            "no_media_upload": True,
            "no_search": True,
            "no_external_links": True,
        },
    }
    material = json_dumps_canonical(payload)
    protocol_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return {
        "baseline_protocol_id": protocol_id,
        "baseline_protocol_version": int(BASELINE_PROTOCOL_VERSION),
        "baseline_protocol_hash": protocol_hash,
        "target_duration_s": int(target_duration_s),
    }


def json_dumps_canonical(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _resolve_script_template(run_ctx: RunContext) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
    return _resolve_script_template_for_package(
        package_name=str(getattr(run_ctx, "package_name", "") or ""),
        messaging_activity=msg_activity,
    )


def _requested_script_template(run_ctx: RunContext) -> str:
    return _requested_script_template_for_package(
        package_name=str(getattr(run_ctx, "package_name", "") or ""),
    )


def preview_script_template_for_package(
    *,
    package_name: str,
    messaging_activity: str | None = None,
) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    run_ctx = RunContext(
        dynamic_run_id="preview",
        package_name=str(package_name or "").strip(),
        duration_seconds=0,
        scenario_id="basic_usage",
        run_dir=Path("."),
        artifacts_dir=Path("."),
        analysis_dir=Path("."),
        notes_dir=Path("."),
        interactive=True,
        run_profile="interaction_scripted",
        interaction_level="scripted",
        messaging_activity=messaging_activity,
        device_serial="preview",
    )
    return _resolve_script_template(run_ctx)


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
    print("  N) skip (not found)")
    choice = prompt_utils.get_choice(["1", "2", "N"], default="1", casefold=True, invalid_message="Choose 1, 2, or N.")
    if choice.upper() == "N":
        return "skip"
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
    return _timing_format_duration(seconds)


def _format_duration_precise(seconds: int) -> str:
    return _timing_format_duration_precise(seconds)


def _pulse_marker(elapsed_seconds: int) -> str:
    return _timing_pulse_marker(elapsed_seconds)


def _wait_for_step_completion_with_stopwatch(
    *,
    step_index: int,
    step_count: int,
    step_id: str,
    script_started_monotonic: float,
    step_started_monotonic: float,
    target_duration_s: int,
) -> str:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when step is complete...")
        return "completed"
    # Operators asked for a single stopwatch view (avoid total + per-step dual timers).
    line_width = 82
    last_rendered = None
    try:
        while True:
            total_elapsed_i = int(time.monotonic() - script_started_monotonic)
            total_elapsed_fmt = _format_duration(total_elapsed_i)
            target_fmt = _format_duration(int(target_duration_s))
            suffix = _pulse_marker(total_elapsed_i)
            msg = (
                f"\rElapsed: {total_elapsed_fmt}/{target_fmt} | "
                f"Step {step_index}/{step_count} {step_id} (Enter=done, N=skip){suffix}"
            ).ljust(line_width)
            if msg != last_rendered:
                sys.stdout.write(msg)
                sys.stdout.flush()
                last_rendered = msg
            readable, _, _ = select.select([sys.stdin], [], [], 1.0)
            if readable:
                action = _parse_timing_action(sys.stdin.readline())
                if action == "abort":
                    _clear_status_line(line_width)
                    print()
                    raise ScenarioAbortRequested("ABORT_DISCARD")
                if action == "stop":
                    _clear_status_line(line_width)
                    print()
                    raise _StopScriptEarly("STOP_FINALIZE")
                if action == "enter":
                    _clear_status_line(line_width)
                    print()
                    return "completed"
                if action == "skip":
                    _clear_status_line(line_width)
                    print()
                    return "skipped_not_found"
    except KeyboardInterrupt:
        _clear_status_line(line_width)
        print()
        raise _StopScriptEarly("STOP_FINALIZE") from None
    return "completed"


def _clear_status_line(line_width: int) -> None:
    _timing_clear_status_line(line_width)


def _parse_timing_action(raw: str | None) -> str:
    return _timing_parse_timing_action(raw)


def _should_continue_collecting(*, elapsed_s: int, target_s: int | None) -> bool:
    min_s = int(_effective_min_sampling_seconds())
    target = int(target_s) if isinstance(target_s, int) and target_s > 0 else None
    required = min(min_s, target) if target else min_s
    if int(elapsed_s) >= int(required):
        return False
    print(
        status_messages.status(
            f"Only {_format_duration(int(elapsed_s))} elapsed (< minimum {_format_duration(int(required))}).",
            level="warn",
        )
    )
    stop_anyway = prompt_utils.prompt_yes_no("Stop now anyway (this run will likely be INVALID)?", default=False)
    return not bool(stop_anyway)


__all__ = [
    "ManualScenarioRunner",
    "ScenarioResult",
    "ScenarioAbortRequested",
    "preview_script_template_for_package",
    "SCRIPT_PROTOCOL_VERSION",
]
