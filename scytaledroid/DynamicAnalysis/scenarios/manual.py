"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

import hashlib
import os
import random
import select
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.capture.console import CbreakTerminal, LiveCaptureConsole, SelectInputReader
from scytaledroid.DynamicAnalysis.capture.state import CaptureAction
from scytaledroid.DynamicAnalysis.capture.surface_probe import (
    infer_runtime_surface as _infer_runtime_surface,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    launch_package_to_foreground as _guided_launch_package_to_foreground,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    make_runtime_pcap_bytes_provider as _guided_make_runtime_pcap_bytes_provider,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    read_device_foreground_target as _guided_read_device_foreground_target,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    read_device_foreground_package as _guided_read_device_foreground_package,
)
from scytaledroid.DynamicAnalysis.controllers.guided_run_capture import (
    target_foreground_label as _guided_target_foreground_label,
)
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.scenarios.script_template_catalog import (
    SNAPCHAT_TEMPLATE_HINTS,
    V3_SCRIPTED_REPRO_TIPS,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_scripted import (
    FACEBOOK_BEHAVIOR_V3 as _FACEBOOK_BEHAVIOR_V3,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_scripted import (
    NEWS_BEHAVIOR_V2 as _NEWS_BEHAVIOR_V2,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_scripted import (
    SCRIPTED_ARTICLE_LIMITATION_REASONS as _SCRIPTED_ARTICLE_LIMITATION_REASONS,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_scripted import (
    SCRIPT_LIMITATION_REASON_LABELS,
    SCRIPT_LIMITATION_REASON_TEXT as _SCRIPT_LIMITATION_REASON_TEXT,
    SCRIPT_PROTOCOL_VERSION,
    build_template_hash as _build_template_hash,
    json_dumps_canonical,
    news_branch_skip_reason as _news_branch_skip_reason,
    normalize_limitation_reason as _normalize_limitation_reason,
    preview_script_template_for_package,
    prompt_facebook_control_account_mode as _prompt_facebook_control_account_mode,
    prompt_facebook_repeat_plan as _prompt_facebook_repeat_plan,
    prompt_news_subscription_branch as _prompt_news_subscription_branch,
    prompt_step3_variant as _prompt_step3_variant,
    requested_script_template as _requested_script_template,
    resolve_script_template as _resolve_script_template,
    script_step_event_metadata as _script_step_event_metadata,
    scripted_step_action_line as _scripted_step_action_line,
    scripted_step_description as _scripted_step_description,
)
from scytaledroid.DynamicAnalysis.scenarios.scripted_protocol_runtime import (
    ScriptedProtocolDeps as _ScriptedProtocolDeps,
)
from scytaledroid.DynamicAnalysis.scenarios.scripted_protocol_runtime import (
    ScriptedProtocolRuntime as _ScriptedProtocolRuntime,
)
from scytaledroid.DynamicAnalysis.scenarios.baseline_guidance import (
    baseline_idle_behavior_lines as _guidance_baseline_idle_behavior_lines,
    baseline_idle_checkpoint_messages as _guidance_baseline_idle_checkpoint_messages,
    baseline_idle_quota_warning as _guidance_baseline_idle_quota_warning,
    baseline_idle_ready_note as _guidance_baseline_idle_ready_note,
    messaging_connected_behavior_lines as _guidance_messaging_connected_behavior_lines,
)
from scytaledroid.DynamicAnalysis.scenarios.interactive_guidance import (
    manual_interaction_behavior_lines as _guidance_manual_interaction_behavior_lines,
    manual_interaction_checkpoint_messages as _guidance_manual_interaction_checkpoint_messages,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    ActiveCaptureConfig as _ActiveCaptureConfig,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    ActiveCaptureRuntime as _ActiveCaptureRuntime,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    capture_controls_status_message as _runtime_capture_controls_status_message,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    capture_phase_label as _runtime_capture_phase_label,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    ensure_target_foreground_before_capture as _runtime_ensure_target_foreground_before_capture,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    extra_hold_timer_message as _runtime_extra_hold_timer_message,
)
from scytaledroid.DynamicAnalysis.scenarios.capture_runtime import (
    resolve_capture_version_code as _runtime_resolve_capture_version_code,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_capture_driver import (
    capture_console_exit_message as _driver_capture_console_exit_message,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_capture_driver import (
    capture_console_launch_message as _driver_capture_console_launch_message,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_capture_driver import (
    make_runtime_surface_probe as _driver_make_runtime_surface_probe,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_capture_driver import (
    run_baseline_interactive_loop as _driver_run_baseline_interactive_loop,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_capture_driver import (
    run_countdown as _driver_run_countdown,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_capture_driver import (
    run_stopwatch as _driver_run_stopwatch,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome import (
    collect_manual_call_outcome as _collect_manual_call_outcome,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    clear_prompt_and_previous_line as _timing_clear_prompt_and_previous_line,
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
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    rewrite_previous_line_preserving_prompt as _timing_rewrite_previous_line_preserving_prompt,
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


BASELINE_PROTOCOL_VERSION = 2
_CALL_SURFACE_LABELS = {
    "rtc_call_audio_surface",
    "rtc_call_surface",
    "rtc_call_video_surface",
    "telegram_call_surface",
    "telegram_video_call_surface",
    "telegram_voice_call_surface",
    "webrtc_call_surface",
    "webrtc_video_call_surface",
    "webrtc_voice_call_surface",
}
BASELINE_PROTOCOL_ID_CONNECTED = "baseline_connected_v2"
BASELINE_PROTOCOL_ID_IDLE = "baseline_idle_v1"
CALL_CONNECT_TIMEOUT_S = 30
CALL_MIN_CONNECTED_DURATION_S = 90
_TERMINAL_HOLD_STEP_IDS = frozenset({"final_hold", "final_home_hold", "hold_foreground", "user_activity"})


def _apply_script_early_stop(
    protocol: dict[str, object],
    *,
    active_step_id: str | None,
) -> None:
    protocol["script_exit_code"] = int(protocol.get("script_exit_code") or 0)
    protocol["stopped_early"] = True
    deviations = protocol.get("deviation_codes")
    if not isinstance(deviations, list):
        deviations = []
        protocol["deviation_codes"] = deviations
    if "STOPPED_EARLY" not in deviations:
        deviations.append("STOPPED_EARLY")
    if str(active_step_id or "").strip() in _TERMINAL_HOLD_STEP_IDS:
        planned = int(protocol.get("step_count_planned") or 0)
        if planned > 0:
            protocol["step_count_completed"] = planned
            protocol["terminal_hold_finalize"] = True
            protocol["stopped_early"] = False
            if "STOPPED_EARLY" in deviations:
                deviations.remove("STOPPED_EARLY")
            if "TERMINAL_HOLD_FINALIZE" not in deviations:
                deviations.append("TERMINAL_HOLD_FINALIZE")
        print(
            status_messages.status(
                "Final hold finalize recorded; completing scripted protocol.",
                level="info",
            )
        )
        return
    print(status_messages.status("Stop requested; finalizing run early.", level="warn"))


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

                    # Paper #3: print short per-template reproducibility tips before capture begins.
                    if str(run_ctx.scenario_id or "") == "paper3_profile_v3":
                        tips = V3_SCRIPTED_REPRO_TIPS.get(str(template_id).strip())
                        if tips:
                            block.append("")
                            block.append("Repro tips:")
                            for t in tips:
                                block.append(f"  - {t}")
                except Exception as exc:
                    block.append(f"Template: unavailable ({exc})")
            # Do not surface run sequencing/slot labels. Operators may run in any order.

            block.append("")
            block.append("User behavior:")
            if str(profile or "").strip().lower().startswith("baseline"):
                category = str(category_for_package(getattr(run_ctx, "package_name", "") or "") or "").strip().lower()
                msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
                if category == "messaging" and msg_activity in {"", "connected_idle", "none"}:
                    block.extend(
                        _guidance_messaging_connected_behavior_lines(
                            getattr(run_ctx, "package_name", "") or ""
                        )
                    )
                else:
                    block.extend(
                        _baseline_idle_behavior_lines(getattr(run_ctx, "package_name", "") or "")
                    )
            else:
                block.extend(
                    _manual_interaction_behavior_lines(
                        getattr(run_ctx, "package_name", "") or "",
                        target_label=_social_feed_baseline_target_label(),
                    )
                )
            print(status_messages.status("\n".join(block).rstrip(), level="info"))
            baseline_warning = _baseline_idle_quota_warning(
                getattr(run_ctx, "package_name", "") or "",
                profile=profile,
            )
            if baseline_warning:
                print(status_messages.status(baseline_warning, level="warn"))
            if run_ctx.scenario_hint:
                print(status_messages.status(run_ctx.scenario_hint, level="info"))
            start_immediately = _maybe_show_raw_high_value_permissions(run_ctx)
            if on_start:
                print(status_messages.status("Starting observers...", level="info"))
                on_start()
            _ensure_target_foreground_before_capture(run_ctx, on_protocol_event=on_protocol_event)
            if _requires_explicit_begin_press(run_ctx=run_ctx, start_immediately=start_immediately):
                print(status_messages.status("Ready. Target app is in foreground.", level="info"))
                ready_note = _baseline_idle_ready_note(getattr(run_ctx, "package_name", "") or "")
                if ready_note:
                    print(status_messages.status(ready_note, level="info"))
                prompt_utils.press_enter_to_continue(_begin_capture_prompt_label(run_ctx))
            started_at = datetime.now(UTC)
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
                    pkg = str(getattr(run_ctx, "package_name", "") or "").strip()
                    ended_at = _run_countdown(
                        duration_seconds,
                        continue_after_target=True,
                        run_profile=profile,
                        app_name=_target_foreground_label(run_ctx),
                        version_code=_resolve_capture_version_code(run_ctx),
                        phase=_capture_phase_label(run_profile=profile, timer_detail="baseline idle"),
                        minimum_duration_s=min_s,
                        timer_detail="baseline idle",
                        device_serial=getattr(run_ctx, "device_serial", None),
                        foreground_package=pkg,
                        checkpoint_messages=_baseline_idle_checkpoint_messages(pkg),
                        surface_probe=_make_runtime_surface_probe(run_ctx),
                        on_protocol_event=on_protocol_event,
                    )
                else:
                    ended_at = _run_stopwatch()
            elif duration_seconds:
                ended_at = _run_countdown(
                    duration_seconds,
                    continue_after_target=True,
                    run_profile=profile,
                    app_name=_target_foreground_label(run_ctx),
                    version_code=_resolve_capture_version_code(run_ctx),
                    phase=_capture_phase_label(run_profile=profile),
                    minimum_duration_s=min_s,
                    device_serial=getattr(run_ctx, "device_serial", None),
                    foreground_package=str(getattr(run_ctx, "package_name", "") or "").strip(),
                    checkpoint_messages=_manual_interaction_checkpoint_messages(
                        str(getattr(run_ctx, "package_name", "") or "").strip()
                    ),
                    surface_probe=_make_runtime_surface_probe(run_ctx),
                )
            else:
                ended_at = _run_stopwatch()
            call_protocol = _manual_call_protocol(getattr(run_ctx, "run_profile", None), run_ctx)
            if call_protocol:
                protocol = dict(protocol or {})
                protocol.update(call_protocol)
                if on_protocol_event:
                    on_protocol_event("MANUAL_CALL_OUTCOME", dict(call_protocol))
            if on_end:
                on_end()
            elapsed = int((ended_at - started_at).total_seconds())
            if profile == "interaction_scripted":
                target_s = int((protocol or {}).get("target_duration_s") or duration_seconds or rec_s)
                overrun_s = int((protocol or {}).get("target_overrun_s") or 0)
                underrun_s = int((protocol or {}).get("target_underrun_s") or 0)
                stopped_early = bool((protocol or {}).get("stopped_early"))
                terminal_hold_finalize = bool((protocol or {}).get("terminal_hold_finalize"))
                completed_steps = int((protocol or {}).get("step_count_completed") or 0)
                planned_steps = int((protocol or {}).get("step_count_planned") or 0)
                status_detail = ", on-target"
                level = "info"
                if terminal_hold_finalize and planned_steps > 0:
                    status_detail = f", final hold completed ({completed_steps}/{planned_steps})"
                elif stopped_early and planned_steps > 0:
                    status_detail = (
                        f", stopped early at step {completed_steps}/{planned_steps}; "
                        "incomplete script will not count toward cohort quota"
                    )
                    level = "warn"
                elif overrun_s > 0:
                    status_detail = f", overrun {overrun_s}s; overrun alone does not invalidate technical validity"
                elif underrun_s > 0:
                    status_detail = f", underrun {underrun_s}s"
                    level = "warn"
                print(
                    status_messages.status(
                        f"Protocol completed in {_format_duration(elapsed)} "
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


def _capture_controls_status_message() -> str:
    return _runtime_capture_controls_status_message()


def _capture_console_launch_message() -> str:
    return _driver_capture_console_launch_message()


def _capture_console_exit_message(action: CaptureAction) -> str:
    return _driver_capture_console_exit_message(action)


def _read_device_foreground_package(device_serial: str | None) -> str | None:
    return _guided_read_device_foreground_package(device_serial)


def _read_device_foreground_target(device_serial: str | None) -> tuple[str | None, str | None]:
    return _guided_read_device_foreground_target(device_serial)


def _target_foreground_label(run_ctx: RunContext) -> str:
    return _guided_target_foreground_label(
        package_name=str(getattr(run_ctx, "package_name", "") or ""),
        static_plan=run_ctx.static_plan if isinstance(run_ctx.static_plan, dict) else None,
    )


def _launch_package_to_foreground(device_serial: str | None, package_name: str | None) -> None:
    _guided_launch_package_to_foreground(device_serial, package_name)


def _ensure_target_foreground_before_capture(
    run_ctx: RunContext,
    *,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
) -> None:
    _runtime_ensure_target_foreground_before_capture(
        run_ctx,
        target_label=_target_foreground_label(run_ctx),
        on_protocol_event=on_protocol_event,
        prompt_continue_fn=prompt_utils.press_enter_to_continue,
        status_printer=lambda message, level="info": print(status_messages.status(message, level=level)),
        read_foreground_fn=_read_device_foreground_target,
        launch_callback=_launch_package_to_foreground,
    )


def _social_feed_baseline_target_label() -> str:
    return _format_duration_precise(_effective_recommended_sampling_seconds())


def _baseline_idle_behavior_lines(package_name: str) -> list[str]:
    return _guidance_baseline_idle_behavior_lines(
        package_name,
        target_label=_social_feed_baseline_target_label(),
    )


def _baseline_idle_quota_warning(package_name: str, *, profile: str | None) -> str | None:
    return _guidance_baseline_idle_quota_warning(package_name, profile=profile)


def _baseline_idle_checkpoint_messages(package_name: str) -> dict[int, str]:
    return _guidance_baseline_idle_checkpoint_messages(package_name)


def _baseline_idle_ready_note(package_name: str) -> str | None:
    return _guidance_baseline_idle_ready_note(package_name)


def _manual_interaction_behavior_lines(package_name: str, *, target_label: str) -> list[str]:
    return _guidance_manual_interaction_behavior_lines(package_name, target_label=target_label)


def _manual_interaction_checkpoint_messages(package_name: str) -> dict[int, str]:
    return _guidance_manual_interaction_checkpoint_messages(package_name)


def _extra_hold_timer_message(
    *,
    target_duration_s: int,
    elapsed_s: int,
    timer_detail: str = "",
    suffix: str = "",
) -> str:
    return _runtime_extra_hold_timer_message(
        target_duration_s=target_duration_s,
        elapsed_s=elapsed_s,
        timer_detail=timer_detail,
        suffix=suffix,
    )


def _capture_phase_label(*, run_profile: str | None, timer_detail: str = "") -> str:
    return _runtime_capture_phase_label(run_profile=run_profile, timer_detail=timer_detail)


def _resolve_capture_version_code(run_ctx: RunContext) -> str | None:
    return _runtime_resolve_capture_version_code(run_ctx)


def _make_runtime_surface_probe(
    run_ctx: RunContext,
) -> Callable[[object], tuple[str | None, str | None]] | None:
    return _driver_make_runtime_surface_probe(
        run_ctx,
        clock=time.monotonic,
        infer_runtime_surface_fn=_infer_runtime_surface,
    )


def _run_baseline_interactive_loop(
    target_duration_s: int,
    *,
    continue_after_target: bool = True,
    run_profile: str | None = None,
    timer_detail: str = "",
    app_name: str | None = None,
    version_code: str | None = None,
    phase: str | None = None,
    minimum_duration_s: int | None = None,
    device_serial: str | None = None,
    foreground_package: str | None = None,
    checkpoint_messages: dict[int, str] | None = None,
    surface_probe: Callable[[object], tuple[str | None, str | None]] | None = None,
    on_elapsed: Callable[[int, Callable[[str, str], None]], None] | None = None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
    pcap_bytes_provider: Callable[[], int | None] | None = None,
) -> datetime:
    return _driver_run_baseline_interactive_loop(
        int(target_duration_s),
        continue_after_target=bool(continue_after_target),
        run_profile=run_profile,
        timer_detail=str(timer_detail or ""),
        app_name=app_name,
        version_code=version_code,
        phase=phase,
        minimum_duration_s=minimum_duration_s,
        minimum_duration_default_s=_effective_min_sampling_seconds(),
        device_serial=device_serial,
        foreground_package=foreground_package,
        checkpoint_messages=checkpoint_messages,
        surface_probe=surface_probe,
        on_elapsed=on_elapsed,
        on_protocol_event=on_protocol_event,
        pcap_bytes_provider=pcap_bytes_provider,
        read_foreground_target=_read_device_foreground_target,
        launch_package_to_foreground=_launch_package_to_foreground,
        should_continue_collecting_fn=_should_continue_collecting,
        clock=time.monotonic,
        stdin=sys.stdin,
        stdout=sys.stdout,
        abort_exception_factory=ScenarioAbortRequested,
        runtime_class=_ActiveCaptureRuntime,
        capture_config_class=_ActiveCaptureConfig,
        console_class=LiveCaptureConsole,
        input_reader_factory=SelectInputReader,
        terminal_factory=CbreakTerminal,
    )


def _run_countdown(
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
    timer_detail: str = "",
    device_serial: str | None = None,
    foreground_package: str | None = None,
    checkpoint_messages: dict[int, str] | None = None,
    surface_probe: Callable[[object], tuple[str | None, str | None]] | None = None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
) -> datetime:
    if allow_early_stop and not ignore_stop_inputs:
        return _run_baseline_interactive_loop(
            int(duration_seconds),
            continue_after_target=continue_after_target,
            run_profile=run_profile,
            app_name=app_name,
            version_code=version_code,
            phase=phase,
            minimum_duration_s=minimum_duration_s,
            timer_detail=timer_detail,
            device_serial=device_serial,
            foreground_package=foreground_package,
            checkpoint_messages=checkpoint_messages,
            surface_probe=surface_probe,
            on_protocol_event=on_protocol_event,
        )
    return _driver_run_countdown(
        int(duration_seconds),
        continue_after_target=continue_after_target,
        allow_early_stop=allow_early_stop,
        ignore_stop_inputs=ignore_stop_inputs,
        run_profile=run_profile,
        app_name=app_name,
        version_code=version_code,
        phase=phase,
        minimum_duration_s=minimum_duration_s,
        minimum_duration_default_s=_effective_min_sampling_seconds(),
        timer_detail=timer_detail,
        device_serial=device_serial,
        foreground_package=foreground_package,
        checkpoint_messages=checkpoint_messages,
        surface_probe=surface_probe,
        on_protocol_event=on_protocol_event,
        should_continue_collecting_fn=_should_continue_collecting,
        abort_exception_factory=ScenarioAbortRequested,
        stop_exception_factory=_StopScriptEarly,
        format_duration_fn=_format_duration,
        pulse_marker_fn=_pulse_marker,
        extra_hold_timer_message_fn=_extra_hold_timer_message,
        clear_status_line_fn=_clear_status_line,
        parse_timing_action_fn=_parse_timing_action,
        read_foreground_target=_read_device_foreground_target,
        launch_package_to_foreground=_launch_package_to_foreground,
        clock=time.monotonic,
        sleep=time.sleep,
        stdin=sys.stdin,
        stdout=sys.stdout,
    )


def _run_stopwatch() -> datetime:
    return _driver_run_stopwatch(
        format_duration_fn=_format_duration,
        controls_message=status_messages.status(_capture_controls_status_message(), level="info"),
        parse_timing_action_fn=_parse_timing_action,
        should_continue_collecting_fn=_should_continue_collecting,
        abort_exception_factory=ScenarioAbortRequested,
        prompt_continue_fn=prompt_utils.press_enter_to_continue,
        clock=time.monotonic,
        stdin=sys.stdin,
        stdout=sys.stdout,
    )


def _run_scripted_protocol(
    *,
    run_ctx: RunContext,
    target_duration_s: int,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None,
) -> dict[str, object]:
    deps = _ScriptedProtocolDeps(
        resolve_script_template=_resolve_script_template,
        requested_script_template=_requested_script_template,
        build_template_hash=_build_template_hash,
        prompt_facebook_control_account_mode=_prompt_facebook_control_account_mode,
        prompt_facebook_repeat_plan=_prompt_facebook_repeat_plan,
        scripted_step_description=_scripted_step_description,
        scripted_step_action_line=_scripted_step_action_line,
        news_branch_skip_reason=_news_branch_skip_reason,
        script_step_event_metadata=_script_step_event_metadata,
        prompt_step3_variant=_prompt_step3_variant,
        wait_for_step_completion_with_stopwatch=_wait_for_step_completion_with_stopwatch,
        run_countdown=_run_countdown,
        normalize_limitation_reason=_normalize_limitation_reason,
        prompt_news_subscription_branch=_prompt_news_subscription_branch,
        apply_script_early_stop=_apply_script_early_stop,
        maybe_mark_scripted_run_as_manual_override=_maybe_mark_scripted_run_as_manual_override,
        format_duration=_format_duration,
        mapping_version=mapping_version,
        mapping_sha256=mapping_sha256,
        prompt_utils=prompt_utils,
        stop_exception_type=_StopScriptEarly,
        abort_exception_factory=ScenarioAbortRequested,
        snapchat_template_hints=SNAPCHAT_TEMPLATE_HINTS,
        terminal_hold_step_ids=_TERMINAL_HOLD_STEP_IDS,
        facebook_behavior_v3=_FACEBOOK_BEHAVIOR_V3,
        news_behavior_v2=_NEWS_BEHAVIOR_V2,
        script_protocol_version=SCRIPT_PROTOCOL_VERSION,
        script_limitation_reason_text=_SCRIPT_LIMITATION_REASON_TEXT,
        scripted_article_limitation_reasons=_SCRIPTED_ARTICLE_LIMITATION_REASONS,
        call_connect_timeout_s=CALL_CONNECT_TIMEOUT_S,
        call_min_connected_duration_s=CALL_MIN_CONNECTED_DURATION_S,
    )
    return _ScriptedProtocolRuntime(deps).run(
        run_ctx=run_ctx,
        target_duration_s=target_duration_s,
        on_protocol_event=on_protocol_event,
    )


def _maybe_mark_scripted_run_as_manual_override(
    *,
    protocol: dict[str, object],
    template_id: str,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None,
) -> None:
    if not isinstance(protocol, dict):
        return
    if bool(protocol.get("script_manual_override")):
        return
    if int(protocol.get("script_exit_code") or 0) != 0:
        return

    limited_count = int(protocol.get("step_limited_count") or 0)
    skipped_count = int(protocol.get("step_skipped_not_found_count") or 0)
    skipped_branch_count = int(protocol.get("step_skipped_branch_not_taken_count") or 0)
    if (limited_count + skipped_count + skipped_branch_count) <= 0:
        return

    continued_manual = prompt_utils.prompt_yes_no(
        (
            "Did the scripted template stop matching reality, after which you continued "
            "as a freeform manual interactive run?"
        ),
        default=False,
    )
    if not continued_manual:
        return

    protocol["script_manual_override"] = True
    protocol["profile_override"] = "interaction_manual"
    protocol["interaction_level_override"] = "manual"
    protocol["script_manual_override_reason"] = "operator_continued_manual_after_script_diverged"
    deviations = protocol.get("deviation_codes")
    if isinstance(deviations, list):
        deviations.append("SCRIPT_CONTINUED_AS_MANUAL")
    if on_protocol_event:
        on_protocol_event(
            "SCRIPT_MANUAL_OVERRIDE",
            {
                "template_id": template_id,
                "step_limited_count": limited_count,
                "step_skipped_not_found_count": skipped_count,
                "step_skipped_branch_not_taken_count": skipped_branch_count,
                "reason": "operator_continued_manual_after_script_diverged",
            },
        )


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

    action_idx = 0
    refresh_emitted = False
    checkpoint_emitted = False
    advisory_prompts_emitted = 0
    pkg = str(getattr(run_ctx, "package_name", "") or "").strip()

    def _on_elapsed(
        elapsed_i: int,
        emit_status: Callable[[str, str], None],
    ) -> None:
        nonlocal action_idx, refresh_emitted, checkpoint_emitted, advisory_prompts_emitted
        while action_idx < len(action_schedule_s) and elapsed_i >= int(action_schedule_s[action_idx]):
            advisory_prompts_emitted += 1
            prompt_msg = (
                "Baseline-connected prompt: perform one allowed non-mutating check "
                "(small thread scroll OR chat-list/thread switch), then continue holding foreground."
            )
            emit_status(prompt_msg, "info")
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
            advisory_prompts_emitted += 1
            emit_status(
                "Baseline-connected prompt: perform the single refresh/check action now, then return to thread and hold.",
                "info",
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
            emit_status(
                "120s checkpoint: if packet span appears low, do one allowed non-mutating check action now.",
                "warn",
            )
            if on_protocol_event:
                on_protocol_event(
                    "BASELINE_CONNECTED_CHECKPOINT_120",
                    {"elapsed_s": int(elapsed_i)},
                )
            checkpoint_emitted = True

    ended_at = _run_baseline_interactive_loop(
        int(target_duration_s),
        continue_after_target=True,
        run_profile=str(getattr(run_ctx, "run_profile", "") or ""),
        app_name=_target_foreground_label(run_ctx),
        version_code=_resolve_capture_version_code(run_ctx),
        phase=_capture_phase_label(run_profile=getattr(run_ctx, "run_profile", None), timer_detail="connected baseline"),
        minimum_duration_s=_effective_min_sampling_seconds(),
        timer_detail="connected baseline",
        device_serial=getattr(run_ctx, "device_serial", None),
        foreground_package=pkg,
        surface_probe=_make_runtime_surface_probe(run_ctx),
        on_elapsed=_on_elapsed,
        on_protocol_event=on_protocol_event,
        pcap_bytes_provider=_guided_make_runtime_pcap_bytes_provider(
            device_serial=getattr(run_ctx, "device_serial", None),
            package_name=pkg,
            dynamic_run_id=str(getattr(run_ctx, "dynamic_run_id", "") or ""),
        ),
    )
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
    return ended_at


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


def _manual_call_protocol(run_profile: str | None, run_ctx: RunContext) -> dict[str, object] | None:
    profile_lc = str(run_profile or "").strip().lower()
    if profile_lc != "interaction_manual":
        return None
    messaging_activity = getattr(run_ctx, "messaging_activity", None)
    effective_activity, foreground_component = _effective_manual_call_activity(run_ctx, messaging_activity)
    payload = _collect_manual_call_outcome(messaging_activity=effective_activity)
    if payload and effective_activity != messaging_activity:
        payload["call_activity_inferred_from_foreground"] = True
        payload["call_activity_original_tag"] = messaging_activity
        payload["call_activity_foreground_component"] = foreground_component
    return payload


def _effective_manual_call_activity(
    run_ctx: RunContext,
    messaging_activity: str | None,
) -> tuple[str | None, str | None]:
    activity = str(messaging_activity or "").strip().lower()
    if activity in {"voice_call", "video_call"}:
        return messaging_activity, None
    foreground_package, foreground_component = _guided_read_device_foreground_target(
        getattr(run_ctx, "device_serial", None)
    )
    expected_package = str(getattr(run_ctx, "package_name", "") or "").strip().lower()
    actual_package = str(foreground_package or "").strip().lower()
    component = str(foreground_component or "").strip()
    component_lc = component.lower()
    if actual_package != expected_package:
        return messaging_activity, component or None
    looks_like_call = _looks_like_call_component(component_lc)
    if not looks_like_call:
        try:
            surface_label, _surface_detail = _infer_runtime_surface(
                expected_package=expected_package,
                foreground_package=actual_package,
                foreground_component=component,
                device_serial=getattr(run_ctx, "device_serial", None),
            )
        except Exception:
            surface_label = None
        looks_like_call = str(surface_label or "").strip() in _CALL_SURFACE_LABELS
    if not looks_like_call:
        return messaging_activity, component or None
    if not sys.stdin.isatty():
        return messaging_activity, component or None
    print(
        status_messages.status(
            f"Foreground call surface detected ({component}). The run was tagged {activity or 'none'}.",
            level="warn",
        )
    )
    print("Record this manual run as a call?")
    print("1) Voice call")
    print("2) Video call")
    print("0) Keep original tag / skip call outcome")
    choice = prompt_utils.get_choice(
        ["1", "2", "0"],
        default="1",
        invalid_message="Choose 1, 2, or 0.",
    )
    if choice == "1":
        return "voice_call", component or None
    if choice == "2":
        return "video_call", component or None
    return messaging_activity, component or None


def _looks_like_call_component(component_lc: str) -> bool:
    if not component_lc:
        return False
    return any(
        token in component_lc
        for token in (
            "webrtccallactivity",
            "callactivity",
            "incall",
            "voip",
            "voicecall",
            "videocall",
        )
    )


def _maybe_show_raw_high_value_permissions(run_ctx: RunContext) -> bool:
    plan = run_ctx.static_plan if isinstance(run_ctx.static_plan, dict) else {}
    perms = plan.get("permissions") if isinstance(plan.get("permissions"), dict) else {}
    high_value = perms.get("high_value") if isinstance(perms.get("high_value"), list) else []
    raw = [str(p).strip() for p in high_value if str(p).strip()]
    if not raw:
        return False
    # Drop stale buffered input so an earlier Enter cannot silently dismiss the
    # last pre-capture prompt and auto-start the run.
    _drain_stdin_nonblocking()
    choice = prompt_utils.prompt_text(
        "Press Enter to continue, or P to view raw high-value permissions",
        required=False,
    ).strip().lower()
    if choice != "p":
        return True
    sample = ", ".join(sorted(raw)[:10])
    print(status_messages.status(f"High-value permissions (sample): {sample}", level="info"))
    return False


def _requires_explicit_begin_press(*, run_ctx: RunContext, start_immediately: bool) -> bool:
    return not start_immediately


def _begin_capture_prompt_label(run_ctx: RunContext) -> str:
    if _is_messaging_connected_baseline_context(run_ctx):
        return "Press Enter to open live capture console and start connected-idle baseline..."
    return "Press Enter to open live capture console and start capture..."


def _format_duration(seconds: int) -> str:
    return _timing_format_duration(seconds)


def _format_duration_precise(seconds: int) -> str:
    return _timing_format_duration_precise(seconds)


def _pulse_marker(elapsed_seconds: int) -> str:
    return _timing_pulse_marker(elapsed_seconds)


def _drain_stdin_nonblocking(*, max_reads: int = 32) -> None:
    if not sys.stdin.isatty():
        return
    reads = 0
    try:
        while reads < max_reads:
            readable, _, _ = select.select([sys.stdin], [], [], 0.0)
            if not readable:
                break
            sys.stdin.readline()
            reads += 1
    except Exception:
        return


def _confirm_script_exit(action: str) -> bool:
    normalized = str(action or "").strip().lower()
    if normalized == "stop":
        confirm = prompt_utils.prompt_text(
            "Finalize early? This may make the run invalid. Type FINALIZE to continue, or Enter to cancel.",
            required=False,
        ).strip()
        return confirm == "FINALIZE"
    if normalized == "abort":
        confirm = prompt_utils.prompt_text(
            "Abort and discard this run? Type ABORT to continue, or Enter to cancel.",
            required=False,
        ).strip()
        return confirm == "ABORT"
    return False


def _wait_for_step_completion_with_stopwatch(
    *,
    step_index: int,
    step_count: int,
    step_id: str,
    script_started_monotonic: float,
    step_started_monotonic: float,
    target_duration_s: int,
    guided_remaining_s: int | None = None,
    on_phase_marker: Callable[[dict[str, object]], None] | None = None,
) -> tuple[str, str | None, str | None]:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when step is complete...")
        return ("completed", None, None)
    # Operators asked for a single stopwatch view with a stable prompt line.
    line_width = 72
    prompt_line = "Action [D/L/N/H] \u203a "
    prompt_width = 64
    last_rendered = None
    last_render_bucket: int | None = None

    def _render_timer_line(message: str) -> None:
        nonlocal last_rendered
        if last_rendered is None:
            sys.stdout.write(message.ljust(line_width) + "\n")
            sys.stdout.write(prompt_line)
            sys.stdout.flush()
            last_rendered = message
            return
        _timing_rewrite_previous_line_preserving_prompt(message, line_width=line_width)
        last_rendered = message

    def _clear_step_prompt_lines() -> None:
        _timing_clear_prompt_and_previous_line(line_width=line_width, prompt_width=prompt_width)

    _drain_stdin_nonblocking()

    try:
        while True:
            total_elapsed_i = int(time.monotonic() - script_started_monotonic)
            total_elapsed_fmt = _format_duration(total_elapsed_i)
            target_fmt = _format_duration(int(target_duration_s))
            render_bucket = total_elapsed_i // 10
            msg = f"Elapsed: {total_elapsed_fmt} / {target_fmt} | Step {step_index}/{step_count} — {step_id}"
            if guided_remaining_s is not None and int(guided_remaining_s) > 0:
                msg = f"{msg} | ~{_format_duration(int(guided_remaining_s))} guided remaining"
            if (
                str(step_id) in _TERMINAL_HOLD_STEP_IDS
                and total_elapsed_i >= int(target_duration_s)
            ):
                msg = f"{msg} | Target reached — press D to complete"
            if msg != last_rendered and (last_render_bucket is None or render_bucket != last_render_bucket):
                _render_timer_line(msg)
                last_render_bucket = render_bucket
            readable, _, _ = select.select([sys.stdin], [], [], 1.0)
            if readable:
                raw_line = sys.stdin.readline()
                if str(raw_line or "").strip() == "":
                    continue
                action = _parse_timing_action(raw_line)
                if action == "abort":
                    if not _confirm_script_exit("abort"):
                        _render_timer_line(msg)
                        continue
                    _clear_step_prompt_lines()
                    print()
                    raise ScenarioAbortRequested("ABORT_DISCARD")
                if action == "stop":
                    if not _confirm_script_exit("stop"):
                        _render_timer_line(msg)
                        continue
                    _clear_step_prompt_lines()
                    print()
                    raise _StopScriptEarly("STOP_FINALIZE")
                if action == "enter":
                    _clear_step_prompt_lines()
                    print()
                    return ("completed", None, None)
                if action == "skip":
                    _clear_step_prompt_lines()
                    print()
                    return ("skipped_not_found", None, None)
                if action == "limited":
                    _clear_step_prompt_lines()
                    print()
                    limitation_reason, operator_note = _prompt_scripted_limitation_details(step_id)
                    return ("limited", limitation_reason, operator_note)
                if action == "return_home":
                    if on_phase_marker:
                        on_phase_marker(
                            {
                                "phase_id": "return_home_manual",
                                "phase_label": "Return Home Manual",
                                "operator_result": "done",
                                "mutation_performed": False,
                            }
                        )
                    print(status_messages.status("Return-home/reset marker recorded.", level="info"))
                    _clear_step_prompt_lines()
                    print()
                    return ("completed", None, None)
    except KeyboardInterrupt:
        _clear_step_prompt_lines()
        print()
        # In strict freeze/demo mode, do not finalize partially-completed scripted runs.
        strict = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
        if strict:
            raise ScenarioAbortRequested("ABORT_DISCARD") from None
        raise _StopScriptEarly("STOP_FINALIZE") from None
    return ("completed", None, None)


def _prompt_scripted_limitation_details(step_id: str) -> tuple[str, str | None]:
    print(status_messages.status(f"Step limitation for {step_id}:", level="warn"))
    for idx, (_key, label) in enumerate(SCRIPT_LIMITATION_REASON_LABELS, start=1):
        print(f"  {idx}) {label}")
    choice = prompt_utils.get_choice(
        [str(i) for i in range(1, len(SCRIPT_LIMITATION_REASON_LABELS) + 1)],
        default="1",
        invalid_message=f"Choose 1-{len(SCRIPT_LIMITATION_REASON_LABELS)}.",
    )
    limitation_reason = _normalize_limitation_reason(SCRIPT_LIMITATION_REASON_LABELS[int(choice) - 1][0])
    operator_note = prompt_utils.prompt_text(
        "Optional operator note",
        required=False,
    ).strip()
    return limitation_reason, (operator_note or None)


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
