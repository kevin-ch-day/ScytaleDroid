"""Scripted interactive protocol runtime for manual scenarios."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.Utils.DisplayUtils import status_messages


@dataclass(frozen=True)
class ScriptedProtocolDeps:
    resolve_script_template: Callable[[RunContext], tuple[str, tuple[tuple[str, str, int], ...]]]
    requested_script_template: Callable[[RunContext], str]
    build_template_hash: Callable[[str, tuple[tuple[str, str, int], ...]], str]
    prompt_facebook_control_account_mode: Callable[[], str]
    prompt_facebook_repeat_plan: Callable[[], dict[str, int]]
    scripted_step_description: Callable[..., str]
    scripted_step_action_line: Callable[..., str]
    news_branch_skip_reason: Callable[..., str | None]
    script_step_event_metadata: Callable[..., dict[str, object]]
    prompt_step3_variant: Callable[[], str]
    wait_for_step_completion_with_stopwatch: Callable[..., object]
    run_countdown: Callable[..., object]
    normalize_limitation_reason: Callable[[str | None], str | None]
    prompt_news_subscription_branch: Callable[[], str]
    apply_script_early_stop: Callable[..., None]
    maybe_mark_scripted_run_as_manual_override: Callable[..., None]
    format_duration: Callable[[int], str]
    mapping_version: Callable[[], str]
    mapping_sha256: Callable[[], str]
    prompt_utils: object
    stop_exception_type: type[BaseException]
    abort_exception_factory: Callable[[str], BaseException]
    snapchat_template_hints: dict[str, str]
    terminal_hold_step_ids: frozenset[str]
    facebook_behavior_v3: str
    news_behavior_v2: str
    script_protocol_version: int
    script_limitation_reason_text: dict[str, str]
    scripted_article_limitation_reasons: set[str]
    call_connect_timeout_s: int
    call_min_connected_duration_s: int


class ScriptedProtocolRuntime:
    def __init__(self, deps: ScriptedProtocolDeps) -> None:
        self.deps = deps

    def run(
        self,
        *,
        run_ctx: RunContext,
        target_duration_s: int,
        on_protocol_event: Callable[[str, dict[str, object]], None] | None,
    ) -> dict[str, object]:
        deps = self.deps
        template_id, steps = deps.resolve_script_template(run_ctx)
        requested_template_id = deps.requested_script_template(run_ctx)
        template_hash = deps.build_template_hash(template_id, steps)
        facebook_mode = (
            deps.prompt_facebook_control_account_mode()
            if template_id == deps.facebook_behavior_v3
            else None
        )
        facebook_repeat_plan = (
            deps.prompt_facebook_repeat_plan()
            if template_id == deps.facebook_behavior_v3
            else None
        )
        protocol: dict[str, object] = {
            "interaction_protocol_version": deps.script_protocol_version,
            "template_id": template_id,
            "template_id_requested": requested_template_id,
            "template_id_actual": template_id,
            "template_map_version": deps.mapping_version(),
            "template_map_hash": deps.mapping_sha256(),
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
        if template_id == deps.facebook_behavior_v3:
            protocol.update(
                {
                    "account_context": "control_test_account",
                    "control_account": True,
                    "control_account_mode": facebook_mode,
                    "mutation_allowed": facebook_mode == "control_account_active",
                    "cleanup_expected": facebook_mode == "control_account_active",
                    "repeat_plan": dict(facebook_repeat_plan or {}),
                }
            )
        started_monotonic = time.monotonic()
        strict_paper = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        is_paper3 = str(getattr(run_ctx, "scenario_id", "") or "").strip() == "paper3_profile_v3"
        if on_protocol_event:
            on_protocol_event(
                "SCRIPT_START",
                {
                    "scenario_template": template_id,
                    "template_id": template_id,
                    "template_id_requested": requested_template_id,
                    "template_id_actual": template_id,
                    "template_hash": template_hash,
                    "template_map_version": deps.mapping_version(),
                    "template_map_hash": deps.mapping_sha256(),
                    "script_name": protocol["script_name"],
                    "script_hash": template_hash,
                    "step_count_planned": len(steps),
                    "interaction_protocol_version": deps.script_protocol_version,
                    "account_context": protocol.get("account_context"),
                    "control_account": protocol.get("control_account"),
                    "control_account_mode": protocol.get("control_account_mode"),
                    "mutation_allowed": protocol.get("mutation_allowed"),
                    "cleanup_expected": protocol.get("cleanup_expected"),
                    "repeat_plan": protocol.get("repeat_plan"),
                    "article_branch": protocol.get("article_branch"),
                    "subscription_branch_choice": protocol.get("subscription_branch_choice"),
                    "protocol_fit": protocol.get("protocol_fit"),
                },
            )
        print(status_messages.status("Scripted interactive run", level="info"))
        print(status_messages.status(f"Template: {template_id}", level="info"))
        guided_pace_s = sum(int(step[2]) for step in steps)
        print(
            status_messages.status(
                f"Plan: {len(steps)} steps (~{deps.format_duration(guided_pace_s)} guided pacing), "
                f"target {deps.format_duration(int(target_duration_s))}",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Controls: D=done | L=limited | N=skip | H=return home/reset | S=stop/finalize | A=abort",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Tip: use D+Enter, L+Enter, or N+Enter. Avoid Ctrl+C.",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Scripted interaction uses guided timed prompts only; phase timestamps are saved for later PCAP correlation.",
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
        show_snapchat_hints = bool(
            pkg_lc == "com.snapchat.android" and template_id == "social_feed_basic_v2"
        )
        go_live_start_skipped = False
        blocked_article_limitation_reason: str | None = None
        blocked_article_operator_note: str | None = None
        article_branch: str | None = None
        subscription_choice: str | None = None
        active_step_id: str | None = None
        try:
            for idx, (step_id, step_desc, expected_s) in enumerate(steps, start=1):
                active_step_id = str(step_id)
                step_outcome = "completed"
                limitation_reason: str | None = None
                operator_note: str | None = None
                skip_stopwatch = False
                print()
                print(status_messages.status(f"Step {idx}/{len(steps)} — {step_id}", level="info"))
                print(
                    status_messages.status(
                        deps.scripted_step_description(
                            step_id,
                            step_desc,
                            package_name=str(getattr(run_ctx, "package_name", "") or ""),
                        ),
                        level="info",
                    )
                )
                print(status_messages.status(f"Expected: {expected_s}s", level="info"))
                if str(step_id) in deps.terminal_hold_step_ids:
                    print(
                        status_messages.status(
                            "Final hold: keep the app in the foreground. "
                            "Press D when finished (avoid Ctrl+C; use S+FINALIZE only if needed).",
                            level="warn",
                        )
                    )
                if template_id == deps.news_behavior_v2:
                    branch_skip_reason = deps.news_branch_skip_reason(
                        step_id=step_id,
                        article_branch=article_branch,
                        subscription_choice=subscription_choice,
                    )
                    if branch_skip_reason:
                        step_outcome = "skipped_branch_not_taken"
                        limitation_reason = branch_skip_reason
                        skip_stopwatch = True
                if (
                    template_id != deps.news_behavior_v2
                    and step_id == "scroll_article"
                    and blocked_article_limitation_reason in deps.scripted_article_limitation_reasons
                ):
                    reason_text = deps.script_limitation_reason_text.get(
                        str(blocked_article_limitation_reason or "").strip(),
                        str(blocked_article_limitation_reason or "").strip() or "prior limitation",
                    )
                    print(
                        status_messages.status(
                            f"Article unavailable from prior limited open_article step ({reason_text}).",
                            level="warn",
                        )
                    )
                    print(
                        status_messages.status(
                            deps.scripted_step_action_line(limited_or_skip_only=True),
                            level="info",
                        )
                    )
                    carry_choice = deps.prompt_utils.get_choice(
                        ["L", "N", "D"],
                        default="L",
                        casefold=True,
                        invalid_message="Choose L, N, or D.",
                    ).upper()
                    if carry_choice == "L":
                        step_outcome = "limited"
                        limitation_reason = blocked_article_limitation_reason
                        operator_note = blocked_article_operator_note
                        skip_stopwatch = True
                    elif carry_choice == "N":
                        step_outcome = "skipped_not_found"
                        skip_stopwatch = True
                else:
                    print(status_messages.status(deps.scripted_step_action_line(), level="info"))
                if show_snapchat_hints:
                    hint = deps.snapchat_template_hints.get(str(step_id))
                    if hint:
                        print(status_messages.status(f"  {hint}", level="info"))
                step_variant = None
                if step_id == "open_info_or_media":
                    step_variant = deps.prompt_step3_variant()
                    if step_variant == "skip":
                        step_outcome = "skipped_not_found"
                        step_variant = "skipped_not_found"
                        print(status_messages.status("  Variant: skipped_not_found", level="warn"))
                    else:
                        print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                if step_id == "open_map":
                    has_map = deps.prompt_utils.prompt_yes_no(
                        "Is Snap Map available/enabled on this account?", default=True
                    )
                    step_variant = "available" if has_map else "not_available"
                    print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                if step_id in {"my_ai_open", "my_ai_chat"}:
                    has_my_ai = deps.prompt_utils.prompt_yes_no(
                        "Is My AI visible/available in this account?", default=True
                    )
                    step_variant = "available" if has_my_ai else "not_available"
                    print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                    if has_my_ai:
                        protocol["ai_used"] = True
                        protocol["ai_provider"] = "snap_my_ai"
                        protocol["ai_prompt_id"] = (
                            "snap_my_ai_chat_prompt_01"
                            if step_id == "my_ai_chat"
                            else "snap_my_ai_view_only_v1"
                        )
                if step_id == "team_snapchat_chat":
                    has_team_snapchat = deps.prompt_utils.prompt_yes_no(
                        "Is 'Team Snapchat' chat visible/available in this account?",
                        default=True,
                    )
                    step_variant = "available" if has_team_snapchat else "not_available"
                    print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                if step_id == "ask_meta_ai":
                    has_meta_ai = deps.prompt_utils.prompt_yes_no(
                        "Is Ask Meta AI visible/available on this account?", default=True
                    )
                    step_variant = "available" if has_meta_ai else "not_available"
                    print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                    if has_meta_ai:
                        protocol["ai_used"] = True
                        protocol["ai_provider"] = "meta_ai"
                        protocol["ai_prompt_id"] = "meta_ai_prompt_01"
                if step_id == "grok_ai_prompt":
                    has_grok = deps.prompt_utils.prompt_yes_no(
                        "Is Grok available/enabled on this account?", default=True
                    )
                    step_variant = "available" if has_grok else "not_available"
                    print(status_messages.status(f"  Variant: {step_variant}", level="info"))
                    if has_grok:
                        protocol["ai_used"] = True
                        protocol["ai_provider"] = "grok"
                        protocol["ai_prompt_id"] = "grok_prompt_01"
                current_step_metadata = deps.script_step_event_metadata(
                    template_id=template_id,
                    step_id=step_id,
                    facebook_mode=facebook_mode,
                    repeat_plan=facebook_repeat_plan,
                    article_branch=article_branch,
                    subscription_choice=subscription_choice,
                )
                if current_step_metadata.get("repeat_enabled") is False:
                    step_outcome = "skipped_optional_repeat"
                    limitation_reason = "optional_repeat_not_selected"
                    skip_stopwatch = True
                if on_protocol_event:
                    on_protocol_event(
                        "STEP_START",
                        {
                            "step_id": step_id,
                            "step_index": idx,
                            "expected_duration_s": expected_s,
                            "step_variant": step_variant,
                            **current_step_metadata,
                        },
                    )
                step_elapsed = 0.0
                if step_outcome in {"skipped_not_found", "skipped_optional_repeat", "skipped_branch_not_taken", "limited"} and skip_stopwatch:
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
                                "limitation_reason": limitation_reason,
                                "operator_note": operator_note,
                                "operator_result": step_outcome,
                                **deps.script_step_event_metadata(
                                    template_id=template_id,
                                    step_id=step_id,
                                    facebook_mode=facebook_mode,
                                    step_outcome=step_outcome,
                                    repeat_plan=facebook_repeat_plan,
                                    article_branch=article_branch,
                                    subscription_choice=subscription_choice,
                                ),
                            },
                        )
                    if step_outcome == "skipped_not_found":
                        protocol["step_skipped_not_found_count"] = int(
                            protocol.get("step_skipped_not_found_count") or 0
                        ) + 1
                        print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                    elif step_outcome == "skipped_optional_repeat":
                        protocol["step_skipped_optional_repeat_count"] = int(
                            protocol.get("step_skipped_optional_repeat_count") or 0
                        ) + 1
                        print(status_messages.status(f"Step skipped optional repeat: {step_id}", level="info"))
                    elif step_outcome == "skipped_branch_not_taken":
                        protocol["step_skipped_branch_not_taken_count"] = int(
                            protocol.get("step_skipped_branch_not_taken_count") or 0
                        ) + 1
                        print(status_messages.status(f"Step skipped branch not taken: {step_id}", level="info"))
                    else:
                        protocol["step_limited_count"] = int(protocol.get("step_limited_count") or 0) + 1
                        if limitation_reason:
                            key = f"limited_reason_{limitation_reason}_count"
                            protocol[key] = int(protocol.get(key) or 0) + 1
                        reason_text = limitation_reason or "unspecified"
                        print(status_messages.status(f"Step marked limited: {step_id} ({reason_text})", level="warn"))
                    protocol["step_count_completed"] = idx
                    continue
                if step_id == "call_active":
                    if protocol.get("call_connected") is True:
                        call_hold_s = int(expected_s)
                        deps.run_countdown(
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
                                    "limitation_reason": limitation_reason,
                                    "operator_note": operator_note,
                                    "operator_result": step_outcome,
                                    **deps.script_step_event_metadata(
                                        template_id=template_id,
                                        step_id=step_id,
                                        facebook_mode=facebook_mode,
                                        step_outcome=step_outcome,
                                        repeat_plan=facebook_repeat_plan,
                                        article_branch=article_branch,
                                        subscription_choice=subscription_choice,
                                    ),
                                },
                            )
                        protocol["step_skipped_not_found_count"] = int(
                            protocol.get("step_skipped_not_found_count") or 0
                        ) + 1
                        print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                        protocol["step_count_completed"] = idx
                        continue
                    live_hold_s = max(int(expected_s), 1)
                    deps.run_countdown(
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
                        if strict_paper and is_paper3:
                            print(
                                status_messages.status(
                                    "Strict hold: do not press Enter; this step auto-completes. (Abort: A+Enter)",
                                    level="warn",
                                )
                            )
                        deps.run_countdown(
                            remaining,
                            continue_after_target=not (strict_paper and is_paper3),
                            allow_early_stop=not (strict_paper and is_paper3),
                            ignore_stop_inputs=bool(strict_paper and is_paper3),
                        )
                        protocol["duration_pad_applied_in_loop"] = True
                else:
                    step_start = time.monotonic()
                    guided_remaining_s = sum(int(step[2]) for step in steps[idx - 1 :])
                    step_outcome = deps.wait_for_step_completion_with_stopwatch(
                        step_index=idx,
                        step_count=len(steps),
                        step_id=step_id,
                        script_started_monotonic=started_monotonic,
                        step_started_monotonic=step_start,
                        target_duration_s=int(target_duration_s),
                        guided_remaining_s=guided_remaining_s,
                        on_phase_marker=(
                            (
                                lambda marker,
                                _idx=idx,
                                _step_id=step_id,
                                _article_branch=article_branch,
                                _subscription_choice=subscription_choice: on_protocol_event(
                                    "PHASE_MARKER",
                                    {
                                        "step_id": _step_id,
                                        "step_index": _idx,
                                        **deps.script_step_event_metadata(
                                            template_id=template_id,
                                            step_id=_step_id,
                                            facebook_mode=facebook_mode,
                                            step_outcome="completed",
                                            repeat_plan=facebook_repeat_plan,
                                            article_branch=_article_branch,
                                            subscription_choice=_subscription_choice,
                                        ),
                                        **marker,
                                    },
                                )
                            )
                            if on_protocol_event
                            else None
                        ),
                    )
                    if isinstance(step_outcome, tuple):
                        step_outcome, limitation_reason, operator_note = step_outcome
                    step_elapsed = max(0.0, time.monotonic() - step_start)
                    if step_outcome == "skipped_not_found":
                        protocol["step_skipped_not_found_count"] = int(
                            protocol.get("step_skipped_not_found_count") or 0
                        ) + 1
                        print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                        if step_id == "go_live_start":
                            go_live_start_skipped = True
                    elif step_outcome == "limited":
                        protocol["step_limited_count"] = int(protocol.get("step_limited_count") or 0) + 1
                        if limitation_reason:
                            key = f"limited_reason_{limitation_reason}_count"
                            protocol[key] = int(protocol.get(key) or 0) + 1
                        reason_text = limitation_reason or "unspecified"
                        print(status_messages.status(f"Step marked limited: {step_id} ({reason_text})", level="warn"))
                        if step_id == "open_article" and limitation_reason in deps.scripted_article_limitation_reasons:
                            blocked_article_limitation_reason = limitation_reason
                            blocked_article_operator_note = operator_note
                    if step_id == "start_call":
                        protocol["call_attempted"] = True
                        connected = deps.prompt_utils.prompt_yes_no("Did the call connect?", default=True)
                        protocol["call_connected"] = bool(connected)
                        protocol["call_connect_latency_s"] = float(round(step_elapsed, 3))
                        protocol["call_connect_timeout_s"] = int(deps.call_connect_timeout_s)
                        if not connected:
                            protocol["call_end_reason"] = "timeout"
                            protocol["call_outcome_reason"] = "CALL_NOT_CONNECTED"
                        elif not protocol.get("call_end_reason"):
                            protocol["call_end_reason"] = "user_end"
                    if step_id == "end_call" and protocol.get("call_attempted") is True:
                        protocol["call_end_reason"] = protocol.get("call_end_reason") or "user_end"
                    if step_id == "open_article":
                        limitation_reason = deps.normalize_limitation_reason(limitation_reason)
                        if step_outcome == "completed":
                            article_branch = "article_opened"
                        elif limitation_reason:
                            article_branch = limitation_reason
                            if limitation_reason == "subscription_required":
                                subscription_choice = deps.prompt_news_subscription_branch()
                            protocol["article_branch"] = article_branch
                            protocol["protocol_fit"] = (
                                "limited_but_compliant"
                                if article_branch in {"subscription_required", "login_required"}
                                else "limited"
                            )
                            protocol["subscription_branch_choice"] = subscription_choice
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
                            "limitation_reason": limitation_reason,
                            "operator_note": operator_note,
                            "operator_result": step_outcome,
                            **deps.script_step_event_metadata(
                                template_id=template_id,
                                step_id=step_id,
                                facebook_mode=facebook_mode,
                                step_outcome=step_outcome,
                                repeat_plan=facebook_repeat_plan,
                                article_branch=article_branch,
                                subscription_choice=subscription_choice,
                            ),
                        },
                    )
                protocol["step_count_completed"] = idx
        except deps.stop_exception_type:
            deps.apply_script_early_stop(protocol, active_step_id=active_step_id)
        except KeyboardInterrupt:
            strict = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if strict:
                raise deps.abort_exception_factory("ABORT_DISCARD") from None
            deps.apply_script_early_stop(protocol, active_step_id=active_step_id)
        elapsed_total = int(time.monotonic() - started_monotonic)
        remaining = max(int(target_duration_s) - elapsed_total, 0)
        if remaining > 0 and int(protocol.get("script_exit_code") or 0) == 0 and not bool(
            protocol.get("duration_pad_applied_in_loop")
        ):
            print(status_messages.status(f"Protocol completed; hold foreground for {remaining}s.", level="info"))
            deps.run_countdown(
                remaining,
                continue_after_target=not (strict_paper and is_paper3),
                allow_early_stop=not (strict_paper and is_paper3),
                ignore_stop_inputs=bool(strict_paper and is_paper3),
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
                    "template_map_version": deps.mapping_version(),
                    "template_map_hash": deps.mapping_sha256(),
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
                    "account_context": protocol.get("account_context"),
                    "control_account": protocol.get("control_account"),
                    "control_account_mode": protocol.get("control_account_mode"),
                    "mutation_allowed": protocol.get("mutation_allowed"),
                    "cleanup_expected": protocol.get("cleanup_expected"),
                    "repeat_plan": protocol.get("repeat_plan"),
                    "terminal_hold_finalize": protocol.get("terminal_hold_finalize"),
                    "stopped_early": protocol.get("stopped_early"),
                },
            )
        if (
            template_id in call_templates
            and protocol.get("call_connected") is True
            and float(protocol.get("call_connected_duration_s") or 0.0)
            < float(deps.call_min_connected_duration_s)
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
            "whatsapp_text_behavior_v2",
        }
        if (
            template_id in non_call_messaging_templates
            and int(protocol.get("script_exit_code") or 0) == 0
            and int(protocol.get("step_count_completed") or 0)
            == int(protocol.get("step_count_planned") or 0)
        ):
            call_in_non_call = deps.prompt_utils.prompt_yes_no(
                f"Did any voice/video call occur during this run? (protocol violation for {template_id})",
                default=False,
            )
            protocol["script_call_in_non_call_template"] = bool(call_in_non_call)
            if call_in_non_call:
                deviations = protocol.get("deviation_codes")
                if isinstance(deviations, list):
                    deviations.append("SCRIPT_CALL_ACTION_NON_CALL_TEMPLATE")
        deps.maybe_mark_scripted_run_as_manual_override(
            protocol=protocol,
            template_id=template_id,
            on_protocol_event=on_protocol_event,
        )
        return protocol


__all__ = ["ScriptedProtocolDeps", "ScriptedProtocolRuntime"]
