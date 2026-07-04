"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

import hashlib
import os
import random
import re
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
    V3_SCRIPTED_REPRO_TIPS,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import (
    requested_script_template as _requested_script_template_for_package,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import (
    resolve_script_template as _resolve_script_template_for_package,
)
from scytaledroid.DynamicAnalysis.scenarios.baseline_guidance import (
    baseline_idle_behavior_lines as _guidance_baseline_idle_behavior_lines,
    baseline_idle_checkpoint_messages as _guidance_baseline_idle_checkpoint_messages,
    baseline_idle_quota_warning as _guidance_baseline_idle_quota_warning,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    clear_prompt_and_previous_line as _timing_clear_prompt_and_previous_line,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    clear_status_line as _timing_clear_status_line,
)
from scytaledroid.DynamicAnalysis.scenarios.manual_timing import (
    countdown_action_prompt_line as _timing_countdown_action_prompt_line,
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


SCRIPT_PROTOCOL_VERSION = 2
BASELINE_PROTOCOL_VERSION = 2
BASELINE_PROTOCOL_ID_CONNECTED = "baseline_connected_v2"
BASELINE_PROTOCOL_ID_IDLE = "baseline_idle_v1"
CALL_CONNECT_TIMEOUT_S = 30
CALL_MIN_CONNECTED_DURATION_S = 90

SCRIPT_LIMITATION_REASON_LABELS: tuple[tuple[str, str], ...] = (
    ("subscription_required", "subscription required / paywall shown"),
    ("login_required", "login required"),
    ("not_available_in_ui_or_account", "not available in this UI/account"),
    ("region_or_content_unavailable", "region or content unavailable"),
    ("app_error", "app error"),
    ("operator_other", "other limitation"),
)
_SCRIPT_LIMITATION_REASON_TEXT = {
    **dict(SCRIPT_LIMITATION_REASON_LABELS),
    "paywall": "subscription required / paywall shown",
    "not_available": "not available in this UI/account",
    "other": "other limitation",
}
_SCRIPTED_ARTICLE_LIMITATION_REASONS = {
    "paywall",
    "subscription_required",
    "login_required",
    "not_available",
    "not_available_in_ui_or_account",
    "region_or_content_unavailable",
    "app_error",
    "operator_other",
}
_NEWS_BEHAVIOR_V2 = "news_reader_behavior_v2"
_NEWS_SUBSCRIPTION_BRANCH_CHOICES = {
    "1": "subscription_wall_observed",
    "2": "subscription_options_observed",
    "3": "return_home",
    "4": "skip_article_branch",
}

_FACEBOOK_BEHAVIOR_V3 = "facebook_behavior_v3"
_FACEBOOK_CONTROL_ACCOUNT_MODES = {
    "1": "observation_only",
    "2": "draft_only",
    "3": "control_account_active",
}
_FACEBOOK_MUTATING_STEP_PREFIXES = (
    "friend_request_accept_",
    "text_post_submit_",
    "photo_post_submit_",
)
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


def _scripted_step_description(step_id: str, default_desc: str) -> str:
    if step_id == "open_article":
        return "Open one article. If subscription/paywall appears, mark subscription_required."
    if step_id in {"scroll_article", "article_scroll"}:
        return "Scroll the visible article content. If content is blocked, mark limited and continue."
    return str(default_desc or "").strip()


def _scripted_step_action_line(*, limited_or_skip_only: bool = False) -> str:
    if limited_or_skip_only:
        return "Action: L=limited | N=skip | D=done | H=return home/reset"
    return "Action: D=done | L=limited | N=skip | H=return home/reset"


def _prompt_facebook_control_account_mode() -> str:
    print(status_messages.status("Facebook control-account behavior mode:", level="info"))
    print("  1) Observation only")
    print("  2) Draft only")
    print("  3) Control-account active mode [recommended for research]")
    choice = prompt_utils.get_choice(
        ["1", "2", "3"],
        default="3",
        invalid_message="Choose 1, 2, or 3.",
    )
    return _FACEBOOK_CONTROL_ACCOUNT_MODES.get(str(choice), "control_account_active")


def _prompt_facebook_repeat_plan() -> dict[str, int]:
    print(status_messages.status("Facebook behavior repeats:", level="info"))
    print("Repeat text post action? 0=no repeat, 1=repeat once, 2=repeat two more times")
    text_choice = prompt_utils.get_choice(
        ["0", "1", "2"],
        default="0",
        invalid_message="Choose 0, 1, or 2.",
    )
    print("Repeat photo post action? 0=no repeat, 1=repeat once, 2=repeat two more times")
    photo_choice = prompt_utils.get_choice(
        ["0", "1", "2"],
        default="0",
        invalid_message="Choose 0, 1, or 2.",
    )
    return {
        "text_post_submit": _repeat_choice_to_total(text_choice, max_total=3),
        "photo_post_submit": _repeat_choice_to_total(photo_choice, max_total=3),
        "friend_request_accept": 2,
    }


def _repeat_choice_to_total(choice: object, *, max_total: int) -> int:
    try:
        repeat_count = int(str(choice).strip())
    except (TypeError, ValueError):
        repeat_count = 0
    return min(max(repeat_count + 1, 1), int(max_total))


def _repeat_metadata_for_step(
    step_id: str,
    *,
    repeat_plan: dict[str, int] | None = None,
) -> dict[str, object]:
    for prefix, group, total in (
        ("text_post_", "text_post_submit", 3),
        ("photo_", "photo_post_submit", 3),
        ("friend_request_accept_", "friend_request_accept", 2),
    ):
        if not step_id.startswith(prefix):
            continue
        suffix = step_id.rsplit("_", 1)[-1]
        if suffix.isdigit():
            repeat_index = int(suffix)
            planned_total = int((repeat_plan or {}).get(group) or total)
            planned_total = min(max(planned_total, 0), int(total))
            return {
                "repeat_group": group,
                "repeat_index": repeat_index,
                "repeat_total": planned_total,
                "repeat_max_total": total,
                "repeat_enabled": bool(repeat_index <= planned_total),
            }
    if step_id.startswith("send_text_"):
        suffix = step_id.rsplit("_", 1)[-1]
        if suffix.isdigit():
            return {
                "repeat_group": "text_message",
                "repeat_index": int(suffix),
                "repeat_total": 3,
                "repeat_max_total": 3,
                "repeat_enabled": True,
            }
    if step_id.startswith("hold_15s_"):
        suffix = step_id.rsplit("_", 1)[-1]
        if suffix.isdigit():
            return {
                "repeat_group": "post_text_hold",
                "repeat_index": int(suffix),
                "repeat_total": 3,
                "repeat_max_total": 3,
                "repeat_enabled": True,
            }
    return {
        "repeat_group": None,
        "repeat_index": None,
        "repeat_total": None,
        "repeat_max_total": None,
        "repeat_enabled": None,
    }


def _whatsapp_text_behavior_metadata(
    *,
    template_id: str,
    step_id: str,
    step_outcome: str | None = None,
) -> dict[str, object]:
    if template_id != "whatsapp_text_behavior_v2":
        return {}
    completed = str(step_outcome or "").strip().lower() == "completed"
    metadata: dict[str, object] = {
        "account_context": "control_test_chat",
        "control_account": True,
        "control_account_mode": "controlled_contact",
        "mutation_allowed": True,
        "cleanup_expected": True,
        "mutation_candidate": False,
        "mutation_performed": False,
        "message_type": None,
        "traffic_phase": "foreground_hold",
    }
    if step_id == "open_app":
        metadata.update({"traffic_phase": "connected_idle"})
    elif step_id == "open_control_chat":
        metadata.update({"traffic_phase": "chat_open_or_sync"})
    elif step_id.startswith("send_text_"):
        metadata.update(
            {
                "message_type": "text",
                "traffic_phase": "text_send",
                "mutation_candidate": True,
                "mutation_performed": completed,
            }
        )
        metadata.update(_repeat_metadata_for_step(step_id))
    elif step_id.startswith("hold_15s_"):
        metadata.update({"traffic_phase": "post_send_hold"})
        metadata.update(_repeat_metadata_for_step(step_id))
    elif step_id == "receive_reply_or_wait":
        metadata.update({"message_type": "reply_or_sync", "traffic_phase": "reply_or_sync_wait"})
    elif step_id == "send_emoji_optional":
        metadata.update(
            {
                "message_type": "emoji_or_sticker",
                "traffic_phase": "optional_message_send",
                "mutation_candidate": True,
                "mutation_performed": completed,
            }
        )
    elif step_id == "send_small_image_optional":
        metadata.update(
            {
                "message_type": "small_image",
                "traffic_phase": "optional_media_send",
                "mutation_candidate": True,
                "mutation_performed": completed,
            }
        )
    elif step_id == "return_chat_list":
        metadata.update({"traffic_phase": "return_chat_list"})
    elif step_id == "hold_foreground":
        metadata.update({"traffic_phase": "foreground_hold"})
    return metadata


def _facebook_traffic_phase_for_step(step_id: str) -> str:
    sid = str(step_id or "").strip()
    if sid in {"home_feed", "final_home_hold"}:
        return "home_feed_hold"
    if sid in {"profile_view", "profile_return_home"}:
        return "profile_surface"
    if sid.startswith("friends_") or sid.startswith("friend_suggestions_"):
        return "friends_surface"
    if sid.startswith("friend_request_accept_"):
        return "friend_request_mutate"
    if sid.startswith("text_post_"):
        return "text_post_flow"
    if sid.startswith("photo_post_") or sid.startswith("photo_attach_"):
        return "photo_post_flow"
    if sid.startswith("reels_"):
        return "reels_surface"
    if sid.startswith("stories_"):
        return "stories_surface"
    if sid.startswith("marketplace_"):
        return "marketplace_surface"
    if sid.startswith("notifications_"):
        return "notifications_surface"
    return "foreground_hold"


def _scripted_step_metadata(
    *,
    template_id: str,
    step_id: str,
    facebook_mode: str | None = None,
    step_outcome: str | None = None,
    repeat_plan: dict[str, int] | None = None,
) -> dict[str, object]:
    if template_id != _FACEBOOK_BEHAVIOR_V3:
        return {}
    mode = str(facebook_mode or "control_account_active").strip().lower()
    mutation_allowed = mode == "control_account_active"
    mutation_candidate = step_id.startswith(_FACEBOOK_MUTATING_STEP_PREFIXES)
    mutation_performed = bool(
        mutation_allowed
        and mutation_candidate
        and str(step_outcome or "").strip().lower() == "completed"
    )
    metadata: dict[str, object] = {
        "account_context": "control_test_account",
        "control_account": True,
        "control_account_mode": mode,
        "mutation_allowed": bool(mutation_allowed),
        "cleanup_expected": bool(mutation_allowed),
        "mutation_candidate": bool(mutation_candidate),
        "mutation_performed": bool(mutation_performed),
        "traffic_phase": _facebook_traffic_phase_for_step(step_id),
    }
    metadata.update(_repeat_metadata_for_step(step_id, repeat_plan=repeat_plan))
    return metadata


def _news_step_metadata(
    *,
    template_id: str,
    step_id: str,
    article_branch: str | None = None,
    subscription_choice: str | None = None,
    step_outcome: str | None = None,
) -> dict[str, object]:
    if template_id != _NEWS_BEHAVIOR_V2:
        return {}
    branch = str(article_branch or "").strip() or None
    subscription_options_opened = bool(subscription_choice == "subscription_options_observed")
    subscription_wall_observed = bool(
        branch == "subscription_required"
        and step_id in {"subscription_wall_observe", "subscription_options_observe", "subscription_return_home"}
        and str(step_outcome or "completed") != "skipped_branch_not_taken"
    )
    return_home_performed = bool(
        step_id in {"article_return_home", "subscription_return_home", "video_or_media_optional"}
        and str(step_outcome or "completed") != "skipped_branch_not_taken"
    )
    return {
        "branch_taken": branch,
        "article_branch": branch,
        "subscription_wall_observed": subscription_wall_observed,
        "subscription_options_opened": bool(
            subscription_options_opened
            and step_id == "subscription_options_observe"
            and str(step_outcome or "completed") != "skipped_branch_not_taken"
        ),
        "return_home_performed": return_home_performed,
        "protocol_fit": "limited_but_compliant" if branch in {"subscription_required", "login_required"} else None,
    }


def _prompt_news_subscription_branch() -> str:
    print(status_messages.status("Article content is blocked by subscription requirement.", level="warn"))
    print("  1) Observe subscription wall for 30 seconds")
    print("  2) Open subscription options, hold 30 seconds, then return")
    print("  3) Return Home")
    print("  4) Skip article branch")
    choice = prompt_utils.get_choice(
        ["1", "2", "3", "4"],
        default="1",
        invalid_message="Choose 1, 2, 3, or 4.",
    )
    return _NEWS_SUBSCRIPTION_BRANCH_CHOICES.get(str(choice), "subscription_wall_observed")


def _normalize_limitation_reason(reason: str | None) -> str | None:
    token = str(reason or "").strip().lower()
    if token in {"paywall", "subscription", "subscription_wall"}:
        return "subscription_required"
    if token == "not_available":
        return "not_available_in_ui_or_account"
    if token == "other":
        return "operator_other"
    return token or None


def _script_step_event_metadata(
    *,
    template_id: str,
    step_id: str,
    facebook_mode: str | None = None,
    repeat_plan: dict[str, int] | None = None,
    article_branch: str | None = None,
    subscription_choice: str | None = None,
    step_outcome: str | None = None,
) -> dict[str, object]:
    return {
        **_whatsapp_text_behavior_metadata(
            template_id=template_id,
            step_id=step_id,
            step_outcome=step_outcome,
        ),
        **_scripted_step_metadata(
            template_id=template_id,
            step_id=step_id,
            facebook_mode=facebook_mode,
            step_outcome=step_outcome,
            repeat_plan=repeat_plan,
        ),
        **_news_step_metadata(
            template_id=template_id,
            step_id=step_id,
            article_branch=article_branch,
            subscription_choice=subscription_choice,
            step_outcome=step_outcome,
        ),
    }


def _news_branch_skip_reason(
    *,
    step_id: str,
    article_branch: str | None,
    subscription_choice: str | None,
) -> str | None:
    branch = str(article_branch or "").strip()
    choice = str(subscription_choice or "").strip()
    if step_id in {"article_scroll", "article_return_home"}:
        return None if branch == "article_opened" else "article_branch_not_opened"
    if step_id == "subscription_wall_observe":
        if branch != "subscription_required":
            return "subscription_branch_not_taken"
        return None if choice in {"subscription_wall_observed", "subscription_options_observed"} else "subscription_wall_observe_not_selected"
    if step_id == "subscription_options_observe":
        if branch != "subscription_required":
            return "subscription_branch_not_taken"
        return None if choice == "subscription_options_observed" else "subscription_options_not_selected"
    if step_id == "subscription_return_home":
        if branch != "subscription_required":
            return "subscription_branch_not_taken"
        return None if choice in {"subscription_wall_observed", "subscription_options_observed", "return_home"} else "subscription_return_home_not_selected"
    return None


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
                    block.append("  - Keep the app in the foreground")
                    block.append("  - Open an existing conversation thread and keep it visible")
                    block.append("  - Every 45-75s, do one non-mutating check action (small scroll OR chat-list/thread switch)")
                    block.append("  - Perform exactly one refresh/check action around minute 2")
                    block.append("  - Do not type, send, call, upload media, search, or open external links")
                else:
                    block.extend(
                        _baseline_idle_behavior_lines(getattr(run_ctx, "package_name", "") or "")
                    )
            else:
                block.append("  - Keep the app in the foreground")
                block.append("  - Use the app normally")
            print(status_messages.status("\n".join(block).rstrip(), level="info"))
            baseline_warning = _baseline_idle_quota_warning(
                getattr(run_ctx, "package_name", "") or "",
                profile=profile,
            )
            if baseline_warning:
                print(status_messages.status(baseline_warning, level="warn"))
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
                    pkg = str(getattr(run_ctx, "package_name", "") or "").strip()
                    ended_at = _run_countdown(
                        duration_seconds,
                        continue_after_target=True,
                        timer_detail="baseline idle",
                        device_serial=getattr(run_ctx, "device_serial", None),
                        foreground_package=pkg,
                        checkpoint_messages=_baseline_idle_checkpoint_messages(pkg),
                        on_protocol_event=on_protocol_event,
                    )
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


_FOREGROUND_DRIFT_CHECK_INTERVAL_S = 30


def _read_device_foreground_package(device_serial: str | None) -> str | None:
    serial = str(device_serial or "").strip()
    if not serial:
        return None
    try:
        from scytaledroid.DeviceAnalysis.adb import client as adb_client

        if not adb_client.is_available():
            return None
        completed = adb_client.run_shell_command(serial, ["dumpsys", "window"], timeout=10)
        text = str(getattr(completed, "stdout", "") or "")
    except Exception:
        return None
    for line in text.splitlines():
        if "mCurrentFocus" not in line and "mFocusedApp" not in line:
            continue
        match = re.search(r"u0\s+([a-zA-Z0-9_.]+)/", line)
        if match:
            return str(match.group(1))
    return None


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


def _extra_hold_timer_message(
    *,
    target_duration_s: int,
    elapsed_s: int,
    timer_detail: str = "",
    suffix: str = "",
) -> str:
    target = _format_duration(int(target_duration_s))
    hold_elapsed = _format_duration(max(int(elapsed_s) - int(target_duration_s), 0))
    detail = f" | {timer_detail}" if str(timer_detail or "").strip() else ""
    return f"Target reached: {target} | extra hold: +{hold_elapsed} | press Enter to finalize{detail}{suffix}"


def _run_baseline_interactive_loop(
    target_duration_s: int,
    *,
    continue_after_target: bool = True,
    timer_detail: str = "",
    device_serial: str | None = None,
    foreground_package: str | None = None,
    checkpoint_messages: dict[int, str] | None = None,
    on_elapsed: Callable[[int, Callable[[str, str], None]], None] | None = None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
) -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        time.sleep(max(int(target_duration_s), 0))
        return datetime.now(UTC)

    start = time.monotonic()
    line_width = 72
    prompt_line = _timing_countdown_action_prompt_line()
    prompt_width = max(len(prompt_line), 64)
    last_rendered: str | None = None
    last_render_bucket: int | None = None
    target_reached_announced = False
    checkpoint_emitted: set[int] = set()
    last_foreground_warn_s = -999

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

    def _clear_timer_lines() -> None:
        _timing_clear_prompt_and_previous_line(line_width=line_width, prompt_width=prompt_width)

    def _emit_status_and_restore_timer(message: str, *, level: str = "info") -> None:
        nonlocal last_rendered, last_render_bucket
        _clear_timer_lines()
        print(status_messages.status(message, level=level))
        last_rendered = None
        last_render_bucket = None

    _drain_stdin_nonblocking()

    try:
        while True:
            elapsed_i = int(time.monotonic() - start)
            remaining = max(int(target_duration_s) - elapsed_i, 0)
            total = _format_duration(int(target_duration_s))
            elapsed_fmt = _format_duration(elapsed_i)
            suffix = _pulse_marker(elapsed_i)
            detail = f" | {timer_detail}" if str(timer_detail or "").strip() else ""
            if remaining > 0:
                timer_msg = f"Elapsed: {elapsed_fmt} / {total}{detail}{suffix}"
            else:
                timer_msg = _extra_hold_timer_message(
                    target_duration_s=int(target_duration_s),
                    elapsed_s=elapsed_i,
                    timer_detail=timer_detail,
                    suffix=suffix,
                )

            if on_elapsed is not None:
                on_elapsed(elapsed_i, lambda message, level="info": _emit_status_and_restore_timer(message, level=level))

            for checkpoint_s, checkpoint_msg in sorted((checkpoint_messages or {}).items()):
                if checkpoint_s in checkpoint_emitted or elapsed_i < int(checkpoint_s):
                    continue
                checkpoint_emitted.add(int(checkpoint_s))
                _emit_status_and_restore_timer(checkpoint_msg, level="info")
                if on_protocol_event:
                    on_protocol_event(
                        f"BASELINE_IDLE_CHECKPOINT_{int(checkpoint_s)}",
                        {"elapsed_s": int(elapsed_i), "checkpoint_s": int(checkpoint_s)},
                    )

            expected_pkg = str(foreground_package or "").strip()
            if (
                expected_pkg
                and device_serial
                and elapsed_i > 0
                and elapsed_i % _FOREGROUND_DRIFT_CHECK_INTERVAL_S == 0
                and elapsed_i != last_foreground_warn_s
            ):
                last_foreground_warn_s = elapsed_i
                actual_pkg = _read_device_foreground_package(device_serial)
                if actual_pkg and actual_pkg != expected_pkg:
                    _emit_status_and_restore_timer(
                        (
                            f"Foreground drift: expected {expected_pkg}, saw {actual_pkg}. "
                            "Return to the target app to keep baseline valid."
                        ),
                        level="warn",
                    )
                    if on_protocol_event:
                        on_protocol_event(
                            "BASELINE_FOREGROUND_DRIFT",
                            {
                                "elapsed_s": int(elapsed_i),
                                "expected_package": expected_pkg,
                                "actual_package": actual_pkg,
                            },
                        )

            render_bucket = elapsed_i // 10
            if timer_msg != last_rendered and (last_render_bucket is None or render_bucket != last_render_bucket):
                _render_timer_line(timer_msg)
                last_render_bucket = render_bucket

            if remaining <= 0 and not target_reached_announced:
                target_message = (
                    "Target reached; finalizing capture."
                    if not continue_after_target
                    else "Target reached. Keep collecting if needed; press Enter when finished."
                )
                _emit_status_and_restore_timer(
                    target_message,
                    level="info",
                )
                target_reached_announced = True
                if not continue_after_target:
                    _clear_timer_lines()
                    print()
                    break

            readable, _, _ = select.select([sys.stdin], [], [], 1.0)
            if not readable:
                continue
            raw_line = sys.stdin.readline()
            if str(raw_line or "").strip() == "":
                continue
            action = _parse_timing_action(raw_line)
            if action == "abort":
                if not _confirm_script_exit("abort"):
                    _render_timer_line(timer_msg)
                    continue
                _clear_timer_lines()
                print()
                raise ScenarioAbortRequested("ABORT_DISCARD")
            if action == "stop":
                if not _confirm_script_exit("stop"):
                    _render_timer_line(timer_msg)
                    continue
                _clear_timer_lines()
                print()
                break
            if action == "enter":
                if _should_continue_collecting(elapsed_s=elapsed_i, target_s=int(target_duration_s)):
                    _render_timer_line(timer_msg)
                    continue
                _clear_timer_lines()
                print()
                break
    except KeyboardInterrupt:
        _clear_timer_lines()
        print()
        raise ScenarioAbortRequested("ABORT_DISCARD") from None
    return datetime.now(UTC)


def _run_countdown(
    duration_seconds: int,
    *,
    continue_after_target: bool = False,
    allow_early_stop: bool = True,
    ignore_stop_inputs: bool = False,
    timer_detail: str = "",
    device_serial: str | None = None,
    foreground_package: str | None = None,
    checkpoint_messages: dict[int, str] | None = None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
) -> datetime:
    if allow_early_stop and not ignore_stop_inputs:
        return _run_baseline_interactive_loop(
            int(duration_seconds),
            continue_after_target=continue_after_target,
            timer_detail=timer_detail,
            device_serial=device_serial,
            foreground_package=foreground_package,
            checkpoint_messages=checkpoint_messages,
            on_protocol_event=on_protocol_event,
        )
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
                message = ("\r" + _extra_hold_timer_message(
                    target_duration_s=int(duration_seconds),
                    elapsed_s=elapsed_i,
                    suffix=suffix,
                )).ljust(line_width)
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
                    if action in {"enter", "stop"} and not ignore_stop_inputs:
                        _clear_status_line(line_width)
                        print()
                        raise _StopScriptEarly("STOP_FINALIZE")
                    # Ignore bare Enter in locked mode to avoid accidental early exits.
    except KeyboardInterrupt:
        _clear_status_line(line_width)
        print()
        if allow_early_stop:
            raise ScenarioAbortRequested("ABORT_DISCARD") from None
        if ignore_stop_inputs:
            # Strict scripted hold should not silently "finalize early" on Ctrl+C.
            raise ScenarioAbortRequested("ABORT_DISCARD") from None
        raise _StopScriptEarly("STOP_FINALIZE") from None
    return datetime.now(UTC)


def _run_stopwatch() -> datetime:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        prompt_utils.press_enter_to_continue("Press Enter when finished (timer stops)...")
        return datetime.now(UTC)
    start = time.monotonic()
    line_width = 56
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
    facebook_mode = (
        _prompt_facebook_control_account_mode()
        if template_id == _FACEBOOK_BEHAVIOR_V3
        else None
    )
    facebook_repeat_plan = (
        _prompt_facebook_repeat_plan()
        if template_id == _FACEBOOK_BEHAVIOR_V3
        else None
    )
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
    if template_id == _FACEBOOK_BEHAVIOR_V3:
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
    strict_paper = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
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
                "template_map_version": mapping_version(),
                "template_map_hash": mapping_sha256(),
                "script_name": protocol["script_name"],
                "script_hash": template_hash,
                "step_count_planned": len(steps),
                "interaction_protocol_version": SCRIPT_PROTOCOL_VERSION,
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
            f"Plan: {len(steps)} steps (~{_format_duration(guided_pace_s)} guided pacing), "
            f"target {_format_duration(int(target_duration_s))}",
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
    show_snapchat_hints = bool(pkg_lc == "com.snapchat.android" and template_id == "social_feed_basic_v2")
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
            print(status_messages.status(_scripted_step_description(step_id, step_desc), level="info"))
            print(status_messages.status(f"Expected: {expected_s}s", level="info"))
            if str(step_id) in _TERMINAL_HOLD_STEP_IDS:
                print(
                    status_messages.status(
                        "Final hold: keep the app in the foreground. "
                        "Press D when finished (avoid Ctrl+C; use S+FINALIZE only if needed).",
                        level="warn",
                    )
                )
            if template_id == _NEWS_BEHAVIOR_V2:
                branch_skip_reason = _news_branch_skip_reason(
                    step_id=step_id,
                    article_branch=article_branch,
                    subscription_choice=subscription_choice,
                )
                if branch_skip_reason:
                    step_outcome = "skipped_branch_not_taken"
                    limitation_reason = branch_skip_reason
                    skip_stopwatch = True
            if (
                template_id != _NEWS_BEHAVIOR_V2
                and step_id == "scroll_article"
                and blocked_article_limitation_reason in _SCRIPTED_ARTICLE_LIMITATION_REASONS
            ):
                reason_text = _SCRIPT_LIMITATION_REASON_TEXT.get(
                    str(blocked_article_limitation_reason or "").strip(),
                    str(blocked_article_limitation_reason or "").strip() or "prior limitation",
                )
                print(
                    status_messages.status(
                        f"Article unavailable from prior limited open_article step ({reason_text}).",
                        level="warn",
                    )
                )
                print(status_messages.status(_scripted_step_action_line(limited_or_skip_only=True), level="info"))
                carry_choice = prompt_utils.get_choice(
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
                print(status_messages.status(_scripted_step_action_line(), level="info"))
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
            current_step_metadata = _script_step_event_metadata(
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
                            "limitation_reason": limitation_reason,
                            "operator_note": operator_note,
                            "operator_result": step_outcome,
                            **_script_step_event_metadata(
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
                protocol["step_skipped_not_found_count"] = int(protocol.get("step_skipped_not_found_count") or 0) + 1
                print(status_messages.status(f"Step marked skipped_not_found: {step_id}", level="warn"))
                protocol["step_count_completed"] = idx
                continue
            if skip_stopwatch and step_outcome == "skipped_optional_repeat":
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
                            **_script_step_event_metadata(
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
                protocol["step_skipped_optional_repeat_count"] = int(protocol.get("step_skipped_optional_repeat_count") or 0) + 1
                print(status_messages.status(f"Step skipped optional repeat: {step_id}", level="info"))
                protocol["step_count_completed"] = idx
                continue
            if skip_stopwatch and step_outcome == "skipped_branch_not_taken":
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
                            **_script_step_event_metadata(
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
                protocol["step_skipped_branch_not_taken_count"] = int(protocol.get("step_skipped_branch_not_taken_count") or 0) + 1
                print(status_messages.status(f"Step skipped branch not taken: {step_id}", level="info"))
                protocol["step_count_completed"] = idx
                continue
            if skip_stopwatch and step_outcome == "limited":
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
                            **_script_step_event_metadata(
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
                                "limitation_reason": limitation_reason,
                                "operator_note": operator_note,
                                "operator_result": step_outcome,
                                **_script_step_event_metadata(
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
                    if strict_paper and is_paper3:
                        print(
                            status_messages.status(
                                "Strict hold: do not press Enter; this step auto-completes. (Abort: A+Enter)",
                                level="warn",
                            )
                        )
                    _run_countdown(
                        remaining,
                        # In strict freeze/demo mode, do not allow accidental early-stop.
                        continue_after_target=not (strict_paper and is_paper3),
                        allow_early_stop=not (strict_paper and is_paper3),
                        ignore_stop_inputs=bool(strict_paper and is_paper3),
                    )
                    protocol["duration_pad_applied_in_loop"] = True
            else:
                step_start = time.monotonic()
                guided_remaining_s = sum(int(step[2]) for step in steps[idx - 1 :])
                step_outcome = _wait_for_step_completion_with_stopwatch(
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
                                    **_script_step_event_metadata(
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
                    protocol["step_skipped_not_found_count"] = int(protocol.get("step_skipped_not_found_count") or 0) + 1
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
                    if step_id == "open_article" and limitation_reason in _SCRIPTED_ARTICLE_LIMITATION_REASONS:
                        blocked_article_limitation_reason = limitation_reason
                        blocked_article_operator_note = operator_note
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
                if step_id == "open_article":
                    limitation_reason = _normalize_limitation_reason(limitation_reason)
                    if step_outcome == "completed":
                        article_branch = "article_opened"
                    elif limitation_reason:
                        article_branch = limitation_reason
                        if limitation_reason == "subscription_required":
                            subscription_choice = _prompt_news_subscription_branch()
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
                        **_script_step_event_metadata(
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
    except _StopScriptEarly:
        _apply_script_early_stop(protocol, active_step_id=active_step_id)
    except KeyboardInterrupt:
        strict = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
        if strict:
            raise ScenarioAbortRequested("ABORT_DISCARD") from None
        _apply_script_early_stop(protocol, active_step_id=active_step_id)
    elapsed_total = int(time.monotonic() - started_monotonic)
    remaining = max(int(target_duration_s) - elapsed_total, 0)
    if remaining > 0 and int(protocol.get("script_exit_code") or 0) == 0 and not bool(
        protocol.get("duration_pad_applied_in_loop")
    ):
        # Safety: ensure scripted runs honor target duration even if the template
        # omitted an explicit hold step.
        print(status_messages.status(f"Protocol completed; hold foreground for {remaining}s.", level="info"))
        _run_countdown(
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
        "whatsapp_text_behavior_v2",
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
        timer_detail="connected baseline",
        device_serial=getattr(run_ctx, "device_serial", None),
        foreground_package=pkg,
        on_elapsed=_on_elapsed,
        on_protocol_event=on_protocol_event,
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
        "control_account_metadata": (
            {
                "account_context": "control_test_account",
                "mutation_allowed_modes": ["control_account_active"],
                "cleanup_expected_modes": ["control_account_active"],
                "repeat_groups": {
                    "friend_request_accept": 2,
                    "text_post_submit": 3,
                    "photo_post_submit": 3,
                },
            }
            if template_id == _FACEBOOK_BEHAVIOR_V3
            else None
        ),
        "news_branch_metadata": (
            {
                "article_branch_values": [
                    "article_opened",
                    "subscription_required",
                    "login_required",
                    "not_available_in_ui_or_account",
                    "region_or_content_unavailable",
                    "app_error",
                    "operator_other",
                ],
                "subscription_branch_choices": dict(_NEWS_SUBSCRIPTION_BRANCH_CHOICES),
                "subscription_protocol_fit": "limited_but_compliant",
            }
            if template_id == _NEWS_BEHAVIOR_V2
            else None
        ),
        "steps": [
            {
                "id": sid,
                "text": sdesc,
                "expected_s": int(sexp),
                **_script_step_event_metadata(
                    template_id=template_id,
                    step_id=sid,
                    facebook_mode="control_account_active",
                    repeat_plan={
                        "text_post_submit": 3,
                        "photo_post_submit": 3,
                        "friend_request_accept": 2,
                    },
                    article_branch="article_opened",
                ),
            }
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
