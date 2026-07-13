"""Scripted scenario helper logic extracted from manual.py.

This module intentionally holds mostly pure or lightly interactive scripted-run
helpers so ``manual.py`` can stay focused on runner orchestration, capture
timing, and operator control flow.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.scenarios.script_template_catalog import (
    requested_script_template as _requested_script_template_for_package,
)
from scytaledroid.DynamicAnalysis.scenarios.script_template_catalog import (
    resolve_script_template as _resolve_script_template_for_package,
)
from scytaledroid.DynamicAnalysis.templates.category_map import mapping_version
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

SCRIPT_PROTOCOL_VERSION = 2

SCRIPT_LIMITATION_REASON_LABELS: tuple[tuple[str, str], ...] = (
    ("subscription_required", "subscription required / paywall shown"),
    ("login_required", "login required"),
    ("not_available_in_ui_or_account", "not available in this UI/account"),
    ("region_or_content_unavailable", "region or content unavailable"),
    ("app_error", "app error"),
    ("operator_other", "other limitation"),
)
SCRIPT_LIMITATION_REASON_TEXT = {
    **dict(SCRIPT_LIMITATION_REASON_LABELS),
    "paywall": "subscription required / paywall shown",
    "not_available": "not available in this UI/account",
    "other": "other limitation",
}
SCRIPTED_ARTICLE_LIMITATION_REASONS = {
    "paywall",
    "subscription_required",
    "login_required",
    "not_available",
    "not_available_in_ui_or_account",
    "region_or_content_unavailable",
    "app_error",
    "operator_other",
}
NEWS_BEHAVIOR_V2 = "news_reader_behavior_v2"
NEWS_SUBSCRIPTION_BRANCH_CHOICES = {
    "1": "subscription_wall_observed",
    "2": "subscription_options_observed",
    "3": "return_home",
    "4": "skip_article_branch",
}

FACEBOOK_BEHAVIOR_V3 = "facebook_behavior_v3"
FACEBOOK_CONTROL_ACCOUNT_MODES = {
    "1": "observation_only",
    "2": "draft_only",
    "3": "control_account_active",
}
FACEBOOK_MUTATING_STEP_PREFIXES = (
    "friend_request_accept_",
    "text_post_submit_",
    "photo_post_submit_",
)


def scripted_step_description(
    step_id: str,
    default_desc: str,
    *,
    package_name: str | None = None,
) -> str:
    pkg = str(package_name or "").strip().lower()
    if step_id == "open_article":
        if pkg == "com.guardian":
            return (
                "Open one article only if you are intentionally collecting interactive evidence. "
                "If sign-in, free registration, or subscription wall appears, mark subscription_required."
            )
        return "Open one article. If subscription/paywall appears, mark subscription_required."
    if step_id in {"scroll_article", "article_scroll"}:
        if pkg == "com.guardian":
            return (
                "Scroll visible article content only when the article actually opened. "
                "If content is blocked by sign-in, free registration, or subscription wall, mark limited and continue."
            )
        return "Scroll the visible article content. If content is blocked, mark limited and continue."
    return str(default_desc or "").strip()


def scripted_step_action_line(*, limited_or_skip_only: bool = False) -> str:
    if limited_or_skip_only:
        return "Action: L=limited | N=skip | D=done | H=return home/reset"
    return "Action: D=done | L=limited | N=skip | H=return home/reset"


def prompt_facebook_control_account_mode() -> str:
    print(status_messages.status("Facebook control-account behavior mode:", level="info"))
    print("  1) Observation only")
    print("  2) Draft only")
    print("  3) Control-account active mode [recommended for research]")
    choice = prompt_utils.get_choice(
        ["1", "2", "3"],
        default="3",
        invalid_message="Choose 1, 2, or 3.",
    )
    return FACEBOOK_CONTROL_ACCOUNT_MODES.get(str(choice), "control_account_active")


def prompt_facebook_repeat_plan() -> dict[str, int]:
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
        "text_post_submit": repeat_choice_to_total(text_choice, max_total=3),
        "photo_post_submit": repeat_choice_to_total(photo_choice, max_total=3),
        "friend_request_accept": 2,
    }


def repeat_choice_to_total(choice: object, *, max_total: int) -> int:
    try:
        repeat_count = int(str(choice).strip())
    except (TypeError, ValueError):
        repeat_count = 0
    return min(max(repeat_count + 1, 1), int(max_total))


def repeat_metadata_for_step(
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


def whatsapp_text_behavior_metadata(
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
        metadata.update(repeat_metadata_for_step(step_id))
    elif step_id.startswith("hold_15s_"):
        metadata.update({"traffic_phase": "post_send_hold"})
        metadata.update(repeat_metadata_for_step(step_id))
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


def facebook_traffic_phase_for_step(step_id: str) -> str:
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


def news_traffic_phase_for_step(step_id: str) -> str:
    sid = str(step_id or "").strip()
    if sid == "open_home":
        return "news_home_feed"
    if sid == "scroll_headlines":
        return "news_feed_scroll"
    if sid == "open_article":
        return "article_open_or_gate"
    if sid == "article_scroll":
        return "article_scroll"
    if sid in {"article_return_home", "subscription_return_home"}:
        return "return_home"
    if sid == "subscription_wall_observe":
        return "subscription_gate_observe"
    if sid == "subscription_options_observe":
        return "subscription_options_observe"
    if sid == "video_or_media_optional":
        return "media_surface_optional"
    return "foreground_hold"


def scripted_step_metadata(
    *,
    template_id: str,
    step_id: str,
    facebook_mode: str | None = None,
    step_outcome: str | None = None,
    repeat_plan: dict[str, int] | None = None,
) -> dict[str, object]:
    if template_id != FACEBOOK_BEHAVIOR_V3:
        return {}
    mode = str(facebook_mode or "control_account_active").strip().lower()
    mutation_allowed = mode == "control_account_active"
    mutation_candidate = step_id.startswith(FACEBOOK_MUTATING_STEP_PREFIXES)
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
        "traffic_phase": facebook_traffic_phase_for_step(step_id),
    }
    metadata.update(repeat_metadata_for_step(step_id, repeat_plan=repeat_plan))
    return metadata


def news_step_metadata(
    *,
    template_id: str,
    step_id: str,
    article_branch: str | None = None,
    subscription_choice: str | None = None,
    step_outcome: str | None = None,
) -> dict[str, object]:
    if template_id != NEWS_BEHAVIOR_V2:
        return {}
    branch = str(article_branch or "").strip() or None
    subscription_options_opened = bool(subscription_choice == "subscription_options_observed")
    subscription_wall_observed = bool(
        branch == "subscription_required"
        and step_id in {
            "subscription_wall_observe",
            "subscription_options_observe",
            "subscription_return_home",
        }
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
        "traffic_phase": news_traffic_phase_for_step(step_id),
        "protocol_fit": "limited_but_compliant" if branch in {"subscription_required", "login_required"} else None,
    }


def prompt_news_subscription_branch() -> str:
    print(
        status_messages.status(
            "Article content is blocked by subscription, sign-in, or free-registration requirement.",
            level="warn",
        )
    )
    print("  1) Observe subscription wall for 30 seconds")
    print("  2) Open sign-in / subscription options, hold 30 seconds, then return")
    print("  3) Return Home")
    print("  4) Skip article branch")
    choice = prompt_utils.get_choice(
        ["1", "2", "3", "4"],
        default="1",
        invalid_message="Choose 1, 2, 3, or 4.",
    )
    return NEWS_SUBSCRIPTION_BRANCH_CHOICES.get(str(choice), "subscription_wall_observed")


def normalize_limitation_reason(reason: str | None) -> str | None:
    token = str(reason or "").strip().lower()
    if token in {"paywall", "subscription", "subscription_wall"}:
        return "subscription_required"
    if token == "not_available":
        return "not_available_in_ui_or_account"
    if token == "other":
        return "operator_other"
    return token or None


def script_step_event_metadata(
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
        **whatsapp_text_behavior_metadata(
            template_id=template_id,
            step_id=step_id,
            step_outcome=step_outcome,
        ),
        **scripted_step_metadata(
            template_id=template_id,
            step_id=step_id,
            facebook_mode=facebook_mode,
            step_outcome=step_outcome,
            repeat_plan=repeat_plan,
        ),
        **news_step_metadata(
            template_id=template_id,
            step_id=step_id,
            article_branch=article_branch,
            subscription_choice=subscription_choice,
            step_outcome=step_outcome,
        ),
    }


def news_branch_skip_reason(
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
        if choice in {"subscription_wall_observed", "subscription_options_observed"}:
            return None
        return "subscription_wall_observe_not_selected"
    if step_id == "subscription_options_observe":
        if branch != "subscription_required":
            return "subscription_branch_not_taken"
        return None if choice == "subscription_options_observed" else "subscription_options_not_selected"
    if step_id == "subscription_return_home":
        if branch != "subscription_required":
            return "subscription_branch_not_taken"
        if choice in {"subscription_wall_observed", "subscription_options_observed", "return_home"}:
            return None
        return "subscription_return_home_not_selected"
    return None


def json_dumps_canonical(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def resolve_script_template(run_ctx: RunContext) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    msg_activity = str(getattr(run_ctx, "messaging_activity", "") or "").strip().lower()
    return _resolve_script_template_for_package(
        package_name=str(getattr(run_ctx, "package_name", "") or ""),
        messaging_activity=msg_activity,
    )


def requested_script_template(run_ctx: RunContext) -> str:
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
    return resolve_script_template(run_ctx)


def json_dumps_sorted(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def build_template_hash(template_id: str, steps: tuple[tuple[str, str, int], ...]) -> str:
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
            if template_id == FACEBOOK_BEHAVIOR_V3
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
                "subscription_branch_choices": dict(NEWS_SUBSCRIPTION_BRANCH_CHOICES),
                "subscription_protocol_fit": "limited_but_compliant",
            }
            if template_id == NEWS_BEHAVIOR_V2
            else None
        ),
        "steps": [
            {
                "id": sid,
                "text": sdesc,
                "expected_s": int(sexp),
                **script_step_event_metadata(
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


def prompt_step3_variant() -> str:
    print(status_messages.status("Step variant (allowed):", level="info"))
    print("  1) info")
    print("  2) media")
    print("  N) skip (not found)")
    choice = prompt_utils.get_choice(
        ["1", "2", "N"],
        default="1",
        casefold=True,
        invalid_message="Choose 1, 2, or N.",
    )
    if choice.upper() == "N":
        return "skip"
    return "media" if choice == "2" else "info"


__all__ = [
    "SCRIPT_PROTOCOL_VERSION",
    "SCRIPT_LIMITATION_REASON_LABELS",
    "SCRIPT_LIMITATION_REASON_TEXT",
    "SCRIPTED_ARTICLE_LIMITATION_REASONS",
    "NEWS_BEHAVIOR_V2",
    "NEWS_SUBSCRIPTION_BRANCH_CHOICES",
    "FACEBOOK_BEHAVIOR_V3",
    "FACEBOOK_CONTROL_ACCOUNT_MODES",
    "FACEBOOK_MUTATING_STEP_PREFIXES",
    "scripted_step_description",
    "scripted_step_action_line",
    "prompt_facebook_control_account_mode",
    "prompt_facebook_repeat_plan",
    "repeat_choice_to_total",
    "repeat_metadata_for_step",
    "whatsapp_text_behavior_metadata",
    "facebook_traffic_phase_for_step",
    "news_traffic_phase_for_step",
    "scripted_step_metadata",
    "news_step_metadata",
    "prompt_news_subscription_branch",
    "normalize_limitation_reason",
    "script_step_event_metadata",
    "news_branch_skip_reason",
    "json_dumps_canonical",
    "resolve_script_template",
    "requested_script_template",
    "preview_script_template_for_package",
    "build_template_hash",
    "prompt_step3_variant",
    "json_dumps_sorted",
]
