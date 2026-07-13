"""Scripted scenario template catalog and package-to-template resolution."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.scenarios.templates_discord import (
    SCRIPT_STEPS_DISCORD_BASIC_V1,
    V3_BASELINE_REPRO_TIPS_DISCORD,
    V3_SCRIPTED_REPRO_TIPS_DISCORD,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_facebook import (
    SCRIPT_STEPS_FACEBOOK_BASIC_V2,
    SCRIPT_STEPS_FACEBOOK_BEHAVIOR_V3,
    V3_SCRIPTED_REPRO_TIPS_FACEBOOK,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_messaging import (
    SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1,
    SCRIPT_STEPS_MESSAGING_IDLE_V1,
    SCRIPT_STEPS_MESSAGING_TEXT_V1,
    SCRIPT_STEPS_MESSAGING_VIDEO_V1,
    SCRIPT_STEPS_MESSAGING_VOICE_V1,
    SCRIPT_STEPS_SOCIAL_MESSAGING_BASIC_V1,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_news_reader import (
    SCRIPT_STEPS_BBC_NEWS_BEHAVIOR_V1,
    SCRIPT_STEPS_GUARDIAN_BEHAVIOR_V1,
    SCRIPT_STEPS_NEWS_READER_BASIC_V1,
    SCRIPT_STEPS_NEWS_READER_BEHAVIOR_V2,
    V3_SCRIPTED_REPRO_TIPS_NEWS,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_productivity import (
    SCRIPT_STEPS_CLOUD_PRODUCTIVITY_BASIC_V1,
    SCRIPT_STEPS_DOCS_OPEN_EDIT_COMMENT_REFRESH_V1,
    SCRIPT_STEPS_DRIVE_BROWSE_SEARCH_OPEN_STAR_V1,
    SCRIPT_STEPS_MEET_JOIN_MIC_ON_CAM_OFF_V1,
    SCRIPT_STEPS_RTC_COLLABORATION_BASIC_V1,
    SCRIPT_STEPS_SHEETS_OPEN_EDIT_SORT_ROW_REFRESH_V1,
    SCRIPT_STEPS_ZOOM_JOIN_AUDIO_ONLY_V1,
    V3_BASELINE_REPRO_TIPS_PRODUCTIVITY,
    V3_SCRIPTED_REPRO_TIPS_PRODUCTIVITY,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_snapchat import (
    SCRIPT_STEPS_SNAPCHAT_BASIC_V1,
    SNAPCHAT_TEMPLATE_HINTS,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_social_feed import (
    SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_tiktok import (
    SCRIPT_STEPS_TIKTOK_BASIC_V1,
    SCRIPT_STEPS_TIKTOK_BASIC_V2,
    V3_SCRIPTED_REPRO_TIPS_TIKTOK,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_whatsapp import (
    SCRIPT_STEPS_WHATSAPP_IDLE_V1,
    SCRIPT_STEPS_WHATSAPP_TEXT_BEHAVIOR_V2,
    SCRIPT_STEPS_WHATSAPP_TEXT_V1,
    SCRIPT_STEPS_WHATSAPP_VIDEO_V1,
    SCRIPT_STEPS_WHATSAPP_VOICE_V1,
)
from scytaledroid.DynamicAnalysis.scenarios.templates_x_twitter import (
    SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V1,
    SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V2,
)
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package

V3_BASELINE_REPRO_TIPS: dict[str, tuple[str, ...]] = {
    **V3_BASELINE_REPRO_TIPS_DISCORD,
    **V3_BASELINE_REPRO_TIPS_PRODUCTIVITY,
}

V3_SCRIPTED_REPRO_TIPS: dict[str, tuple[str, ...]] = {
    **V3_SCRIPTED_REPRO_TIPS_DISCORD,
    **V3_SCRIPTED_REPRO_TIPS_FACEBOOK,
    **V3_SCRIPTED_REPRO_TIPS_NEWS,
    **V3_SCRIPTED_REPRO_TIPS_PRODUCTIVITY,
    **V3_SCRIPTED_REPRO_TIPS_TIKTOK,
}

_TEMPLATE_DEFINITIONS: dict[str, tuple[tuple[str, str, int], ...]] = {
    "social_feed_basic_v2": SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2,
    "bbc_news_behavior_v1": SCRIPT_STEPS_BBC_NEWS_BEHAVIOR_V1,
    "guardian_behavior_v1": SCRIPT_STEPS_GUARDIAN_BEHAVIOR_V1,
    "news_reader_basic_v1": SCRIPT_STEPS_NEWS_READER_BASIC_V1,
    "news_reader_behavior_v2": SCRIPT_STEPS_NEWS_READER_BEHAVIOR_V2,
    "messaging_idle_v1": SCRIPT_STEPS_MESSAGING_IDLE_V1,
    "messaging_text_v1": SCRIPT_STEPS_MESSAGING_TEXT_V1,
    "messaging_voice_v1": SCRIPT_STEPS_MESSAGING_VOICE_V1,
    "messaging_video_v1": SCRIPT_STEPS_MESSAGING_VIDEO_V1,
    "messaging_call_basic_v1": SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1,
    "whatsapp_idle_v1": SCRIPT_STEPS_WHATSAPP_IDLE_V1,
    "whatsapp_text_v1": SCRIPT_STEPS_WHATSAPP_TEXT_V1,
    "whatsapp_text_behavior_v2": SCRIPT_STEPS_WHATSAPP_TEXT_BEHAVIOR_V2,
    "whatsapp_voice_v1": SCRIPT_STEPS_WHATSAPP_VOICE_V1,
    "whatsapp_video_v1": SCRIPT_STEPS_WHATSAPP_VIDEO_V1,
    "facebook_basic_v2": SCRIPT_STEPS_FACEBOOK_BASIC_V2,
    "facebook_behavior_v3": SCRIPT_STEPS_FACEBOOK_BEHAVIOR_V3,
    "snapchat_basic_v1": SCRIPT_STEPS_SNAPCHAT_BASIC_V1,
    "x_twitter_full_session_v1": SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V1,
    "x_twitter_full_session_v2": SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V2,
    "social_messaging_basic_v1": SCRIPT_STEPS_SOCIAL_MESSAGING_BASIC_V1,
    "discord_basic_v1": SCRIPT_STEPS_DISCORD_BASIC_V1,
    "tiktok_basic_v1": SCRIPT_STEPS_TIKTOK_BASIC_V1,
    "tiktok_basic_v2": SCRIPT_STEPS_TIKTOK_BASIC_V2,
    "cloud_productivity_basic_v1": SCRIPT_STEPS_CLOUD_PRODUCTIVITY_BASIC_V1,
    "drive_browse_search_open_star_v1": SCRIPT_STEPS_DRIVE_BROWSE_SEARCH_OPEN_STAR_V1,
    "docs_open_edit_comment_refresh_v1": SCRIPT_STEPS_DOCS_OPEN_EDIT_COMMENT_REFRESH_V1,
    "sheets_open_edit_sort_row_refresh_v1": SCRIPT_STEPS_SHEETS_OPEN_EDIT_SORT_ROW_REFRESH_V1,
    "rtc_collaboration_basic_v1": SCRIPT_STEPS_RTC_COLLABORATION_BASIC_V1,
    "zoom_join_audio_only_v1": SCRIPT_STEPS_ZOOM_JOIN_AUDIO_ONLY_V1,
    "meet_join_mic_on_cam_off_v1": SCRIPT_STEPS_MEET_JOIN_MIC_ON_CAM_OFF_V1,
}


def resolve_script_template(
    *,
    package_name: str,
    messaging_activity: str | None = None,
) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    pkg = str(package_name or "").strip().lower()
    template_id = resolved_template_for_package(pkg)
    if not template_id:
        raise RuntimeError(f"BLOCKED_UNKNOWN_CATEGORY:{pkg}")
    msg_activity = str(messaging_activity or "").strip().lower()
    if template_id == "messaging_basic_v1":
        if msg_activity == "voice_call":
            return ("messaging_voice_v1", SCRIPT_STEPS_MESSAGING_VOICE_V1)
        if msg_activity == "video_call":
            return ("messaging_video_v1", SCRIPT_STEPS_MESSAGING_VIDEO_V1)
        if msg_activity == "mixed":
            return ("messaging_call_basic_v1", SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1)
        if msg_activity in {"idle", "none", ""}:
            return ("messaging_idle_v1", SCRIPT_STEPS_MESSAGING_IDLE_V1)
        return ("messaging_text_v1", SCRIPT_STEPS_MESSAGING_TEXT_V1)
    if template_id == "whatsapp_basic_v1":
        if msg_activity == "voice_call":
            return ("whatsapp_voice_v1", SCRIPT_STEPS_WHATSAPP_VOICE_V1)
        if msg_activity == "video_call":
            return ("whatsapp_video_v1", SCRIPT_STEPS_WHATSAPP_VIDEO_V1)
        if msg_activity == "mixed":
            return ("messaging_call_basic_v1", SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1)
        if msg_activity in {"idle", "none", ""}:
            return ("whatsapp_idle_v1", SCRIPT_STEPS_WHATSAPP_IDLE_V1)
        return ("whatsapp_text_behavior_v2", SCRIPT_STEPS_WHATSAPP_TEXT_BEHAVIOR_V2)
    steps = _TEMPLATE_DEFINITIONS.get(str(template_id))
    if steps is None:
        raise RuntimeError(f"BLOCKED_UNKNOWN_CATEGORY:{pkg}")
    return str(template_id), steps


def requested_script_template(*, package_name: str) -> str:
    template_id = resolved_template_for_package(str(package_name or "").strip().lower())
    return str(template_id or "unknown")


def template_steps_for_id(template_id: str) -> tuple[tuple[str, str, int], ...] | None:
    return _TEMPLATE_DEFINITIONS.get(str(template_id or "").strip())


__all__ = [
    "SNAPCHAT_TEMPLATE_HINTS",
    "V3_BASELINE_REPRO_TIPS",
    "V3_SCRIPTED_REPRO_TIPS",
    "resolve_script_template",
    "requested_script_template",
    "template_steps_for_id",
]
