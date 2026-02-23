"""Scripted scenario template definitions and app-template resolution."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package

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

SCRIPT_STEPS_MESSAGING_IDLE_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread and keep it visible (stay in thread).", 25),
    ("scroll_thread", "Scroll slightly within the thread (no typing/sending).", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_MESSAGING_TEXT_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread and keep it visible (stay in thread).", 25),
    ("send_text_1", "Send fixed text message: 'Test message 1' (no media).", 20),
    ("send_text_2", "Send fixed text message: 'Test message 2' (no media).", 20),
    ("open_info_or_media", "Open conversation info OR shared media and return.", 20),
    ("search_or_new_chat", "Open search or new chat briefly and return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_MESSAGING_VOICE_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread (stay in thread).", 20),
    ("start_call", "Initiate a voice call to a test contact.", 15),
    ("call_active", "Keep call active for 90s if connected.", 90),
    ("end_call", "End the call and remain in thread.", 15),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_MESSAGING_VIDEO_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread (stay in thread).", 20),
    ("start_call", "Initiate a video call to a test contact.", 15),
    ("call_active", "Keep call active for 90s if connected.", 90),
    ("end_call", "End the call and remain in thread.", 15),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    # Mixed/exploratory call stimulus (voice-compatible).
    ("open_thread", "Open a recent conversation thread (stay in thread).", 20),
    ("start_call", "Initiate a voice call to a test contact.", 15),
    ("call_active", "Keep call active for 90s if connected.", 90),
    ("end_call", "End the call and remain in thread.", 15),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_WHATSAPP_IDLE_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread and keep it visible (stay in thread).", 25),
    ("scroll_thread", "Scroll slightly within the thread (no typing/sending).", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_WHATSAPP_TEXT_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread and keep it visible (stay in thread).", 25),
    ("send_text_1", "Send fixed text message: 'Test message 1' (no media).", 20),
    ("send_text_2", "Send fixed text message: 'Test message 2' (no media).", 20),
    ("ask_meta_ai", "Open Ask Meta AI and send fixed prompt: 'Summarize top cybersecurity topics in 3 bullets.'", 25),
    ("open_info_or_media", "Open conversation info OR shared media and return.", 20),
    ("search_or_new_chat", "Open search or new chat briefly and return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_WHATSAPP_VOICE_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread (stay in thread).", 20),
    ("start_call", "Initiate a voice call to a test contact.", 15),
    ("call_active", "Keep call active for 90s if connected.", 90),
    ("end_call", "End the call and remain in thread.", 15),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_WHATSAPP_VIDEO_V1: tuple[tuple[str, str, int], ...] = (
    ("open_thread", "Open a recent conversation thread (stay in thread).", 20),
    ("start_call", "Initiate a video call to a test contact.", 15),
    ("call_active", "Keep call active for 90s if connected.", 90),
    ("end_call", "End the call and remain in thread.", 15),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_FACEBOOK_BASIC_V2: tuple[tuple[str, str, int], ...] = (
    ("open_app", "Open Facebook app and settle on Home feed.", 20),
    ("open_profile_page", "Open your profile page briefly, then return.", 20),
    ("open_friends_scroll", "Open Friends tab/page and scroll briefly.", 20),
    (
        "open_add_friends_review",
        "Open add-friends / friend-requests surface and review briefly (no add/accept actions).",
        20,
    ),
    ("create_text_post_draft", "Open text post composer, type short draft, then discard.", 25),
    ("create_photo_post_draft", "Open photo post composer, attach one photo draft, then discard.", 30),
    ("open_reels", "Open Reels and watch/scroll briefly.", 25),
    ("view_stories", "Open Stories and view 1-2 segments briefly.", 25),
    ("open_marketplace", "Open Marketplace briefly and scroll.", 20),
    ("open_notifications", "Open Notifications and scroll slightly.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_SNAPCHAT_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("launch_app", "Open camera home and keep app foregrounded.", 20),
    ("open_profile_page", "Open your account/profile page briefly, then return.", 20),
    ("open_map", "Open Snap Map briefly, pan slightly, then return.", 20),
    ("open_chats", "Swipe to chats, open a recent thread, then return (no typing/send).", 20),
    ("open_stories", "Open Stories, watch 1-2 segments, then return.", 25),
    ("add_to_your_stories", "Open 'Add to Your Story' composer, then back out without posting.", 25),
    ("my_ai_chat", "Open My AI chat, send one short fixed prompt, view response briefly, then return.", 25),
    ("team_snapchat_chat", "Open 'Team Snapchat' chat, send one short fixed prompt, view response briefly, then return.", 25),
    ("open_spotlight", "Open Spotlight and scroll; interact via like/comments/repost where available, then return.", 25),
    (
        "user_activity",
        "Continue light non-mutating activity across Snapchat surfaces (optionally view My AI if available) until timer target.",
        0,
    ),
)

SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V1: tuple[tuple[str, str, int], ...] = (
    ("launch_home", "Launch app and settle on home timeline.", 20),
    ("home_scroll_media_pause", "Scroll home timeline and pause on one media post briefly.", 40),
    ("open_post_detail_engagement", "Open one post detail, view engagement/replies briefly, then return.", 25),
    ("open_profile_page", "Open a profile page briefly, then return.", 20),
    ("search_static_keyword", "Search fixed keyword 'cybersecurity', open one result briefly, then return.", 25),
    ("open_notifications", "Open notifications tab, scroll slightly, then return.", 15),
    ("open_dm_thread", "Open messages, open one existing thread briefly, then return (no typing).", 15),
    (
        "grok_ai_prompt",
        "Open Grok and use fixed prompt: 'Summarize today's top cybersecurity topics in 3 bullets.'",
        20,
    ),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SNAPCHAT_TEMPLATE_HINTS: dict[str, str] = {
    "launch_feed": "Snapchat mapping: use Stories/Spotlight surface and scroll briefly.",
    "open_reply_or_comments": "Snapchat mapping: open a reply/share panel on a story item, then return.",
    "compose_post": "Snapchat mapping: open camera/create flow, then back out without capture/post.",
    "search_nav": "Snapchat mapping: use Discover/Spotlight/search briefly, then return.",
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
        if msg_activity in {"voice_call"}:
            return ("messaging_voice_v1", SCRIPT_STEPS_MESSAGING_VOICE_V1)
        if msg_activity in {"video_call"}:
            return ("messaging_video_v1", SCRIPT_STEPS_MESSAGING_VIDEO_V1)
        if msg_activity in {"mixed"}:
            return ("messaging_call_basic_v1", SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1)
        if msg_activity in {"idle", "none", ""}:
            return ("messaging_idle_v1", SCRIPT_STEPS_MESSAGING_IDLE_V1)
        return ("messaging_text_v1", SCRIPT_STEPS_MESSAGING_TEXT_V1)
    if template_id == "facebook_basic_v2":
        return ("facebook_basic_v2", SCRIPT_STEPS_FACEBOOK_BASIC_V2)
    if template_id == "whatsapp_basic_v1":
        if msg_activity in {"voice_call"}:
            return ("whatsapp_voice_v1", SCRIPT_STEPS_WHATSAPP_VOICE_V1)
        if msg_activity in {"video_call"}:
            return ("whatsapp_video_v1", SCRIPT_STEPS_WHATSAPP_VIDEO_V1)
        if msg_activity in {"mixed"}:
            return ("messaging_call_basic_v1", SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1)
        if msg_activity in {"idle", "none", ""}:
            return ("whatsapp_idle_v1", SCRIPT_STEPS_WHATSAPP_IDLE_V1)
        return ("whatsapp_text_v1", SCRIPT_STEPS_WHATSAPP_TEXT_V1)
    if template_id == "x_twitter_full_session_v1":
        return ("x_twitter_full_session_v1", SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V1)
    if template_id == "snapchat_basic_v1":
        return ("snapchat_basic_v1", SCRIPT_STEPS_SNAPCHAT_BASIC_V1)
    if template_id == "social_feed_basic_v2":
        return ("social_feed_basic_v2", SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2)
    raise RuntimeError(f"BLOCKED_UNKNOWN_CATEGORY:{pkg}")


def requested_script_template(*, package_name: str) -> str:
    template_id = resolved_template_for_package(str(package_name or "").strip().lower())
    return str(template_id or "unknown")


__all__ = [
    "SNAPCHAT_TEMPLATE_HINTS",
    "resolve_script_template",
    "requested_script_template",
]
