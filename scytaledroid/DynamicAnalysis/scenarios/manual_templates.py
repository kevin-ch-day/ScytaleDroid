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

SCRIPT_STEPS_SOCIAL_MESSAGING_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home_surface", "Open the main home/feed surface and scroll for new content.", 30),
    ("open_detail_or_thread", "Open any post/detail OR any conversation thread briefly, then return.", 25),
    ("open_search", "Open search/navigation briefly (no external links), then return.", 20),
    ("open_notifications", "Open notifications/activity surface briefly, then return.", 20),
    ("open_messages_surface", "Open messages/inbox surface briefly (no send), then return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_DISCORD_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open Discord landing/home and wait for initial sync.", 10),
    ("open_fixed_server", "Open the designated server (same server every run).", 15),
    ("open_fixed_text_channel", "Open a designated text channel and wait for messages to load.", 25),
    ("scroll_history_briefly", "Scroll up 2 swipes, pause, then down 2 swipes.", 30),
    ("open_member_or_profile", "Open a user/profile OR member list briefly, then return.", 20),
    ("reaction_or_copy_optional", "Optional: add 1 reaction OR copy text (no typing required).", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_TIKTOK_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_for_you_feed", "Open the main 'For You' feed and watch/scroll several items.", 45),
    ("open_comments_panel", "Open comments on one video, scroll briefly, then close and return.", 25),
    ("open_creator_profile", "Open a creator profile briefly, then return.", 20),
    ("search_hashtag", "Use search for a hashtag (e.g., 'cybersecurity'), open one result briefly, then return.", 30),
    ("open_share_panel_cancel", "Open share panel on a video, then cancel/back (no send).", 20),
    ("open_inbox_optional", "Optional: open Inbox/Notifications briefly, then return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_TIKTOK_BASIC_V2: tuple[tuple[str, str, int], ...] = (
    # Rebalanced durations to reduce "timer pressure". Minor overruns are fine.
    ("open_for_you_feed", "Open the main 'For You' feed and watch/scroll several items.", 60),
    ("open_comments_panel", "Open comments on one video, scroll briefly, then close and return.", 20),
    ("open_creator_profile", "Open a creator profile briefly, then return.", 15),
    ("search_hashtag", "Use search for a hashtag (e.g., 'cybersecurity'), open one result briefly, then return.", 40),
    ("open_share_panel_cancel", "Open share panel on a video, then cancel/back (no send).", 15),
    ("open_inbox_optional", "Optional: open Inbox/Notifications briefly, then return.", 15),
    # Make hold "look normal" even when we're already over 4:00; runner still holds to target duration.
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_CLOUD_PRODUCTIVITY_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    # This template is intentionally generic across cloud/productivity apps (Drive/Docs/Sheets/Dropbox/Notion/Acrobat).
    # Keep actions non-destructive and avoid sending/sharing to external recipients.
    ("sign_in_if_prompted", "If prompted, sign in with the test account; otherwise continue without changes.", 25),
    ("browse_files", "Browse recent files/documents/notes and open the file browser/list surface.", 25),
    ("open_item", "Open any item (file/doc/sheet/note/PDF) and scroll within it briefly.", 40),
    (
        "upload_or_import_preview",
        "If available: start an upload/import/add-file flow (e.g., to Drive/Dropbox) then cancel before final commit; otherwise skip.",
        30,
    ),
    ("search_in_app", "Use in-app search/find briefly, then return.", 25),
    ("open_account_settings", "Open account/settings/help surface briefly, then return.", 20),
    ("sign_out_optional", "Optional: view sign-out option but do not sign out unless explicitly required for the runbook.", 10),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_DRIVE_BROWSE_SEARCH_OPEN_STAR_V1: tuple[tuple[str, str, int], ...] = (
    ("wait_settle", "Wait on the home surface to allow sync/metadata to settle.", 10),
    ("search_short_term", "Use Search: type fixed term (e.g., 'report') and execute search.", 25),
    ("wait_after_search", "Wait after search results load.", 15),
    ("open_folder_scroll", "Open a folder and scroll 2-3 swipes (no file edits).", 25),
    ("wait_after_folder", "Wait after browsing folder listing.", 10),
    ("open_file_preview", "Open a file preview (PDF/Doc) and keep it open briefly, then back.", 25),
    ("pull_to_refresh", "Pull-to-refresh once on the list surface.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_DOCS_OPEN_EDIT_COMMENT_REFRESH_V1: tuple[tuple[str, str, int], ...] = (
    ("wait_settle", "Wait on the document list surface to settle.", 10),
    ("open_known_doc", "Open a known existing document (same doc each run).", 25),
    ("wait_in_doc", "Wait in the document for content sync/autosave to stabilize.", 20),
    ("type_10_chars", "Tap body and type ~10 characters, then pause (non-destructive if possible).", 20),
    ("undo_redo", "Undo then redo once, then pause.", 20),
    ("add_comment_optional", "Optional: add a comment on a word/selection; skip if UI differs.", 25),
    ("back_to_list_refresh", "Return to list and pull-to-refresh once.", 25),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_SHEETS_OPEN_EDIT_SORT_ROW_REFRESH_V1: tuple[tuple[str, str, int], ...] = (
    ("wait_settle", "Wait on the sheet list surface to settle.", 10),
    ("open_known_sheet", "Open a known existing sheet (same sheet each run).", 25),
    ("wait_in_sheet", "Wait in the sheet for grid load/sync to stabilize.", 20),
    ("edit_two_cells", "Edit two cells (e.g., add 1 then 2), then pause.", 25),
    ("sort_or_filter_optional", "Optional: apply a simple sort/filter; skip if not found.", 25),
    ("insert_row_optional", "Optional: insert a new row; skip if not found.", 20),
    ("exit_to_list_refresh", "Exit to list and pull-to-refresh once.", 25),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_RTC_COLLABORATION_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open the app and settle on the home surface.", 20),
    ("open_meeting_surface", "Open new meeting/join meeting/calls surface (do not start a call), then return.", 25),
    ("open_chat_or_channels", "Open chat/channels/contacts surface briefly, then return.", 25),
    ("open_profile_settings", "Open profile/settings surface briefly, then return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_ZOOM_JOIN_AUDIO_ONLY_V1: tuple[tuple[str, str, int], ...] = (
    ("wait_settle", "Wait on the home surface to settle.", 10),
    ("tap_join_meeting", "Tap Join (do not host/start).", 15),
    ("enter_meeting_id_fixed", "Enter fixed Meeting ID (same every run).", 20),
    ("enter_name_fixed_join", "Enter fixed display name (same every run) and join.", 20),
    ("join_internet_audio_camera_off", "Join with Internet audio; keep Camera OFF (consistent).", 25),
    ("in_meeting_hold_audio_only", "Stay connected audio-only for ~90-120s (no chat/reactions).", 120),
    ("leave_meeting_confirm", "Leave meeting and confirm.", 15),
    ("return_home_wait", "Return to home and wait briefly.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_MEET_JOIN_MIC_ON_CAM_OFF_V1: tuple[tuple[str, str, int], ...] = (
    ("wait_settle", "Wait on the home surface to settle.", 10),
    ("tap_join_with_code", "Tap Join with a code (or equivalent).", 15),
    ("enter_meeting_code_fixed", "Enter fixed meeting code (same every run).", 20),
    ("prejoin_set_cam_off_mic_on", "On pre-join: Camera OFF; Mic ON (or OFF, but be consistent).", 20),
    ("tap_join", "Join meeting.", 10),
    ("in_meeting_hold", "Stay connected ~90-120s (no chat/reactions).", 120),
    ("leave_meeting_confirm", "Leave meeting and confirm.", 15),
    ("return_home_wait", "Return to home and wait briefly.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SNAPCHAT_TEMPLATE_HINTS: dict[str, str] = {
    "launch_feed": "Snapchat mapping: use Stories/Spotlight surface and scroll briefly.",
    "open_reply_or_comments": "Snapchat mapping: open a reply/share panel on a story item, then return.",
    "compose_post": "Snapchat mapping: open camera/create flow, then back out without capture/post.",
    "search_nav": "Snapchat mapping: use Discover/Spotlight/search briefly, then return.",
}

# Paper #3 v3 reproducibility tips: keep these short and actionable.
# These are printed before the run begins so the operator does not need to consult a separate runbook.
V3_BASELINE_REPRO_TIPS: dict[str, tuple[str, ...]] = {
    "com.discord": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Discord home surface; do not type, join voice, or browse channels.",
    ),
    "com.google.android.apps.docs": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Drive home surface; do not open files, search, or scroll.",
    ),
    "com.google.android.apps.docs.editors.docs": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Docs list surface; do not open a doc, search, or scroll.",
    ),
    "com.google.android.apps.docs.editors.sheets": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Sheets list surface; do not open a sheet, search, or scroll.",
    ),
    "us.zoom.videomeetings": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Zoom home/landing screen; do not join/host/schedule.",
    ),
    "com.google.android.apps.tachyon": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Meet home screen; do not join/create a meeting.",
    ),
}

V3_SCRIPTED_REPRO_TIPS: dict[str, tuple[str, ...]] = {
    "discord_basic_v1": (
        "Use the same fixed server + fixed text channel each run.",
        "Avoid typing/sending; reactions/copy are optional and controlled.",
    ),
    "drive_browse_search_open_star_v1": (
        "Use the same fixed search term each run (e.g., 'report').",
        "Prefer the same folder/file targets each run (pin to Recent if possible).",
    ),
    "docs_open_edit_comment_refresh_v1": (
        "Use the same known document each run (pin to Recent).",
        "Keep edits non-destructive (type small text, undo/redo); avoid sharing/sending.",
    ),
    "sheets_open_edit_sort_row_refresh_v1": (
        "Use the same known sheet each run (pin to Recent).",
        "Keep edits non-destructive; skip sort/filter/insert if the UI doesn't match.",
    ),
    "zoom_join_audio_only_v1": (
        "Use the same Meeting ID + display name every run.",
        "Keep camera OFF unless the template explicitly says otherwise; do not background the app.",
    ),
    "meet_join_mic_on_cam_off_v1": (
        "Use the same meeting code every run (a controlled test room).",
        "Keep camera/mic policy consistent; do not background the app.",
    ),
    "tiktok_basic_v2": (
        "Scroll feed continuously; pause to watch a clip; open comments; return.",
        "Avoid external links; Inbox step is optional (skip if missing).",
    ),
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
    if template_id == "social_messaging_basic_v1":
        return ("social_messaging_basic_v1", SCRIPT_STEPS_SOCIAL_MESSAGING_BASIC_V1)
    if template_id == "discord_basic_v1":
        return ("discord_basic_v1", SCRIPT_STEPS_DISCORD_BASIC_V1)
    if template_id == "tiktok_basic_v1":
        return ("tiktok_basic_v1", SCRIPT_STEPS_TIKTOK_BASIC_V1)
    if template_id == "tiktok_basic_v2":
        return ("tiktok_basic_v2", SCRIPT_STEPS_TIKTOK_BASIC_V2)
    if template_id == "cloud_productivity_basic_v1":
        return ("cloud_productivity_basic_v1", SCRIPT_STEPS_CLOUD_PRODUCTIVITY_BASIC_V1)
    if template_id == "drive_browse_search_open_star_v1":
        return ("drive_browse_search_open_star_v1", SCRIPT_STEPS_DRIVE_BROWSE_SEARCH_OPEN_STAR_V1)
    if template_id == "docs_open_edit_comment_refresh_v1":
        return ("docs_open_edit_comment_refresh_v1", SCRIPT_STEPS_DOCS_OPEN_EDIT_COMMENT_REFRESH_V1)
    if template_id == "sheets_open_edit_sort_row_refresh_v1":
        return ("sheets_open_edit_sort_row_refresh_v1", SCRIPT_STEPS_SHEETS_OPEN_EDIT_SORT_ROW_REFRESH_V1)
    if template_id == "rtc_collaboration_basic_v1":
        return ("rtc_collaboration_basic_v1", SCRIPT_STEPS_RTC_COLLABORATION_BASIC_V1)
    if template_id == "zoom_join_audio_only_v1":
        return ("zoom_join_audio_only_v1", SCRIPT_STEPS_ZOOM_JOIN_AUDIO_ONLY_V1)
    if template_id == "meet_join_mic_on_cam_off_v1":
        return ("meet_join_mic_on_cam_off_v1", SCRIPT_STEPS_MEET_JOIN_MIC_ON_CAM_OFF_V1)
    raise RuntimeError(f"BLOCKED_UNKNOWN_CATEGORY:{pkg}")


def requested_script_template(*, package_name: str) -> str:
    template_id = resolved_template_for_package(str(package_name or "").strip().lower())
    return str(template_id or "unknown")


__all__ = [
    "SNAPCHAT_TEMPLATE_HINTS",
    "V3_BASELINE_REPRO_TIPS",
    "V3_SCRIPTED_REPRO_TIPS",
    "resolve_script_template",
    "requested_script_template",
]
