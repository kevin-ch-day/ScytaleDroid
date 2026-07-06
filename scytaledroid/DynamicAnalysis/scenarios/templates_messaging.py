"""Generic messaging scripted templates."""

from __future__ import annotations

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
    ("open_thread", "Open a recent conversation thread (stay in thread).", 20),
    ("start_call", "Initiate a voice call to a test contact.", 15),
    ("call_active", "Keep call active for 90s if connected.", 90),
    ("end_call", "End the call and remain in thread.", 15),
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

__all__ = [
    "SCRIPT_STEPS_MESSAGING_IDLE_V1",
    "SCRIPT_STEPS_MESSAGING_TEXT_V1",
    "SCRIPT_STEPS_MESSAGING_VOICE_V1",
    "SCRIPT_STEPS_MESSAGING_VIDEO_V1",
    "SCRIPT_STEPS_MESSAGING_CALL_BASIC_V1",
    "SCRIPT_STEPS_SOCIAL_MESSAGING_BASIC_V1",
]
