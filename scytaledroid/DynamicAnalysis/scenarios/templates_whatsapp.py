"""WhatsApp-specific scripted templates."""

from __future__ import annotations

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

SCRIPT_STEPS_WHATSAPP_TEXT_BEHAVIOR_V2: tuple[tuple[str, str, int], ...] = (
    ("open_app", "Open WhatsApp and wait for initial sync.", 10),
    ("open_control_chat", "Open the designated control/test chat and wait for the thread to settle.", 15),
    ("send_text_1", "Send fixed text message 1 to the control/test chat.", 15),
    ("hold_15s_1", "Hold the chat in foreground for 15 seconds after text message 1.", 15),
    ("send_text_2", "Send fixed text message 2 to the same control/test chat.", 15),
    ("hold_15s_2", "Hold the chat in foreground for 15 seconds after text message 2.", 15),
    ("send_text_3", "Send fixed text message 3 to the same control/test chat.", 15),
    ("hold_15s_3", "Hold the chat in foreground for 15 seconds after text message 3.", 15),
    (
        "receive_reply_or_wait",
        "If a controlled contact can reply, wait for the reply/sync; otherwise hold the chat and mark limited.",
        30,
    ),
    ("send_emoji_optional", "Optional controlled action: send one emoji or sticker, then hold briefly.", 15),
    ("send_small_image_optional", "Optional controlled action: send one small safe test image, then hold briefly.", 20),
    ("return_chat_list", "Return to the WhatsApp chat list.", 10),
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

__all__ = [
    "SCRIPT_STEPS_WHATSAPP_IDLE_V1",
    "SCRIPT_STEPS_WHATSAPP_TEXT_V1",
    "SCRIPT_STEPS_WHATSAPP_TEXT_BEHAVIOR_V2",
    "SCRIPT_STEPS_WHATSAPP_VOICE_V1",
    "SCRIPT_STEPS_WHATSAPP_VIDEO_V1",
]
