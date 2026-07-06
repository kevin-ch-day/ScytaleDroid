"""TikTok-specific scripted templates."""

from __future__ import annotations

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
    ("open_for_you_feed", "Open the main 'For You' feed and watch/scroll several items.", 60),
    ("open_comments_panel", "Open comments on one video, scroll briefly, then close and return.", 20),
    ("open_creator_profile", "Open a creator profile briefly, then return.", 15),
    ("search_hashtag", "Use search for a hashtag (e.g., 'cybersecurity'), open one result briefly, then return.", 40),
    ("open_share_panel_cancel", "Open share panel on a video, then cancel/back (no send).", 15),
    ("open_inbox_optional", "Optional: open Inbox/Notifications briefly, then return.", 15),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

V3_SCRIPTED_REPRO_TIPS_TIKTOK: dict[str, tuple[str, ...]] = {
    "tiktok_basic_v2": (
        "Scroll feed continuously; pause to watch a clip; open comments; return.",
        "Avoid external links; Inbox step is optional (skip if missing).",
    ),
}

__all__ = [
    "SCRIPT_STEPS_TIKTOK_BASIC_V1",
    "SCRIPT_STEPS_TIKTOK_BASIC_V2",
    "V3_SCRIPTED_REPRO_TIPS_TIKTOK",
]
