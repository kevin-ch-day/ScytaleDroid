"""X/Twitter-specific scripted templates."""

from __future__ import annotations

SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V1: tuple[tuple[str, str, int], ...] = (
    ("launch_home", "Launch app and settle on home timeline.", 20),
    ("home_scroll_media_pause", "Scroll home timeline and pause on one media post briefly.", 40),
    ("open_post_detail_engagement", "Open one post detail, view engagement/replies briefly, then return.", 25),
    ("open_profile_page", "Open a profile page briefly, then return.", 20),
    ("search_static_keyword", "Search fixed keyword 'cybersecurity', open one result briefly, then return.", 25),
    ("open_notifications", "Open notifications tab, scroll slightly, then return.", 15),
    ("open_dm_thread", "Open messages, open one existing thread briefly, then return (no typing).", 15),
    ("grok_ai_prompt", "Open Grok and use fixed prompt: 'Summarize today's top cybersecurity topics in 3 bullets.'", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

__all__ = ["SCRIPT_STEPS_X_TWITTER_FULL_SESSION_V1"]
