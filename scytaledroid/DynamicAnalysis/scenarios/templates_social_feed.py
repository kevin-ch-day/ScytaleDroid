"""Generic social-feed scripted templates."""

from __future__ import annotations

SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2: tuple[tuple[str, str, int], ...] = (
    ("launch_feed", "Scroll the main feed for new content.", 25),
    ("open_reply_or_comments", "Open a reply/comments thread on one post and return.", 20),
    (
        "open_media_or_detail",
        "Open a visible organic media/detail surface, scroll briefly, then return.",
        25,
    ),
    ("search_nav", "Use search/navigation briefly and return.", 20),
    (
        "profile_or_notifications",
        "Open profile, inbox, or notification/account surfaces briefly, then return to the feed.",
        20,
    ),
)

__all__ = ["SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2"]
