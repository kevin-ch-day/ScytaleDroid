"""Generic social-feed scripted templates."""

from __future__ import annotations

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

__all__ = ["SCRIPT_STEPS_SOCIAL_FEED_BASIC_V2"]
