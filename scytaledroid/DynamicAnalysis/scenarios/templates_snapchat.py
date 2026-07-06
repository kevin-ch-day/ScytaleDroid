"""Snapchat-specific scripted templates and hints."""

from __future__ import annotations

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
    ("user_activity", "Continue light non-mutating activity across Snapchat surfaces (optionally view My AI if available) until timer target.", 0),
)

SNAPCHAT_TEMPLATE_HINTS: dict[str, str] = {
    "launch_feed": "Snapchat mapping: use Stories/Spotlight surface and scroll briefly.",
    "open_reply_or_comments": "Snapchat mapping: open a reply/share panel on a story item, then return.",
    "compose_post": "Snapchat mapping: open camera/create flow, then back out without capture/post.",
    "search_nav": "Snapchat mapping: use Discover/Spotlight/search briefly, then return.",
}

__all__ = ["SCRIPT_STEPS_SNAPCHAT_BASIC_V1", "SNAPCHAT_TEMPLATE_HINTS"]
