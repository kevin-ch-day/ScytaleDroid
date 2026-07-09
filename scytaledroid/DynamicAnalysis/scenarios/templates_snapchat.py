"""Snapchat-specific scripted templates and hints."""

from __future__ import annotations

SCRIPT_STEPS_SNAPCHAT_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("launch_app", "Open camera home and keep app foregrounded.", 20),
    ("open_profile_page", "Open your account/profile page briefly, then return without changing settings.", 20),
    ("open_stories_or_discover", "Open Stories or Discover, let public media cards load, scroll briefly, then return.", 30),
    ("open_spotlight", "Open Spotlight and scroll public content; do not like, comment, repost, follow, or share.", 30),
    ("open_search", "Open Search, view suggestions or neutral results briefly, then return without adding contacts.", 25),
    (
        "my_ai_chat",
        "Optional: only if the thread is clearly labeled My AI, send one short fixed non-sensitive research prompt, wait for the AI reply, then return.",
        30,
    ),
    ("open_lenses_carousel", "Open/scroll the lens carousel briefly, then return without capturing or sending media.", 25),
    ("return_camera", "Return to Camera/Landing and hold briefly without pressing capture.", 20),
    ("user_activity", "Continue light non-mutating activity on public content-loading surfaces until timer target.", 0),
)

SNAPCHAT_TEMPLATE_HINTS: dict[str, str] = {
    "launch_feed": "Snapchat mapping: use Stories/Spotlight surface and scroll briefly.",
    "open_reply_or_comments": "Snapchat mapping: skip human reply/share panels; My AI is allowed only when clearly labeled and with one fixed non-sensitive prompt.",
    "compose_post": "Snapchat mapping: open camera/create flow, then back out without capture/post.",
    "search_nav": "Snapchat mapping: use Discover/Spotlight/search briefly, then return without adding contacts or sharing.",
}

__all__ = ["SCRIPT_STEPS_SNAPCHAT_BASIC_V1", "SNAPCHAT_TEMPLATE_HINTS"]
