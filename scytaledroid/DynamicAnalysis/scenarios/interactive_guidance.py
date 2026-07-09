"""Operator guidance for manual interactive capture surfaces.

This module is intentionally UI-only. It suggests high-value foreground actions
for manual interactive runs without changing quota, countability, or evidence
policy.
"""

from __future__ import annotations


def manual_interaction_behavior_lines(package_name: str, *, target_label: str) -> list[str]:
    pkg = str(package_name or "").strip().lower()
    if pkg == "com.twitter.android":
        return [
            "  - Keep X in the foreground and generate real navigation, not just idle feed dwell",
            "  - Start with a short home/feed scroll, then pause briefly on one post",
            "  - Open one post detail or replies view briefly, then return",
            "  - Open one profile page briefly, then return",
            "  - Visit Search and Explore; prefer Trending or News for a second contrast surface",
            "  - Optionally open Notifications or Chat if those surfaces are available on this account",
            "  - Avoid compose/posting, likes, follows, DMs, purchases, account changes, or external links",
            f"  - Aim for the {target_label} target with 2-4 distinct in-app surfaces",
        ]
    if pkg == "com.pinterest":
        return [
            "  - Keep Pinterest in the foreground and generate real navigation, not just idle feed dwell",
            "  - Start with a short Home feed scroll, then pause briefly on visible content",
            "  - Open one non-sponsored pin/detail view briefly, scroll once if needed, then return",
            "  - Visit Search with a neutral topic and scroll the result grid",
            "  - Open one search-result pin/detail view briefly, then return",
            "  - If app-link behavior is in scope, open one pinterest.com or pin.it link that resolves back into Pinterest",
            "  - Avoid Create, Save, Follow, comments, messages, outbound shopping/ad links, account changes, or external share targets",
            f"  - Aim for the {target_label} target with feed, search, detail, and optional app-link surfaces",
        ]
    if pkg == "com.snapchat.android":
        return [
            "  - Keep Snapchat in the foreground and generate real navigation, not just camera idle dwell",
            "  - Start from Camera/Landing, then move to Stories or Discover and scroll public content briefly",
            "  - Visit Spotlight or Search briefly if available, then return to a non-compose surface",
            "  - Let media cards load long enough to exercise Snapchat API, analytics, and CDN traffic",
            "  - Optional: if the thread is clearly labeled My AI, send one fixed non-sensitive research prompt and wait for the AI reply",
            "  - If a human Chat, unlabeled text input, or record-button surface opens, back out without typing, recording, or sending",
            "  - Avoid capturing/sending snaps, chats, friend requests, follows/subscriptions, story posting, purchases, location sharing, account changes, or external share targets",
            f"  - Aim for the {target_label} target with camera/landing plus Stories/Discover/Spotlight/Search and optional My AI surfaces",
        ]
    return [
        "  - Keep the app in the foreground",
        "  - Use the app normally",
    ]


def manual_interaction_checkpoint_messages(package_name: str) -> dict[int, str]:
    pkg = str(package_name or "").strip().lower()
    if pkg == "com.twitter.android":
        return {
            60: (
                "60s checkpoint: if you are still only on the X home feed, open one post or profile briefly, then return."
            ),
            120: (
                "120s checkpoint: visit Search and Explore or another distinct X surface such as Trending, News, Notifications, or Chat if available."
            ),
            180: (
                "180s checkpoint: aim to finish with 2-4 distinct in-app X surfaces captured; avoid compose/posting, DMs, follows, and external links."
            ),
        }
    if pkg == "com.pinterest":
        return {
            60: (
                "60s checkpoint: if you are still only on the Pinterest home feed, open one non-sponsored pin/detail view briefly, then return."
            ),
            120: (
                "120s checkpoint: visit Pinterest Search with a neutral topic, scroll results, and open one non-sponsored result briefly."
            ),
            180: (
                "180s checkpoint: capture feed, search, detail, and optional verified app-link behavior; avoid Save, Follow, Create, comments, messages, ads, and share targets."
            ),
        }
    if pkg == "com.snapchat.android":
        return {
            60: (
                "60s checkpoint: if you are still only on Camera/Landing, move to Stories or Discover and scroll public content briefly."
            ),
            120: (
                "120s checkpoint: visit Spotlight or Search if available; My AI is allowed only with one fixed non-sensitive prompt to the clearly labeled AI thread."
            ),
            180: (
                "180s checkpoint: capture camera/landing plus content-loading surfaces; avoid snaps, human chats, stories, follows/subscriptions, purchases, location sharing, and account changes."
            ),
        }
    return {}


__all__ = [
    "manual_interaction_behavior_lines",
    "manual_interaction_checkpoint_messages",
]
