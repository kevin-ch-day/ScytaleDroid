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
    return {}


__all__ = [
    "manual_interaction_behavior_lines",
    "manual_interaction_checkpoint_messages",
]
