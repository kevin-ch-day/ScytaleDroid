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
            "  - Start with a short Home / For You feed scroll, then pause briefly on one media or video post",
            "  - Open one post detail or replies view briefly, then return",
            "  - Open one profile page briefly, then return",
            "  - Visit Search and Explore with a neutral topic such as 'android privacy security', then scroll results",
            "  - Open Grok, Notifications, and Chat landing surfaces if available on this account",
            "  - Compose is draft-only by default; submit one clearly labeled benign test post only on a controlled test account",
            "  - Open a DM thread only if it is a controlled test thread; otherwise use Chat landing only",
            "  - Avoid likes, follows, purchases, account settings changes, ad click-throughs, and external links unless those are the explicit test branch",
            f"  - Aim for the {target_label} target with feed, post detail, profile, search/explore, Grok, notifications/chat, and optional controlled compose surfaces",
        ]
    if pkg == "com.instagram.android":
        return [
            "  - Keep Instagram in the foreground and generate real navigation, not just idle feed dwell",
            "  - Start with Home feed scrolling, then pause briefly on one organic post or reel",
            "  - View Stories briefly and tap through several story cards, then return",
            "  - Visit Reels, swipe through multiple videos, and optionally open the share sheet then back out without sending",
            "  - Visit Explore/Search with a neutral topic and scroll the result grid",
            "  - Open Profile and switch among grid, reels, repost/tagged tabs briefly, then return",
            "  - Open the create/camera preview briefly to exercise camera/microphone/media-library surfaces, then back out without publishing",
            "  - If account-state writes are intentionally in scope, prefer reversible actions such as like/unlike or save/unsave; label them in notes",
            "  - Avoid public comments, DMs to human accounts, follows, purchases, ad click-throughs, and web deeplinks unless those are the explicit test branch",
            "  - Public instagram.com deeplinks may resolve back to feed/ad surfaces; use in-app navigation as the primary event generator",
            f"  - Aim for the {target_label} target with feed, Stories, Reels, Explore/Search, Profile, and optional create-camera preview surfaces",
        ]
    if pkg == "com.pinterest":
        return [
            "  - Keep Pinterest in the foreground and generate real navigation, not just idle feed dwell",
            "  - Start with a short Home feed scroll, then pause briefly on visible content",
            "  - Open one non-sponsored native pin/detail view briefly, scroll once if needed, then return",
            "  - Visit Search with a neutral topic and scroll the result grid",
            "  - Open one non-promoted search-result pin/detail view briefly, then return",
            "  - Search grids often mix sponsored cards and Visit site buttons; use those only as intentional outbound-web branches",
            "  - Native pin-detail modals may initialize media, WebView, camera, or image-processing components; close them without More/Save actions",
            "  - If a pin opens a publisher page or Chrome Custom Tab, label it as outbound web behavior and back out",
            "  - If app-link behavior is in scope, open one pinterest.com or pin.it link that resolves back into Pinterest",
            "  - Avoid Create, Save, Follow, comments, messages, outbound shopping/ad links, ad overlays, account changes, or external share targets",
            f"  - Aim for the {target_label} target with feed, search, native detail, and optional app-link/outbound-web surfaces",
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
                "120s checkpoint: visit Search/Explore with a neutral query, Grok, Notifications, or Chat landing if available."
            ),
            180: (
                "180s checkpoint: finish with distinct X surfaces captured; compose/test-post and DM thread actions require a controlled test account."
            ),
        }
    if pkg == "com.instagram.android":
        return {
            60: (
                "60s checkpoint: if you are still only on the Instagram Home feed, move through Stories or Reels briefly, then return."
            ),
            120: (
                "120s checkpoint: visit Explore/Search with a neutral topic and open one native media/detail surface; avoid ad click-throughs unless intentional."
            ),
            180: (
                "180s checkpoint: capture Profile tabs and optional create-camera preview; back out before publishing, commenting, DM sending, or external web flows unless explicitly in scope."
            ),
        }
    if pkg == "com.pinterest":
        return {
            60: (
                "60s checkpoint: if you are still only on the Pinterest home feed, open one non-sponsored native pin/detail view briefly, then return."
            ),
            120: (
                "120s checkpoint: visit Pinterest Search with a neutral topic, scroll results, and open one non-promoted native result briefly; avoid Visit site unless outbound-web behavior is intentional."
            ),
            180: (
                "180s checkpoint: capture feed, search, native detail, and optional verified app-link/outbound-web behavior; avoid Save, Follow, Create, comments, messages, ads, and share targets."
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
