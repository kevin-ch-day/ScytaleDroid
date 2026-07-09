"""Foreground-surface probes for live dynamic capture.

This is a read-model helper only. It improves operator visibility and event
logging for apps whose meaningful states are multiplexed inside one activity.
"""

from __future__ import annotations

import html
import re
from collections.abc import Sequence

from scytaledroid.DeviceAnalysis.adb import shell as adb_shell

_UI_TEXT_RE = re.compile(r'(?:text|content-desc)="([^"]+)"')


def _normalize_component(component_name: str | None) -> str:
    return str(component_name or "").strip().lower()


def _extract_ui_strings(xml_text: str) -> list[str]:
    values: list[str] = []
    for match in _UI_TEXT_RE.finditer(str(xml_text or "")):
        value = html.unescape(str(match.group(1) or "").strip())
        if value:
            values.append(value)
    return values


def _read_ui_strings(device_serial: str) -> list[str]:
    adb_shell.run_shell(
        device_serial,
        ["uiautomator", "dump", "/sdcard/uidump.xml"],
        timeout=8.0,
    )
    xml_text = adb_shell.run_shell(
        device_serial,
        ["cat", "/sdcard/uidump.xml"],
        timeout=8.0,
    )
    return _extract_ui_strings(xml_text)


def _contains_any(values: Sequence[str], *needles: str) -> bool:
    haystack = "\n".join(str(value or "").lower() for value in values)
    return any(str(needle or "").lower() in haystack for needle in needles)


def infer_guardian_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "com.guardian":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "feature.search.searchactivity" in component:
        return ("search_results", "in-app search")

    if "feature.renderedarticle.newarticleactivity" in component:
        if _contains_any(
            strings,
            "you now need to sign in",
            "register for free",
            "learn about registering with the guardian",
        ):
            return ("article_auth_wall", "registration / sign-in wall")
        return ("article_render", "article activity")

    if "homeactivity" not in component and "newhomeactivity" not in component:
        return (None, None)

    if _contains_any(strings, "Support the Guardian", "Support us now", "I already support the Guardian"):
        return ("support_paywall", "support / subscription wall")
    if _contains_any(strings, "Guardian sections", "Settings", "US news", "World news", "Discover", "Live"):
        return ("menu_sections", "sections / settings menu")
    if _contains_any(strings, "Captivating listening", "Video podcast", "Discover episodes and series"):
        return ("podcasts", "podcast discovery")
    if _contains_any(
        strings,
        "Explore categories and choose topics you care about to personalise My Guardian.",
        "Following",
        "Saved",
        "History",
    ):
        return ("my_guardian", "personalized guardian lane")
    if _contains_any(strings, "Support us", "Search", "Sign in", "The Guardian"):
        return ("home_feed", "front page feed")
    return ("homeactivity_unknown", "guardian homeactivity state")


def infer_bbc_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "bbc.mobile.news.ww":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "mainactivity" not in component:
        return (None, None)

    if _contains_any(strings, "settings", "text size", "theme", "privacy", "sign out"):
        return ("settings", "bbc settings")

    if _contains_any(strings, "bbc verify") and _contains_any(
        strings,
        "these taylor swift wedding pictures are not real",
        "more on this story.",
        "artificial intelligence",
    ):
        return ("verify_article_detail", "bbc verify article detail")

    if _contains_any(strings, "bbc verify") and _contains_any(
        strings,
        "iran nuclear and military damage revealed after restricted satellite images released",
        "is this golden eagle on the white house real?",
        "these taylor swift wedding pictures are not real",
    ):
        return ("verify_feed", "bbc verify editorial feed")

    if _contains_any(strings, "more bbc", "saved items", "search for news, topics and more", "bbc verify"):
        return ("more_menu", "more / sections hub")

    if _contains_any(strings, "audio", "podcast categories", "radio stations", "audio faqs"):
        if _contains_any(
            strings,
            "the global story: is the american century over? your questions answered",
            "the global story",
        ):
            return ("audio_hub_with_miniplayer", "audio hub with active miniplayer")
        return ("audio_hub", "audio hub")

    if _contains_any(strings, "save", "follow", "download", "available for over a year") and _contains_any(
        strings,
        "the global story",
        "is the american century over? your questions answered",
    ):
        return ("podcast_detail", "podcast episode detail")

    if _contains_any(strings, "video", "explore more"):
        if _contains_any(strings, "player"):
            return ("video_player", "video feed with inline player")
        return ("video_feed", "video feed")

    if _contains_any(strings, "home", "news", "world cup", "business", "technology", "index-page-flatlist"):
        if _contains_any(
            strings,
            "trump confirms he asked fifa to review balogun ban",
            "ronaldo starts for portugal against spain in last 16",
        ):
            return ("home_feed", "bbc home / top stories")
        return ("home_feed", "bbc section feed")

    return ("mainactivity_unknown", "bbc mainactivity state")


def infer_x_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "com.twitter.android":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "search.implementation.results.searchactivity" in component:
        if _contains_any(strings, "Top", "Latest", "People", "Media", "Lists", "Search X"):
            return ("search_results", "search results")
        return ("search_results", "search activity")

    if "tweetdetail.tweetdetailactivity" in component:
        if _contains_any(strings, "Most relevant replies", "Post your reply", "Discover more"):
            return ("tweet_detail", "post detail / replies")
        return ("tweet_detail", "post detail")

    if "profiles.profileactivity" in component:
        if _contains_any(strings, "Posts", "Replies", "Highlights", "Media", "Followers", "Following"):
            return ("profile_surface", "profile timeline")
        return ("profile_surface", "profile activity")

    if "main.mainactivity" not in component:
        return (None, None)

    if _contains_any(strings, "Go Live", "Spaces", "Photos") and _contains_any(strings, "New post", "Post"):
        return ("compose_actions", "composer radial actions")

    if _contains_any(strings, "Posts", "Replies", "Highlights", "Media") and _contains_any(
        strings,
        "Followers",
        "Following",
        "Profile image",
    ):
        return ("profile_surface", "profile timeline hosted in mainactivity")

    if _contains_any(strings, "Search and Explore") and _contains_any(
        strings,
        "Trending",
        "News",
        "Sports",
        "Entertainment",
        "Trending in United States",
        "Posts For You",
        "Trend options",
    ):
        return ("explore_surface", "search and explore / trends")

    if _contains_any(strings, "Home timeline list", "For you", "Following", "New post"):
        return ("home_feed", "home timeline")

    return ("mainactivity_unknown", "x mainactivity state")


def infer_instagram_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "com.instagram.android":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "maintabactivity" not in component:
        return (None, None)

    if _contains_any(strings, "Settings and activity", "Accounts Center", "Your activity", "Time management"):
        return ("settings_activity", "instagram settings and activity")

    if _contains_any(strings, "Saved", "All Posts", "Collections") and _contains_any(strings, "Back"):
        return ("saved_items", "instagram saved items")

    if _contains_any(strings, "Archive", "Stories archive", "Posts archive"):
        return ("archive_surface", "instagram archive")

    if _contains_any(strings, "Your profile", "Posts", "followers", "following") and _contains_any(
        strings,
        "Edit profile",
        "Share profile",
        "Professional dashboard",
        "gremlinthazhath",
        "Profile",
    ):
        return ("profile_surface", "instagram profile")

    if _contains_any(strings, "Instagram Home Feed", "Home", "Reels", "Search and explore") and _contains_any(
        strings,
        "Turn sound off",
        "Suggested for you",
        "More actions for this post",
        "Original audio",
        "reels tray container",
    ):
        return ("home_feed", "instagram home feed")

    if _contains_any(strings, "Message", "Write a message", "Chats") and _contains_any(strings, "Search", "General"):
        return ("direct_inbox", "instagram direct inbox")

    return ("maintabactivity_unknown", "instagram main tab state")


def infer_messenger_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "com.facebook.orca":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "messaging.rtc.incall.activity.incallactivity" in component:
        if _contains_any(strings, "end-to-end encrypted call with") and _contains_any(strings, "end", "mute microphone"):
            if _contains_any(
                strings,
                "showing front camera",
                "showing back camera",
                "effects",
                "turn camera off",
            ):
                return ("rtc_call_video_surface", "messenger rtc video call surface")
            if _contains_any(strings, "turn camera on", "turn speaker on", "speaker on"):
                return ("rtc_call_audio_surface", "messenger rtc audio call surface")
            return ("rtc_call_surface", "messenger rtc call surface")
        return ("rtc_call_surface", "messenger rtc call surface")

    if "messenger.neue.mainactivity" in component or component.endswith(".auth.startscreenactivity"):
        if _contains_any(strings, "chats", "calls", "stories", "meta ai"):
            return ("inbox_surface", "messenger inbox / tabs")
        if _contains_any(strings, "write a message", "audio call", "video call", "type a message", "send"):
            return ("thread_surface", "messenger conversation thread")
        return ("mainactivity_unknown", "messenger main activity state")

    return (None, None)


def infer_signal_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "org.thoughtcrime.securesms":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "components.webrtc.v2.webrtccallactivity" in component:
        if _contains_any(strings, "turn camera off", "flip camera", "showing front camera", "video"):
            return ("webrtc_video_call_surface", "signal webrtc video call surface")
        if _contains_any(strings, "turn camera on", "speaker"):
            return ("webrtc_voice_call_surface", "signal webrtc voice call surface")
        return ("webrtc_call_surface", "signal webrtc call surface")

    if component.endswith(".routingactivity"):
        return ("routing_activity", "signal routing activity")

    if "conversation" in component or "conversationactivity" in component:
        return ("conversation_surface", "signal conversation surface")

    if "mainactivity" in component:
        return ("main_activity", "signal main activity")

    return (None, None)


def infer_telegram_surface(
    *,
    package_name: str | None,
    component_name: str | None,
    ui_strings: Sequence[str] | None = None,
) -> tuple[str | None, str | None]:
    if str(package_name or "").strip().lower() != "org.telegram.messenger":
        return (None, None)
    component = _normalize_component(component_name)
    strings = list(ui_strings or [])

    if "defaulticon" not in component and "launchactivity" not in component and "telegramactivity" not in component:
        return (None, None)

    if _contains_any(strings, "telegram video call"):
        return ("telegram_video_call_surface", "telegram video call surface")

    if _contains_any(strings, "telegram call", "encryption key of this call") and _contains_any(
        strings,
        "end call",
        "mute",
    ):
        if _contains_any(strings, "stop video", "flip camera", "camera off"):
            return ("telegram_video_call_surface", "telegram video call surface")
        if _contains_any(strings, "start video", "speaker"):
            return ("telegram_voice_call_surface", "telegram voice call surface")
        return ("telegram_call_surface", "telegram call surface")

    if _contains_any(strings, "chats", "contacts", "settings") and _contains_any(strings, "telegram"):
        return ("telegram_main_surface", "telegram main surface")

    return (None, None)


def infer_runtime_surface(
    *,
    expected_package: str | None,
    foreground_package: str | None,
    foreground_component: str | None,
    device_serial: str | None,
) -> tuple[str | None, str | None]:
    expected = str(expected_package or "").strip().lower()
    actual = str(foreground_package or "").strip().lower()
    component = _normalize_component(foreground_component)
    serial = str(device_serial or "").strip()

    supported = {
        "bbc.mobile.news.ww",
        "com.facebook.orca",
        "com.guardian",
        "com.instagram.android",
        "com.twitter.android",
        "org.telegram.messenger",
        "org.thoughtcrime.securesms",
    }
    if expected not in supported:
        return (None, None)

    if expected == "org.telegram.messenger" and actual == "org.telegram.messenger":
        strings = _read_ui_strings(serial) if serial else []
        return infer_telegram_surface(
            package_name=actual,
            component_name=component,
            ui_strings=strings,
        )

    if expected == "org.thoughtcrime.securesms" and actual == "org.thoughtcrime.securesms":
        strings = _read_ui_strings(serial) if serial else []
        return infer_signal_surface(
            package_name=actual,
            component_name=component,
            ui_strings=strings,
        )

    if expected == "com.facebook.orca" and actual == "com.facebook.orca":
        strings = _read_ui_strings(serial) if serial else []
        return infer_messenger_surface(
            package_name=actual,
            component_name=component,
            ui_strings=strings,
        )

    if expected == "com.instagram.android" and actual == "com.instagram.android":
        strings = _read_ui_strings(serial) if serial else []
        return infer_instagram_surface(
            package_name=actual,
            component_name=component,
            ui_strings=strings,
        )

    if expected != "com.guardian":
        if expected != "com.twitter.android":
            if expected != "bbc.mobile.news.ww":
                if expected != "com.instagram.android":
                    if expected != "org.thoughtcrime.securesms":
                        return (None, None)

    if expected == "com.instagram.android" and actual == "com.android.chrome":
        if "customtabs.customtabactivity" in component:
            return ("external_custom_tab", "browser-backed instagram flow")
        return (None, None)

    if expected == "bbc.mobile.news.ww" and actual == "bbc.mobile.news.ww":
        strings = _read_ui_strings(serial) if serial else []
        return infer_bbc_surface(
            package_name=actual,
            component_name=component,
            ui_strings=strings,
        )

    if expected != "com.guardian":
        if expected != "com.twitter.android":
            return (None, None)

    if expected == "com.twitter.android" and actual == "com.twitter.android":
        strings = _read_ui_strings(serial) if serial else []
        return infer_x_surface(
            package_name=actual,
            component_name=component,
            ui_strings=strings,
        )

    if expected == "com.twitter.android" and actual == "com.android.chrome":
        if "customtabs.customtabactivity" in component:
            return ("external_custom_tab", "browser-backed x flow")
        return (None, None)

    if actual == "com.guardian":
        if "feature.search.searchactivity" in component:
            return ("search_results", "in-app search")
        if "feature.renderedarticle.newarticleactivity" in component:
            strings = _read_ui_strings(serial) if serial else []
            return infer_guardian_surface(
                package_name=actual,
                component_name=component,
                ui_strings=strings,
            )
        if "homeactivity" in component or "newhomeactivity" in component:
            strings = _read_ui_strings(serial) if serial else []
            return infer_guardian_surface(
                package_name=actual,
                component_name=component,
                ui_strings=strings,
            )

    if actual == "com.android.chrome" and "customtabs.customtabactivity" in component:
        strings = _read_ui_strings(serial) if serial else []
        if _contains_any(strings, "profile.theguardian.com"):
            return ("external_auth_custom_tab", "guardian sign-in browser flow")
        return ("external_custom_tab", "browser-backed guardian flow")

    return (None, None)


__all__ = [
    "infer_bbc_surface",
    "infer_guardian_surface",
    "infer_instagram_surface",
    "infer_messenger_surface",
    "infer_runtime_surface",
    "infer_signal_surface",
    "infer_telegram_surface",
    "infer_x_surface",
]
