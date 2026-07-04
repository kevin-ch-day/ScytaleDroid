"""Operator guidance for baseline-idle capture surfaces.

This module is intentionally UI-only. It explains how operators should stage
baseline-idle captures without changing quota math or classifier policy.
"""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package


def package_category_name(package_name: str) -> str:
    return str(category_for_package(str(package_name or "").strip()) or "").strip().lower()


def is_social_feed_package(package_name: str) -> bool:
    return package_category_name(package_name) == "social_feed"


def social_feed_stable_screen_guidance() -> str:
    return "profile, settings, bookmarks, lists, saved items, or a static detail page"


def x_baseline_tip_line() -> str:
    return (
        "  - X baseline tip: Home / For You often triggers media prefetch or video traffic; "
        "prefer profile, settings, bookmarks, lists, or another stable non-video screen"
    )


def baseline_idle_behavior_lines(package_name: str, *, target_label: str) -> list[str]:
    pkg = str(package_name or "").strip()
    category = package_category_name(pkg)
    if category == "social_feed":
        lines = [
            "  - Avoid Home / For You / feed timelines when possible",
            "  - Avoid video/media-heavy screens",
            f"  - Prefer a stable low-motion screen such as {social_feed_stable_screen_guidance()}",
            "  - Let initial loading settle before the timer starts",
            "  - Do not scroll, refresh, open media, type, search, or follow links",
            f"  - Stop near the {target_label} target; longer capture is optional evidence, not better quota evidence",
        ]
        if pkg.lower() == "com.twitter.android":
            lines.append(x_baseline_tip_line())
        return lines
    if category == "news_reader":
        return [
            "  - Get the app into a calm foreground surface before the timer starts",
            "  - Prefer a stable article or section over a live home/feed surface when possible",
            "  - Avoid autoplay video, podcasts/audio, search, sign-in, and support/paywall flows",
            "  - Best-effort idle after setup; interact only if needed (e.g., prevent screen lock)",
        ]
    return [
        "  - Get the app running, then leave it in the foreground",
        "  - Best-effort idle; interact only if needed (e.g., prevent screen lock)",
    ]


def baseline_idle_quota_warning(package_name: str, *, profile: str | None) -> str | None:
    profile_lc = str(profile or "").strip().lower()
    if not profile_lc.startswith("baseline"):
        return None
    if not is_social_feed_package(package_name):
        return None
    return (
        "Quota baseline requires quiet foreground behavior. Feed/media traffic can cause a valid run to be retained as non-idle instead of quota-counted."
    )


def baseline_idle_checkpoint_messages(package_name: str) -> dict[int, str]:
    pkg = str(package_name or "").strip() or "the target app"
    category = package_category_name(pkg)
    if category == "social_feed":
        return {
            60: (
                f"60s checkpoint: if {pkg} is still on Home / For You or another moving feed, "
                "switch once to a stable non-video screen, then go idle again."
            ),
            120: (
                f"120s checkpoint: keep {pkg} on a stable non-feed screen; avoid media, refresh, "
                "search, or scroll. Stop near the target unless you want supplemental evidence."
            ),
        }
    if category == "news_reader":
        return {
            60: (
                f"60s checkpoint: if {pkg} is still on a live home/feed surface, "
                "move once to a calm article or section, then go idle again."
            ),
            120: (
                f"120s checkpoint: keep {pkg} in the foreground; avoid autoplay video, "
                "podcasts/audio, search, sign-in, and support/paywall flows."
            ),
        }
    return {
        60: (
            f"60s checkpoint: keep {pkg} in the foreground; "
            "nudge only if needed to prevent screen lock."
        ),
        120: (
            f"120s checkpoint: keep {pkg} in the foreground; "
            "nudge only if needed to prevent screen lock."
        ),
    }


def baseline_not_idle_next_step(package_name: str | None) -> str:
    pkg = str(package_name or "").strip().lower()
    category = package_category_name(pkg)
    if category == "social_feed":
        if pkg == "com.twitter.android":
            return (
                "Retry on profile, settings, bookmarks, lists, or another stable non-feed/non-video X screen if quota progress is needed."
            )
        return "Retry on a stable non-feed/non-video screen if quota progress is needed."
    return "Repeat with stricter idle behavior if quota progress is needed."

