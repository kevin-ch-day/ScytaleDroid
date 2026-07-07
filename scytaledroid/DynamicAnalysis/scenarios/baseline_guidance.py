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


def facebook_stable_screen_guidance() -> str:
    return "profile, Friends, Menu, Notifications, or another calm non-feed/non-reels/non-marketplace screen"


def linkedin_stable_screen_guidance() -> str:
    return "My Network, Jobs, profile, settings, or a static company/profile page"


def pinterest_stable_screen_guidance() -> str:
    return "profile, settings, saved items, a static board page, or another non-video/non-promoted surface"


def instagram_stable_screen_guidance() -> str:
    return "Settings and activity, Saved, Archive, or another calm non-feed/non-reels/non-story surface"


def guardian_stable_screen_guidance() -> str:
    return "My Guardian, Profile, Menu, or another calm non-article/non-podcast screen"


def bbc_stable_screen_guidance() -> str:
    return "the More tab, or a calm section tab such as News / Business / Technology after it settles"


def x_baseline_tip_line() -> str:
    return (
        "  - X baseline tip: Home / For You often triggers media prefetch or video traffic; "
        "prefer profile, settings, bookmarks, lists, or another stable non-video screen"
    )


def x_autoplay_tip_line() -> str:
    return (
        "  - If X video autoplay is enabled, switch it to Wi-Fi only or Never before strict idle quota attempts"
    )


def signal_connected_baseline_tip_line() -> str:
    return (
        "  - Signal baseline tip: a quiet foreground thread can produce very little traffic; "
        "do not force extra actions just to raise bytes or packets"
    )


def linkedin_baseline_tip_line() -> str:
    return (
        "  - LinkedIn baseline tip: Home and Video can keep refreshing posts, media, and messaging indicators; "
        "prefer My Network, Jobs, profile, settings, or a static company/profile page"
    )


def facebook_baseline_tip_line() -> str:
    return (
        "  - Facebook baseline tip: Home, Reels, Stories, and Marketplace can keep prefetching media, comments, "
        "and embedded content even when you stop touching the app; prefer profile, Friends, Menu, Notifications, or another calm screen"
    )


def facebook_launch_surface_tip_line() -> str:
    return (
        "  - If Facebook relaunches to Home, Reels, or Marketplace, switch once to profile, Friends, Menu, Notifications, "
        "or another calm in-app screen before the timer starts"
    )


def facebook_baseline_warning_line() -> str:
    return (
        "Quota baseline requires a calm Facebook foreground surface. Home feed, Reels, Stories, Marketplace, "
        "and embedded-browser/content flows can keep generating app-driven traffic even when the operator is hands-off."
    )


def linkedin_launch_surface_tip_line() -> str:
    return (
        "  - If LinkedIn launches to Home, switch once to My Network, Jobs, profile, settings, "
        "or a static company/profile page before the timer starts"
    )


def linkedin_baseline_warning_line() -> str:
    return (
        "Quota baseline requires a calm LinkedIn foreground surface. Home feed, Video, and active messaging surfaces can "
        "keep generating app-driven traffic even when the operator is hands-off."
    )


def pinterest_baseline_tip_line() -> str:
    return (
        "  - Pinterest baseline tip: Home can keep surfacing promoted pins, media cards, and video-capable content; "
        "prefer profile, saved items, a static board page, settings, or another calm non-feed screen"
    )


def pinterest_launch_surface_tip_line() -> str:
    return (
        "  - If Pinterest launches to Home, switch once to profile, saved items, a static board page, "
        "settings, or another non-video/non-promoted surface before the timer starts"
    )


def pinterest_baseline_warning_line() -> str:
    return (
        "Quota baseline requires a calm Pinterest foreground surface. Home feed, promoted pins, and video-capable pins can "
        "keep generating app-driven traffic even when the operator is hands-off."
    )


def instagram_baseline_tip_line() -> str:
    return (
        "  - Instagram baseline tip: Home, Stories, Reels, and autoplay post surfaces can keep pulling media, suggestions, "
        "and messaging indicators even when you stop touching the app; prefer Settings and activity, Saved, Archive, or another calm surface"
    )


def instagram_launch_surface_tip_line() -> str:
    return (
        "  - If Instagram relaunches to Home, switch once to Settings and activity, Saved, Archive, "
        "or another calm non-feed/non-reels/non-story surface before the timer starts"
    )


def instagram_baseline_warning_line() -> str:
    return (
        "Quota baseline requires a calm Instagram foreground surface. Home feed, Stories, Reels, profile-grid browsing, "
        "and autoplay post/video surfaces can keep generating app-driven traffic even when the operator is hands-off."
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
            lines.append(x_autoplay_tip_line())
        if pkg.lower() == "com.facebook.katana":
            lines[2] = f"  - Prefer a stable low-motion screen such as {facebook_stable_screen_guidance()}"
            lines.insert(3, facebook_launch_surface_tip_line())
            lines.append(facebook_baseline_tip_line())
        if pkg.lower() == "com.linkedin.android":
            lines[2] = f"  - Prefer a stable low-motion screen such as {linkedin_stable_screen_guidance()}"
            lines.insert(3, linkedin_launch_surface_tip_line())
            lines.append(linkedin_baseline_tip_line())
        if pkg.lower() == "com.pinterest":
            lines[2] = f"  - Prefer a stable low-motion screen such as {pinterest_stable_screen_guidance()}"
            lines.insert(3, pinterest_launch_surface_tip_line())
            lines.append(pinterest_baseline_tip_line())
        if pkg.lower() == "com.instagram.android":
            lines[2] = f"  - Prefer a stable low-motion screen such as {instagram_stable_screen_guidance()}"
            lines.insert(3, instagram_launch_surface_tip_line())
            lines.append(instagram_baseline_tip_line())
        return lines
    if category == "news_reader":
        if pkg.lower() == "bbc.mobile.news.ww":
            return [
                "  - Avoid the Home top-story rail when possible for strict idle baseline attempts",
                f"  - Prefer {bbc_stable_screen_guidance()}",
                "  - Avoid Video, Live, autoplay media, and Audio playback during quota baseline attempts",
                "  - Do not open articles, trigger sign-in / register prompts, search, or follow links during idle quota attempts",
                "  - If you need article-open, sign-in/register-wall, Video, Live, or Audio evidence, use manual/scripted interactive instead",
                f"  - Stop near the {target_label} target; longer capture is optional evidence, not better quota evidence",
            ]
        if pkg.lower() == "com.guardian":
            return [
                "  - Avoid Home and article-open flows for strict idle baseline attempts",
                f"  - Prefer {guardian_stable_screen_guidance()}",
                "  - Avoid Search, Support us, Follow, Podcasts playback, and sign-in / free-registration walls",
                "  - Do not scroll, open articles, trigger Follow/account-create flows, or start audio/video",
                "  - If you need section/search navigation, native podcast-playback, article-open, or registration-wall evidence, use manual/scripted interactive instead",
                f"  - Stop near the {target_label} target; longer capture is optional evidence, not better quota evidence",
            ]
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
    pkg = str(package_name or "").strip().lower()
    if pkg == "com.guardian":
        return (
            "Quota baseline requires a calm Guardian foreground surface. Home-feed scrolling, article opens, "
            "Follow actions, podcast playback, and sign-in / free-registration walls belong in interactive evidence, not strict idle quota."
        )
    if pkg == "bbc.mobile.news.ww":
        return (
            "Quota baseline requires a calm BBC foreground surface. Home top stories, Video, Live, Audio playback, "
            "and article-open / sign-in-register flows belong in interactive evidence, not strict idle quota."
        )
    if pkg == "com.linkedin.android":
        return linkedin_baseline_warning_line()
    if pkg == "com.facebook.katana":
        return facebook_baseline_warning_line()
    if pkg == "com.pinterest":
        return pinterest_baseline_warning_line()
    if pkg == "com.instagram.android":
        return instagram_baseline_warning_line()
    if not is_social_feed_package(package_name):
        return None
    return (
        "Quota baseline requires quiet foreground behavior. Feed/media traffic can cause a valid run to be retained as non-idle instead of quota-counted."
    )


def messaging_connected_behavior_lines(package_name: str) -> list[str]:
    pkg = str(package_name or "").strip().lower()
    lines = [
        "  - Keep the app in the foreground",
        "  - Open an existing conversation thread and keep it visible",
        "  - Every 45-75s, do one non-mutating check action (small scroll OR chat-list/thread switch)",
        "  - Perform exactly one refresh/check action around minute 2",
        "  - Do not type, send, call, upload media, search, or open external links",
    ]
    if pkg == "org.thoughtcrime.securesms":
        lines.append(signal_connected_baseline_tip_line())
    return lines


def baseline_idle_ready_note(package_name: str) -> str | None:
    pkg = str(package_name or "").strip().lower()
    if pkg == "com.linkedin.android":
        return (
            "LinkedIn often reopens on Home after relaunch. Before pressing Enter, switch once to "
            "My Network, Jobs, profile, settings, or a static company/profile page if Home is still selected."
        )
    if pkg == "com.facebook.katana":
        return (
            "Facebook often reopens on Home, Reels, or Marketplace after relaunch. Before pressing Enter, switch once to "
            "profile, Friends, Menu, Notifications, or another calm in-app screen if a moving feed or media surface is still selected."
        )
    if pkg == "com.pinterest":
        return (
            "Pinterest often reopens on Home after relaunch. Before pressing Enter, switch once to "
            "profile, saved items, a static board page, settings, or another non-video/non-promoted surface if Home is still selected."
        )
    if pkg == "com.instagram.android":
        return (
            "Instagram often reopens on Home after relaunch. Before pressing Enter, switch once to "
            "Settings and activity, Saved, Archive, or another calm non-feed/non-reels/non-story surface if Home is still selected."
        )
    return None


def baseline_idle_checkpoint_messages(package_name: str) -> dict[int, str]:
    pkg = str(package_name or "").strip() or "the target app"
    category = package_category_name(pkg)
    if category == "social_feed":
        if pkg == "com.facebook.katana":
            return {
                60: (
                    "60s checkpoint: if Facebook is still on Home, Reels, Stories, or Marketplace, switch once to "
                    "profile, Friends, Menu, Notifications, or another calm non-feed/non-video screen, then hold idle."
                ),
                120: (
                    "120s checkpoint: keep Facebook off feed/reels/story/media surfaces and embedded browser flows; "
                    "avoid comments, links, search, marketplace item opens, notifications opens, or switching back into discovery surfaces."
                ),
            }
        if pkg == "com.linkedin.android":
            return {
                60: (
                    "60s checkpoint: if LinkedIn is still on Home or Video, switch once to My Network, Jobs, "
                    "profile, settings, or a static company/profile page, then hold idle."
                ),
                120: (
                    "120s checkpoint: keep LinkedIn off Home feed/video refresh and messaging surfaces; avoid search, "
                    "post compose, opening media, or entering chat."
                ),
            }
        if pkg == "com.pinterest":
            return {
                60: (
                    "60s checkpoint: if Pinterest is still on Home, a promoted pin, or a video-capable pin surface, "
                    "switch once to profile, saved items, a static board page, settings, or another calm non-feed screen, then hold idle."
                ),
                120: (
                    "120s checkpoint: keep Pinterest off Home feed refresh, promoted pins, and video/media cards; "
                    "avoid search, opening pins, scrolling, or switching back into feed discovery."
                ),
            }
        if pkg == "com.instagram.android":
            return {
                60: (
                    "60s checkpoint: if Instagram is still on Home, Stories, Reels, or an autoplay post surface, "
                    "switch once to Settings and activity, Saved, Archive, or another calm non-feed screen, then hold idle."
                ),
                120: (
                    "120s checkpoint: keep Instagram off Home feed refresh, Stories, Reels, profile-grid browsing, and autoplay post/video surfaces; "
                    "avoid search, opening posts, scrolling, or switching back into discovery surfaces."
                ),
            }
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
        if pkg == "bbc.mobile.news.ww":
            return {
                60: (
                    "60s checkpoint: if BBC is still on the Home lead-story rail, switch once to More or a calm "
                    "section tab such as News / Business / Technology, then hold idle."
                ),
                120: (
                    "120s checkpoint: keep BBC off Video, Live, and Audio playback; avoid article opens and "
                    "sign-in/register prompts during idle quota attempts."
                ),
            }
        if pkg == "com.guardian":
            return {
                60: (
                    "60s checkpoint: if Guardian is still on Home or a live story rail, switch once to "
                    "My Guardian, Profile, or Menu, then hold idle."
                ),
                120: (
                    "120s checkpoint: keep Guardian on a calm non-article/non-podcast screen; avoid search, support, "
                    "Follow, podcast playback, article opens, and sign-in / free-registration walls."
                ),
            }
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
        if pkg == "com.facebook.katana":
            return (
                "Retry on profile, Friends, Menu, Notifications, or another calm non-feed/non-reels/non-marketplace Facebook screen if quota progress is needed."
            )
        if pkg == "com.linkedin.android":
            return (
                "Retry on My Network, Jobs, profile, settings, or a static company/profile page if quota progress is needed."
            )
        if pkg == "com.pinterest":
            return (
                "Retry on profile, saved items, a static board page, settings, or another non-video/non-promoted Pinterest screen if quota progress is needed."
            )
        if pkg == "com.instagram.android":
            return (
                "Retry on Settings and activity, Saved, Archive, or another calm non-feed/non-reels/non-story Instagram screen if quota progress is needed."
            )
        return "Retry on a stable non-feed/non-video screen if quota progress is needed."
    if pkg == "com.guardian":
        return (
            "Retry on My Guardian, Profile, Menu, or another calm non-article/non-podcast Guardian screen if quota progress is needed; "
            "use interactive mode for section/search navigation, native podcast playback, article-open, Follow/auth-gate, or registration-wall evidence."
        )
    if pkg == "bbc.mobile.news.ww":
        return (
            "Retry on BBC More or a calm section tab if quota progress is needed; use interactive mode for article-open, "
            "sign-in/register-wall, Video, Live, or Audio evidence."
        )
    return "Repeat with stricter idle behavior if quota progress is needed."
