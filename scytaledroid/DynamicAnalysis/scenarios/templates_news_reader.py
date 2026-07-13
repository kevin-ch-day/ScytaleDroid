"""News-reader scripted templates and reproducibility tips."""

from __future__ import annotations

SCRIPT_STEPS_NEWS_READER_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open the app and wait on the main/home feed.", 30),
    ("scroll_headlines", "Slowly scroll the main headline/feed list.", 45),
    (
        "open_article",
        "Open one free article if available; if a paywall/subscription wall appears, stay on that screen and mark the step limited.",
        45,
    ),
    (
        "scroll_article",
        "Scroll the visible article content; if article content is blocked by a paywall, mark the step limited and continue.",
        45,
    ),
    ("return_home", "Return to the home/feed screen.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 55),
)

SCRIPT_STEPS_NEWS_READER_BEHAVIOR_V2: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open the app and wait on the main/home feed.", 30),
    ("scroll_headlines", "Slowly scroll the headline/feed list.", 45),
    (
        "open_article",
        "Open one article. If it opens, hold briefly. If subscription wall appears, mark subscription_required.",
        30,
    ),
    ("article_scroll", "Article-opened branch: scroll visible article content.", 45),
    ("article_return_home", "Article-opened branch: return Home and hold briefly.", 15),
    ("subscription_wall_observe", "Subscription branch: observe subscription wall.", 30),
    ("subscription_options_observe", "Subscription branch: open subscription options, hold, then return.", 30),
    ("subscription_return_home", "Subscription branch: return Home and hold briefly.", 15),
    (
        "video_or_media_optional",
        "Optional: open a visible video, Shorts, Watch, Audio, or podcast surface, watch/hold briefly, then return Home. Avoid external share, sign-in, or payment flows.",
        30,
    ),
    ("final_hold", "Remain on the main feed until target duration completes.", 0),
)

SCRIPT_STEPS_BBC_NEWS_BEHAVIOR_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open BBC News and let the opening feed settle.", 30),
    (
        "open_calm_section",
        "Move once to a calmer BBC surface if needed, such as News, Business, Technology, or More. Avoid Video, Live, and Audio playback.",
        30,
    ),
    (
        "open_article",
        "Open one text article if available. If a sign-in or register prompt appears, mark the step limited and stay on that screen briefly.",
        35,
    ),
    (
        "article_scroll_or_gate_observe",
        "If the article opened, scroll visible article text. If a sign-in/register wall appeared, observe it briefly and mark limited.",
        40,
    ),
    (
        "return_to_section",
        "Return to the prior calm section or More screen. Avoid switching into Video, Live, or Audio playback.",
        20,
    ),
    (
        "optional_static_nav_check",
        "Optional: briefly open another calm BBC section tab (for example Business or Technology), then stop interacting.",
        20,
    ),
    ("final_hold", "Remain on a calm BBC foreground surface until the target duration completes.", 0),
)

SCRIPT_STEPS_GUARDIAN_BEHAVIOR_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open Guardian and let the opening feed settle briefly.", 25),
    (
        "open_native_navigation",
        "Open Search or Menu and move into a native Guardian section/subject surface such as Politics, World news, or another section page. Prefer native section navigation over opening headline cards.",
        35,
    ),
    (
        "scroll_section",
        "Slowly scroll the native section/search results screen. Keep the interaction inside Guardian and avoid article-open if section navigation is enough for this run.",
        40,
    ),
    (
        "play_native_podcast_card",
        "If a visible in-card podcast play control is present, start native podcast playback briefly and hold on the same Guardian screen. If no playable card is visible, mark limited.",
        35,
    ),
    (
        "observe_gate_branch",
        "Optional auth-gate branch: open one article or Follow action only if you intentionally want gated evidence. If sign-in, free registration, or account-create wall appears, observe briefly and mark login_required.",
        35,
    ),
    (
        "return_to_native_section",
        "Return to the native section/search screen after any gated branch. Keep the app on a Guardian-owned foreground surface rather than leaving it in a browser/custom-tab.",
        20,
    ),
    ("final_hold", "Remain on the native Guardian section/search surface until the target duration completes.", 0),
)

V3_SCRIPTED_REPRO_TIPS_NEWS: dict[str, tuple[str, ...]] = {
    "news_reader_basic_v1": (
        "Use the public home/feed surface only; avoid login, comments, or sharing.",
        "Open one article, scroll slowly, then return to the home/feed screen. If a paywall/subscription wall appears, mark the affected step limited rather than skipping.",
    ),
    "news_reader_behavior_v2": (
        "Use public/home feed surfaces; avoid login, comments, or sharing.",
        "If an article is blocked by subscription/login, follow the matching branch instead of scrolling blocked content.",
        "Subscription walls are useful runtime phases; observe them rather than treating them as failed article reads.",
        "CNN-like apps may expose separate Shorts, Watch, Audio, podcast, or interactive surfaces; record gated previews and subscription-required states as media/subscription phases rather than failures.",
    ),
    "bbc_news_behavior_v1": (
        "Prefer calm BBC section surfaces such as News, Business, Technology, or More; avoid Video, Live, and Audio playback unless media behavior is the goal.",
        "If BBC presents a sign-in or free-registration prompt after opening an article, mark the step limited and observe the gate rather than forcing more navigation.",
        "Use the scripted BBC flow when you want article-open or register-wall evidence; use BBC idle baseline guidance when you need strict quota baseline behavior.",
    ),
    "guardian_behavior_v1": (
        "Guardian has a split interaction graph: native section/search navigation and in-card podcast playback can stay inside the app, while article opens and Follow can route into sign-in or account-create gates.",
        "Prefer native section/subject navigation for reproducible interactive evidence. Use article-open or Follow only when you intentionally want auth-gated branch evidence.",
        "If a Guardian action launches a browser/custom-tab sign-in flow, observe it briefly if useful, then return to a native Guardian surface rather than letting the run sit off-surface.",
    ),
}

__all__ = [
    "SCRIPT_STEPS_BBC_NEWS_BEHAVIOR_V1",
    "SCRIPT_STEPS_GUARDIAN_BEHAVIOR_V1",
    "SCRIPT_STEPS_NEWS_READER_BASIC_V1",
    "SCRIPT_STEPS_NEWS_READER_BEHAVIOR_V2",
    "V3_SCRIPTED_REPRO_TIPS_NEWS",
]
