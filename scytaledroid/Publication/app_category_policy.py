"""Publication-facing app labels and primary-function taxonomy.

This policy is intentionally separate from DB app categories.  Database
categories are operational metadata; publication figures and tables need a
stable, low-cardinality taxonomy so repeated report generation does not
reintroduce one-off labels such as ``Social/content`` or ``Messaging/social``.
"""

from __future__ import annotations

from dataclasses import dataclass


TAXONOMY_VERSION = "integrated-primary-function-v1"

PUBLICATION_APP_ORDER = [
    "bbc.mobile.news.ww",
    "com.cnn.mobile.android.phone",
    "com.facebook.katana",
    "com.facebook.orca",
    "com.instagram.android",
    "com.linkedin.android",
    "com.pinterest",
    "com.reddit.frontpage",
    "org.thoughtcrime.securesms",
    "com.snapchat.android",
    "org.telegram.messenger",
    "com.guardian",
    "com.zhiliaoapp.musically",
    "com.whatsapp",
    "com.twitter.android",
]


@dataclass(frozen=True)
class AppCategoryPolicy:
    package_name: str
    app_display_name: str
    category: str
    primary_function: str
    assignment_rationale: str
    taxonomy_version: str = TAXONOMY_VERSION


APP_CATEGORY_POLICY: dict[str, AppCategoryPolicy] = {
    "bbc.mobile.news.ww": AppCategoryPolicy(
        "bbc.mobile.news.ww",
        "BBC News",
        "News",
        "news publishing",
        "Primary user-facing function is news consumption.",
    ),
    "com.cnn.mobile.android.phone": AppCategoryPolicy(
        "com.cnn.mobile.android.phone",
        "CNN",
        "News",
        "news publishing",
        "Primary user-facing function is news consumption.",
    ),
    "com.guardian": AppCategoryPolicy(
        "com.guardian",
        "The Guardian",
        "News",
        "news publishing",
        "Primary user-facing function is news consumption.",
    ),
    "com.facebook.katana": AppCategoryPolicy(
        "com.facebook.katana",
        "Facebook",
        "Social Media",
        "social networking and feed",
        "Primary user-facing function is social network feed and content interaction.",
    ),
    "com.instagram.android": AppCategoryPolicy(
        "com.instagram.android",
        "Instagram",
        "Social Media",
        "social media content sharing",
        "Primary user-facing function is social content sharing and feed interaction.",
    ),
    "com.linkedin.android": AppCategoryPolicy(
        "com.linkedin.android",
        "LinkedIn",
        "Professional Networking",
        "professional networking",
        "Primary user-facing function is professional networking rather than general social media.",
    ),
    "com.pinterest": AppCategoryPolicy(
        "com.pinterest",
        "Pinterest",
        "Social Media",
        "social content discovery",
        "Primary user-facing function is social content discovery and curation.",
    ),
    "com.reddit.frontpage": AppCategoryPolicy(
        "com.reddit.frontpage",
        "Reddit",
        "Social Media",
        "community discussion",
        "Primary user-facing function is community social discussion and content interaction.",
    ),
    "com.snapchat.android": AppCategoryPolicy(
        "com.snapchat.android",
        "Snapchat",
        "Social Media",
        "social media messaging and stories",
        "Classified by primary product function for this study; messaging features are not treated as a separate high-level category.",
    ),
    "com.twitter.android": AppCategoryPolicy(
        "com.twitter.android",
        "X",
        "Social Media",
        "microblogging and social feed",
        "Primary user-facing function is social feed and microblogging interaction.",
    ),
    "com.zhiliaoapp.musically": AppCategoryPolicy(
        "com.zhiliaoapp.musically",
        "TikTok",
        "Social Media",
        "short-form social video",
        "Primary user-facing function is social video creation and consumption.",
    ),
    "com.facebook.orca": AppCategoryPolicy(
        "com.facebook.orca",
        "Facebook Msg",
        "Messaging",
        "messaging",
        "Primary user-facing function is private messaging.",
    ),
    "com.whatsapp": AppCategoryPolicy(
        "com.whatsapp",
        "WhatsApp",
        "Messaging",
        "messaging",
        "Primary user-facing function is private messaging and calls.",
    ),
    "org.telegram.messenger": AppCategoryPolicy(
        "org.telegram.messenger",
        "Telegram",
        "Messaging",
        "messaging",
        "Primary user-facing function is private and group messaging.",
    ),
    "org.thoughtcrime.securesms": AppCategoryPolicy(
        "org.thoughtcrime.securesms",
        "Signal",
        "Messaging",
        "messaging",
        "Primary user-facing function is private messaging and calls.",
    ),
}

RETIRED_PUBLICATION_CATEGORY_LABELS = {
    "Messaging/social",
    "Professional social",
    "Social/content",
    "Social/video",
}


def app_display_name(package_name: str, fallback: str | None = None) -> str:
    policy = APP_CATEGORY_POLICY.get(package_name)
    return policy.app_display_name if policy else (fallback or package_name)


def app_category(package_name: str, fallback: str | None = None) -> str:
    policy = APP_CATEGORY_POLICY.get(package_name)
    return policy.category if policy else (fallback or "Consumer App")


def app_category_policy_rows() -> list[dict[str, str]]:
    return [
        {
            "app_display_name": item.app_display_name,
            "package_name": item.package_name,
            "category": item.category,
            "primary_function": item.primary_function,
            "assignment_rationale": item.assignment_rationale,
            "taxonomy_version": item.taxonomy_version,
        }
        for item in [APP_CATEGORY_POLICY[pkg] for pkg in PUBLICATION_APP_ORDER]
    ]


__all__ = [
    "APP_CATEGORY_POLICY",
    "PUBLICATION_APP_ORDER",
    "RETIRED_PUBLICATION_CATEGORY_LABELS",
    "TAXONOMY_VERSION",
    "app_category",
    "app_category_policy_rows",
    "app_display_name",
]
