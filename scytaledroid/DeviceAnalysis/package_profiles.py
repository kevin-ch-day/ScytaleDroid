"""package_profiles.py - Heuristics for categorising Android packages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class PackageProfile:
    """Represent a family of applications with analysis guidance."""

    id: str
    name: str
    matchers: Iterable[str]
    description: str
    artifacts: Iterable[str]
    pull_strategy: Iterable[str]


PROFILES: List[PackageProfile] = [
    PackageProfile(
        id="social",
        name="Social",
        matchers=(
            "com.facebook.",
            "com.instagram.",
            "com.snapchat.",
            "com.twitter.",
            "com.reddit.",
            "com.tiktok.",
            "com.whatsapp",
            "com.linkedin.",
        ),
        description=(
            "High-profile social media clients with heavy background connectivity, "
            "media capture, analytics SDKs, and dynamic modules."
        ),
        artifacts=(
            "/data/data/<pkg>/databases/ for tokens, drafts, cached timelines",
            "/sdcard/Android/data/<pkg>/ for media caches and downloads",
            "Embedded WebView storage (cookies/local storage) containing session traces",
        ),
        pull_strategy=(
            "Use `pm path` and pull every APK split from the /data/app token directory.",
            "Capture external OBB or cache folders when present (stories, reels, offline media).",
            "If rooted/debuggable, tar private storage for session tokens and drafts.",
        ),
    ),
    PackageProfile(
        id="messaging",
        name="Messaging / Comms",
        matchers=(
            "com.whatsapp",
            "org.telegram.messenger",
            "com.google.android.apps.messaging",
            "com.facebook.orca",
            "com.snapchat.android",
            "com.discord",
            "com.signal",
        ),
        description=(
            "Real-time messaging clients with encrypted stores, attachment caches, and push receivers."
        ),
        artifacts=(
            "Conversation databases (e.g., msgstore.db) in /data/data/<pkg>/databases/",
            "Media folders such as /sdcard/WhatsApp/Media/ or /sdcard/Android/data/<pkg>/files/",
            "Backup metadata and crypt keys (root required).",
        ),
        pull_strategy=(
            "Pull all APK splits; messaging apps are almost always modularised.",
            "Harvest external media directories for forensic evidence.",
            "For message stores, require root or run-as; document presence of backups if inaccessible.",
        ),
    ),
    PackageProfile(
        id="finance",
        name="Finance",
        matchers=(
            "com.paypal",
            "com.chase",
            "com.bankofamerica",
            "com.wf.wellsfargomobile",
            "com.citi",
            "com.usbank",
            "com.americanexpress",
        ),
        description=(
            "Banking and payment clients with strong protections, heavy obfuscation, and strict policies."
        ),
        artifacts=(
            "Encrypted SQLite databases and preference stores inside /data/data/<pkg>/",
            "Hardware-backed keystore entries (non-extractable without instrumentation)",
            "Crash logs or analytics traces indicating certificate pinning failures.",
        ),
        pull_strategy=(
            "Pull APK(s) and extract manifest for exported components, debuggable, and crypto usage.",
            "Expect native libs (libcrypto, libssl). Verify signature fingerprints.",
            "Runtime secrets typically require rooted device or instrumentation harness.",
        ),
    ),
    PackageProfile(
        id="shopping",
        name="Shopping",
        matchers=(
            "com.amazon.",
            "com.einnovation.temu",
            "com.alibaba.",
            "com.ebay.",
            "com.target.",
            "com.walmart.",
        ),
        description=(
            "E-commerce clients with product feeds, payment integrations, deep links, and heavy SDK usage."
        ),
        artifacts=(
            "Cart state and receipts in app storage or embedded WebView caches.",
            "External image/cache directories under /sdcard/Android/data/<pkg>/cache/",
            "OEM preload managers (e.g., Amazon AppManager) stored under /product/priv-app/",
        ),
        pull_strategy=(
            "Pull APK splits and any OEM preload components for integration analysis.",
            "Inspect WebView cache/cookies where permitted for session traces.",
            "Document analytics SDKs and trackers discovered in manifest/lib/assets.",
        ),
    ),
]


def lookup_profile(package_name: str) -> Optional[PackageProfile]:
    """Return the first matching profile for the package, if any."""
    package_name = package_name.lower()
    for profile in PROFILES:
        for matcher in profile.matchers:
            matcher = matcher.lower()
            if matcher.endswith("*"):
                if package_name.startswith(matcher[:-1]):
                    return profile
            elif matcher.endswith("."):
                if package_name.startswith(matcher):
                    return profile
            else:
                if package_name.startswith(matcher):
                    return profile
    return None
