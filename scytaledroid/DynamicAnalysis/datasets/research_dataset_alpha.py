"""Canonical Research Dataset Alpha definition.

This module provides a DB-free fallback for dataset orchestration.
The DB can be used as a derived index (labels/profiles), but dataset capture
must remain usable even if DB schema/persistence is unavailable.
"""

from __future__ import annotations

from collections.abc import Sequence

PROFILE_KEY = "RESEARCH_DATASET_ALPHA"

# Canonical 12-app cohort definition used by the operational dataset flow.
CANONICAL_PACKAGES: tuple[str, ...] = (
    "com.zhiliaoapp.musically",  # TikTok
    "com.facebook.katana",  # Facebook
    "com.facebook.orca",  # Facebook Messenger
    "com.instagram.android",  # Instagram
    "com.linkedin.android",  # LinkedIn
    "com.pinterest",  # Pinterest
    "com.reddit.frontpage",  # Reddit
    "com.snapchat.android",  # Snapchat
    "com.twitter.android",  # X
    "com.whatsapp",  # WhatsApp
    "org.telegram.messenger",  # Telegram
    "org.thoughtcrime.securesms",  # Signal
)

# Messaging apps where operator activity type (text vs voice/video) is a meaningful
# stratification tag for network behavior.
MESSAGING_PACKAGES: tuple[str, ...] = (
    "com.facebook.orca",  # Facebook Messenger
    "com.whatsapp",  # WhatsApp
    "org.telegram.messenger",  # Telegram
    "org.thoughtcrime.securesms",  # Signal
)


def load_dataset_packages() -> Sequence[str]:
    """Prefer DB profile mapping; fall back to the canonical list if unavailable."""
    try:
        from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages

        pkgs = load_profile_packages(PROFILE_KEY)
        pkgs = [p for p in pkgs if isinstance(p, str) and p.strip()]
        return pkgs or list(CANONICAL_PACKAGES)
    except Exception:
        return list(CANONICAL_PACKAGES)


__all__ = ["PROFILE_KEY", "CANONICAL_PACKAGES", "MESSAGING_PACKAGES", "load_dataset_packages"]
