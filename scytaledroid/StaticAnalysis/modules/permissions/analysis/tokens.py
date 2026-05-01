"""Token helpers: protection parsing, scoring, and classification."""

from __future__ import annotations

from collections.abc import Sequence

_SPECIAL_ACCESS_TOKENS = frozenset({"appop", "preinstalled", "development"})

_SPECIAL_RISK_NORMAL_SHORTS = frozenset(
    {
        "SYSTEM_ALERT_WINDOW",
        "WRITE_SETTINGS",
        "PACKAGE_USAGE_STATS",
        "QUERY_ALL_PACKAGES",
        "BIND_ACCESSIBILITY_SERVICE",
        "BIND_NOTIFICATION_LISTENER_SERVICE",
        "REQUEST_INSTALL_PACKAGES",
        "REQUEST_DELETE_PACKAGES",
        "SCHEDULE_EXACT_ALARM",
        "MANAGE_OWN_CALLS",
    }
)
_NOTEWORTHY_NORMAL_SHORTS = frozenset(
    {
        "RECEIVE_BOOT_COMPLETED",
        "WAKE_LOCK",
        "FOREGROUND_SERVICE",
        "FOREGROUND_SERVICE_SPECIAL_USE",
        "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        "USE_FULL_SCREEN_INTENT",
        "ACCESS_NOTIFICATION_POLICY",
    }
)
_NOISY_CUSTOM_PREFIXES = (
    "com.android.launcher.permission.",
    "com.google.android.c2dm.permission.",
    "com.android.vending.",
)
_NOISY_CUSTOM_TOKENS = (
    "install_shortcut",
    "uninstall_shortcut",
    "badge",
    "billing",
    "ads",
    "ad_id",
    "advertising",
    "install_referrer",
    "push",
    "receive",
    ".provider.access",
    ".permission.create_shortcut",
)

_TOKEN_WEIGHTS = {
    "dangerous": 60,
    "signature": 80,
    "privileged": 70,
    "development": 40,
    "installer": 35,
    "appop": 45,
    "preinstalled": 30,
    "oem": 25,
}


def tokenise_protection(raw: object) -> set[str]:
    tokens: set[str] = set()
    if raw is None:
        return tokens
    if isinstance(raw, (list, tuple, set)):
        for entry in raw:
            tokens.update(tokenise_protection(entry))
        return tokens
    text = str(raw).lower()
    for delimiter in ("|", "/", ","):
        text = text.replace(delimiter, " ")
    for part in text.split():
        cleaned = part.strip()
        if cleaned:
            tokens.add(cleaned)
    return tokens


def normalize_tokens(detail_entry: Sequence[object]) -> tuple[str, ...]:
    if not detail_entry:
        return ("normal",)
    raw = detail_entry[0] if detail_entry else None
    tokens = tokenise_protection(raw)
    if not tokens:
        return ("normal",)
    return tuple(sorted(tokens))


def tokens_from_db(value: object | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    low = str(value).strip().lower()
    if not low:
        return None
    # Map DB protection to canonical token set
    if low in {"dangerous", "signature", "normal"}:
        return (low,)
    return None


def is_special_access(tokens: Sequence[str]) -> bool:
    return any(token in _SPECIAL_ACCESS_TOKENS for token in tokens)


def is_custom_permission(name: str) -> bool:
    return not str(name).startswith("android.permission.")


def score_tokens(tokens: Sequence[str], *, is_custom: bool) -> int:
    score = 0
    for token in tokens:
        score += _TOKEN_WEIGHTS.get(token, 0)
    if "signature" in tokens and "privileged" in tokens:
        score += 20
    if "dangerous" in tokens and "appop" in tokens:
        score += 15
    return score


def classify_flagged_normal(
    name: str,
    *,
    tokens: Sequence[str],
    severity: int,
    is_runtime_dangerous: bool,
    is_signature: bool,
    is_privileged: bool,
    is_special_access: bool,
    is_custom: bool,
) -> str | None:
    if is_runtime_dangerous or is_signature or is_privileged:
        return None

    normalized = str(name or "").strip()
    short = normalized.split(".")[-1].upper()
    lowered = normalized.lower()

    if is_special_access or short in _SPECIAL_RISK_NORMAL_SHORTS:
        return "special_risk_normal"
    if short in _NOTEWORTHY_NORMAL_SHORTS:
        return "noteworthy_normal"

    if normalized.startswith("android.permission."):
        if severity <= 0:
            return None
        return "noisy_normal"

    if lowered.startswith(_NOISY_CUSTOM_PREFIXES):
        return "noisy_normal"
    if any(token in lowered for token in _NOISY_CUSTOM_TOKENS):
        return "noisy_normal"
    if is_custom:
        return "noisy_normal"
    if severity <= 0:
        return None
    return "noisy_normal"


def is_scored_flagged_normal(flagged_normal_class: str | None) -> bool:
    return flagged_normal_class in {"noteworthy_normal", "special_risk_normal"}


__all__ = [
    "tokenise_protection",
    "normalize_tokens",
    "tokens_from_db",
    "is_special_access",
    "is_custom_permission",
    "score_tokens",
    "classify_flagged_normal",
    "is_scored_flagged_normal",
]
