"""Token helpers: protection parsing, scoring, and classification."""

from __future__ import annotations

from collections.abc import Sequence

from .curves import independent_risk_combine
from .name_patterns import is_background_sensitive_name, is_health_permission_name

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
    "signatureorsystem": 80,
    "signatureorinstaller": 80,
    "internal": 75,
    "privileged": 70,
    "development": 40,
    "installer": 35,
    "appop": 45,
    "preinstalled": 30,
    "oem": 25,
    "role": 25,
    "vendorprivileged": 40,
    "knownsigner": 35,
    "recents": 20,
    "module": 20,
    "verifier": 25,
    "setup": 15,
    "companion": 20,
    "instant": 8,
    "pre23": 5,
    "retaildemo": 8,
    "incidentreportapprover": 20,
    "system": 15,
    "runtime": 10,
    "configurator": 15,
}
_MAX_PERMISSION_SEVERITY = 255
_TOKEN_COMBINE_SCALE = 180
_HEALTH_NAME_FLOOR = 60
_GROUP_SCORE_BONUS = {
    "HEALTH": 15,
    "SENSORS": 10,
    "PHONE": 10,
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
    tokens = tuple(sorted(tokenise_protection(value)))
    return tokens or None


def is_special_access(tokens: Sequence[str]) -> bool:
    return any(token in _SPECIAL_ACCESS_TOKENS for token in tokens)


def is_custom_permission(name: str) -> bool:
    return not str(name).startswith("android.permission.")


def _canonical_group_short(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.lower().startswith("android.permission-group."):
        text = text.rsplit(".", 1)[-1]
    if text.upper() == "UNDEFINED":
        return None
    return text


def score_tokens(tokens: Sequence[str], *, is_custom: bool) -> int:
    return score_permission(tokens, is_custom=is_custom)


def score_permission(
    tokens: Sequence[str],
    *,
    is_custom: bool = False,
    name: str | None = None,
    permission_group: str | None = None,
    background_permission: str | None = None,
    authority_class: str | None = None,
    feature_dependency: str | None = None,
) -> int:
    """Score one permission from PI protection tokens plus catalog context.

    Protection modifiers and catalog context share one impact dimension, so
    they combine with the CVSS Impact Sub-Score (noisy-OR) identity rather
    than a linear sum that re-hits the 255 cap. Severity is still clipped at
    255 to match ``static_permission_matrix.severity``.
    """

    del is_custom
    token_set = {str(token).strip().lower() for token in tokens if token}
    impact_weights: list[float] = [
        float(_TOKEN_WEIGHTS[token]) for token in token_set if token in _TOKEN_WEIGHTS
    ]
    if is_health_permission_name(name) and (
        not impact_weights or max(impact_weights) < _HEALTH_NAME_FLOOR
    ):
        impact_weights.append(float(_HEALTH_NAME_FLOOR))
    if any(token.startswith("signature") for token in token_set) and "privileged" in token_set:
        impact_weights.append(20.0)
    if "dangerous" in token_set and "appop" in token_set:
        impact_weights.append(15.0)
    if "signature" in token_set and "role" in token_set:
        impact_weights.append(10.0)
    if "internal" in token_set and "appop" in token_set:
        impact_weights.append(10.0)
    if str(background_permission or "").strip():
        impact_weights.append(20.0)
    if is_background_sensitive_name(name):
        impact_weights.append(25.0)
    group = _canonical_group_short(permission_group)
    if group:
        group_bonus = _GROUP_SCORE_BONUS.get(group.upper(), 0)
        if group_bonus:
            impact_weights.append(float(group_bonus))
    elif is_health_permission_name(name):
        impact_weights.append(float(_GROUP_SCORE_BONUS["HEALTH"]))
    if str(authority_class or "").strip().upper() == "AOSP_INTERNAL":
        impact_weights.append(8.0)
    if str(feature_dependency or "").strip():
        impact_weights.append(4.0)
    score = independent_risk_combine(impact_weights, scale=float(_TOKEN_COMBINE_SCALE))
    return min(_MAX_PERMISSION_SEVERITY, int(round(score)))


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
    if any(str(token).lower() == "internal" for token in tokens):
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
    "score_permission",
    "classify_flagged_normal",
    "is_scored_flagged_normal",
]
