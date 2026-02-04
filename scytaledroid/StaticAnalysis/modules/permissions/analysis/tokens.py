"""Token helpers: protection parsing, scoring, and classification."""

from __future__ import annotations

from collections.abc import Sequence

_SPECIAL_ACCESS_TOKENS = frozenset({"appop", "preinstalled", "development"})

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
    if is_custom:
        score += 25
    return score


__all__ = [
    "tokenise_protection",
    "normalize_tokens",
    "tokens_from_db",
    "is_special_access",
    "is_custom_permission",
    "score_tokens",
]