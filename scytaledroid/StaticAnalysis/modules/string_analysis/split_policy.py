"""Split-aware gating helpers for expensive string-analysis stages."""

from __future__ import annotations

from collections.abc import Mapping

from .indexing.models import IndexedString
from .origins import canonical_origin_type

_DIRECT_SECRET_PREFIXES: tuple[str, ...] = (
    "akia",
    "asia",
    "aiza",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "glpat-",
    "sk_live_",
    "rk_live_",
    "pk_live_",
    "sq0atp-",
    "sq0csp-",
    "sq0idp-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
)
_STRONG_SIGNAL_TOKENS: tuple[str, ...] = (
    "authorization",
    "bearer",
    "x-api-key",
    "api_key",
    "apikey",
    "client_secret",
    "clientid",
    "client_id",
    "oauth",
    "refresh_token",
    "id_token",
    "access_token",
    "secretkeyspec",
    "javax.crypto",
    "cipher.getinstance",
    "keystore",
    "private key",
    "aws_access_key",
    "aws_secret",
    "google_api_key",
    "firebase",
    "stripe",
    "github",
    "twilio",
    "webhook",
    "jwt",
    "token",
    "signin",
)


def _contains_secret_prefix_fragment(value: str, prefix: str) -> bool:
    start = 0
    while True:
        index = value.find(prefix, start)
        if index < 0:
            return False
        before_ok = index == 0 or not value[index - 1].isalnum()
        after_index = index + len(prefix)
        after_ok = after_index >= len(value) or not value[after_index].isalnum()
        if before_ok and after_ok:
            return True
        start = index + 1


def is_split_member_context(artifact_context: Mapping[str, object] | None) -> bool:
    """Return whether *artifact_context* represents a split-member artifact."""

    return bool(artifact_context and artifact_context.get("is_split_member"))


def has_strong_secret_signal(entry: IndexedString) -> bool:
    """Return whether *entry* carries direct secret-like or auth-like context."""

    value = str(entry.value or "").strip()
    if not value:
        return False

    lowered_value = value.lower()
    if any(
        lowered_value.startswith(prefix)
        or _contains_secret_prefix_fragment(lowered_value, prefix)
        for prefix in _DIRECT_SECRET_PREFIXES
    ):
        return True
    if "-----begin " in lowered_value and " private key-----" in lowered_value:
        return True

    combined = " ".join(
        part
        for part in (
            lowered_value,
            str(entry.context or "").lower(),
            str(entry.origin or "").lower(),
        )
        if part
    )
    return any(token in combined for token in _STRONG_SIGNAL_TOKENS)


def should_skip_split_secret_entry(
    entry: IndexedString,
    *,
    artifact_context: Mapping[str, object] | None,
) -> bool:
    """Return whether a split-member string entry should skip secret matching entirely."""

    if not is_split_member_context(artifact_context):
        return False

    origin_type = canonical_origin_type(entry.origin_type)
    if origin_type == "code":
        return False
    if has_strong_secret_signal(entry):
        return False
    return origin_type in {"native", "asset", "rn_bundle", "resource", "raw"}


def should_skip_split_regex_work(
    entry: IndexedString,
    *,
    artifact_context: Mapping[str, object] | None,
) -> bool:
    """Return whether low-value split-member entries should skip expensive regex work."""

    if not is_split_member_context(artifact_context):
        return False

    origin_type = canonical_origin_type(entry.origin_type)
    if origin_type == "code":
        return False
    if has_strong_secret_signal(entry):
        return False

    if origin_type in {"native", "asset", "rn_bundle"}:
        return True
    if origin_type in {"resource", "raw"} and str(entry.confidence or "").lower() == "low":
        return True
    return False


__all__ = [
    "has_strong_secret_signal",
    "is_split_member_context",
    "should_skip_split_secret_entry",
    "should_skip_split_regex_work",
]
