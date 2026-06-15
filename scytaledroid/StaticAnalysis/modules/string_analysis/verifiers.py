"""Optional verifier hook metadata for high-value string candidates.

This module is intentionally network-free. It defines opt-in verifier hook
contracts so the static string layer can describe what *could* be verified
without making live requests during normal analysis.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationHook:
    provider: str
    hook_id: str
    enabled_by_default: bool = False
    network_required: bool = True
    receipt_required: bool = True
    rate_limit_hint: str = "manual"


_HOOKS: tuple[VerificationHook, ...] = (
    VerificationHook(provider="google", hook_id="google_api_key_probe"),
    VerificationHook(provider="stripe", hook_id="stripe_key_probe"),
    VerificationHook(provider="aws", hook_id="aws_token_probe"),
    VerificationHook(provider="github", hook_id="github_token_probe"),
)

_SUPPORTED_PROVIDERS = {hook.provider for hook in _HOOKS}


def available_verification_hooks() -> tuple[VerificationHook, ...]:
    return _HOOKS


def verification_status_for(*, provider: str | None, bucket: str) -> str:
    if bucket not in {"api_keys", "high_entropy"}:
        return "not_applicable"
    if provider and provider.lower() in _SUPPORTED_PROVIDERS:
        return "supported_opt_in"
    return "unverified"


__all__ = [
    "VerificationHook",
    "available_verification_hooks",
    "verification_status_for",
]
