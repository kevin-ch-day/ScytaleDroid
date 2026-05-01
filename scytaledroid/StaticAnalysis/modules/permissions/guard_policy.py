"""Guard policy overrides for permission strength classification."""

from __future__ import annotations

GUARD_DENYLIST: frozenset[str] = frozenset(
    {
        "android.permission.INTERNET",
    }
)

GUARD_ALLOWLIST: frozenset[str] = frozenset()


def apply_guard_policy(name: str, strength: str) -> str:
    """Apply explicit allow/deny overrides to a guard strength label."""

    lowered = name.lower()
    if lowered in GUARD_DENYLIST:
        return "weak"
    if lowered in GUARD_ALLOWLIST:
        return "signature"
    return strength


__all__ = ["apply_guard_policy", "GUARD_ALLOWLIST", "GUARD_DENYLIST"]
