"""Runtime flags toggled by menu flows (avoid CLI/env drift)."""

from __future__ import annotations


_ALLOW_INVENTORY_FALLBACKS = False


def set_allow_inventory_fallbacks(enabled: bool) -> None:
    global _ALLOW_INVENTORY_FALLBACKS
    _ALLOW_INVENTORY_FALLBACKS = bool(enabled)


def allow_inventory_fallbacks() -> bool:
    return _ALLOW_INVENTORY_FALLBACKS
