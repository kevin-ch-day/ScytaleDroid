"""Shared operator-facing labels for inventory collection modes."""

from __future__ import annotations


def inventory_mode_label(mode: object) -> str | None:
    value = str(mode or "").strip().lower()
    if not value:
        return None
    if value == "bulk":
        return "harvest-ready"
    if value == "baseline":
        return "full device"
    if value == "user_only":
        return "profile-only"
    return value.replace("_", "-")


def inventory_mode_suffix(mode: object, *, prefix: str = " ") -> str:
    label = inventory_mode_label(mode)
    if not label:
        return ""
    return f"{prefix}{label}"


__all__ = ["inventory_mode_label", "inventory_mode_suffix"]
