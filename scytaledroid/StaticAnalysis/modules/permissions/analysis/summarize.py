"""Formatting helpers for permission analysis summaries and notes."""

from __future__ import annotations


def format_summary(
    *,
    total: int,
    dangerous: int,
    signature: int,
    custom: int,
    health: int = 0,
    background: int = 0,
) -> str:
    if total == 0:
        return "No manifest permissions declared"
    parts = [f"Declared {total}"]
    parts.append(f"dangerous {dangerous}")
    parts.append(f"signature {signature}")
    parts.append(f"custom {custom}")
    if health:
        parts.append(f"health {health}")
    if background:
        parts.append(f"background {background}")
    return ", ".join(parts)


def build_notes(
    *,
    total: int,
    dangerous: int,
    signature: int,
    privileged: int,
    special_access: int,
    health: int = 0,
    background: int = 0,
    catalog_matched: int = 0,
) -> list[str]:
    notes: list[str] = []
    if total == 0:
        return notes
    if dangerous:
        notes.append(f"Contains {dangerous} runtime dangerous permission(s)")
    if signature:
        notes.append(f"Includes {signature} signature level permission(s)")
    if privileged:
        notes.append(f"Declares {privileged} privileged permission(s)")
    if special_access:
        notes.append("Requests permissions gated by special access workflows")
    if health:
        notes.append(f"Requests {health} Health Connect / health-data permission(s)")
    if background:
        notes.append(f"Declares {background} background-sensitive permission(s)")
    if catalog_matched:
        notes.append(
            f"Permission Intel catalog classified {catalog_matched}/{total} declared permission(s)"
        )
    return notes


__all__ = ["format_summary", "build_notes"]