"""Formatting helpers for permission analysis summaries and notes."""

from __future__ import annotations

from typing import Iterable, Sequence


def format_summary(*, total: int, dangerous: int, signature: int, custom: int) -> str:
    if total == 0:
        return "No manifest permissions declared"
    parts = [f"Declared {total}"]
    parts.append(f"dangerous {dangerous}")
    parts.append(f"signature {signature}")
    parts.append(f"custom {custom}")
    return ", ".join(parts)


def build_notes(*, total: int, dangerous: int, signature: int, privileged: int, special_access: int) -> list[str]:
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
    return notes


__all__ = ["format_summary", "build_notes"]

