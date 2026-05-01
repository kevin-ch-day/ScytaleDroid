"""Rendering helpers for static session reconcile menu actions."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import status_messages


def format_collation_preview(package_collations: dict[str, int], *, limit: int = 4) -> str:
    preview = ", ".join(f"{key}={value}" for key, value in sorted(package_collations.items())[:limit])
    remaining = len(package_collations) - min(limit, len(package_collations))
    if remaining > 0:
        preview += f", +{remaining} more"
    return preview


def print_warning_preview(label: str, values: set[str], *, limit: int = 8) -> None:
    if not values:
        return
    preview = ", ".join(sorted(values)[:limit])
    remaining = len(values) - min(limit, len(values))
    if remaining > 0:
        preview += f", +{remaining} more"
    print(status_messages.status(f"{label}: {preview}", level="warn"))
