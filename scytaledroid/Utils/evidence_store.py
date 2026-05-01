"""Filesystem-safe helpers for evidence artifacts."""

from __future__ import annotations

import re


def filesystem_safe_slug(value: str) -> str:
    """Return a filesystem-safe slug for evidence paths."""

    if not value:
        return "evidence"
    cleaned = value.replace(":", "_")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", cleaned)
    return cleaned.strip("_") or "evidence"


__all__ = ["filesystem_safe_slug"]
