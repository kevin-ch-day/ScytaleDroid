"""Helpers for rejecting ZIP members that would escape an archive root."""

from __future__ import annotations

from pathlib import Path


def is_unsafe_zip_member_name(name: str) -> bool:
    """Return True when extracting *name* would leave the archive root."""

    raw = str(name or "").replace("\\", "/")
    if not raw or raw.startswith("/") or raw.startswith("../") or "/../" in f"/{raw}":
        return True
    parts = Path(raw).parts
    return any(part == ".." or part.startswith("/") for part in parts)
