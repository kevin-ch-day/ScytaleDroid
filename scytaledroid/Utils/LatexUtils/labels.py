"""Stable label helpers for LaTeX outputs."""

from __future__ import annotations

import re


_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def latex_labelify(prefix: str, name: str) -> str:
    """Create a stable LaTeX \\label key, e.g., latex_labelify('tab', 'RDI Summary')."""

    p = (prefix or "").strip().lower()
    n = (name or "").strip().lower()
    if not p:
        p = "item"
    if not n:
        n = "unnamed"
    n = _NON_ALNUM.sub("_", n).strip("_")
    return f"{p}:{n}"


__all__ = ["latex_labelify"]

