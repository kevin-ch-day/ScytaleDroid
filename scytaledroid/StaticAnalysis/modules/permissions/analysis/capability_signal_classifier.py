"""Capability signal classifier (permissions → groups).

Re-exports the classification helpers. Prefer importing from this module.
"""

from __future__ import annotations

from .signals import compute_group_strengths, iter_group_hits, _GROUP_ORDER

__all__ = ["compute_group_strengths", "iter_group_hits", "_GROUP_ORDER"]
