"""Capability signal classifier (permissions → groups).

Re-exports the classification helpers. Prefer importing from this module.
"""

from __future__ import annotations

from .signals import _GROUP_ORDER, compute_group_strengths, iter_group_hits

__all__ = ["compute_group_strengths", "iter_group_hits", "_GROUP_ORDER"]