"""Backward-compatible import wrapper.

The dynamic evidence-pack operator menu lives under:
`scytaledroid.DynamicAnalysis.tools.evidence.menu`.
"""

from __future__ import annotations

from .evidence.menu import evidence_packs_menu

__all__ = ["evidence_packs_menu"]

