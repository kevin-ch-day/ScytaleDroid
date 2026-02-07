"""Backward-compatible import wrapper.

Manifest repair utilities live under:
`scytaledroid.DynamicAnalysis.tools.evidence.manifest_repair`.
"""

from __future__ import annotations

from .evidence.manifest_repair import RepairResult, backfill_dataset_block

__all__ = ["RepairResult", "backfill_dataset_block"]

