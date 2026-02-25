"""Compatibility shim for the former `paper_contract.py` module.

Canonical implementation lives in `scytaledroid.DynamicAnalysis.freeze_contract`.
"""

from __future__ import annotations

from typing import Any

from scytaledroid.DynamicAnalysis.freeze_contract import (
    FREEZE_CONTRACT_VERSION as PAPER_CONTRACT_VERSION,
)
from scytaledroid.DynamicAnalysis.freeze_contract import (
    build_freeze_contract_snapshot as _build_freeze_contract_snapshot,
)
from scytaledroid.DynamicAnalysis.freeze_contract import (
    freeze_contract_hash as _freeze_contract_hash,
)

def build_paper_contract_snapshot() -> dict[str, Any]:
    # Kept for backward compatibility. Prefer build_freeze_contract_snapshot().
    return _build_freeze_contract_snapshot()


def paper_contract_hash(snapshot: dict[str, Any] | None = None) -> str:
    # Kept for backward compatibility. Prefer freeze_contract_hash().
    return _freeze_contract_hash(snapshot)


__all__ = [
    "PAPER_CONTRACT_VERSION",
    "build_paper_contract_snapshot",
    "paper_contract_hash",
]
