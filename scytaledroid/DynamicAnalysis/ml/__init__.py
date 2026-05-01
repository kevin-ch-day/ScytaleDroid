"""ML module for Paper #2 (unsupervised, offline, evidence-pack driven).

Keep imports lazy because sklearn/scipy are optional for some operator flows.
"""

from __future__ import annotations

from typing import Any

__all__ = ["run_ml_on_evidence_packs"]


def __getattr__(name: str) -> Any:  # pragma: no cover - import-time shim
    if name == "run_ml_on_evidence_packs":
        from .evidence_pack_ml_orchestrator import run_ml_on_evidence_packs as fn

        return fn
    raise AttributeError(name)

