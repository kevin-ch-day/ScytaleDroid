"""Dynamic analysis post-processing utilities.

Keep imports lazy to avoid circular imports between analysis/core modules.
"""

from __future__ import annotations

from typing import Any

__all__ = ["DynamicRunSummarizer"]


def __getattr__(name: str) -> Any:  # pragma: no cover - import-time shim
    if name == "DynamicRunSummarizer":
        from .summarizer import DynamicRunSummarizer

        return DynamicRunSummarizer
    raise AttributeError(name)

