"""Dynamic analysis persistence scaffolding."""

from __future__ import annotations

from typing import Dict, Any

from ..core.session import DynamicSessionConfig, DynamicSessionResult


def persist_dynamic_summary(
    config: DynamicSessionConfig, result: DynamicSessionResult, payload: Dict[str, Any]
) -> None:
    _ = (config, result, payload)
    raise NotImplementedError("Dynamic persistence not implemented yet.")

