"""Baseline dynamic probes (Tier 0)."""

from __future__ import annotations

from typing import Any

from ..core.session import DynamicSessionConfig


def run_baseline_probes(config: DynamicSessionConfig) -> dict[str, Any]:
    return {
        "status": "pending",
        "duration_seconds": config.duration_seconds,
        "notes": "Baseline probes not implemented yet.",
    }
