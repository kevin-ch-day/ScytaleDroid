"""Policy helpers for static analysis result orchestration."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.intel_gate import governance_ready

REQUIRED_PAPER_ARTIFACTS: tuple[str, ...] = (
    "static_baseline_json",
    "static_dynamic_plan_json",
    "static_report",
    "manifest_evidence",
    "dep_snapshot",
)

__all__ = ["REQUIRED_PAPER_ARTIFACTS", "governance_ready"]
