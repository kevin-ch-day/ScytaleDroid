"""Probe registry helpers for dynamic analysis."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.probes.baseline import run_baseline_probes
from scytaledroid.DynamicAnalysis.probes.targets import run_targeted_probes


def resolve_requested_probes(
    config: DynamicSessionConfig,
    plan_payload: Mapping[str, Any] | None,
) -> list[str]:
    if config.probes:
        return _dedupe([str(item) for item in config.probes])
    if not plan_payload:
        return []
    suggested = plan_payload.get("suggested_probes")
    if isinstance(suggested, Sequence):
        return _dedupe([str(item) for item in suggested if str(item).strip()])
    return []


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def run_probe_set(
    config: DynamicSessionConfig,
    plan_payload: Mapping[str, Any] | None,
) -> dict[str, Any]:
    requested = resolve_requested_probes(config, plan_payload)
    if config.tier == "targeted":
        tier_result = run_targeted_probes(config)
    else:
        tier_result = run_baseline_probes(config)
    probe_results = {
        probe: {
            "status": "pending",
            "notes": "Probe execution not implemented yet.",
        }
        for probe in requested
    }
    return {
        "tier": config.tier,
        "requested_probes": requested,
        "tier_result": tier_result,
        "probe_results": probe_results,
    }


__all__ = ["resolve_requested_probes", "run_probe_set"]
